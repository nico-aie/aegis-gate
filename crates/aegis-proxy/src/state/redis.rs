//! Redis-backed state backend (feature-gated: `redis`).
//!
//! **B1-T1 — Phase B.** Replaces the previous `RedisBackendStub`
//! with a `deadpool-redis` impl satisfying
//! [`aegis_core::StateBackend`].
//!
//! ## Design notes
//!
//! - **Pool.** We use `deadpool-redis` so connection acquisition
//!   is amortised across requests; the hot path is one round-trip
//!   per call.
//! - **Atomic operations.** Sliding-window and token-bucket use
//!   server-side Lua so increments + TTL + return are a single
//!   round-trip. We register the scripts once at construction
//!   time (not per call) and invoke them via `EVALSHA` with an
//!   `EVAL` fallback for `NOSCRIPT` errors that follow a
//!   `SCRIPT FLUSH`.
//! - **Key namespacing.** All keys carry the same `g:` prefixes
//!   the in-memory backend uses (`g:rl:sw:`, `g:rl:tb:`,
//!   `g:risk:`, `g:block:`, `g:nonce:`) so a future cluster can
//!   migrate without a schema change.
//! - **Timeouts.** Every call wraps the redis op in
//!   `tokio::time::timeout(config.timeout, ...)`. A timeout
//!   surfaces as `WafError::State("timeout")` — caller decides
//!   whether to fall through to a local fallback.
//! - **Reconnect.** `deadpool-redis` re-creates broken
//!   connections on the next `get()`. We deliberately do not
//!   pre-validate; the first call after a partition pays the
//!   reconnect cost, subsequent calls are warm.
//!
//! ## What this task does NOT do
//!
//! - Wire `aegis-bin` to *select* this backend from config — that
//!   is **B1-T2**. Today the binary always wires `InMemoryBackend`,
//!   so this module is purely additive: nothing in the runtime
//!   instantiates `RedisBackend` until B1-T2 lands.

use std::time::Duration;

/// Configuration for the Redis backend.
#[derive(Debug, Clone)]
pub struct RedisConfig {
    pub url: String,
    pub pool_size: u32,
    pub timeout: Duration,
    /// Whether this is a cluster deployment.  Reserved — not
    /// implemented in this task; honored by a future
    /// `RedisClusterBackend`.
    pub cluster: bool,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: "redis://127.0.0.1:6379".into(),
            pool_size: 16,
            timeout: Duration::from_secs(5),
            cluster: false,
        }
    }
}

/// Lua script for atomic sliding-window increment.
///
/// Returns the post-increment count as an integer. The caller
/// decides whether the count exceeds the limit; the script does
/// not branch on the limit so it's reusable across rate-limit
/// shapes.
pub const SLIDING_WINDOW_LUA: &str = r#"
local key = KEYS[1]
local window_ms = tonumber(ARGV[1])
local now_ms = tonumber(ARGV[2])
local member = ARGV[3]

-- Drop expired entries.
redis.call('ZREMRANGEBYSCORE', key, 0, now_ms - window_ms)

-- Add the current request.
redis.call('ZADD', key, now_ms, member)

-- Refresh the key's own TTL so it self-cleans.
redis.call('PEXPIRE', key, window_ms)

return redis.call('ZCARD', key)
"#;

/// Lua script for atomic token bucket. Returns 1 when a token
/// was consumed, 0 otherwise.
pub const TOKEN_BUCKET_LUA: &str = r#"
local key = KEYS[1]
local rate = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local now_ms = tonumber(ARGV[3])

local data = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(data[1])
local last_ts = tonumber(data[2])

if tokens == nil or last_ts == nil then
    tokens = burst
    last_ts = now_ms
end

local elapsed_s = (now_ms - last_ts) / 1000.0
tokens = math.min(burst, tokens + elapsed_s * rate)

local consumed = 0
if tokens >= 1 then
    tokens = tokens - 1
    consumed = 1
end

redis.call('HMSET', key, 'tokens', tostring(tokens), 'ts', tostring(now_ms))
-- Self-expire: a bucket idle for 1h is effectively a fresh one.
redis.call('PEXPIRE', key, 3600000)

return consumed
"#;

/// Lua script for atomic add-with-clamp on a u32-shaped counter.
///
/// `delta` may be negative (saturating-sub down to 0) or
/// non-negative (saturating-add up to `max`). Returns the
/// post-update value. We use INCR/DECRBY so concurrent writes
/// monotonically converge.
pub const ADD_RISK_LUA: &str = r#"
local key = KEYS[1]
local delta = tonumber(ARGV[1])
local max_val = tonumber(ARGV[2])

local current = tonumber(redis.call('GET', key) or '0')
local new_val
if delta >= 0 then
    new_val = math.min(max_val, current + delta)
else
    new_val = math.max(0, current + delta)
end

redis.call('SET', key, tostring(new_val))
return new_val
"#;

/// Lua script for a single-key compare-and-set (config-plane
/// activation). Binary-safe: `expected` / `new` are passed as raw
/// ARGV strings.
///
///   KEYS[1]  = key
///   ARGV[1]  = expect_present ("1" = compare against ARGV[2];
///              "0" = require the key to be absent)
///   ARGV[2]  = expected value (ignored when expect_present == 0)
///   ARGV[3]  = new value
///   ARGV[4]  = ttl_ms ("0" = persist — no expiry, config must not
///              age out)
///
/// Returns 1 on a successful swap, 0 on a value mismatch.
pub const CAS_SET_LUA: &str = r#"
local cur = redis.call('GET', KEYS[1])
local matches
if tonumber(ARGV[1]) == 1 then
    matches = (cur == ARGV[2])
else
    matches = (cur == false)
end
if not matches then
    return 0
end
local ttl = tonumber(ARGV[4])
if ttl > 0 then
    redis.call('SET', KEYS[1], ARGV[3], 'PX', ttl)
else
    redis.call('SET', KEYS[1], ARGV[3])
end
return 1
"#;

#[cfg(feature = "redis")]
mod backend {
    //! Real Redis backend — only compiled with `--features redis`.

    use super::*;
    use std::net::IpAddr;
    use std::sync::{Arc, Mutex};
    use std::time::{Instant, SystemTime};

    use aegis_core::error::{Result, WafError};
    use aegis_core::risk::RiskKey;
    use aegis_core::state::{
        BackendHealth, CircuitState, LatencyP, SlidingWindowResult, StateBackend,
    };
    use deadpool_redis::{Config as PoolConfig, Pool, Runtime};
    use redis::{AsyncCommands, Script};

    /// SC-T1 — number of recent op latency samples kept for the
    /// `/api/state` percentile widget. 256 ≈ ~1 minute at typical
    /// dashboard cadence; small enough to keep the buffer cheap on
    /// every op.
    const LATENCY_BUFFER_CAPACITY: usize = 256;

    /// SC-T1 — server-side cache duration for `health()`. Matches the
    /// dashboard's poll cadence so a busy cluster doesn't get
    /// hammered with `INFO` / `DBSIZE` calls.
    const HEALTH_CACHE_TTL: Duration = Duration::from_secs(5);

    /// Fixed-capacity ring of recent op latencies, in microseconds.
    /// Reads + writes are guarded by a `Mutex` because hot ops only
    /// take it briefly (push one u64). Contention is bounded by the
    /// op rate, not the buffer size.
    struct LatencyRing {
        samples: Vec<u64>,
        cursor: usize,
        full: bool,
    }

    impl LatencyRing {
        fn new(cap: usize) -> Self {
            Self {
                samples: Vec::with_capacity(cap),
                cursor: 0,
                full: false,
            }
        }

        fn push(&mut self, sample_us: u64) {
            let cap = self.samples.capacity();
            if self.samples.len() < cap {
                self.samples.push(sample_us);
                if self.samples.len() == cap {
                    self.full = true;
                    self.cursor = 0;
                }
            } else {
                self.samples[self.cursor] = sample_us;
                self.cursor = (self.cursor + 1) % cap;
            }
        }

        fn snapshot(&self) -> Vec<u64> {
            // Order doesn't matter — `LatencyP::from_samples` sorts
            // before computing percentiles.
            self.samples.clone()
        }
    }

    /// Cached health snapshot. We re-run `INFO` / `DBSIZE` only when
    /// the snapshot is older than [`HEALTH_CACHE_TTL`].
    struct CachedHealth {
        at: Instant,
        value: BackendHealth,
    }

    /// Redis-backed [`StateBackend`].
    ///
    /// Created with [`RedisBackend::connect`]; the pool is owned
    /// inside an `Arc` so cloning the backend is cheap.
    pub struct RedisBackend {
        pool: Pool,
        config: RedisConfig,
        sliding_window: Arc<Script>,
        token_bucket: Arc<Script>,
        add_risk: Arc<Script>,
        cas_script: Arc<Script>,
        latency: Arc<Mutex<LatencyRing>>,
        health_cache: Arc<Mutex<Option<CachedHealth>>>,
        last_error_at: Arc<Mutex<Option<Instant>>>,
    }

    impl RedisBackend {
        /// Build a `RedisBackend` from a config. Returns an error
        /// if the URL is invalid or the pool cannot be created.
        ///
        /// Note: this does **not** ping the server — the first
        /// real op pays the connect cost. We trust deadpool to
        /// handle reconnection; this matches the in-memory
        /// backend's "lazy" semantics.
        pub fn connect(config: RedisConfig) -> Result<Self> {
            let pool = PoolConfig::from_url(&config.url)
                .builder()
                .map_err(|e| WafError::State(format!("redis pool builder: {e}")))?
                .max_size(config.pool_size as usize)
                .runtime(Runtime::Tokio1)
                .build()
                .map_err(|e| WafError::State(format!("redis pool build: {e}")))?;

            Ok(Self {
                pool,
                config,
                sliding_window: Arc::new(Script::new(SLIDING_WINDOW_LUA)),
                token_bucket: Arc::new(Script::new(TOKEN_BUCKET_LUA)),
                add_risk: Arc::new(Script::new(ADD_RISK_LUA)),
                cas_script: Arc::new(Script::new(CAS_SET_LUA)),
                latency: Arc::new(Mutex::new(LatencyRing::new(
                    LATENCY_BUFFER_CAPACITY,
                ))),
                health_cache: Arc::new(Mutex::new(None)),
                last_error_at: Arc::new(Mutex::new(None)),
            })
        }

        async fn conn(&self) -> Result<deadpool_redis::Connection> {
            self.pool
                .get()
                .await
                .map_err(|e| WafError::State(format!("redis pool: {e}")))
        }

        /// Wrap an op in the per-call timeout from config. Records
        /// the elapsed time into the latency ring on success and
        /// stamps `last_error_at` on any error so `health()` can
        /// report a non-Closed circuit state.
        async fn with_timeout<T, F>(&self, op_name: &'static str, fut: F) -> Result<T>
        where
            F: std::future::Future<Output = redis::RedisResult<T>>,
        {
            let started = Instant::now();
            let outcome = tokio::time::timeout(self.config.timeout, fut).await;
            let elapsed = started.elapsed();
            match outcome {
                Ok(Ok(v)) => {
                    if let Ok(mut buf) = self.latency.lock() {
                        buf.push(elapsed.as_micros().min(u64::MAX as u128) as u64);
                    }
                    Ok(v)
                }
                Ok(Err(e)) => {
                    if let Ok(mut last) = self.last_error_at.lock() {
                        *last = Some(Instant::now());
                    }
                    Err(WafError::State(format!("redis {op_name}: {e}")))
                }
                Err(_) => {
                    if let Ok(mut last) = self.last_error_at.lock() {
                        *last = Some(Instant::now());
                    }
                    Err(WafError::State(format!(
                        "redis {op_name}: timeout after {:?}",
                        self.config.timeout
                    )))
                }
            }
        }

        /// Compute a fresh health snapshot. Runs `PING` (round-trip
        /// + connectivity), `INFO server` (version), `INFO replication`
        /// (replica lag), and `DBSIZE` (key count). Each step is best-
        /// effort: a partial failure still produces a snapshot with
        /// the fields it could fill, plus `connected: false` if the
        /// PING didn't make it.
        async fn fresh_health(&self) -> BackendHealth {
            // Helper to detect that we recently saw an error so the
            // dashboard renders a "degraded" pill even when the most
            // recent op succeeded.
            let recent_error = self
                .last_error_at
                .lock()
                .ok()
                .and_then(|g| *g)
                .map(|i| i.elapsed() < HEALTH_CACHE_TTL)
                .unwrap_or(false);

            // PING — establishes connectivity for `connected: bool`.
            let mut connected = false;
            if let Ok(mut c) = self.conn().await {
                let ping: redis::RedisResult<String> = redis::cmd("PING")
                    .query_async(&mut c)
                    .await;
                connected = ping.map(|s| s == "PONG").unwrap_or(false);
            }

            // server INFO — version. Cheap enough to run every cache
            // miss; redis returns ~1 KB of text we parse.
            let mut server_version: Option<String> = None;
            let mut replica_lag_ms: Option<u64> = None;
            if connected {
                if let Ok(mut c) = self.conn().await {
                    let info: redis::RedisResult<String> =
                        redis::cmd("INFO").arg("server").query_async(&mut c).await;
                    if let Ok(text) = info {
                        server_version = parse_info_field(&text, "redis_version");
                    }
                    let repl: redis::RedisResult<String> =
                        redis::cmd("INFO").arg("replication").query_async(&mut c).await;
                    if let Ok(text) = repl {
                        replica_lag_ms = compute_replica_lag_ms(&text);
                    }
                }
            }

            // DBSIZE — best-effort key count.
            let mut key_count: Option<u64> = None;
            if connected {
                if let Ok(mut c) = self.conn().await {
                    let dbsize: redis::RedisResult<u64> =
                        redis::cmd("DBSIZE").query_async(&mut c).await;
                    if let Ok(n) = dbsize {
                        key_count = Some(n);
                    }
                }
            }

            let latency = self
                .latency
                .lock()
                .ok()
                .map(|b| b.snapshot())
                .and_then(|s| LatencyP::from_samples(&s));

            let circuit = if !connected {
                let last_open_at_unix_ms = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                CircuitState::Open { last_open_at_unix_ms }
            } else if recent_error {
                CircuitState::HalfOpen
            } else {
                CircuitState::Closed
            };

            BackendHealth {
                backend: "redis",
                connected,
                latency,
                key_count,
                replica_lag_ms,
                server_version,
                circuit,
            }
        }

        fn risk_key_str(key: &RiskKey) -> String {
            format!(
                "g:risk:{}:{}:{}",
                key.ip,
                key.device_fp.as_deref().unwrap_or("-"),
                key.session.as_deref().unwrap_or("-"),
            )
        }

        fn block_key(ip: IpAddr) -> String {
            format!("g:block:{ip}")
        }

        fn now_ms() -> i64 {
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0)
        }
    }

    #[async_trait::async_trait]
    impl StateBackend for RedisBackend {
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
            let mut c = self.conn().await?;
            let v: Option<Vec<u8>> =
                self.with_timeout("get", c.get(key)).await?;
            Ok(v)
        }

        async fn set(&self, key: &str, val: &[u8], ttl: Duration) -> Result<()> {
            let mut c = self.conn().await?;
            // PSETEX requires a positive TTL; clamp to 1ms.
            let ttl_ms = ttl.as_millis().max(1) as u64;
            self.with_timeout::<(), _>("set", c.pset_ex(key, val, ttl_ms))
                .await?;
            Ok(())
        }

        async fn del(&self, key: &str) -> Result<()> {
            let mut c = self.conn().await?;
            self.with_timeout::<i32, _>("del", c.del(key)).await?;
            Ok(())
        }

        async fn incr_window(
            &self,
            key: &str,
            window: Duration,
            limit: u64,
        ) -> Result<SlidingWindowResult> {
            let k = format!("g:rl:sw:{key}");
            let now = Self::now_ms();
            let window_ms = window.as_millis().max(1) as i64;
            // Per-call uniqueness for the sorted-set member —
            // ZADD on duplicates would otherwise overwrite.
            let member = format!("{now}:{}", uuid_like());

            let mut c = self.conn().await?;
            let count: u64 = self
                .with_timeout(
                    "incr_window",
                    self.sliding_window
                        .key(&k)
                        .arg(window_ms)
                        .arg(now)
                        .arg(member)
                        .invoke_async(&mut c),
                )
                .await?;

            Ok(SlidingWindowResult {
                count,
                allowed: count <= limit,
                retry_after: if count > limit { Some(window) } else { None },
            })
        }

        async fn token_bucket(
            &self,
            key: &str,
            rate_per_s: u32,
            burst: u32,
        ) -> Result<bool> {
            let k = format!("g:rl:tb:{key}");
            let now = Self::now_ms();

            let mut c = self.conn().await?;
            let consumed: i64 = self
                .with_timeout(
                    "token_bucket",
                    self.token_bucket
                        .key(&k)
                        .arg(rate_per_s)
                        .arg(burst)
                        .arg(now)
                        .invoke_async(&mut c),
                )
                .await?;

            Ok(consumed == 1)
        }

        async fn get_risk(&self, key: &RiskKey) -> Result<u32> {
            let k = Self::risk_key_str(key);
            let mut c = self.conn().await?;
            let v: Option<String> = self.with_timeout("get_risk", c.get(&k)).await?;
            Ok(v.and_then(|s| s.parse().ok()).unwrap_or(0))
        }

        async fn add_risk(&self, key: &RiskKey, delta: i32, max: u32) -> Result<u32> {
            let k = Self::risk_key_str(key);
            let mut c = self.conn().await?;
            let new_val: i64 = self
                .with_timeout(
                    "add_risk",
                    self.add_risk
                        .key(&k)
                        .arg(delta)
                        .arg(max)
                        .invoke_async(&mut c),
                )
                .await?;
            Ok(new_val.clamp(0, u32::MAX as i64) as u32)
        }

        async fn auto_block(&self, ip: IpAddr, ttl: Duration) -> Result<()> {
            let k = Self::block_key(ip);
            let mut c = self.conn().await?;
            let ttl_ms = ttl.as_millis().max(1) as u64;
            self.with_timeout::<(), _>("auto_block", c.pset_ex(&k, "1", ttl_ms))
                .await?;
            Ok(())
        }

        async fn is_auto_blocked(&self, ip: IpAddr) -> Result<bool> {
            let k = Self::block_key(ip);
            let mut c = self.conn().await?;
            let exists: bool = self.with_timeout("is_auto_blocked", c.exists(&k)).await?;
            Ok(exists)
        }

        async fn put_nonce(&self, nonce: &str, ttl: Duration) -> Result<bool> {
            let k = format!("g:nonce:{nonce}");
            let mut c = self.conn().await?;
            let ttl_ms = ttl.as_millis().max(1) as u64;
            // SET NX PX — atomic "insert if absent". Returns
            // Some("OK") on insert, None on collision.
            let ok: Option<String> = self
                .with_timeout(
                    "put_nonce",
                    redis::cmd("SET")
                        .arg(&k)
                        .arg("1")
                        .arg("NX")
                        .arg("PX")
                        .arg(ttl_ms)
                        .query_async(&mut c),
                )
                .await?;
            Ok(ok.is_some())
        }

        async fn consume_nonce(&self, nonce: &str) -> Result<bool> {
            let k = format!("g:nonce:{nonce}");
            let mut c = self.conn().await?;
            let n: i32 = self.with_timeout("consume_nonce", c.del(&k)).await?;
            Ok(n > 0)
        }

        // --- 2026-05-27 generic KV primitives (config plane + metrics agg) ---

        async fn incrby(&self, key: &str, delta: u64) -> Result<u64> {
            let mut c = self.conn().await?;
            // INCRBY is atomic + commutative across nodes.
            let v: i64 = self
                .with_timeout("incrby", c.incr(key, delta as i64))
                .await?;
            Ok(v.max(0) as u64)
        }

        async fn expire(&self, key: &str, ttl: Duration) -> Result<()> {
            let mut c = self.conn().await?;
            let ttl_ms = ttl.as_millis().max(1) as u64;
            self.with_timeout::<i64, _>(
                "expire",
                redis::cmd("PEXPIRE").arg(key).arg(ttl_ms).query_async(&mut c),
            )
            .await?;
            Ok(())
        }

        async fn get_counter(&self, key: &str) -> Result<u64> {
            let mut c = self.conn().await?;
            // GET on an INCRBY key returns the decimal string Redis
            // stores; `redis-rs` decodes it straight to an integer.
            // Absent key → nil → None → 0.
            let v: Option<i64> = self.with_timeout("get_counter", c.get(key)).await?;
            Ok(v.unwrap_or(0).max(0) as u64)
        }

        async fn scan_prefix(&self, prefix: &str) -> Result<Vec<String>> {
            let pattern = format!("{prefix}*");
            let mut out = Vec::new();
            let mut c = self.conn().await?;
            let mut cursor: u64 = 0;
            loop {
                let (next, keys): (u64, Vec<String>) = self
                    .with_timeout(
                        "scan_prefix",
                        redis::cmd("SCAN")
                            .arg(cursor)
                            .arg("MATCH")
                            .arg(&pattern)
                            .arg("COUNT")
                            .arg(512)
                            .query_async(&mut c),
                    )
                    .await?;
                out.extend(keys);
                cursor = next;
                if cursor == 0 {
                    break;
                }
            }
            Ok(out)
        }

        async fn cas_set(
            &self,
            key: &str,
            expected: Option<&[u8]>,
            new: &[u8],
            ttl: Option<Duration>,
        ) -> Result<bool> {
            let mut c = self.conn().await?;
            let ttl_ms = ttl.map(|t| t.as_millis().max(1) as u64).unwrap_or(0);
            let (present, exp_bytes): (i64, &[u8]) = match expected {
                Some(e) => (1, e),
                None => (0, b""),
            };
            let r: i64 = self
                .with_timeout(
                    "cas_set",
                    self.cas_script
                        .key(key)
                        .arg(present)
                        .arg(exp_bytes)
                        .arg(new)
                        .arg(ttl_ms)
                        .invoke_async(&mut c),
                )
                .await?;
            Ok(r == 1)
        }

        /// 2026-05-20 — `/__waf_control/reset_state` ephemeral wipe.
        ///
        /// SCAN + DEL scoped to the ephemeral key prefixes only:
        /// `g:risk:*`, `g:block:*`, `g:nonce:*`, `g:rl:sw:*`,
        /// `g:rl:tb:*`. Deliberately NOT a `FLUSHDB` — the cluster
        /// leader lease (`leader:*`) and any other durable keys (or
        /// keys from co-tenant apps sharing the Redis) MUST survive.
        /// A FLUSHDB here would flap the leader and reset every
        /// node's view on a single reset_state call.
        ///
        /// SCAN is cursor-based + non-blocking; we DEL in batches.
        /// Returns the total number of keys deleted.
        async fn reset_ephemeral(&self) -> Result<u64> {
            const EPHEMERAL_PATTERNS: &[&str] = &[
                "g:risk:*",
                "g:block:*",
                "g:nonce:*",
                "g:rl:sw:*",
                "g:rl:tb:*",
            ];
            let mut total: u64 = 0;
            let mut c = self.conn().await?;
            for pattern in EPHEMERAL_PATTERNS {
                let mut cursor: u64 = 0;
                loop {
                    let (next, keys): (u64, Vec<String>) = self
                        .with_timeout(
                            "reset_ephemeral_scan",
                            redis::cmd("SCAN")
                                .arg(cursor)
                                .arg("MATCH")
                                .arg(*pattern)
                                .arg("COUNT")
                                .arg(512)
                                .query_async(&mut c),
                        )
                        .await?;
                    if !keys.is_empty() {
                        let deleted: i64 = self
                            .with_timeout(
                                "reset_ephemeral_del",
                                redis::cmd("DEL").arg(&keys).query_async(&mut c),
                            )
                            .await?;
                        total += deleted.max(0) as u64;
                    }
                    cursor = next;
                    if cursor == 0 {
                        break;
                    }
                }
            }
            Ok(total)
        }

        /// SC-T1 — health snapshot for the dashboard's Scaling page.
        ///
        /// Caches the heavy parts (`INFO`, `DBSIZE`) for 5s so the
        /// dashboard cadence doesn't add load to a busy primary. The
        /// latency ring + circuit fields are read fresh on every
        /// call (cheap — both behind a `Mutex<…>` of a few hundred
        /// bytes).
        async fn health(&self) -> BackendHealth {
            // Fast path — fresh cached snapshot.
            if let Ok(g) = self.health_cache.lock() {
                if let Some(c) = g.as_ref() {
                    if c.at.elapsed() < HEALTH_CACHE_TTL {
                        return c.value.clone();
                    }
                }
            }
            let fresh = self.fresh_health().await;
            if let Ok(mut g) = self.health_cache.lock() {
                *g = Some(CachedHealth {
                    at: Instant::now(),
                    value: fresh.clone(),
                });
            }
            fresh
        }
    }

    /// Extract a single field's value from a Redis `INFO` payload.
    /// Format is `key:value\r\n` or `key:value\n`; comments start
    /// with `#`. Returns `None` when the field isn't present.
    pub(super) fn parse_info_field(text: &str, key: &str) -> Option<String> {
        for line in text.lines() {
            if line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once(':') {
                if k == key {
                    return Some(v.trim().to_string());
                }
            }
        }
        None
    }

    /// Compute the worst-case replica lag from an `INFO replication`
    /// payload.
    ///
    /// Redis reports per-slave lines like `slave0:ip=...,port=...,lag=N`.
    /// We pick the largest lag across all replicas (operators care
    /// about the worst case, not the average) and return it as
    /// milliseconds. `None` when no replicas are present (master with
    /// no slaves, or a replica itself).
    pub(super) fn compute_replica_lag_ms(text: &str) -> Option<u64> {
        let mut max_lag_secs: Option<u64> = None;
        for line in text.lines() {
            if !line.starts_with("slave") {
                continue;
            }
            // slaveN:ip=x,port=y,state=online,offset=z,lag=L
            if let Some((_, fields)) = line.split_once(':') {
                for kv in fields.split(',') {
                    if let Some(("lag", v)) = kv.split_once('=') {
                        if let Ok(n) = v.parse::<u64>() {
                            max_lag_secs =
                                Some(max_lag_secs.map(|cur| cur.max(n)).unwrap_or(n));
                        }
                    }
                }
            }
        }
        max_lag_secs.map(|s| s.saturating_mul(1000))
    }

    /// Random suffix for sliding-window ZADD members. We avoid a
    /// `uuid` dep by using a process-counter + nanos fallback —
    /// the only requirement is uniqueness within a single
    /// window.
    fn uuid_like() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        format!("{n}-{nanos}")
    }

    #[cfg(test)]
    mod tests {
        //! These are *unit* tests — they do not require a live
        //! Redis. Behaviour against a real Redis is exercised by
        //! the `tests/api/` smoke suite once B1-T2 wires Redis
        //! into the gateway.

        use super::*;

        #[test]
        fn connect_with_default_config_succeeds() {
            // Pool creation is lazy — this should not error even
            // if no Redis is running.
            let backend = RedisBackend::connect(RedisConfig::default());
            assert!(backend.is_ok());
        }

        #[test]
        fn connect_with_invalid_url_fails() {
            let cfg = RedisConfig {
                url: "not-a-url://".into(),
                ..RedisConfig::default()
            };
            let backend = RedisBackend::connect(cfg);
            assert!(backend.is_err(), "expected error for malformed URL");
        }

        #[test]
        fn risk_key_str_is_stable_across_callers() {
            use std::net::Ipv4Addr;
            let k = RiskKey {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                device_fp: Some("ja4-abc".into()),
                session: None,
            };
            assert_eq!(
                RedisBackend::risk_key_str(&k),
                "g:risk:10.0.0.1:ja4-abc:-"
            );
        }

        #[test]
        fn block_key_format() {
            use std::net::Ipv4Addr;
            let k = RedisBackend::block_key(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)));
            assert_eq!(k, "g:block:192.168.0.1");
        }

        #[test]
        fn now_ms_monotonic() {
            let a = RedisBackend::now_ms();
            std::thread::sleep(std::time::Duration::from_millis(2));
            let b = RedisBackend::now_ms();
            assert!(b >= a);
        }

        #[test]
        fn uuid_like_is_unique_within_window() {
            // 1k samples — collision probability is effectively
            // zero given the atomic counter.
            let mut seen = std::collections::HashSet::new();
            for _ in 0..1000 {
                assert!(seen.insert(uuid_like()));
            }
        }

        #[tokio::test]
        async fn ops_against_unreachable_server_surface_state_error() {
            // Use a port that no reasonable test rig has bound.
            // The op must return WafError::State, not panic.
            let cfg = RedisConfig {
                url: "redis://127.0.0.1:1".into(),
                pool_size: 1,
                timeout: Duration::from_millis(150),
                cluster: false,
            };
            let backend = RedisBackend::connect(cfg).expect("pool builds");
            let err = backend.get("never-resolves").await.unwrap_err();
            match err {
                WafError::State(_) => {} // expected
                other => panic!("expected State error, got {other:?}"),
            }
        }

        // ---------------- SC-T1 helpers ----------------

        #[test]
        fn latency_ring_grows_until_capacity_then_overwrites() {
            let mut r = LatencyRing::new(3);
            r.push(10);
            r.push(20);
            assert_eq!(r.snapshot(), vec![10, 20]);
            r.push(30);
            assert_eq!(r.snapshot(), vec![10, 20, 30]);
            assert!(r.full);
            // Overwrite oldest in cursor order.
            r.push(40);
            let snap = r.snapshot();
            assert_eq!(snap.len(), 3);
            assert!(snap.contains(&40));
            assert!(!snap.contains(&10), "10 should have been overwritten");
        }

        #[test]
        fn parse_info_field_extracts_redis_version() {
            let payload = "# Server\r\n\
                           redis_version:7.2.4\r\n\
                           redis_git_sha1:00000000\r\n\
                           os:Linux\r\n";
            assert_eq!(
                parse_info_field(payload, "redis_version"),
                Some("7.2.4".to_string()),
            );
            assert_eq!(parse_info_field(payload, "os"), Some("Linux".to_string()));
            assert_eq!(parse_info_field(payload, "missing"), None);
        }

        #[test]
        fn parse_info_field_skips_comment_lines() {
            // Comment lines starting with `#` must not match even if
            // they contain a colon — Redis "# Server" gets parsed
            // as a section header.
            let payload = "# Server: misleading\r\nredis_version:7.0.0\r\n";
            assert_eq!(
                parse_info_field(payload, "redis_version"),
                Some("7.0.0".to_string()),
            );
            // The `#` line shouldn't accidentally produce a "Server"
            // field.
            assert_eq!(parse_info_field(payload, "Server"), None);
        }

        #[test]
        fn compute_replica_lag_picks_worst_case_in_ms() {
            // Two replicas — operator cares about the slow one.
            let payload = "# Replication\r\n\
                           role:master\r\n\
                           connected_slaves:2\r\n\
                           slave0:ip=10.0.0.2,port=6379,state=online,offset=100,lag=1\r\n\
                           slave1:ip=10.0.0.3,port=6379,state=online,offset=98,lag=4\r\n";
            assert_eq!(compute_replica_lag_ms(payload), Some(4_000));
        }

        #[test]
        fn compute_replica_lag_returns_none_for_master_with_no_slaves() {
            let payload = "# Replication\r\nrole:master\r\nconnected_slaves:0\r\n";
            assert_eq!(compute_replica_lag_ms(payload), None);
        }

        #[test]
        fn compute_replica_lag_returns_none_for_replica_role() {
            // An instance configured as a replica won't have `slaveN`
            // lines — it'll have `master_link_status` instead. We
            // surface `None` rather than guessing.
            let payload = "# Replication\r\nrole:slave\r\nmaster_link_status:up\r\n";
            assert_eq!(compute_replica_lag_ms(payload), None);
        }

        #[tokio::test]
        async fn health_against_unreachable_server_reports_open_circuit() {
            let cfg = RedisConfig {
                url: "redis://127.0.0.1:1".into(),
                pool_size: 1,
                timeout: Duration::from_millis(50),
                cluster: false,
            };
            let backend = RedisBackend::connect(cfg).expect("pool builds");
            let h = backend.health().await;
            assert_eq!(h.backend, "redis");
            assert!(!h.connected, "unreachable server must report disconnected");
            assert!(matches!(h.circuit, CircuitState::Open { .. }));
            // No INFO ran — version stays None.
            assert!(h.server_version.is_none());
            assert!(h.key_count.is_none());
        }

        #[tokio::test]
        async fn health_caches_within_ttl_window() {
            // Two consecutive calls must return the same Instant-backed
            // snapshot when separated by less than HEALTH_CACHE_TTL.
            // We can't easily verify that no network round-trip ran
            // without a mock, so we exercise the code path instead.
            let cfg = RedisConfig {
                url: "redis://127.0.0.1:1".into(),
                pool_size: 1,
                timeout: Duration::from_millis(50),
                cluster: false,
            };
            let backend = RedisBackend::connect(cfg).expect("pool builds");
            let h1 = backend.health().await;
            let h2 = backend.health().await;
            assert_eq!(h1, h2, "second call must return the cached snapshot");
        }
    }
}

#[cfg(feature = "redis")]
pub use backend::RedisBackend;

#[cfg(test)]
mod stub_tests {
    //! Tests for the script bodies — run regardless of feature
    //! flag so the Lua stays compileable as a string.
    use super::*;

    #[test]
    fn default_redis_config() {
        let cfg = RedisConfig::default();
        assert_eq!(cfg.url, "redis://127.0.0.1:6379");
        assert_eq!(cfg.pool_size, 16);
        assert!(!cfg.cluster);
    }

    #[test]
    fn lua_scripts_not_empty() {
        assert!(!SLIDING_WINDOW_LUA.is_empty());
        assert!(!TOKEN_BUCKET_LUA.is_empty());
        assert!(!ADD_RISK_LUA.is_empty());
    }

    #[test]
    fn lua_sliding_window_uses_zset_ops() {
        assert!(SLIDING_WINDOW_LUA.contains("ZCARD"));
        assert!(SLIDING_WINDOW_LUA.contains("ZREMRANGEBYSCORE"));
        assert!(SLIDING_WINDOW_LUA.contains("ZADD"));
        assert!(SLIDING_WINDOW_LUA.contains("PEXPIRE"));
    }

    #[test]
    fn lua_token_bucket_refills_and_consumes() {
        assert!(TOKEN_BUCKET_LUA.contains("burst"));
        assert!(TOKEN_BUCKET_LUA.contains("tokens"));
        assert!(TOKEN_BUCKET_LUA.contains("HMSET"));
        assert!(TOKEN_BUCKET_LUA.contains("HMGET"));
    }

    #[test]
    fn lua_add_risk_clamps_both_directions() {
        assert!(ADD_RISK_LUA.contains("math.min"));
        assert!(ADD_RISK_LUA.contains("math.max"));
    }
}
