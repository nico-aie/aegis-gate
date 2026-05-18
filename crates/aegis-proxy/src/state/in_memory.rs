use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;

use aegis_core::error::Result;
use aegis_core::risk::RiskKey;
use aegis_core::state::{
    BackendHealth, CircuitState, SlidingWindowResult, StateBackend,
};

struct Entry {
    value: Vec<u8>,
    expires_at: Option<Instant>,
}

impl Entry {
    fn is_expired(&self) -> bool {
        self.expires_at
            .map(|t| Instant::now() >= t)
            .unwrap_or(false)
    }
}

pub struct InMemoryBackend {
    kv: Arc<DashMap<String, Entry>>,
}

impl InMemoryBackend {
    pub fn new() -> Self {
        Self {
            kv: Arc::new(DashMap::new()),
        }
    }

    /// Spawn a background task that periodically sweeps expired entries.
    pub fn spawn_reaper(&self, interval: Duration) -> tokio::task::JoinHandle<()> {
        let kv = self.kv.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            loop {
                tick.tick().await;
                kv.retain(|_, entry| !entry.is_expired());
            }
        })
    }

    /// Number of entries currently stored (including possibly expired).
    pub fn len(&self) -> usize {
        self.kv.len()
    }

    pub fn is_empty(&self) -> bool {
        self.kv.is_empty()
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
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl StateBackend for InMemoryBackend {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        match self.kv.get(key) {
            Some(entry) if !entry.is_expired() => Ok(Some(entry.value.clone())),
            Some(_) => {
                self.kv.remove(key);
                Ok(None)
            }
            None => Ok(None),
        }
    }

    async fn set(&self, key: &str, val: &[u8], ttl: Duration) -> Result<()> {
        self.kv.insert(
            key.to_string(),
            Entry {
                value: val.to_vec(),
                expires_at: Some(Instant::now() + ttl),
            },
        );
        Ok(())
    }

    async fn del(&self, key: &str) -> Result<()> {
        self.kv.remove(key);
        Ok(())
    }

    async fn incr_window(
        &self,
        key: &str,
        window: Duration,
        limit: u64,
    ) -> Result<SlidingWindowResult> {
        let k = format!("g:rl:sw:{key}");
        let now = Instant::now();

        let mut entry = self.kv.entry(k).or_insert_with(|| Entry {
            value: 0u64.to_le_bytes().to_vec(),
            expires_at: Some(now + window),
        });

        if entry.is_expired() {
            entry.value = 1u64.to_le_bytes().to_vec();
            entry.expires_at = Some(now + window);
            return Ok(SlidingWindowResult {
                count: 1,
                allowed: 1 <= limit,
                retry_after: if 1 > limit {
                    Some(window)
                } else {
                    None
                },
            });
        }

        let current = u64::from_le_bytes(
            entry.value[..8].try_into().unwrap_or([0; 8]),
        );
        let new_count = current + 1;
        entry.value = new_count.to_le_bytes().to_vec();

        Ok(SlidingWindowResult {
            count: new_count,
            allowed: new_count <= limit,
            retry_after: if new_count > limit {
                entry.expires_at.map(|e| e.duration_since(now))
            } else {
                None
            },
        })
    }

    async fn token_bucket(
        &self,
        key: &str,
        rate_per_s: u32,
        burst: u32,
    ) -> Result<bool> {
        let k = format!("g:rl:tb:{key}");
        let now = Instant::now();

        let mut entry = self.kv.entry(k).or_insert_with(|| {
            let tokens_and_ts = encode_bucket(burst as f64, now);
            Entry {
                value: tokens_and_ts,
                expires_at: None,
            }
        });

        let (tokens, last) = decode_bucket(&entry.value);
        let elapsed = now.duration_since(last).as_secs_f64();
        let refilled = (tokens + elapsed * rate_per_s as f64).min(burst as f64);

        if refilled >= 1.0 {
            entry.value = encode_bucket(refilled - 1.0, now);
            Ok(true)
        } else {
            entry.value = encode_bucket(refilled, now);
            Ok(false)
        }
    }

    async fn get_risk(&self, key: &RiskKey) -> Result<u32> {
        let k = Self::risk_key_str(key);
        match self.kv.get(&k) {
            Some(entry) if !entry.is_expired() => {
                let val = u32::from_le_bytes(
                    entry.value[..4].try_into().unwrap_or([0; 4]),
                );
                Ok(val)
            }
            _ => Ok(0),
        }
    }

    async fn add_risk(&self, key: &RiskKey, delta: i32, max: u32) -> Result<u32> {
        // F-HIGH-stateful (2026-05-17 s-tester audit): pre-fix the
        // entry had `expires_at: None` so every IP that ever made
        // a request kept a risk-score row in memory forever. Under
        // sustained traffic from many unique IPs (bot scan, large
        // fleet) the DashMap grew unbounded. Now each write sets a
        // 24-hour TTL; the `spawn_reaper` task evicts expired
        // entries periodically. The TTL is several multiples of
        // `cfg.risk.decay_half_life` (default 5 min) so an entry
        // past the cutoff is statistically zero anyway.
        let k = Self::risk_key_str(key);
        let new_expiry = Some(Instant::now() + Duration::from_secs(24 * 3600));
        let mut entry = self.kv.entry(k).or_insert_with(|| Entry {
            value: 0u32.to_le_bytes().to_vec(),
            expires_at: new_expiry,
        });

        let current = u32::from_le_bytes(
            entry.value[..4].try_into().unwrap_or([0; 4]),
        );
        let new_val = if delta >= 0 {
            current.saturating_add(delta as u32).min(max)
        } else {
            current.saturating_sub(delta.unsigned_abs())
        };
        entry.value = new_val.to_le_bytes().to_vec();
        // Slide the TTL on every write — an IP that keeps tripping
        // the gate keeps its row alive. Once it goes quiet the row
        // ages out within 24 h.
        entry.expires_at = new_expiry;
        Ok(new_val)
    }

    async fn auto_block(&self, ip: IpAddr, ttl: Duration) -> Result<()> {
        let k = Self::block_key(ip);
        self.kv.insert(
            k,
            Entry {
                value: vec![1],
                expires_at: Some(Instant::now() + ttl),
            },
        );
        Ok(())
    }

    async fn is_auto_blocked(&self, ip: IpAddr) -> Result<bool> {
        let k = Self::block_key(ip);
        match self.kv.get(&k) {
            Some(entry) if !entry.is_expired() => Ok(true),
            Some(_) => {
                self.kv.remove(&k);
                Ok(false)
            }
            None => Ok(false),
        }
    }

    async fn put_nonce(&self, nonce: &str, ttl: Duration) -> Result<bool> {
        let k = format!("g:nonce:{nonce}");
        if self.kv.contains_key(&k) {
            return Ok(false);
        }
        self.kv.insert(
            k,
            Entry {
                value: vec![1],
                expires_at: Some(Instant::now() + ttl),
            },
        );
        Ok(true)
    }

    async fn consume_nonce(&self, nonce: &str) -> Result<bool> {
        let k = format!("g:nonce:{nonce}");
        Ok(self.kv.remove(&k).is_some())
    }

    /// SC-T1 — health snapshot for the in-memory backend.
    ///
    /// Always reports `connected: true` (the data structure is owned
    /// in-process; there's no remote to lose). Latency / replica-lag
    /// / version are `None` — the in-memory path doesn't measure
    /// them and surfacing fake numbers would only confuse the
    /// dashboard. Key count is the live `DashMap::len`.
    async fn health(&self) -> BackendHealth {
        BackendHealth {
            backend: "in_memory",
            connected: true,
            latency: None,
            key_count: Some(self.kv.len() as u64),
            replica_lag_ms: None,
            server_version: None,
            circuit: CircuitState::Closed,
        }
    }
}

/// Process-monotonic anchor used by `encode_bucket` / `decode_bucket`
/// to serialise/deserialise an `Instant` as a `u64` nanos-since-epoch
/// offset. Initialised on first access at boot; stable for the
/// lifetime of the process.
fn bucket_epoch() -> Instant {
    static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    *EPOCH.get_or_init(Instant::now)
}

fn encode_bucket(tokens: f64, ts: Instant) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16);
    buf.extend_from_slice(&tokens.to_le_bytes());
    // Pre-2026-05-17 (BUG-F-CRITICAL-007): this stored
    // `ts.elapsed().as_nanos()` which is always near-zero relative
    // to `ts == now` at write time, and `decode_bucket` discarded
    // the field entirely. Result: bucket never refilled — every IP
    // got exactly `burst` requests then permanent 429. Now we store
    // `ts` as nanos-since-process-epoch so decode can reconstruct
    // the real Instant and compute genuine elapsed time between
    // writes.
    let nanos = ts.saturating_duration_since(bucket_epoch()).as_nanos() as u64;
    buf.extend_from_slice(&nanos.to_le_bytes());
    buf
}

fn decode_bucket(data: &[u8]) -> (f64, Instant) {
    let tokens = f64::from_le_bytes(data[..8].try_into().unwrap_or([0; 8]));
    let nanos = u64::from_le_bytes(data[8..16].try_into().unwrap_or([0; 8]));
    let ts = bucket_epoch() + Duration::from_nanos(nanos);
    (tokens, ts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn backend() -> InMemoryBackend {
        InMemoryBackend::new()
    }

    #[tokio::test]
    async fn get_set_del() {
        let b = backend();
        b.set("key1", b"hello", Duration::from_secs(60)).await.unwrap();
        let val = b.get("key1").await.unwrap();
        assert_eq!(val, Some(b"hello".to_vec()));

        b.del("key1").await.unwrap();
        let val = b.get("key1").await.unwrap();
        assert!(val.is_none());
    }

    #[tokio::test]
    async fn get_returns_none_for_missing_key() {
        let b = backend();
        let val = b.get("nonexistent").await.unwrap();
        assert!(val.is_none());
    }

    #[tokio::test]
    async fn sliding_window_increments() {
        let b = backend();
        let r1 = b.incr_window("test-ip", Duration::from_secs(60), 5).await.unwrap();
        assert_eq!(r1.count, 1);
        assert!(r1.allowed);

        let r2 = b.incr_window("test-ip", Duration::from_secs(60), 5).await.unwrap();
        assert_eq!(r2.count, 2);
        assert!(r2.allowed);
    }

    #[tokio::test]
    async fn sliding_window_exceeds_limit() {
        let b = backend();
        for _ in 0..5 {
            b.incr_window("flood", Duration::from_secs(60), 5).await.unwrap();
        }
        let r = b.incr_window("flood", Duration::from_secs(60), 5).await.unwrap();
        assert_eq!(r.count, 6);
        assert!(!r.allowed);
        assert!(r.retry_after.is_some());
    }

    #[tokio::test]
    async fn token_bucket_allows_within_burst() {
        let b = backend();
        // burst=3, so first 3 should succeed
        assert!(b.token_bucket("api", 1, 3).await.unwrap());
        assert!(b.token_bucket("api", 1, 3).await.unwrap());
        assert!(b.token_bucket("api", 1, 3).await.unwrap());
    }

    #[tokio::test]
    async fn token_bucket_denies_after_burst_exhausted() {
        // Regression for F-CRITICAL-007: prior to 2026-05-17,
        // `decode_bucket` discarded the stored timestamp and returned
        // `Instant::now()` so `elapsed` was always 0, refill was
        // always 0, and the 4th call here used to *succeed* (the
        // tokens field stayed at exactly `burst` forever). After
        // the fix the bucket is properly drained.
        let b = backend();
        // burst=3, rate=1/s — exhaust within a few ms (well under
        // any refill).
        assert!(b.token_bucket("ip1", 1, 3).await.unwrap());
        assert!(b.token_bucket("ip1", 1, 3).await.unwrap());
        assert!(b.token_bucket("ip1", 1, 3).await.unwrap());
        // 4th call within the same window must be denied.
        assert!(!b.token_bucket("ip1", 1, 3).await.unwrap());
    }

    #[tokio::test]
    async fn token_bucket_refills_after_window() {
        // Regression for F-CRITICAL-007 (companion): once the
        // window elapses, the bucket must refill. Run at rate=100/s
        // so a 50 ms sleep produces ~5 fresh tokens.
        let b = backend();
        assert!(b.token_bucket("ip2", 100, 3).await.unwrap());
        assert!(b.token_bucket("ip2", 100, 3).await.unwrap());
        assert!(b.token_bucket("ip2", 100, 3).await.unwrap());
        assert!(!b.token_bucket("ip2", 100, 3).await.unwrap());
        tokio::time::sleep(Duration::from_millis(50)).await;
        // After refill (50 ms × 100/s = 5 tokens, capped at burst=3)
        // at least one call must succeed.
        assert!(b.token_bucket("ip2", 100, 3).await.unwrap());
    }

    #[tokio::test]
    async fn risk_score_starts_at_zero() {
        let b = backend();
        let key = RiskKey {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            device_fp: None,
            session: None,
            tenant_id: None,
        };
        assert_eq!(b.get_risk(&key).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn risk_score_add_and_clamp() {
        let b = backend();
        let key = RiskKey {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            device_fp: None,
            session: None,
            tenant_id: None,
        };
        let v = b.add_risk(&key, 50, 100).await.unwrap();
        assert_eq!(v, 50);

        let v = b.add_risk(&key, 70, 100).await.unwrap();
        assert_eq!(v, 100); // clamped to max

        let v = b.add_risk(&key, -30, 100).await.unwrap();
        assert_eq!(v, 70);
    }

    #[tokio::test]
    async fn risk_score_entries_get_a_ttl_so_reaper_can_evict() {
        // F-HIGH-stateful regression. Pre-fix `add_risk` created
        // entries with `expires_at: None` so they lived forever —
        // the kv DashMap grew unbounded under sustained traffic
        // from many unique IPs. After the fix every write sets a
        // TTL, and the reaper task evicts entries past it.
        let b = backend();
        let key = RiskKey {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)),
            device_fp: None,
            session: None,
            tenant_id: None,
        };
        b.add_risk(&key, 10, 100).await.unwrap();
        // Reach into the DashMap to verify the TTL is non-None.
        // The risk row key matches `risk_key_str`.
        let k = InMemoryBackend::risk_key_str(&key);
        let entry = b.kv.get(&k).expect("entry must exist");
        assert!(
            entry.expires_at.is_some(),
            "risk entry must have an expires_at so spawn_reaper can evict it",
        );
    }

    #[tokio::test]
    async fn auto_block_and_check() {
        let b = backend();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

        assert!(!b.is_auto_blocked(ip).await.unwrap());
        b.auto_block(ip, Duration::from_secs(300)).await.unwrap();
        assert!(b.is_auto_blocked(ip).await.unwrap());
    }

    #[tokio::test]
    async fn nonce_put_and_consume() {
        let b = backend();

        // First put succeeds
        assert!(b.put_nonce("abc123", Duration::from_secs(60)).await.unwrap());
        // Duplicate put fails
        assert!(!b.put_nonce("abc123", Duration::from_secs(60)).await.unwrap());

        // Consume succeeds once
        assert!(b.consume_nonce("abc123").await.unwrap());
        // Second consume fails
        assert!(!b.consume_nonce("abc123").await.unwrap());
    }

    #[tokio::test]
    async fn nonce_consume_nonexistent() {
        let b = backend();
        assert!(!b.consume_nonce("doesnotexist").await.unwrap());
    }

    #[tokio::test]
    async fn concurrent_sliding_window_never_exceeds_limit() {
        let b = Arc::new(backend());
        let limit = 100u64;
        let writers = 20;
        let requests_per_writer = 10;

        let mut handles = Vec::new();
        for _ in 0..writers {
            let b2 = b.clone();
            handles.push(tokio::spawn(async move {
                for _ in 0..requests_per_writer {
                    let r = b2
                        .incr_window("concurrent-key", Duration::from_secs(60), limit)
                        .await
                        .unwrap();
                    // Count should always be positive.
                    assert!(r.count > 0);
                    // If allowed, count must be within limit.
                    if r.allowed {
                        assert!(r.count <= limit);
                    }
                }
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        // Final count should equal total requests.
        let final_result = b
            .incr_window("concurrent-key", Duration::from_secs(60), limit)
            .await
            .unwrap();
        let total = (writers * requests_per_writer + 1) as u64;
        assert_eq!(final_result.count, total);
    }

    #[tokio::test]
    async fn reaper_cleans_expired_entries() {
        let b = backend();
        b.set("short-lived", b"val", Duration::from_millis(50))
            .await
            .unwrap();
        assert!(!b.is_empty());

        // Wait for TTL + a little extra.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Manually trigger reap logic (same as reaper does).
        b.kv.retain(|_, entry| !entry.is_expired());
        assert!(b.is_empty());
    }

    // ---------------- SC-T1 ----------------

    #[tokio::test]
    async fn health_reports_in_memory_backend_as_connected() {
        let b = backend();
        let h = b.health().await;
        assert_eq!(h.backend, "in_memory");
        assert!(h.connected, "in-memory is always connected — no remote");
        assert_eq!(h.key_count, Some(0));
        assert!(h.latency.is_none(), "in-memory doesn't measure latency");
        assert!(h.replica_lag_ms.is_none());
        assert!(h.server_version.is_none());
        assert_eq!(h.circuit, aegis_core::state::CircuitState::Closed);
    }

    #[tokio::test]
    async fn health_key_count_tracks_inserts() {
        let b = backend();
        b.set("k1", b"v", Duration::from_secs(60)).await.unwrap();
        b.set("k2", b"v", Duration::from_secs(60)).await.unwrap();
        let h = b.health().await;
        assert_eq!(h.key_count, Some(2));
    }
}
