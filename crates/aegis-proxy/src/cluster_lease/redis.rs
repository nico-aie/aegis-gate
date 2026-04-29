//! Redis-backed [`LeaseStore`] (feature-gated: `redis`).
//!
//! Wire format:
//!
//! ```text
//! key:    g:lease:<lease-key>          (string)
//!         value = "<node_id>:<fence>"
//!         pexpire = ttl_ms
//!
//! key:    g:lease:<lease-key>:fence    (counter)
//!         INCR'd before each new acquire so fence is monotonic
//!         across the entire lease lifecycle (not just one node)
//! ```
//!
//! `acquire` is `SET NX PX`. `renew` and `release` are CAS Lua
//! scripts that compare the stored value against
//! `<node_id>:<fence>` so a node can only mutate a lease it
//! actually holds.
//!
//! Operational notes:
//!
//! - All ops are wrapped in `tokio::time::timeout(config.timeout)`.
//!   A timeout surfaces as `WafError::State` from `acquire` /
//!   `release`, but `renew` deliberately maps timeout-or-error
//!   to `Ok(false)` because the heartbeat treats those identically
//!   ("lease likely lost — stop the leader-only task"). That's
//!   safer than panicking the heartbeat.
//! - Reconnect delegated to deadpool — same pattern as
//!   `state::redis::RedisBackend`.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use aegis_core::cluster::{LeaseHandle, LeaseStore, NodeId};
use aegis_core::error::{Result, WafError};
use deadpool_redis::{Config as PoolConfig, Pool, Runtime};
use redis::{AsyncCommands, Script};

use crate::state::RedisConfig;

/// Lua: PEXPIRE only if the value still belongs to us.
///
/// Returns 1 if renewed, 0 if the value changed (we lost the
/// lease) or doesn't exist. Atomic — no TOCTOU between the
/// GET and the PEXPIRE.
const RENEW_CAS_LUA: &str = r#"
local key = KEYS[1]
local expected = ARGV[1]
local ttl_ms = tonumber(ARGV[2])

local current = redis.call('GET', key)
if current == expected then
    redis.call('PEXPIRE', key, ttl_ms)
    return 1
else
    return 0
end
"#;

/// Lua: DEL only if the value still belongs to us.
const RELEASE_CAS_LUA: &str = r#"
local key = KEYS[1]
local expected = ARGV[1]

local current = redis.call('GET', key)
if current == expected then
    redis.call('DEL', key)
    return 1
else
    return 0
end
"#;

/// Redis-backed lease store.
pub struct RedisLease {
    pool: Pool,
    config: RedisConfig,
    self_id: NodeId,
    renew_cas: Arc<Script>,
    release_cas: Arc<Script>,
}

impl RedisLease {
    /// Build a `RedisLease`. Lazy — the first op pays the
    /// connect cost, matching the in-process impl's "no
    /// pre-flight" semantics.
    pub fn connect(config: RedisConfig, self_id: NodeId) -> Result<Self> {
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
            self_id,
            renew_cas: Arc::new(Script::new(RENEW_CAS_LUA)),
            release_cas: Arc::new(Script::new(RELEASE_CAS_LUA)),
        })
    }

    /// Identity this store holds leases as.
    pub fn self_id(&self) -> &NodeId {
        &self.self_id
    }

    async fn conn(&self) -> Result<deadpool_redis::Connection> {
        self.pool
            .get()
            .await
            .map_err(|e| WafError::State(format!("redis pool: {e}")))
    }

    async fn with_timeout<T, F>(&self, op_name: &'static str, fut: F) -> Result<T>
    where
        F: std::future::Future<Output = redis::RedisResult<T>>,
    {
        match tokio::time::timeout(self.config.timeout, fut).await {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => Err(WafError::State(format!("redis {op_name}: {e}"))),
            Err(_) => Err(WafError::State(format!(
                "redis {op_name}: timeout after {:?}",
                self.config.timeout
            ))),
        }
    }

    fn lease_key(key: &str) -> String {
        format!("g:lease:{key}")
    }

    fn fence_key(key: &str) -> String {
        format!("g:lease:{key}:fence")
    }

    fn token(holder: &NodeId, fence: u64) -> String {
        format!("{holder}:{fence}")
    }
}

#[async_trait::async_trait]
impl LeaseStore for RedisLease {
    async fn acquire(&self, key: &str, ttl: Duration) -> Result<Option<LeaseHandle>> {
        let lkey = Self::lease_key(key);
        let fkey = Self::fence_key(key);
        let ttl_ms = ttl.as_millis().max(1) as u64;

        let mut c = self.conn().await?;

        // Fast path: try to take the lease with a fresh fence.
        // We INCR the fence counter before the SET-NX so a take
        // always gets a strictly-increasing token. If the
        // SET-NX fails we either (a) we already hold it (refresh
        // path) or (b) someone else holds it.
        let next_fence: u64 = self
            .with_timeout("lease incr fence", c.incr(&fkey, 1u64))
            .await?;
        let candidate_token = Self::token(&self.self_id, next_fence);

        let acquired: Option<String> = self
            .with_timeout(
                "lease SET NX PX",
                redis::cmd("SET")
                    .arg(&lkey)
                    .arg(&candidate_token)
                    .arg("NX")
                    .arg("PX")
                    .arg(ttl_ms)
                    .query_async(&mut c),
            )
            .await?;

        if acquired.is_some() {
            return Ok(Some(LeaseHandle {
                key: key.to_string(),
                holder: self.self_id.clone(),
                fence: next_fence,
            }));
        }

        // SET-NX failed — find out who holds it. If it's us,
        // refresh the TTL with the existing token and return the
        // existing fence (don't drift). If someone else, return
        // None.
        let current: Option<String> =
            self.with_timeout("lease GET", c.get(&lkey)).await?;
        let Some(current) = current else {
            // Race: between SET-NX and GET the holder vanished.
            // The fence we already INCR'd is wasted — return
            // None to keep semantics clean; the caller will
            // retry on the next heartbeat tick.
            return Ok(None);
        };

        if let Some((holder, fence_str)) = current.rsplit_once(':') {
            if holder == self.self_id.as_str() {
                if let Ok(existing_fence) = fence_str.parse::<u64>() {
                    // We already hold it — refresh PEXPIRE
                    // CAS-style so we don't accidentally extend
                    // someone else's lease if a race happened.
                    let renewed: i64 = self
                        .with_timeout::<i64, _>(
                            "lease self-refresh",
                            self.renew_cas
                                .key(&lkey)
                                .arg(&current)
                                .arg(ttl_ms as i64)
                                .invoke_async(&mut c),
                        )
                        .await?;
                    if renewed == 1 {
                        return Ok(Some(LeaseHandle {
                            key: key.to_string(),
                            holder: self.self_id.clone(),
                            fence: existing_fence,
                        }));
                    }
                }
            }
        }

        Ok(None)
    }

    async fn renew(&self, lease: &LeaseHandle, ttl: Duration) -> Result<bool> {
        let lkey = Self::lease_key(&lease.key);
        let token = Self::token(&lease.holder, lease.fence);
        let ttl_ms = ttl.as_millis().max(1) as u64;

        let mut c = match self.conn().await {
            Ok(c) => c,
            // Conn failure → treat as lost. Heartbeat will fire
            // `lost` and the leader-only task stops, which is
            // exactly what we want when Redis is unreachable.
            Err(e) => {
                tracing::warn!(
                    key = %lease.key,
                    holder = %lease.holder,
                    error = %e,
                    "renew: pool unreachable — treating as lease lost",
                );
                return Ok(false);
            }
        };

        let result: std::result::Result<
            std::result::Result<i64, redis::RedisError>,
            tokio::time::error::Elapsed,
        > = tokio::time::timeout(
            self.config.timeout,
            self.renew_cas
                .key(&lkey)
                .arg(token)
                .arg(ttl_ms as i64)
                .invoke_async(&mut c),
        )
        .await;

        match result {
            Ok(Ok(1)) => Ok(true),
            Ok(Ok(_)) => Ok(false),
            Ok(Err(e)) => {
                tracing::warn!(
                    key = %lease.key,
                    error = %e,
                    "renew: redis error — treating as lease lost",
                );
                Ok(false)
            }
            Err(_) => {
                tracing::warn!(
                    key = %lease.key,
                    "renew: timeout — treating as lease lost",
                );
                Ok(false)
            }
        }
    }

    async fn release(&self, lease: &LeaseHandle) -> Result<()> {
        let lkey = Self::lease_key(&lease.key);
        let token = Self::token(&lease.holder, lease.fence);

        let mut c = self.conn().await?;
        // Best-effort. Return value (0 or 1) is informational —
        // a 0 just means we already lost it, which is fine.
        let _: i64 = self
            .with_timeout::<i64, _>(
                "lease release CAS",
                self.release_cas
                    .key(&lkey)
                    .arg(token)
                    .invoke_async(&mut c),
            )
            .await?;
        Ok(())
    }

    async fn holder(&self, key: &str) -> Result<Option<NodeId>> {
        let lkey = Self::lease_key(key);
        let mut c = self.conn().await?;
        let v: Option<String> =
            self.with_timeout("lease holder GET", c.get(&lkey)).await?;
        Ok(v.and_then(|s| {
            // Strip the `:<fence>` suffix.
            s.rsplit_once(':')
                .map(|(holder, _fence)| NodeId::new(holder))
        }))
    }
}

// Quiet the linter — `SystemTime` is conditionally used by future
// extensions (drift detection etc.). Importing it now keeps the
// surface stable.
#[allow(dead_code)]
fn _suppress_unused_import_warning() -> SystemTime {
    SystemTime::now()
}

#[cfg(test)]
mod tests {
    //! Unit tests — do **not** require a live Redis. Live
    //! parity is exercised by `tests/redis_lease_parity.rs`.

    use super::*;

    fn cfg() -> RedisConfig {
        RedisConfig::default()
    }

    #[test]
    fn lease_keys_have_g_prefix() {
        assert_eq!(RedisLease::lease_key("acme"), "g:lease:acme");
        assert_eq!(RedisLease::fence_key("acme"), "g:lease:acme:fence");
    }

    #[test]
    fn token_format_is_holder_colon_fence() {
        assert_eq!(
            RedisLease::token(&NodeId::new("waf-0"), 42),
            "waf-0:42",
        );
    }

    #[test]
    fn connect_with_default_config_succeeds() {
        let l = RedisLease::connect(cfg(), NodeId::new("waf-0"));
        assert!(l.is_ok());
    }

    #[test]
    fn connect_with_invalid_url_fails() {
        let bad = RedisConfig {
            url: "not-a-url://".into(),
            ..cfg()
        };
        assert!(RedisLease::connect(bad, NodeId::new("waf-0")).is_err());
    }

    #[tokio::test]
    async fn renew_against_unreachable_returns_ok_false() {
        // `renew` deliberately maps unreachable-Redis → Ok(false)
        // so the heartbeat treats it as "lease lost" and stops
        // the leader-only task instead of panicking the loop.
        let bad = RedisConfig {
            url: "redis://127.0.0.1:1".into(),
            pool_size: 1,
            timeout: Duration::from_millis(150),
            cluster: false,
        };
        let l = RedisLease::connect(bad, NodeId::new("waf-0")).expect("pool builds");
        let fake = LeaseHandle {
            key: "doesnt-matter".into(),
            holder: NodeId::new("waf-0"),
            fence: 1,
        };
        assert!(!l.renew(&fake, Duration::from_secs(1)).await.unwrap());
    }

    #[tokio::test]
    async fn acquire_against_unreachable_surfaces_state_error() {
        // `acquire` is allowed to return Err — caller must
        // distinguish "couldn't reach Redis" from "another node
        // owns it".
        let bad = RedisConfig {
            url: "redis://127.0.0.1:1".into(),
            pool_size: 1,
            timeout: Duration::from_millis(150),
            cluster: false,
        };
        let l = RedisLease::connect(bad, NodeId::new("waf-0")).expect("pool builds");
        let err = l
            .acquire("never-resolves", Duration::from_secs(1))
            .await
            .unwrap_err();
        match err {
            WafError::State(_) => {}
            other => panic!("expected State error, got {other:?}"),
        }
    }
}
