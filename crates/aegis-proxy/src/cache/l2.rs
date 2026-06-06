//! SC-1 Phase 3 — L2 shared-Redis cache tier (behind L1).
//!
//! A thin, **best-effort** wrapper over a dedicated cache Redis. Every op is
//! timeout-bounded; any error/timeout degrades to a miss (the request falls
//! through to origin) — Redis is never allowed to stall or fail a request.
//!
//! Only compiled with `--features redis`. Keys are namespaced
//! `<key_prefix>:<pool>:<hex(cache-key)>` so multiple pools / WAFs sharing one
//! Redis don't collide and a per-pool prefix purge is possible.

use std::time::Duration;

use deadpool_redis::{Config as PoolConfig, Pool, Runtime};
use redis::AsyncCommands as _; // brings `scan_match` into scope

use aegis_core::config::CacheL2Config;

use super::{CacheEntry, CacheKey};

/// Shared L2 (Redis) cache for one pool.
pub struct L2Cache {
    pool: Pool,
    key_prefix: String,
    pool_name: String,
    timeout: Duration,
}

impl L2Cache {
    /// Build from config. Returns `None` (with a warning) if the pool can't be
    /// constructed — the cache then runs L1-only, which is safe.
    pub fn connect(pool_name: &str, cfg: &CacheL2Config) -> Option<Self> {
        let url = cfg.urls.first()?;
        if cfg.cluster {
            // Cluster client is a later increment; single-node connection to the
            // first URL works as an L2 today (a cluster front node still serves).
            tracing::warn!(
                pool = pool_name,
                "cache.l2.cluster=true — using single-node client to the first URL \
                 (Redis Cluster client not yet wired)",
            );
        }
        let pool = PoolConfig::from_url(url)
            .builder()
            .ok()
            .and_then(|b| b.runtime(Runtime::Tokio1).build().ok());
        match pool {
            Some(pool) => {
                tracing::info!(pool = pool_name, prefix = %cfg.key_prefix, "cache L2 (redis) wired");
                Some(Self {
                    pool,
                    key_prefix: cfg.key_prefix.clone(),
                    pool_name: pool_name.to_string(),
                    timeout: cfg.timeout,
                })
            }
            None => {
                tracing::warn!(pool = pool_name, "cache L2 pool build failed; running L1-only");
                None
            }
        }
    }

    fn redis_key(&self, key: &CacheKey) -> String {
        let mut s = String::with_capacity(self.key_prefix.len() + self.pool_name.len() + 70);
        s.push_str(&self.key_prefix);
        s.push(':');
        s.push_str(&self.pool_name);
        s.push(':');
        for b in key {
            s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
            s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
        }
        s
    }

    /// Look up an entry. Miss / error / timeout ⇒ `None`.
    pub async fn get(&self, key: &CacheKey) -> Option<CacheEntry> {
        let rkey = self.redis_key(key);
        let fut = async {
            let mut conn = self.pool.get().await.ok()?;
            let bytes: Option<Vec<u8>> = redis::cmd("GET")
                .arg(&rkey)
                .query_async(&mut *conn)
                .await
                .ok()?;
            bytes
        };
        match tokio::time::timeout(self.timeout, fut).await {
            Ok(Some(bytes)) => CacheEntry::decode_from_l2(&bytes),
            _ => None,
        }
    }

    /// Store an entry with `EX <ttl>`. Best-effort; failures are swallowed.
    pub async fn put(&self, key: &CacheKey, entry: &CacheEntry) {
        let rkey = self.redis_key(key);
        let ttl = entry.ttl.as_secs().max(1);
        let blob = entry.encode_for_l2();
        let fut = async {
            let mut conn = self.pool.get().await.ok()?;
            redis::cmd("SET")
                .arg(&rkey)
                .arg(blob)
                .arg("EX")
                .arg(ttl)
                .query_async::<()>(&mut *conn)
                .await
                .ok()?;
            Some(())
        };
        let _ = tokio::time::timeout(self.timeout, fut).await;
    }

    /// Delete every L2 key for this pool (`<prefix>:<pool>:*`) via SCAN + UNLINK.
    /// Best-effort; on a Cluster front node SCAN only sees one shard, so callers
    /// should also rely on the L1 pub/sub fan-out + TTL (see the plan).
    pub async fn invalidate_prefix(&self) {
        let pattern = format!("{}:{}:*", self.key_prefix, self.pool_name);
        let fut = async {
            let mut conn = self.pool.get().await.ok()?;
            let keys: Vec<String> = {
                let mut iter = conn.scan_match::<_, String>(&pattern).await.ok()?;
                let mut v = Vec::new();
                while let Some(k) = iter.next_item().await {
                    v.push(k);
                }
                v
            };
            if !keys.is_empty() {
                redis::cmd("UNLINK")
                    .arg(&keys)
                    .query_async::<()>(&mut *conn)
                    .await
                    .ok()?;
            }
            Some(keys.len())
        };
        match tokio::time::timeout(Duration::from_secs(5), fut).await {
            Ok(Some(n)) => tracing::debug!(pool = %self.pool_name, removed = n, "cache L2 prefix purge"),
            _ => tracing::debug!(pool = %self.pool_name, "cache L2 prefix purge skipped (error/timeout)"),
        }
    }
}
