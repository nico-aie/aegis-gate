//! SC-1 Phase 3 — L2 shared-Redis cache tier (behind L1).
//!
//! A thin, **best-effort** wrapper over a dedicated cache Redis. Every op is
//! timeout-bounded; any error/timeout degrades to a miss (the request falls
//! through to origin) — Redis is never allowed to stall or fail a request.
//!
//! Only compiled with `--features redis`. Keys are namespaced
//! `<key_prefix>:<pool>:<hex(cache-key)>` so multiple pools / WAFs sharing one
//! Redis don't collide and a per-pool prefix purge is possible.
//!
//! ## Single-node vs Redis Cluster
//!
//! Both topologies are wired behind one [`Backend`] enum:
//!
//! - `cluster: false` → a single-node `deadpool_redis::Pool`. The right default
//!   for one machine (or a single managed Redis); lowest overhead.
//! - `cluster: true` → a `deadpool_redis::cluster::Pool` backed by the
//!   async cluster client. Keys hash to slots across masters automatically.
//!   Use only once the cache working set outgrows one node's memory.
//!
//! Both connection types implement [`redis::aio::ConnectionLike`], so the GET /
//! SET / SCAN command bodies are identical — the [`with_conn`] macro runs each
//! body against whichever backend is configured (type-checked once per concrete
//! connection type).

use std::time::Duration;

use deadpool_redis::cluster::{Config as ClusterPoolConfig, Pool as ClusterPool};
use deadpool_redis::{Config as PoolConfig, Pool, Runtime};
use redis::AsyncCommands as _; // brings `scan_match` into scope

use aegis_core::config::CacheL2Config;

use super::{CacheEntry, CacheKey};

/// Which Redis topology backs this L2 tier. Resolved once at [`L2Cache::connect`]
/// from `cfg.cluster`; the data path never branches on config again.
enum Backend {
    /// Single-node (or single managed endpoint) pool.
    Single(Pool),
    /// Redis Cluster pool — keys sharded across masters by CRC16 slot.
    Cluster(ClusterPool),
}

/// Run a command `body` against a pooled connection from whichever backend is
/// configured. `body` is expanded once per concrete connection type, so type
/// inference resolves each independently. A pool-checkout failure short-circuits
/// the enclosing `-> Option<_>` async block to `None` via `?` (degrade to miss).
macro_rules! with_conn {
    ($backend:expr, $conn:ident => $body:block) => {
        match $backend {
            Backend::Single(pool) => {
                let mut $conn = pool.get().await.ok()?;
                $body
            }
            Backend::Cluster(pool) => {
                let mut $conn = pool.get().await.ok()?;
                $body
            }
        }
    };
}

/// Shared L2 (Redis) cache for one pool.
pub struct L2Cache {
    backend: Backend,
    key_prefix: String,
    pool_name: String,
    timeout: Duration,
}

impl L2Cache {
    /// Build from config. Returns `None` (with a warning) if the pool can't be
    /// constructed — the cache then runs L1-only, which is safe.
    pub fn connect(pool_name: &str, cfg: &CacheL2Config) -> Option<Self> {
        if cfg.urls.is_empty() {
            return None;
        }

        let backend = if cfg.cluster {
            let pool = ClusterPoolConfig::from_urls(cfg.urls.clone())
                .builder()
                .ok()
                .and_then(|b| b.runtime(Runtime::Tokio1).build().ok());
            match pool {
                Some(pool) => {
                    tracing::info!(
                        pool = pool_name,
                        nodes = cfg.urls.len(),
                        prefix = %cfg.key_prefix,
                        "cache L2 (redis cluster) wired",
                    );
                    Backend::Cluster(pool)
                }
                None => {
                    tracing::warn!(
                        pool = pool_name,
                        "cache L2 cluster pool build failed; running L1-only",
                    );
                    return None;
                }
            }
        } else {
            // Single-node: connect to the first URL. Extra URLs are ignored
            // here (they only carry meaning for `cluster: true`).
            let url = cfg.urls.first()?;
            let pool = PoolConfig::from_url(url)
                .builder()
                .ok()
                .and_then(|b| b.runtime(Runtime::Tokio1).build().ok());
            match pool {
                Some(pool) => {
                    tracing::info!(
                        pool = pool_name,
                        prefix = %cfg.key_prefix,
                        "cache L2 (redis) wired",
                    );
                    Backend::Single(pool)
                }
                None => {
                    tracing::warn!(
                        pool = pool_name,
                        "cache L2 pool build failed; running L1-only",
                    );
                    return None;
                }
            }
        };

        Some(Self {
            backend,
            key_prefix: cfg.key_prefix.clone(),
            pool_name: pool_name.to_string(),
            timeout: cfg.timeout,
        })
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
            let bytes: Option<Vec<u8>> = with_conn!(&self.backend, conn => {
                redis::cmd("GET")
                    .arg(&rkey)
                    .query_async(&mut *conn)
                    .await
                    .ok()?
            });
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
            with_conn!(&self.backend, conn => {
                redis::cmd("SET")
                    .arg(&rkey)
                    .arg(&blob)
                    .arg("EX")
                    .arg(ttl)
                    .query_async::<()>(&mut *conn)
                    .await
                    .ok()?;
            });
            Some(())
        };
        let _ = tokio::time::timeout(self.timeout, fut).await;
    }

    /// Delete every L2 key for this pool (`<prefix>:<pool>:*`).
    ///
    /// Best-effort, timeout-bounded. On single-node it's one SCAN + UNLINK. On
    /// Cluster, `SCAN` is node-local (redis-rs routes it to one node), so this
    /// discovers the masters via `CLUSTER NODES` and SCANs each directly —
    /// otherwise keys on the other shards would survive the purge. A key caught
    /// mid-resharding can still be missed, so the L1 pub/sub fan-out + TTL
    /// remain the purge backstop (see the plan).
    pub async fn invalidate_prefix(&self) {
        let pattern = format!("{}:{}:*", self.key_prefix, self.pool_name);
        let removed = match &self.backend {
            Backend::Single(pool) => {
                let fut = async {
                    let mut conn = pool.get().await.ok()?;
                    scan_unlink_multi(&mut *conn, &pattern).await
                };
                tokio::time::timeout(Duration::from_secs(5), fut)
                    .await
                    .ok()
                    .flatten()
            }
            Backend::Cluster(pool) => {
                tokio::time::timeout(Duration::from_secs(10), Self::cluster_purge(pool, &pattern))
                    .await
                    .ok()
                    .flatten()
            }
        };
        match removed {
            Some(n) => {
                tracing::debug!(pool = %self.pool_name, removed = n, "cache L2 prefix purge")
            }
            None => {
                tracing::debug!(pool = %self.pool_name, "cache L2 prefix purge skipped (error/timeout)")
            }
        }
    }

    /// Cluster purge: SCAN + UNLINK on every master independently.
    async fn cluster_purge(pool: &ClusterPool, pattern: &str) -> Option<usize> {
        let mut conn = pool.get().await.ok()?;
        let nodes: String = redis::cmd("CLUSTER")
            .arg("NODES")
            .query_async(&mut *conn)
            .await
            .ok()?;
        let mut removed = 0usize;
        for addr in parse_cluster_master_addrs(&nodes) {
            // A direct single-node connection to the master: SCAN sees only its
            // own slots, and per-key UNLINK avoids CROSSSLOT on multi-key dels.
            if let Ok(client) = redis::Client::open(format!("redis://{addr}")) {
                if let Ok(mut node_conn) = client.get_multiplexed_async_connection().await {
                    if let Some(n) = scan_unlink_per_key(&mut node_conn, pattern).await {
                        removed += n;
                    }
                }
            }
        }
        Some(removed)
    }
}

/// SCAN `pattern` and UNLINK all matches in one multi-key call (single-node
/// only — multi-key UNLINK is illegal across cluster slots). Returns the count.
async fn scan_unlink_multi<C>(conn: &mut C, pattern: &str) -> Option<usize>
where
    C: redis::aio::ConnectionLike + Send,
{
    let keys = scan_collect(conn, pattern).await?;
    if !keys.is_empty() {
        redis::cmd("UNLINK")
            .arg(&keys)
            .query_async::<()>(conn)
            .await
            .ok()?;
    }
    Some(keys.len())
}

/// SCAN `pattern` and UNLINK matches one key at a time. Used against an
/// individual cluster master, where a multi-key UNLINK spanning slots would
/// fail CROSSSLOT — single-key commands are always in-slot. Pipelined so the
/// per-key cost is one round trip, not N.
async fn scan_unlink_per_key<C>(conn: &mut C, pattern: &str) -> Option<usize>
where
    C: redis::aio::ConnectionLike + Send,
{
    let keys = scan_collect(conn, pattern).await?;
    if !keys.is_empty() {
        let mut pipe = redis::pipe();
        for k in &keys {
            pipe.cmd("UNLINK").arg(k).ignore();
        }
        pipe.query_async::<()>(conn).await.ok()?;
    }
    Some(keys.len())
}

/// Collect every key matching `pattern` via a cursor-based `SCAN`.
async fn scan_collect<C>(conn: &mut C, pattern: &str) -> Option<Vec<String>>
where
    C: redis::aio::ConnectionLike + Send,
{
    let mut iter = conn.scan_match::<_, String>(pattern).await.ok()?;
    let mut v = Vec::new();
    while let Some(k) = iter.next_item().await {
        v.push(k);
    }
    Some(v)
}

/// Parse `CLUSTER NODES` output into the `ip:port` of each reachable master.
/// Line shape: `<id> <ip:port@cport> <flags> <master-id> ...`; `flags` is a
/// comma list (e.g. `myself,master`). Replicas and failed nodes are skipped.
fn parse_cluster_master_addrs(nodes: &str) -> Vec<String> {
    nodes
        .lines()
        .filter_map(|line| {
            let mut f = line.split_whitespace();
            let _id = f.next()?;
            let addr = f.next()?; // ip:port@cport
            let flags = f.next()?;
            if flags.contains("fail") || !flags.contains("master") {
                return None;
            }
            Some(addr.split('@').next()?.to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::parse_cluster_master_addrs;

    #[test]
    fn parses_masters_skips_replicas_and_failed() {
        // Real-ish `CLUSTER NODES` dump: 3 masters (one is `myself`), 2 healthy
        // replicas, 1 failed master. Only the 3 live masters' ip:port return.
        let dump = "\
a1 127.0.0.1:7100@17100 myself,master - 0 0 1 connected 0-5460
b2 127.0.0.1:7101@17101 master - 0 0 2 connected 5461-10922
c3 127.0.0.1:7102@17102 master - 0 0 3 connected 10923-16383
d4 127.0.0.1:7103@17103 slave a1 0 0 1 connected
e5 127.0.0.1:7104@17104 slave b2 0 0 2 connected
f6 127.0.0.1:7105@17105 master,fail - 0 0 4 disconnected
";
        let masters = parse_cluster_master_addrs(dump);
        assert_eq!(
            masters,
            vec!["127.0.0.1:7100", "127.0.0.1:7101", "127.0.0.1:7102"]
        );
    }

    #[test]
    fn empty_or_garbage_lines_yield_no_masters() {
        assert!(parse_cluster_master_addrs("").is_empty());
        assert!(parse_cluster_master_addrs("\n   \n").is_empty());
    }
}
