//! 2026-05-27 (Phase C — multi-node metrics aggregation) — shared
//! local-ring → state-backend flush + aggregated read, used by both
//! P5 `RouteActivityWindow` and P4 `AccessListHits`.
//!
//! ## Why
//!
//! The per-route / per-entry counters live in process-local rings, so a
//! dashboard on `node-A` only ever sees node-A's slice of the fleet's
//! traffic. This module flushes the local rings into shared
//! `INCRBY` counters keyed by **absolute bucket timestamp**, so the
//! dashboard can sum a cluster-wide view. See
//! `plans/future/multi-node-metrics-aggregation.md`.
//!
//! ## Why key by absolute bucket timestamp
//!
//! The naive design (flush per-ring-index delta) breaks when a ring
//! bucket rotates between flushes: the new window's count is *smaller*
//! than the previous occupant's, so a `saturating_sub` delta silently
//! drops counts. Keying by the bucket's absolute wall-clock second
//! (`bucket_idx * bucket_secs`) sidesteps this entirely — a rotated
//! bucket appears under a brand-new key and the old one drops out of
//! the source's report (and gets pruned from `last_seen`).
//!
//! ## Key schema
//!
//! `<prefix>:<abs_bucket_ts>:<id>` — the `abs_bucket_ts` segment is
//! always numeric, so the read path can `strip_prefix` then `split_once`
//! to recover `(abs_ts, id)` even when `id` itself contains `:`
//! (e.g. an IPv6 access-list entry).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use aegis_core::state::StateBackend;

/// A counter source the flush task drains each cycle: yields, per id,
/// the live `(absolute_bucket_ts, cumulative_count)` pairs. Implemented
/// by `RouteActivityWindow` (P5) and `AccessListHits` (P4).
pub trait BucketSource: Send + Sync {
    /// Snapshot every tracked id's live buckets as
    /// `(absolute_bucket_ts, cumulative_count)`. `now_secs` lets the
    /// source skip buckets that have already rotated out of its window.
    fn drain_buckets(&self, now_secs: u64) -> Vec<(String, Vec<(u64, u64)>)>;
}

/// Outcome of one flush cycle — surfaced so the boot task can emit a
/// `flush_failed` audit event when `errors` stays non-zero.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FlushOutcome {
    /// Distinct `(id, bucket)` deltas successfully written this cycle.
    pub keys_written: usize,
    /// Backend errors this cycle. The corresponding deltas are NOT
    /// recorded as flushed, so they retry on the next cycle.
    pub errors: usize,
}

/// Periodic local-ring → state-backend flush for one counter class.
/// Holds the per-`(id, abs_ts)` last-flushed count so each cycle writes
/// only the delta (`INCRBY` is commutative, so concurrent per-node
/// flushes converge to the right total).
pub struct WindowFlush {
    key_prefix: String,
    ttl: Duration,
    last_seen: HashMap<(String, u64), u64>,
}

impl WindowFlush {
    /// `key_prefix` namespaces this counter class (e.g. `waf:route` or
    /// `waf:hits:bl`). `ttl` should be ≥ 2× the read window so stale
    /// buckets garbage-collect themselves without a sweeper.
    pub fn new(key_prefix: impl Into<String>, ttl: Duration) -> Self {
        Self {
            key_prefix: key_prefix.into(),
            ttl,
            last_seen: HashMap::new(),
        }
    }

    /// Flush the deltas accumulated since the previous cycle. For each
    /// `(id, abs_ts)` whose cumulative count grew, `incrby` the delta
    /// into `<prefix>:<abs_ts>:<id>` and refresh its TTL. On a backend
    /// error the delta is left unrecorded so it retries next cycle.
    /// Buckets the source no longer reports are pruned from `last_seen`
    /// to bound memory.
    pub async fn flush(
        &mut self,
        source: &dyn BucketSource,
        state: &Arc<dyn StateBackend>,
        now_secs: u64,
    ) -> FlushOutcome {
        let mut out = FlushOutcome::default();
        let mut seen: HashSet<(String, u64)> = HashSet::new();
        for (id, buckets) in source.drain_buckets(now_secs) {
            for (abs_ts, count) in buckets {
                let k = (id.clone(), abs_ts);
                seen.insert(k.clone());
                let prev = self.last_seen.get(&k).copied().unwrap_or(0);
                let delta = count.saturating_sub(prev);
                if delta == 0 {
                    continue;
                }
                let key = format!("{}:{}:{}", self.key_prefix, abs_ts, id);
                match state.incrby(&key, delta).await {
                    Ok(_) => {
                        let _ = state.expire(&key, self.ttl).await;
                        self.last_seen.insert(k, count);
                        out.keys_written += 1;
                    }
                    Err(_) => out.errors += 1,
                }
            }
        }
        // Drop buckets that rotated out of the source's report.
        self.last_seen.retain(|k, _| seen.contains(k));
        out
    }
}

/// Scan every aggregated bucket under `key_prefix` and group them by id
/// as `(abs_bucket_ts, count)` (no window filter — that's applied at
/// read time by [`sum_window`], so a single scan serves any window the
/// dashboard asks for). `INCRBY` already summed across nodes. Empty when
/// the backend has no matching keys.
pub async fn read_buckets(
    state: &Arc<dyn StateBackend>,
    key_prefix: &str,
    _now_secs: u64,
) -> HashMap<String, Vec<(u64, u64)>> {
    let mut out: HashMap<String, Vec<(u64, u64)>> = HashMap::new();
    let scan = format!("{key_prefix}:");
    let keys = match state.scan_prefix(&scan).await {
        Ok(k) => k,
        Err(_) => return out,
    };
    for key in keys {
        // `<prefix>:<abs_ts>:<id>` — strip the prefix, split the numeric
        // bucket-ts off the front; the remainder is the id verbatim.
        let Some(rest) = key.strip_prefix(&scan) else {
            continue;
        };
        let Some((ts_str, id)) = rest.split_once(':') else {
            continue;
        };
        let Ok(abs_ts) = ts_str.parse::<u64>() else {
            continue;
        };
        let v = state.get_counter(&key).await.unwrap_or(0);
        out.entry(id.to_string()).or_default().push((abs_ts, v));
    }
    out
}

/// Sum the cached per-bucket aggregate over `[now - window_secs, now]`,
/// dropping ids whose windowed total is zero. Pure + sync so a
/// synchronous dashboard endpoint can serve any window off a single
/// cached snapshot.
pub fn sum_window(
    buckets: &HashMap<String, Vec<(u64, u64)>>,
    window_secs: u64,
    now_secs: u64,
) -> HashMap<String, u64> {
    let cutoff = now_secs.saturating_sub(window_secs);
    buckets
        .iter()
        .filter_map(|(id, bs)| {
            let total: u64 = bs
                .iter()
                .filter(|(ts, _)| *ts >= cutoff)
                .map(|(_, c)| *c)
                .sum();
            (total > 0).then(|| (id.clone(), total))
        })
        .collect()
}

/// Read an aggregated window from the state backend in one shot
/// (`read_buckets` + `sum_window`). Returns `id -> total`; empty when
/// the backend has no matching keys, so callers fall back to local rings
/// on `in_memory` single-node deployments.
pub async fn read_window(
    state: &Arc<dyn StateBackend>,
    key_prefix: &str,
    window_secs: u64,
    now_secs: u64,
) -> HashMap<String, u64> {
    let buckets = read_buckets(state, key_prefix, now_secs).await;
    sum_window(&buckets, window_secs, now_secs)
}

/// 2026-05-27 (Phase C) — read-cheap snapshot of the latest cluster-wide
/// per-bucket aggregate for one counter class. The flush task refreshes
/// it each cycle (`read_buckets` → `store`); the synchronous dashboard
/// endpoints call [`Self::window_totals`] without awaiting — sidestepping
/// the sync admin GET dispatcher's inability to `.await` a Redis read.
#[derive(Clone)]
pub struct AggregateCache {
    inner: Arc<arc_swap::ArcSwap<HashMap<String, Vec<(u64, u64)>>>>,
}

impl AggregateCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(arc_swap::ArcSwap::from_pointee(HashMap::new())),
        }
    }

    /// Cluster-wide windowed totals computed synchronously from the
    /// cached per-bucket aggregate.
    pub fn window_totals(&self, window_secs: u64, now_secs: u64) -> HashMap<String, u64> {
        sum_window(&self.inner.load(), window_secs, now_secs)
    }

    fn store(&self, buckets: HashMap<String, Vec<(u64, u64)>>) {
        self.inner.store(Arc::new(buckets));
    }
}

impl Default for AggregateCache {
    fn default() -> Self {
        Self::new()
    }
}

fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn flush_failed_event(key_prefix: &str, errors: usize) -> aegis_core::audit::AuditEvent {
    aegis_core::audit::AuditEvent {
        schema_version: 1,
        ts: chrono::Utc::now(),
        request_id: String::new(),
        class: aegis_core::audit::AuditClass::Admin,
        tenant_id: None,
        tier: None,
        action: "metrics_flush_failed".into(),
        reason: format!("counter flush to state backend failing ({key_prefix})"),
        client_ip: String::new(),
        route_id: None,
        rule_id: None,
        risk_score: None,
        method: None,
        path: None,
        mode: None,
        fields: serde_json::json!({ "key_prefix": key_prefix, "errors": errors }),
    }
}

/// 2026-05-27 (Phase C) — spawn the background flush loop for one counter
/// class. Each `interval` tick: flush local-ring deltas into the shared
/// `INCRBY` counters, then refresh `cache` with a fresh cluster-wide
/// per-bucket read. A `metrics_flush_failed` audit event is emitted
/// (edge-triggered) when the backend starts erroring and the loop keeps
/// running on the local rings in the meantime. Exits when the last
/// strong ref to `source` is dropped.
pub fn spawn_flush_task(
    source: Arc<dyn BucketSource>,
    state: Arc<dyn StateBackend>,
    bus: aegis_core::audit::AuditBus,
    cache: AggregateCache,
    key_prefix: String,
    ttl: Duration,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut flusher = WindowFlush::new(key_prefix.clone(), ttl);
        let mut ticker = tokio::time::interval(interval);
        let mut in_error_episode = false;
        loop {
            ticker.tick().await;
            let now = now_secs();
            let out = flusher.flush(source.as_ref(), &state, now).await;
            cache.store(read_buckets(&state, &key_prefix, now).await);
            if out.errors > 0 && !in_error_episode {
                in_error_episode = true;
                bus.emit(flush_failed_event(&key_prefix, out.errors));
            } else if out.errors == 0 {
                in_error_episode = false;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::risk::RiskKey;
    use aegis_core::state::{SlidingWindowResult, StateBackend};
    use aegis_core::Result;
    use async_trait::async_trait;
    use std::net::IpAddr;
    use std::sync::Mutex;

    /// Functional counter backend for the flush↔read round-trip. The
    /// real `in_memory` backend lives in `aegis-proxy` (which depends on
    /// this crate, not the other way around), so the test double lives
    /// here. Only the counter primitives carry real behaviour.
    struct MapBackend {
        ctr: Mutex<HashMap<String, u64>>,
    }
    impl MapBackend {
        fn new() -> Self {
            Self {
                ctr: Mutex::new(HashMap::new()),
            }
        }
    }
    #[async_trait]
    impl StateBackend for MapBackend {
        async fn get(&self, _k: &str) -> Result<Option<Vec<u8>>> {
            Ok(None)
        }
        async fn set(&self, _k: &str, _v: &[u8], _t: Duration) -> Result<()> {
            Ok(())
        }
        async fn del(&self, _k: &str) -> Result<()> {
            Ok(())
        }
        async fn incr_window(&self, _k: &str, _w: Duration, _l: u64) -> Result<SlidingWindowResult> {
            Ok(SlidingWindowResult { count: 1, allowed: true, retry_after: None })
        }
        async fn token_bucket(&self, _k: &str, _r: u32, _b: u32) -> Result<bool> {
            Ok(true)
        }
        async fn get_risk(&self, _k: &RiskKey) -> Result<u32> {
            Ok(0)
        }
        async fn add_risk(&self, _k: &RiskKey, _d: i32, _m: u32) -> Result<u32> {
            Ok(0)
        }
        async fn auto_block(&self, _ip: IpAddr, _t: Duration) -> Result<()> {
            Ok(())
        }
        async fn is_auto_blocked(&self, _ip: IpAddr) -> Result<bool> {
            Ok(false)
        }
        async fn put_nonce(&self, _n: &str, _t: Duration) -> Result<bool> {
            Ok(true)
        }
        async fn consume_nonce(&self, _n: &str) -> Result<bool> {
            Ok(true)
        }
        async fn incrby(&self, key: &str, delta: u64) -> Result<u64> {
            let mut m = self.ctr.lock().unwrap();
            let e = m.entry(key.to_string()).or_insert(0);
            *e += delta;
            Ok(*e)
        }
        async fn get_counter(&self, key: &str) -> Result<u64> {
            Ok(self.ctr.lock().unwrap().get(key).copied().unwrap_or(0))
        }
        async fn scan_prefix(&self, prefix: &str) -> Result<Vec<String>> {
            Ok(self
                .ctr
                .lock()
                .unwrap()
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect())
        }
    }

    struct FixedSource(Vec<(String, Vec<(u64, u64)>)>);
    impl BucketSource for FixedSource {
        fn drain_buckets(&self, _now: u64) -> Vec<(String, Vec<(u64, u64)>)> {
            self.0.clone()
        }
    }

    fn backend() -> Arc<dyn StateBackend> {
        Arc::new(MapBackend::new())
    }

    #[test]
    fn sum_window_filters_window_and_drops_zero_ids() {
        let mut b: HashMap<String, Vec<(u64, u64)>> = HashMap::new();
        b.insert("a".into(), vec![(1000, 5), (970, 3), (10, 99)]); // 10 is stale
        b.insert("idle".into(), vec![(10, 7)]); // entirely outside window
        let totals = sum_window(&b, 60, 1000);
        assert_eq!(totals.get("a"), Some(&8), "5 + 3 within window; 99 excluded");
        assert!(totals.get("idle").is_none(), "zero-in-window id dropped");
    }

    #[test]
    fn aggregate_cache_starts_empty() {
        let c = AggregateCache::new();
        assert!(c.window_totals(60, 1000).is_empty());
    }

    #[tokio::test]
    async fn flush_then_read_sums_buckets_in_window() {
        let state = backend();
        let now = 1_000_000u64;
        // route "a": two buckets (now, now-30); route "b": one bucket.
        let source = FixedSource(vec![
            ("a".into(), vec![(now, 5), (now - 30, 3)]),
            ("b".into(), vec![(now, 7)]),
        ]);
        let mut flush = WindowFlush::new("waf:route", Duration::from_secs(120));
        let out = flush.flush(&source, &state, now).await;
        assert_eq!(out.errors, 0);
        assert_eq!(out.keys_written, 3);

        let totals = read_window(&state, "waf:route", 60, now).await;
        assert_eq!(totals.get("a"), Some(&8), "5 + 3 within the 60s window");
        assert_eq!(totals.get("b"), Some(&7));
    }

    #[tokio::test]
    async fn second_flush_writes_only_the_delta() {
        let state = backend();
        let now = 2_000_000u64;
        let mut flush = WindowFlush::new("waf:route", Duration::from_secs(120));

        flush
            .flush(&FixedSource(vec![("a".into(), vec![(now, 5)])]), &state, now)
            .await;
        // Cumulative count grew 5 -> 12; only +7 should be INCRBY'd.
        let out = flush
            .flush(&FixedSource(vec![("a".into(), vec![(now, 12)])]), &state, now)
            .await;
        assert_eq!(out.keys_written, 1);

        let totals = read_window(&state, "waf:route", 60, now).await;
        assert_eq!(totals.get("a"), Some(&12), "INCRBY 5 then 7 = 12, not 17");
    }

    #[tokio::test]
    async fn read_excludes_buckets_outside_window() {
        let state = backend();
        let now = 3_000_000u64;
        let source = FixedSource(vec![(
            "a".into(),
            vec![(now, 4), (now - 5000, 9)], // second bucket far outside a 60s window
        )]);
        let mut flush = WindowFlush::new("waf:route", Duration::from_secs(86_400));
        flush.flush(&source, &state, now).await;

        let totals = read_window(&state, "waf:route", 60, now).await;
        assert_eq!(totals.get("a"), Some(&4), "stale bucket excluded from the window sum");
    }

    #[tokio::test]
    async fn id_with_colon_round_trips() {
        // IPv6 access-list entries contain ':'. The id is everything
        // after the numeric bucket-ts, so it survives the split.
        let state = backend();
        let now = 4_000_000u64;
        let id = "2001:db8::1";
        let mut flush = WindowFlush::new("waf:hits:bl", Duration::from_secs(120));
        flush
            .flush(&FixedSource(vec![(id.into(), vec![(now, 11)])]), &state, now)
            .await;
        let totals = read_window(&state, "waf:hits:bl", 60, now).await;
        assert_eq!(totals.get(id), Some(&11));
    }

    #[tokio::test]
    async fn rotated_buckets_are_pruned_from_last_seen() {
        let state = backend();
        let now = 5_000_000u64;
        let mut flush = WindowFlush::new("waf:route", Duration::from_secs(120));
        flush
            .flush(&FixedSource(vec![("a".into(), vec![(now - 100, 5)])]), &state, now)
            .await;
        // Next cycle no longer reports the old bucket → it's pruned, so a
        // fresh bucket at the same id starts its delta from 0 again.
        let out = flush
            .flush(&FixedSource(vec![("a".into(), vec![(now, 2)])]), &state, now)
            .await;
        assert_eq!(out.keys_written, 1);
        let totals = read_window(&state, "waf:route", u64::MAX, now).await;
        assert_eq!(totals.get("a"), Some(&7), "5 (old bucket) + 2 (new bucket)");
    }
}
