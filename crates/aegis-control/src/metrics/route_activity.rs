//! Per-route 60-second sliding-window request counter.
//!
//! **P5 (2026-05-11) — Phase 3b.** Operators reading the Routing
//! & Upstreams table need to tell live routes from dead ones at
//! a glance — today the table tells them *what's configured*,
//! not *what's serving traffic*. `RouteLatencyHistogram` already
//! tracks per-route samples but only exposes the cumulative
//! count since boot, which is useless for "is this route still
//! hot?".
//!
//! This module adds a sliding-window counter: for each route, a
//! 60-bucket ring of 1-second granularity plus a `last_ts`
//! atomic. The hot path is one `fetch_add` on the current
//! bucket + one `store` on `last_ts` per request. Snapshot reads
//! sum the buckets that fall inside the requested window.
//!
//! ## Cardinality + memory
//!
//! - 60 × 8 bytes per bucket = 480 bytes per route.
//! - Plus 8 bytes for `last_ts`, 8 bytes for `last_bucket_ts`.
//! - Plus the `DashMap` entry overhead (~64 bytes).
//! - At 50 routes (typical config size) → ~28 KB total. Trivial.
//!
//! ## Hot-path cost
//!
//! `record(route, now)` does one `DashMap::entry` lookup
//! (hashmap-of-shards, ~ns) plus one bucket-index modulo plus
//! one atomic `fetch_add` plus one atomic `store`. The bucket-
//! ring's rotation is lazy — we don't reset old buckets on a
//! timer; instead, `snapshot` skips buckets older than the
//! window. Concurrent `record` and `snapshot` calls touch the
//! same atomics with `Ordering::Relaxed` since we're counting,
//! not synchronising.
//!
//! ## Why not a `Mutex<Vec<u64>>`?
//!
//! Per-request mutex contention at 5k+ RPS hurts. The atomic
//! ring keeps the hot path lock-free; the `DashMap` shard is
//! the only contention point and it's a single read for "get
//! the route's ring" then atomic operations on the ring itself.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;

/// Window size in seconds — 60 matches the "req/min" framing
/// the dashboard pill uses. Bumping this widens the snapshot
/// window but also enlarges the per-route memory footprint
/// linearly.
pub const WINDOW_SECS: u64 = 60;

/// Per-route fixed-size ring. Each bucket holds the count for
/// `bucket_index` modulo `WINDOW_SECS`. The ring is shared via
/// `Arc` so the `DashMap` entry can be cloned cheaply and the
/// snapshot path doesn't hold the shard lock while it sums.
struct RouteRing {
    /// `WINDOW_SECS` 1-second buckets. Indexed by
    /// `(ts_secs % WINDOW_SECS)`.
    buckets: [AtomicU64; WINDOW_SECS as usize],
    /// Wall-clock second of the most-recent bucket touched by
    /// `record`. Used by `snapshot` to detect buckets that have
    /// "expired" (any bucket whose owning second is older than
    /// `now - WINDOW_SECS` is treated as zero — the writer
    /// hasn't reset it yet because resets happen lazily).
    last_bucket_ts: AtomicU64,
    /// Wall-clock second of the most-recent request. Drives the
    /// "Last request: 23 s ago" tooltip on the dashboard.
    last_seen_ts: AtomicU64,
}

impl RouteRing {
    fn new() -> Self {
        // `[T; N]` initialisation for non-Copy types needs the
        // array-of-fn-results pattern.
        let buckets = std::array::from_fn(|_| AtomicU64::new(0));
        Self {
            buckets,
            last_bucket_ts: AtomicU64::new(0),
            last_seen_ts: AtomicU64::new(0),
        }
    }

    /// Hot-path: record one hit at `now_secs`. Idempotent across
    /// multiple writers — the bucket counter is an atomic.
    ///
    /// Lazy reset: when the writer touches a bucket whose
    /// `last_bucket_ts` indicates it's from a previous window
    /// rotation, the counter is reset before the increment so
    /// stale counts don't bleed into the new minute. Cheaper than
    /// a sweep thread.
    fn record(&self, now_secs: u64) {
        let idx = (now_secs % WINDOW_SECS) as usize;
        let prev_ts = self.last_bucket_ts.swap(now_secs, Ordering::Relaxed);
        // If the same writer or any other touched THIS bucket index
        // within the same second (or within WINDOW_SECS), keep the
        // running count. Otherwise reset before increment.
        // We detect rotation by checking if the previous TS was in
        // the same second AS THIS bucket index would map to — i.e.
        // `prev_ts / WINDOW_SECS == now_secs / WINDOW_SECS` and
        // `prev_ts % WINDOW_SECS == idx` is too tight; we just
        // compare absolute distance.
        if now_secs.saturating_sub(prev_ts) >= WINDOW_SECS {
            // Bucket is stale across the whole ring — reset every
            // bucket. Rare in production (only happens when a
            // route is idle for the entire window).
            for b in &self.buckets {
                b.store(0, Ordering::Relaxed);
            }
        } else if prev_ts != now_secs {
            // We rolled into a new second. Reset only the bucket
            // we're about to write — the others stay until their
            // turn comes around.
            self.buckets[idx].store(0, Ordering::Relaxed);
        }
        self.buckets[idx].fetch_add(1, Ordering::Relaxed);
        self.last_seen_ts.store(now_secs, Ordering::Relaxed);
    }

    /// Snapshot the count over the last `WINDOW_SECS` seconds.
    /// Skips buckets whose owning second falls outside the
    /// window — those are stale-but-not-yet-reset.
    fn snapshot(&self, now_secs: u64) -> RouteActivity {
        let oldest = now_secs.saturating_sub(WINDOW_SECS - 1);
        let last_bucket_ts = self.last_bucket_ts.load(Ordering::Relaxed);
        let mut count_60s = 0u64;
        if last_bucket_ts >= oldest {
            // The ring has live data. Sum every bucket; the lazy-
            // reset means stale buckets are already zero or about
            // to be zeroed by the next writer.
            for b in &self.buckets {
                count_60s = count_60s.saturating_add(b.load(Ordering::Relaxed));
            }
        }
        let last_seen_ts = self.last_seen_ts.load(Ordering::Relaxed);
        let last_seen_age_s = if last_seen_ts == 0 {
            None
        } else {
            Some(now_secs.saturating_sub(last_seen_ts))
        };
        RouteActivity {
            count_60s,
            last_seen_age_s,
        }
    }
}

/// One route's activity snapshot. Returned by
/// [`RouteActivityWindow::snapshot`].
#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub struct RouteActivity {
    /// Count of requests this route received in the last
    /// `WINDOW_SECS` seconds.
    pub count_60s: u64,
    /// Seconds since the most recent request, or `None` if the
    /// route has never been hit since process boot.
    pub last_seen_age_s: Option<u64>,
}

/// Sliding-window activity tracker keyed by `route_id`. Cheap to
/// clone — the `DashMap` is `Arc`-shared internally. Construct
/// once at boot in `aegis-proxy::run` and hand the same handle
/// to both the data plane (for `record`) and `DashboardServices`
/// (for the `/api/analytics/route-activity` endpoint).
#[derive(Clone)]
pub struct RouteActivityWindow {
    rings: Arc<DashMap<String, Arc<RouteRing>>>,
}

impl RouteActivityWindow {
    pub fn new() -> Self {
        Self {
            rings: Arc::new(DashMap::new()),
        }
    }

    /// Hot-path: record one request for `route_id`. Creates the
    /// per-route ring on first call (one `DashMap::entry` write
    /// per new route; every subsequent call hits the `get_or_*`
    /// fast path).
    pub fn record(&self, route_id: &str) {
        let now_secs = current_secs();
        let entry = self
            .rings
            .entry(route_id.to_string())
            .or_insert_with(|| Arc::new(RouteRing::new()));
        entry.record(now_secs);
    }

    /// Snapshot every known route. Returns `(route_id,
    /// activity)` pairs sorted by `count_60s` descending. The
    /// list never contains routes that have zero recorded
    /// requests since process boot.
    pub fn snapshot_all(&self) -> Vec<(String, RouteActivity)> {
        let now = current_secs();
        let mut out: Vec<(String, RouteActivity)> = self
            .rings
            .iter()
            .map(|kv| (kv.key().clone(), kv.value().snapshot(now)))
            .collect();
        out.sort_by(|a, b| b.1.count_60s.cmp(&a.1.count_60s));
        out
    }

    /// Snapshot a single route. Returns `None` when the route
    /// has never been recorded.
    pub fn snapshot(&self, route_id: &str) -> Option<RouteActivity> {
        let now = current_secs();
        self.rings.get(route_id).map(|r| r.value().snapshot(now))
    }
}

impl RouteRing {
    /// 2026-05-27 (Phase C) — report every live bucket as
    /// `(absolute_bucket_ts, count)` for the metrics flush. The bucket
    /// at index `idx` represents the most recent second `t <=
    /// last_bucket_ts` with `t % WINDOW_SECS == idx`; lazy reset
    /// guarantees the bucket's count belongs to that second (an older
    /// occupant would have been zeroed when the index was reused, which
    /// happens within `WINDOW_SECS`). A fully-idle ring (last bucket
    /// older than the window) reports nothing.
    fn drain_buckets(&self, now_secs: u64) -> Vec<(u64, u64)> {
        let last = self.last_bucket_ts.load(Ordering::Relaxed);
        if last == 0 || last < now_secs.saturating_sub(WINDOW_SECS - 1) {
            return Vec::new();
        }
        let w = WINDOW_SECS as i64;
        let mut out = Vec::new();
        for (idx, b) in self.buckets.iter().enumerate() {
            let count = b.load(Ordering::Relaxed);
            if count == 0 {
                continue;
            }
            // back = how many seconds before `last` this index last owned.
            let back = (((last % WINDOW_SECS) as i64 - idx as i64) % w + w) % w;
            out.push((last.saturating_sub(back as u64), count));
        }
        out
    }
}

impl super::window_flush::BucketSource for RouteActivityWindow {
    fn drain_buckets(&self, now_secs: u64) -> Vec<(String, Vec<(u64, u64)>)> {
        self.rings
            .iter()
            .map(|kv| (kv.key().clone(), kv.value().drain_buckets(now_secs)))
            .filter(|(_, b)| !b.is_empty())
            .collect()
    }
}

impl Default for RouteActivityWindow {
    fn default() -> Self {
        Self::new()
    }
}

fn current_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper — bypass `current_secs()` so tests can drive the
    /// clock deterministically. Production calls go through
    /// `record`, which reads `SystemTime::now()`.
    fn record_at(w: &RouteActivityWindow, route: &str, ts: u64) {
        let entry = w
            .rings
            .entry(route.to_string())
            .or_insert_with(|| Arc::new(RouteRing::new()));
        entry.record(ts);
    }

    fn snapshot_at(w: &RouteActivityWindow, route: &str, ts: u64) -> Option<RouteActivity> {
        w.rings.get(route).map(|r| r.value().snapshot(ts))
    }

    #[test]
    fn snapshot_returns_none_for_unknown_route() {
        let w = RouteActivityWindow::new();
        assert!(snapshot_at(&w, "ghost", 100).is_none());
    }

    #[test]
    fn drain_buckets_reconstructs_absolute_timestamps() {
        use super::super::window_flush::BucketSource;
        let w = RouteActivityWindow::new();
        record_at(&w, "r", 1000); // idx 40, abs_ts 1000
        record_at(&w, "r", 1000); // count 2 at 1000
        record_at(&w, "r", 1005); // idx 45, abs_ts 1005, count 1
        let ring = w.rings.get("r").unwrap();
        let mut got = ring.value().drain_buckets(1010);
        got.sort();
        assert_eq!(got, vec![(1000, 2), (1005, 1)]);

        // Source view yields the per-route grouping.
        let all = w.drain_buckets(1010);
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].0, "r");
    }

    #[test]
    fn drain_buckets_empty_for_idle_ring() {
        use super::super::window_flush::BucketSource;
        let w = RouteActivityWindow::new();
        record_at(&w, "r", 1000);
        // now far past the window — ring is stale, reports nothing.
        assert!(w.drain_buckets(1000 + WINDOW_SECS + 5).is_empty());
    }

    #[test]
    fn single_hit_shows_count_one_and_zero_age() {
        let w = RouteActivityWindow::new();
        record_at(&w, "api", 100);
        let s = snapshot_at(&w, "api", 100).unwrap();
        assert_eq!(s.count_60s, 1);
        assert_eq!(s.last_seen_age_s, Some(0));
    }

    #[test]
    fn many_hits_in_same_second_aggregate() {
        let w = RouteActivityWindow::new();
        for _ in 0..100 {
            record_at(&w, "api", 100);
        }
        let s = snapshot_at(&w, "api", 100).unwrap();
        assert_eq!(s.count_60s, 100);
    }

    #[test]
    fn hits_across_seconds_sum_within_window() {
        let w = RouteActivityWindow::new();
        for sec in 100..=110 {
            for _ in 0..3 {
                record_at(&w, "api", sec);
            }
        }
        // 11 seconds × 3 hits = 33 total, all within last 60s of t=120.
        let s = snapshot_at(&w, "api", 120).unwrap();
        assert_eq!(s.count_60s, 33);
        assert_eq!(s.last_seen_age_s, Some(10));
    }

    #[test]
    fn hits_outside_window_drop_off() {
        let w = RouteActivityWindow::new();
        // Burst at t=100.
        for _ in 0..50 {
            record_at(&w, "api", 100);
        }
        // Querying at t=200 (100s later) → all hits expired.
        let s = snapshot_at(&w, "api", 200).unwrap();
        assert_eq!(s.count_60s, 0);
        // last_seen_age_s still reflects the burst — operators want
        // "this route went quiet ~100s ago".
        assert_eq!(s.last_seen_age_s, Some(100));
    }

    #[test]
    fn second_window_after_idle_starts_clean() {
        let w = RouteActivityWindow::new();
        // Heavy traffic at t=100.
        for _ in 0..200 {
            record_at(&w, "api", 100);
        }
        // Long idle, then a single hit at t=300.
        record_at(&w, "api", 300);
        let s = snapshot_at(&w, "api", 300).unwrap();
        assert_eq!(s.count_60s, 1, "old burst must not leak into the new window");
        assert_eq!(s.last_seen_age_s, Some(0));
    }

    #[test]
    fn snapshot_all_sorts_by_count_descending() {
        let w = RouteActivityWindow::new();
        for _ in 0..5 {
            record_at(&w, "low", 100);
        }
        for _ in 0..50 {
            record_at(&w, "high", 100);
        }
        for _ in 0..20 {
            record_at(&w, "mid", 100);
        }
        let snaps: Vec<(String, RouteActivity)> = w
            .rings
            .iter()
            .map(|kv| (kv.key().clone(), kv.value().snapshot(100)))
            .collect();
        let mut sorted = snaps.clone();
        sorted.sort_by(|a, b| b.1.count_60s.cmp(&a.1.count_60s));
        assert_eq!(sorted[0].0, "high");
        assert_eq!(sorted[1].0, "mid");
        assert_eq!(sorted[2].0, "low");
    }

    #[test]
    fn record_at_second_boundary_does_not_double_count() {
        let w = RouteActivityWindow::new();
        // 100 hits in second 100, 100 in second 101 → 200 total.
        for _ in 0..100 {
            record_at(&w, "api", 100);
        }
        for _ in 0..100 {
            record_at(&w, "api", 101);
        }
        let s = snapshot_at(&w, "api", 101).unwrap();
        assert_eq!(s.count_60s, 200);
    }

    #[test]
    fn record_after_full_ring_idle_resets_every_bucket() {
        let w = RouteActivityWindow::new();
        // Spray hits across every bucket position.
        for sec in 100..160 {
            record_at(&w, "api", sec);
        }
        let s = snapshot_at(&w, "api", 159).unwrap();
        assert_eq!(s.count_60s, 60, "one hit per bucket = 60 in the window");
        // Long idle (> WINDOW_SECS).
        record_at(&w, "api", 500);
        let s = snapshot_at(&w, "api", 500).unwrap();
        assert_eq!(s.count_60s, 1, "long-idle ring must zero every bucket");
    }
}
