//! Cluster Phase 3 — leaderless fleet **metrics** snapshot + merge
//! (cluster plan §2a / §5).
//!
//! Each node periodically serialises its own live-traffic rollup
//! ([`FleetSnapshot`]) and writes it to a self-owned, short-TTL state
//! key `fleet:snap:<node_id>`. Any node's console reads the fleet view
//! by scanning `fleet:snap:*`, decoding each peer's snapshot, and
//! [`merge`]-ing them into a [`MergedFleet`] held in an [`FleetCache`]
//! (`ArcSwap`) that the synchronous admin GET handlers read without
//! `.await` — the same constraint the P4/P5 `AggregateCache` solved.
//!
//! Leaderless by construction: no coordinator, no sweeper. A dead
//! node's key ages out via its TTL (default 5× the publish cadence),
//! so it simply drops from the next merge.
//!
//! ## Merge rules (the only subtle part — §5)
//!
//! - **Sums** (RPS, blocks, action/detector/bot mix): add across nodes.
//! - **Percentiles**: you cannot average p95s. Each node ships its
//!   decision-latency **histogram buckets** (identical bucket bounds
//!   fleet-wide — same histogram config on every node); the merge sums
//!   them bucket-wise and recomputes p50/p95/p99 from the merged
//!   histogram via the shared [`quantile_ms`].
//! - **Top-attackers**: each node ships its bounded top-K; the merge
//!   sums per-identifier hits across nodes, unions detector categories,
//!   takes max risk + latest `last_seen`, re-sorts, truncates. Slightly
//!   lossy at the long tail (an identifier ranked #(K+1) on every node
//!   is undercounted) — acceptable for a dashboard; exact per-IP risk
//!   stays correct in shared state for enforcement.

use std::collections::BTreeMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};

use crate::metrics::request_duration::quantile_ms;

/// State-key prefix for per-node snapshots. The read path scans this.
pub const FLEET_SNAP_PREFIX: &str = "fleet:snap:";

/// Build the snapshot key for a node id.
pub fn snapshot_key(node_id: &str) -> String {
    format!("{FLEET_SNAP_PREFIX}{node_id}")
}

/// One cumulative histogram bucket `(upper_bound, cumulative_count)`,
/// serializable (unlike `prometheus::proto::Bucket`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct LatencyBucket {
    pub upper_bound: f64,
    pub cumulative_count: u64,
}

/// One attacker row carried in a snapshot — the mergeable subset of
/// the dashboard's `Attacker` shape.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SnapAttacker {
    pub identifier: String,
    pub hits: u64,
    pub categories: Vec<String>,
    pub risk: u32,
    /// Most-recent-hit timestamp, Unix epoch ms (mergeable as max).
    pub last_seen_ms: i64,
    pub country: Option<String>,
    pub asn: Option<u32>,
    pub asn_class: Option<String>,
}

/// One node's view of a composite RiskKey bucket `{ip, device_fp,
/// session}`, published for the fleet-merged Top Attackers "Composite
/// RiskKey" table. `level` is an owned `String` (the wire `RiskSnapshot`
/// uses a `&'static str`, which can't round-trip through Redis), mapped
/// back to the static form at render time.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SnapRiskBucket {
    pub ip: String,
    pub device_fp: Option<String>,
    pub session: Option<String>,
    pub score: u32,
    pub strikes: u32,
    pub idle_seconds: u64,
    pub level: String,
    pub strike_blocked: bool,
}

/// One node's live-traffic rollup, published to `fleet:snap:<node_id>`.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct FleetSnapshot {
    pub node_id: String,
    pub ts_ms: i64,
    pub build: String,
    // --- stats (/api/stats) ---
    pub request_rate: f64,
    /// Windowed block rate (%). Merged as a request-rate-weighted
    /// average across nodes.
    pub block_rate_pct: f64,
    pub blocks_total: u64,
    pub active_threats: u32,
    // --- decision latency (cumulative histogram) ---
    pub latency_count: u64,
    pub latency_buckets: Vec<LatencyBucket>,
    // --- mixes ---
    pub action_mix: BTreeMap<String, u64>,
    pub detector_mix: BTreeMap<String, u64>,
    pub bot_mix: BTreeMap<String, u64>,
    // --- top attackers (this node's bounded top-K) ---
    pub top_attackers: Vec<SnapAttacker>,
    // --- composite RiskKey buckets (this node's bounded top-K) ---
    #[serde(default)]
    pub risk_buckets: Vec<SnapRiskBucket>,
}

/// Merged percentiles recomputed from the summed histogram.
#[derive(Clone, Copy, Debug, Serialize, PartialEq)]
pub struct MergedLatency {
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub samples: u64,
}

/// Fleet-wide merged view, recomputed each publish tick.
#[derive(Clone, Debug, Serialize, Default)]
pub struct MergedFleet {
    /// Number of live nodes whose snapshot fed this merge.
    pub nodes: usize,
    pub request_rate: f64,
    /// Request-rate-weighted fleet block rate (%).
    pub block_rate_pct: f64,
    pub blocks_total: u64,
    pub active_threats: u32,
    /// `None` when no node reported any latency samples.
    pub latency: Option<MergedLatency>,
    pub action_mix: BTreeMap<String, u64>,
    pub detector_mix: BTreeMap<String, u64>,
    pub bot_mix: BTreeMap<String, u64>,
    pub top_attackers: Vec<SnapAttacker>,
    /// Composite RiskKey buckets deduped across nodes (display-only —
    /// per-node enforcement state surfaced for the dashboard, not a
    /// cluster-authoritative risk verdict).
    pub risk_buckets: Vec<SnapRiskBucket>,
}

/// Merge a set of per-node snapshots into the fleet view. `top_k`
/// caps the merged top-attacker list.
pub fn merge(snaps: &[FleetSnapshot], top_k: usize) -> MergedFleet {
    let mut out = MergedFleet {
        nodes: snaps.len(),
        ..Default::default()
    };
    let mut block_rate_weighted = 0.0_f64;
    for s in snaps {
        out.request_rate += s.request_rate;
        block_rate_weighted += s.request_rate * s.block_rate_pct;
        out.blocks_total = out.blocks_total.saturating_add(s.blocks_total);
        out.active_threats = out.active_threats.saturating_add(s.active_threats);
        sum_into(&mut out.action_mix, &s.action_mix);
        sum_into(&mut out.detector_mix, &s.detector_mix);
        sum_into(&mut out.bot_mix, &s.bot_mix);
    }
    // Request-rate-weighted fleet block rate (a node with no traffic
    // doesn't skew the average). Falls back to a plain mean if every
    // node is idle (request_rate == 0).
    out.block_rate_pct = if out.request_rate > 0.0 {
        block_rate_weighted / out.request_rate
    } else if !snaps.is_empty() {
        snaps.iter().map(|s| s.block_rate_pct).sum::<f64>() / snaps.len() as f64
    } else {
        0.0
    };
    out.latency = merge_latency(snaps);
    out.top_attackers = merge_top_attackers(snaps, top_k);
    out.risk_buckets = merge_risk_buckets(snaps, top_k);
    out
}

fn sum_into(dst: &mut BTreeMap<String, u64>, src: &BTreeMap<String, u64>) {
    for (k, v) in src {
        *dst.entry(k.clone()).or_insert(0) += *v;
    }
}

/// Bucket-wise sum the per-node cumulative histograms (keyed by upper
/// bound — identical bounds fleet-wide), then recompute percentiles
/// from the merged histogram. `None` when total samples == 0.
fn merge_latency(snaps: &[FleetSnapshot]) -> Option<MergedLatency> {
    let mut summed: BTreeMap<u64, u64> = BTreeMap::new(); // upper_bound bits → cum count
    let mut total: u64 = 0;
    for s in snaps {
        total = total.saturating_add(s.latency_count);
        for b in &s.latency_buckets {
            // f64 key via bit pattern so identical bounds collide
            // exactly (bucket bounds are fixed constants, never NaN).
            *summed.entry(b.upper_bound.to_bits()).or_insert(0) += b.cumulative_count;
        }
    }
    if total == 0 || summed.is_empty() {
        return None;
    }
    // Rebuild proto buckets (sorted by upper bound) so we can reuse the
    // shared `quantile_ms` (PromQL-style linear interpolation).
    let mut bounds: Vec<(f64, u64)> = summed
        .into_iter()
        .map(|(bits, c)| (f64::from_bits(bits), c))
        .collect();
    bounds.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
    let proto: Vec<prometheus::proto::Bucket> = bounds
        .iter()
        .map(|(ub, c)| {
            let mut b = prometheus::proto::Bucket::default();
            b.set_upper_bound(*ub);
            b.set_cumulative_count(*c);
            b
        })
        .collect();
    Some(MergedLatency {
        p50_ms: quantile_ms(&proto, total, 0.50),
        p95_ms: quantile_ms(&proto, total, 0.95),
        p99_ms: quantile_ms(&proto, total, 0.99),
        samples: total,
    })
}

/// Merge per-node top-K attacker lists: sum hits per identifier, union
/// categories, max risk, latest `last_seen`, then re-sort + truncate.
fn merge_top_attackers(snaps: &[FleetSnapshot], top_k: usize) -> Vec<SnapAttacker> {
    let mut by_id: BTreeMap<String, SnapAttacker> = BTreeMap::new();
    for s in snaps {
        for a in &s.top_attackers {
            let entry = by_id.entry(a.identifier.clone()).or_insert_with(|| SnapAttacker {
                identifier: a.identifier.clone(),
                ..Default::default()
            });
            entry.hits = entry.hits.saturating_add(a.hits);
            entry.risk = entry.risk.max(a.risk);
            if a.last_seen_ms > entry.last_seen_ms {
                entry.last_seen_ms = a.last_seen_ms;
            }
            for c in &a.categories {
                if !entry.categories.contains(c) {
                    entry.categories.push(c.clone());
                }
            }
            // GeoIP fields: keep the first non-None seen (an identifier's
            // geo is node-independent).
            if entry.country.is_none() {
                entry.country = a.country.clone();
            }
            if entry.asn.is_none() {
                entry.asn = a.asn;
            }
            if entry.asn_class.is_none() {
                entry.asn_class = a.asn_class.clone();
            }
        }
    }
    let mut rows: Vec<SnapAttacker> = by_id.into_values().collect();
    for r in &mut rows {
        r.categories.sort();
    }
    // Sort by hits desc, then identifier for stable ties.
    rows.sort_by(|a, b| {
        b.hits
            .cmp(&a.hits)
            .then_with(|| a.identifier.cmp(&b.identifier))
    });
    rows.truncate(top_k);
    rows
}

/// Worst-wins ordering for the composite-RiskKey `level` pill.
fn level_rank(level: &str) -> u8 {
    match level {
        "block" => 2,
        "challenge" => 1,
        _ => 0,
    }
}

/// Merge per-node composite-RiskKey buckets: dedup by `{ip, device_fp,
/// session}`, taking max score, max strikes, min idle, OR `strike_blocked`,
/// and the worst (most-restrictive) level — then re-sort `(strikes desc,
/// score desc)` and truncate. Display-only: surfaces per-node enforcement
/// state, never a cluster-authoritative verdict.
fn merge_risk_buckets(snaps: &[FleetSnapshot], top_k: usize) -> Vec<SnapRiskBucket> {
    type Key = (String, Option<String>, Option<String>);
    let mut by_key: BTreeMap<Key, SnapRiskBucket> = BTreeMap::new();
    for s in snaps {
        for r in &s.risk_buckets {
            let key = (r.ip.clone(), r.device_fp.clone(), r.session.clone());
            match by_key.get_mut(&key) {
                None => {
                    by_key.insert(key, r.clone());
                }
                Some(entry) => {
                    entry.score = entry.score.max(r.score);
                    entry.strikes = entry.strikes.max(r.strikes);
                    entry.idle_seconds = entry.idle_seconds.min(r.idle_seconds);
                    entry.strike_blocked |= r.strike_blocked;
                    if level_rank(&r.level) > level_rank(&entry.level) {
                        entry.level = r.level.clone();
                    }
                }
            }
        }
    }
    let mut rows: Vec<SnapRiskBucket> = by_key.into_values().collect();
    // Sort by strikes desc, then score desc, then ip for stable ties.
    rows.sort_by(|a, b| {
        b.strikes
            .cmp(&a.strikes)
            .then_with(|| b.score.cmp(&a.score))
            .then_with(|| a.ip.cmp(&b.ip))
    });
    rows.truncate(top_k);
    rows
}

/// Build this node's snapshot from its live local sources. Reads only
/// already-collected aggregates (no hot-path work). `action_mix` is
/// left empty for now — its canonical source (`DecisionMetrics`) isn't
/// wired to the dashboard services and no endpoint serves a fleet
/// action-mix; the field is kept for forward-compat.
#[allow(clippy::too_many_arguments)]
pub fn build_snapshot(
    node_id: &str,
    window_seconds: u32,
    top_k: u32,
    stats_agg: &crate::api::stats::StatsAggregator,
    attacks_agg: &crate::api::attacks::AttacksAggregator,
    risk: &aegis_security::risk::RiskTracker,
    hist: &crate::metrics::request_duration::RequestStageHistogram,
    latency_stage: &str,
) -> FleetSnapshot {
    let stats = stats_agg.snapshot();
    let (latency_count, latency_buckets) = hist
        .stage_buckets(latency_stage)
        .map(|(total, b)| {
            (
                total,
                b.into_iter()
                    .map(|(upper_bound, cumulative_count)| LatencyBucket {
                        upper_bound,
                        cumulative_count,
                    })
                    .collect(),
            )
        })
        .unwrap_or((0, Vec::new()));

    let detector_mix = attacks_agg
        .by_detector(window_seconds)
        .detectors
        .into_iter()
        .map(|d| (d.name, d.count))
        .collect();
    let bot_mix = attacks_agg
        .bot_mix(window_seconds)
        .categories
        .into_iter()
        .map(|c| (c.name, c.count))
        .collect();
    let top_attackers = attacks_agg
        .top(window_seconds, top_k)
        .attackers
        .into_iter()
        .map(|a| SnapAttacker {
            identifier: a.identifier,
            hits: a.hits,
            categories: a.categories,
            risk: a.risk,
            last_seen_ms: a.last_seen.timestamp_millis(),
            country: a.country,
            asn: a.asn,
            asn_class: a.asn_class,
        })
        .collect();

    // Composite RiskKey buckets — this node's bounded top-K, deduped
    // across the fleet at merge time. Owned `level` round-trips Redis.
    let risk_buckets: Vec<SnapRiskBucket> = risk
        .top(top_k as usize)
        .into_iter()
        .map(|r| SnapRiskBucket {
            ip: r.ip,
            device_fp: r.device_fp,
            session: r.session,
            score: r.score,
            strikes: r.strikes,
            idle_seconds: r.idle_seconds,
            level: r.level.to_string(),
            strike_blocked: r.strike_blocked,
        })
        .collect();

    FleetSnapshot {
        node_id: node_id.to_string(),
        ts_ms: chrono::Utc::now().timestamp_millis(),
        build: env!("CARGO_PKG_VERSION").to_string(),
        request_rate: stats.request_rate,
        block_rate_pct: stats.block_rate_pct,
        blocks_total: stats.blocks_total,
        active_threats: stats.active_threats,
        latency_count,
        latency_buckets,
        action_mix: BTreeMap::new(),
        detector_mix,
        bot_mix,
        top_attackers,
        risk_buckets,
    }
}

/// Scan every live `fleet:snap:*` key off the shared backend, decode
/// each, and [`merge`] them. Dead nodes' keys have already TTL'd out of
/// the keyspace, so they simply don't appear. Used by the publish task;
/// factored out for testability. Decode failures are skipped (a peer on
/// a newer snapshot schema shouldn't poison the whole merge).
pub async fn scan_and_merge(
    backend: &dyn aegis_core::state::StateBackend,
    top_k: usize,
) -> MergedFleet {
    let mut snaps: Vec<FleetSnapshot> = Vec::new();
    if let Ok(keys) = backend.scan_prefix(FLEET_SNAP_PREFIX).await {
        for k in keys {
            if let Ok(Some(bytes)) = backend.get(&k).await {
                if let Ok(s) = serde_json::from_slice::<FleetSnapshot>(&bytes) {
                    snaps.push(s);
                }
            }
        }
    }
    merge(&snaps, top_k)
}

/// PB / F6 (2026-06-11) — merge peers' snapshots by a KNOWN node roster
/// (one `GET fleet:snap:<node>` per id) instead of a whole-keyspace
/// `SCAN MATCH`. Same rationale as
/// [`crate::metrics::fleet_audit::merge_audit_from_roster`]: bounded
/// O(nodes), timeout-safe, cluster-Redis-safe. A node whose snapshot has
/// TTL'd out returns `None` and is skipped.
pub async fn merge_from_roster(
    backend: &dyn aegis_core::state::StateBackend,
    node_ids: &[String],
    top_k: usize,
) -> MergedFleet {
    let mut snaps: Vec<FleetSnapshot> = Vec::new();
    for id in node_ids {
        let key = snapshot_key(id);
        if let Ok(Some(bytes)) = backend.get(&key).await {
            if let Ok(s) = serde_json::from_slice::<FleetSnapshot>(&bytes) {
                snaps.push(s);
            }
        }
    }
    merge(&snaps, top_k)
}

/// `ArcSwap`-backed cache of the latest merged fleet view. The publish
/// task refreshes it each tick; synchronous admin GET handlers read it
/// without `.await`. `None` until the first successful merge (read path
/// then falls back to the local panels).
#[derive(Clone, Default)]
pub struct FleetCache {
    inner: Arc<ArcSwap<Option<MergedFleet>>>,
}

impl FleetCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(None)),
        }
    }

    /// Replace the cached merged view (called on each publish tick).
    pub fn store(&self, merged: MergedFleet) {
        self.inner.store(Arc::new(Some(merged)));
    }

    /// Latest merged view, or `None` before the first merge.
    pub fn load(&self) -> Option<MergedFleet> {
        (**self.inner.load()).clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(node: &str) -> FleetSnapshot {
        FleetSnapshot {
            node_id: node.into(),
            ts_ms: 1,
            build: "test".into(),
            ..Default::default()
        }
    }

    fn buckets(pairs: &[(f64, u64)]) -> Vec<LatencyBucket> {
        pairs
            .iter()
            .map(|(ub, c)| LatencyBucket {
                upper_bound: *ub,
                cumulative_count: *c,
            })
            .collect()
    }

    fn rbucket(
        ip: &str,
        fp: Option<&str>,
        score: u32,
        strikes: u32,
        idle: u64,
        level: &str,
        blocked: bool,
    ) -> SnapRiskBucket {
        SnapRiskBucket {
            ip: ip.into(),
            device_fp: fp.map(Into::into),
            session: None,
            score,
            strikes,
            idle_seconds: idle,
            level: level.into(),
            strike_blocked: blocked,
        }
    }

    #[test]
    fn merge_risk_buckets_dedups_composite_key_worst_wins() {
        // Same composite key {10.0.0.1, fp=aa, session=none} seen on two
        // nodes with divergent enforcement state → one merged row taking
        // max score, max strikes, min idle, OR strike_blocked, worst level.
        let mut a = snap("a");
        a.risk_buckets = vec![
            rbucket("10.0.0.1", Some("aa"), 40, 2, 90, "challenge", false),
            rbucket("10.0.0.9", None, 30, 1, 5, "challenge", false),
        ];
        let mut b = snap("b");
        b.risk_buckets = vec![rbucket("10.0.0.1", Some("aa"), 70, 5, 10, "block", true)];

        let m = merge(&[a, b], 50);

        // Two distinct composite keys survive (the shared one collapsed).
        assert_eq!(m.risk_buckets.len(), 2);
        // Sorted by (strikes desc, score desc): the merged 10.0.0.1 row first.
        let top = &m.risk_buckets[0];
        assert_eq!(top.ip, "10.0.0.1");
        assert_eq!(top.device_fp.as_deref(), Some("aa"));
        assert_eq!(top.score, 70, "max score");
        assert_eq!(top.strikes, 5, "max strikes");
        assert_eq!(top.idle_seconds, 10, "min idle");
        assert!(top.strike_blocked, "OR strike_blocked");
        assert_eq!(top.level, "block", "worst level wins");
    }

    #[test]
    fn merge_risk_buckets_truncates_to_top_k() {
        let mut a = snap("a");
        a.risk_buckets = (0..10)
            .map(|i| rbucket(&format!("10.0.0.{i}"), None, i, i, 0, "challenge", false))
            .collect();
        let m = merge(&[a], 3);
        assert_eq!(m.risk_buckets.len(), 3);
        // Highest strikes first.
        assert_eq!(m.risk_buckets[0].ip, "10.0.0.9");
    }

    #[test]
    fn merge_sums_scalars_and_mixes() {
        let mut a = snap("a");
        a.request_rate = 10.0;
        a.blocks_total = 3;
        a.active_threats = 1;
        a.action_mix = BTreeMap::from([("allow".into(), 100), ("block".into(), 3)]);
        let mut b = snap("b");
        b.request_rate = 5.0;
        b.blocks_total = 2;
        b.active_threats = 2;
        b.action_mix = BTreeMap::from([("allow".into(), 50), ("challenge".into(), 4)]);

        let m = merge(&[a, b], 50);
        assert_eq!(m.nodes, 2);
        assert_eq!(m.request_rate, 15.0);
        assert_eq!(m.blocks_total, 5);
        assert_eq!(m.active_threats, 3);
        assert_eq!(m.action_mix.get("allow"), Some(&150));
        assert_eq!(m.action_mix.get("block"), Some(&3));
        assert_eq!(m.action_mix.get("challenge"), Some(&4));
    }

    #[test]
    fn merge_recomputes_percentiles_from_summed_histograms() {
        // Two nodes with identical bucket bounds. Node A: 10 samples
        // all ≤10ms. Node B: 10 samples all ≤100ms. Merged total 20;
        // p50 should land in the ≤10 bucket region, p95/p99 in ≤100.
        let bounds = [(10.0, 0u64), (100.0, 0u64), (1000.0, 0u64)];
        let mut a = snap("a");
        a.latency_count = 10;
        a.latency_buckets = buckets(&[(10.0, 10), (100.0, 10), (1000.0, 10)]);
        let mut b = snap("b");
        b.latency_count = 10;
        b.latency_buckets = buckets(&[(10.0, 0), (100.0, 10), (1000.0, 10)]);
        let _ = bounds;

        let m = merge(&[a, b], 50).latency.expect("latency present");
        assert_eq!(m.samples, 20);
        // Merged cumulative: ≤10 → 10, ≤100 → 20, ≤1000 → 20.
        // p50 (target 10) sits at the ≤10 boundary; p95 (target 19)
        // interpolates inside the (10,100] bucket.
        assert!(m.p50_ms <= 10.0, "p50={}", m.p50_ms);
        assert!(m.p95_ms > 10.0 && m.p95_ms <= 100.0, "p95={}", m.p95_ms);
        assert!(m.p99_ms > 10.0 && m.p99_ms <= 100.0, "p99={}", m.p99_ms);
    }

    #[test]
    fn merge_latency_none_when_no_samples() {
        let a = snap("a");
        let b = snap("b");
        assert!(merge(&[a, b], 50).latency.is_none());
    }

    #[test]
    fn merge_top_attackers_sums_and_truncates() {
        let mut a = snap("a");
        a.top_attackers = vec![
            SnapAttacker {
                identifier: "1.1.1.1".into(),
                hits: 10,
                categories: vec!["sqli".into()],
                risk: 80,
                last_seen_ms: 100,
                ..Default::default()
            },
            SnapAttacker {
                identifier: "2.2.2.2".into(),
                hits: 5,
                ..Default::default()
            },
        ];
        let mut b = snap("b");
        b.top_attackers = vec![
            SnapAttacker {
                identifier: "1.1.1.1".into(),
                hits: 7,
                categories: vec!["xss".into()],
                risk: 60,
                last_seen_ms: 200,
                ..Default::default()
            },
            SnapAttacker {
                identifier: "3.3.3.3".into(),
                hits: 9,
                ..Default::default()
            },
        ];

        let merged = merge(&[a, b], 2).top_attackers;
        assert_eq!(merged.len(), 2, "truncated to top_k=2");
        // 1.1.1.1: 10+7=17 hits → rank 1; categories unioned; risk max; last_seen latest.
        assert_eq!(merged[0].identifier, "1.1.1.1");
        assert_eq!(merged[0].hits, 17);
        assert_eq!(merged[0].categories, vec!["sqli".to_string(), "xss".to_string()]);
        assert_eq!(merged[0].risk, 80);
        assert_eq!(merged[0].last_seen_ms, 200);
        // 3.3.3.3 (9) outranks 2.2.2.2 (5) for the second slot.
        assert_eq!(merged[1].identifier, "3.3.3.3");
    }

    #[test]
    fn fleet_cache_round_trips() {
        let cache = FleetCache::new();
        assert!(cache.load().is_none());
        cache.store(merge(&[snap("a")], 50));
        assert_eq!(cache.load().unwrap().nodes, 1);
    }

    /// Minimal in-memory `StateBackend` for the scan+merge test —
    /// only the three methods `scan_and_merge` touches are real; the
    /// rest defer to the trait defaults / unreachable stubs.
    struct MockBackend {
        kv: std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
    }

    #[async_trait::async_trait]
    impl aegis_core::state::StateBackend for MockBackend {
        async fn get(&self, key: &str) -> aegis_core::Result<Option<Vec<u8>>> {
            Ok(self.kv.lock().unwrap().get(key).cloned())
        }
        async fn set(&self, key: &str, val: &[u8], _: std::time::Duration) -> aegis_core::Result<()> {
            self.kv.lock().unwrap().insert(key.to_string(), val.to_vec());
            Ok(())
        }
        async fn scan_prefix(&self, prefix: &str) -> aegis_core::Result<Vec<String>> {
            Ok(self
                .kv
                .lock()
                .unwrap()
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect())
        }
        // --- trivial stubs (not exercised by scan_and_merge) ---
        async fn del(&self, _: &str) -> aegis_core::Result<()> {
            Ok(())
        }
        async fn incr_window(
            &self,
            _: &str,
            _: std::time::Duration,
            _: u64,
        ) -> aegis_core::Result<aegis_core::state::SlidingWindowResult> {
            Ok(aegis_core::state::SlidingWindowResult {
                count: 0,
                allowed: true,
                retry_after: None,
            })
        }
        async fn token_bucket(&self, _: &str, _: u32, _: u32) -> aegis_core::Result<bool> {
            Ok(true)
        }
        async fn get_risk(&self, _: &aegis_core::risk::RiskKey) -> aegis_core::Result<u32> {
            Ok(0)
        }
        async fn add_risk(
            &self,
            _: &aegis_core::risk::RiskKey,
            _: i32,
            _: u32,
        ) -> aegis_core::Result<u32> {
            Ok(0)
        }
        async fn auto_block(&self, _: std::net::IpAddr, _: std::time::Duration) -> aegis_core::Result<()> {
            Ok(())
        }
        async fn is_auto_blocked(&self, _: std::net::IpAddr) -> aegis_core::Result<bool> {
            Ok(false)
        }
        async fn put_nonce(&self, _: &str, _: std::time::Duration) -> aegis_core::Result<bool> {
            Ok(true)
        }
        async fn consume_nonce(&self, _: &str) -> aegis_core::Result<bool> {
            Ok(true)
        }
    }

    #[tokio::test]
    async fn scan_and_merge_sums_live_nodes_and_skips_ttld() {
        use aegis_core::state::StateBackend as _;
        let backend = MockBackend {
            kv: std::sync::Mutex::new(std::collections::HashMap::new()),
        };
        // Three live nodes publish snapshots with RPS 10 / 20 / 30.
        for (node, rps) in [("a", 10.0), ("b", 20.0), ("c", 30.0)] {
            let mut s = snap(node);
            s.request_rate = rps;
            let bytes = serde_json::to_vec(&s).unwrap();
            backend
                .set(&snapshot_key(node), &bytes, std::time::Duration::from_secs(10))
                .await
                .unwrap();
        }
        let merged = scan_and_merge(&backend, 50).await;
        assert_eq!(merged.nodes, 3);
        assert_eq!(merged.request_rate, 60.0, "RPS = sum across live nodes");

        // Node "c" TTLs out (key removed) → drops from the merge.
        backend.kv.lock().unwrap().remove(&snapshot_key("c"));
        let merged = scan_and_merge(&backend, 50).await;
        assert_eq!(merged.nodes, 2, "TTL'd node dropped");
        assert_eq!(merged.request_rate, 30.0);
    }

    // PB / F6 — roster-driven merge: GET each known node's key, no SCAN.
    #[tokio::test]
    async fn merge_from_roster_uses_known_nodes_only() {
        use aegis_core::state::StateBackend as _;
        let backend = MockBackend {
            kv: std::sync::Mutex::new(std::collections::HashMap::new()),
        };
        for (node, rps) in [("a", 10.0), ("b", 20.0), ("c", 30.0)] {
            let mut s = snap(node);
            s.request_rate = rps;
            let bytes = serde_json::to_vec(&s).unwrap();
            backend
                .set(&snapshot_key(node), &bytes, std::time::Duration::from_secs(10))
                .await
                .unwrap();
        }
        // Roster lists a/b/c → all three merged via GET (no scan_prefix).
        let ids = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let merged = merge_from_roster(&backend, &ids, 50).await;
        assert_eq!(merged.nodes, 3);
        assert_eq!(merged.request_rate, 60.0);

        // A roster id whose key is absent (dead / TTL'd) is skipped; an
        // id NOT in the roster is never read even though its key exists.
        let ids = vec!["a".to_string(), "ghost".to_string()];
        let merged = merge_from_roster(&backend, &ids, 50).await;
        assert_eq!(merged.nodes, 1, "only the live, rostered node merged");
        assert_eq!(merged.request_rate, 10.0);
    }

    #[test]
    fn snapshot_json_round_trips() {
        let mut s = snap("node-7");
        s.request_rate = 42.0;
        s.latency_buckets = buckets(&[(10.0, 5)]);
        s.top_attackers = vec![SnapAttacker {
            identifier: "9.9.9.9".into(),
            hits: 3,
            ..Default::default()
        }];
        let bytes = serde_json::to_vec(&s).unwrap();
        let back: FleetSnapshot = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.node_id, "node-7");
        assert_eq!(back.request_rate, 42.0);
        assert_eq!(back.top_attackers[0].identifier, "9.9.9.9");
    }
}
