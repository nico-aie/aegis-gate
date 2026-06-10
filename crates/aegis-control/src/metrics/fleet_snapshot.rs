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

/// One node's live-traffic rollup, published to `fleet:snap:<node_id>`.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct FleetSnapshot {
    pub node_id: String,
    pub ts_ms: i64,
    pub build: String,
    // --- stats (/api/stats) ---
    pub request_rate: f64,
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
    pub blocks_total: u64,
    pub active_threats: u32,
    /// `None` when no node reported any latency samples.
    pub latency: Option<MergedLatency>,
    pub action_mix: BTreeMap<String, u64>,
    pub detector_mix: BTreeMap<String, u64>,
    pub bot_mix: BTreeMap<String, u64>,
    pub top_attackers: Vec<SnapAttacker>,
}

/// Merge a set of per-node snapshots into the fleet view. `top_k`
/// caps the merged top-attacker list.
pub fn merge(snaps: &[FleetSnapshot], top_k: usize) -> MergedFleet {
    let mut out = MergedFleet {
        nodes: snaps.len(),
        ..Default::default()
    };
    for s in snaps {
        out.request_rate += s.request_rate;
        out.blocks_total = out.blocks_total.saturating_add(s.blocks_total);
        out.active_threats = out.active_threats.saturating_add(s.active_threats);
        sum_into(&mut out.action_mix, &s.action_mix);
        sum_into(&mut out.detector_mix, &s.detector_mix);
        sum_into(&mut out.bot_mix, &s.bot_mix);
    }
    out.latency = merge_latency(snaps);
    out.top_attackers = merge_top_attackers(snaps, top_k);
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
