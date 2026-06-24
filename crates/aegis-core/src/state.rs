use std::net::IpAddr;
use std::time::Duration;

use crate::error::Result;
use crate::risk::RiskKey;

// --- 2026-06-24 — durable, reset-exempt control-plane keys for the
// `redis-interim-durability` bridge (P1–P3). Siblings of the cluster's
// `control:waf:modes` / `:reset_epoch` convention
// (`aegis-control::interop::cluster_sync`); they live HERE in aegis-core
// rather than in that module because the producers span crates that can't
// see aegis-control — `RiskTracker` (aegis-security) writes
// [`CONTROL_RISK_KEY`], the incidents/stats trackers (aegis-control) write
// the other two. All three are single Redis HASH keys so a `reset_state`
// wipe is one `UNLINK`, not a million-key `SCAN`+`DEL` (see
// `plans/future/redis-interim-durability.md` §9 invariant 3). They are
// deliberately OUTSIDE the `g:*` ephemeral prefixes the standard
// `reset_ephemeral` wipe touches — the durability plan opts these specific
// keys back into reset wiring explicitly (§4). ---

/// HASH `alert_id → IncidentState` JSON. Operator ack/snooze/resolve
/// overlay survives restart (P1).
pub const CONTROL_INCIDENTS_KEY: &str = "control:waf:incidents";

/// HASH `RiskKey → {score, strikes, last_seen}` JSON. Lifetime strikes /
/// "permanent block" survive restart (P2). Only `strikes > 0` /
/// above-threshold slots are written so memory stays bounded.
pub const CONTROL_RISK_KEY: &str = "control:waf:risk";

/// HASH of small monotone lifetime totals (`blocks_total`, …) so the
/// Overview top-line numbers survive restart (P3).
pub const CONTROL_STATS_COUNTERS_KEY: &str = "control:waf:stats:counters";

pub struct SlidingWindowResult {
    pub count: u64,
    pub allowed: bool,
    pub retry_after: Option<Duration>,
}

/// SC-T1 — backend health snapshot returned by `StateBackend::health()`.
///
/// Populated best-effort: any field that the concrete backend can't
/// produce cheaply (e.g. an in-memory backend has no replication lag,
/// a Redis backend in degraded mode may not have a fresh key count)
/// is left as `None`. The `connected` flag is the single load-bearing
/// boolean — operators read it to decide whether the data plane has a
/// usable shared state at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendHealth {
    /// Stable identifier — `"redis"` / `"in_memory"` / `"reconciling"`.
    /// String literals so the dashboard can pattern-match without
    /// pulling in a public enum.
    pub backend: &'static str,
    /// `true` when the backend last responded successfully. Backends
    /// that never reach out (in-memory) report `true`.
    pub connected: bool,
    /// Recent round-trip latency percentiles. `None` when the backend
    /// hasn't recorded any samples yet (cold boot) or doesn't measure
    /// (in-memory).
    pub latency: Option<LatencyP>,
    /// Best-effort key count. `None` for in-memory (cheap but not
    /// surfaced today) and for Redis backends that can't run `DBSIZE`
    /// (e.g. degraded / read-only / Cluster topologies).
    pub key_count: Option<u64>,
    /// Replication offset diff in milliseconds (Redis primary →
    /// replica). `None` when no replicas configured or backend
    /// doesn't replicate.
    pub replica_lag_ms: Option<u64>,
    /// `INFO server.redis_version` or equivalent. Surfaced for
    /// dashboard troubleshooting; never load-bearing.
    pub server_version: Option<String>,
    /// Circuit-breaker state for this backend's wrapper. Drives the
    /// "is the data plane in degraded mode?" pill.
    pub circuit: CircuitState,
}

impl BackendHealth {
    /// Default snapshot for backends that don't override `health()`.
    /// Keeps the trait backwards-compatible while still letting the
    /// dashboard render *something*.
    ///
    /// **2026-05-11 CORE-06 fix.** `connected` was previously
    /// `false`, which actively signalled a problem ("backend
    /// disconnected") for any backend that happened not to
    /// override `health()`. The dashboard's data-plane status
    /// pill went red on test stubs and third-party
    /// integrations that were serving traffic just fine. The
    /// trait default now returns "status unknown but assumed
    /// up" (`connected: true`, `backend: "unknown"`) — the
    /// honest answer is "we don't know," and the unknown
    /// backend string makes the gap visible without colour-
    /// flagging it as a failure.
    pub fn unknown() -> Self {
        Self {
            backend: "unknown",
            connected: true,
            latency: None,
            key_count: None,
            replica_lag_ms: None,
            server_version: None,
            circuit: CircuitState::Closed,
        }
    }
}

/// Round-trip latency percentiles in microseconds. Computed over a
/// rolling window (size and cadence are backend-specific).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LatencyP {
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
}

impl LatencyP {
    /// Compute p50/p95/p99 from a slice of microsecond samples.
    /// Returns `None` when the slice is empty so the dashboard can
    /// distinguish "no samples yet" from "samples all zero".
    pub fn from_samples(samples_us: &[u64]) -> Option<Self> {
        if samples_us.is_empty() {
            return None;
        }
        let mut sorted: Vec<u64> = samples_us.to_vec();
        sorted.sort_unstable();
        Some(Self {
            p50_us: percentile(&sorted, 50),
            p95_us: percentile(&sorted, 95),
            p99_us: percentile(&sorted, 99),
        })
    }
}

/// Nearest-rank percentile on a sorted slice. `q` is 0..=100. Caller
/// must pre-sort. Empty slice panics — callers go through
/// `LatencyP::from_samples` which guards.
///
/// Uses the standard nearest-rank definition:
/// `rank = ceil(q/100 * n)` (1-indexed), so e.g. `p99` of 100 samples
/// returns `sorted[98]` and `p50` of 100 samples returns `sorted[49]`.
fn percentile(sorted: &[u64], q: u8) -> u64 {
    debug_assert!(!sorted.is_empty(), "percentile of empty slice");
    debug_assert!(q <= 100, "q must be 0..=100");
    let n = sorted.len();
    // ceil((q/100) * n) — done in integer arithmetic.
    let rank = ((q as usize) * n).div_ceil(100).max(1);
    sorted[(rank - 1).min(n - 1)]
}

/// Circuit-breaker state for a state backend wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Healthy — calls flow through.
    Closed,
    /// Degraded but probing — limited calls allowed.
    HalfOpen,
    /// Tripped — backend calls short-circuit. Carries the unix-ms
    /// timestamp of the most recent open transition for "tripped Xs ago".
    Open { last_open_at_unix_ms: u64 },
}

#[async_trait::async_trait]
pub trait StateBackend: Send + Sync + 'static {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    async fn set(&self, key: &str, val: &[u8], ttl: Duration) -> Result<()>;
    async fn del(&self, key: &str) -> Result<()>;

    async fn incr_window(
        &self,
        key: &str,
        window: Duration,
        limit: u64,
    ) -> Result<SlidingWindowResult>;

    async fn token_bucket(
        &self,
        key: &str,
        rate_per_s: u32,
        burst: u32,
    ) -> Result<bool>;

    async fn get_risk(&self, key: &RiskKey) -> Result<u32>;
    async fn add_risk(&self, key: &RiskKey, delta: i32, max: u32) -> Result<u32>;

    async fn auto_block(&self, ip: IpAddr, ttl: Duration) -> Result<()>;
    async fn is_auto_blocked(&self, ip: IpAddr) -> Result<bool>;

    async fn put_nonce(&self, nonce: &str, ttl: Duration) -> Result<bool>;
    async fn consume_nonce(&self, nonce: &str) -> Result<bool>;

    // --- 2026-05-27 — generic KV primitives for the multi-node config
    // plane + counter aggregation (see
    // `plans/future/cluster-config-sync-and-scaling.md` and
    // `multi-node-metrics-aggregation.md`). Default impls keep the
    // many test-stub + out-of-tree backends compiling; the shipped
    // `redis` / `in_memory` backends and the `Reconciling` / `Metered`
    // wrappers override them. ---

    /// Atomically add `delta` to the integer at `key` (treating an
    /// absent/expired key as 0) and return the new value. Commutative
    /// across nodes — the metrics flush relies on `INCRBY` semantics so
    /// concurrent per-node flushes converge to the right total.
    async fn incrby(&self, _key: &str, _delta: u64) -> Result<u64> {
        Err(crate::error::WafError::State(
            "incrby unsupported by this backend".into(),
        ))
    }

    /// Set / refresh the TTL on an existing key. No-op default (a
    /// backend that can't expire just keeps the key).
    async fn expire(&self, _key: &str, _ttl: Duration) -> Result<()> {
        Ok(())
    }

    /// Return every key matching `prefix`. Default returns empty so
    /// callers fall back to their local in-process view (single-node).
    async fn scan_prefix(&self, _prefix: &str) -> Result<Vec<String>> {
        Ok(Vec::new())
    }

    /// Read an `incrby` counter at `key`, decoding it to a `u64`
    /// (absent/expired → 0). A dedicated primitive because the on-disk
    /// representation differs per backend (Redis stores the decimal
    /// string `INCRBY` produces; the in-memory backend stores LE bytes),
    /// so a generic `get` + parse can't be backend-agnostic. The metrics
    /// aggregation read path (`window_flush::read_window`) sums these
    /// across nodes. Default 0 keeps stub backends compiling.
    async fn get_counter(&self, _key: &str) -> Result<u64> {
        Ok(0)
    }

    /// Single-key compare-and-set: write `new` iff the current value
    /// equals `expected` (`None` = key must be absent). `ttl = None`
    /// persists the key (config must not expire). Returns `true` on a
    /// successful swap, `false` on a value mismatch (optimistic-
    /// concurrency conflict). The config plane uses this to activate a
    /// new config version atomically. Default errors so backends opt in.
    async fn cas_set(
        &self,
        _key: &str,
        _expected: Option<&[u8]>,
        _new: &[u8],
        _ttl: Option<Duration>,
    ) -> Result<bool> {
        Err(crate::error::WafError::State(
            "cas_set unsupported by this backend".into(),
        ))
    }

    // --- 2026-06-24 — HASH primitives for the durable control-plane
    // keyspace (`redis-interim-durability` P1–P3). The interim durability
    // bridge stores three single HASH keys (incidents / risk / counters —
    // see [`CONTROL_INCIDENTS_KEY`] et al.). A single hash per concern
    // keeps `reset_state` an O(1) `UNLINK` instead of a million-key
    // `SCAN`+`DEL` under bench churn. Default impls are inert no-ops so the
    // many test-stub + out-of-tree backends keep compiling; the shipped
    // `redis` / `in_memory` backends and the `Reconciling` / `Metered`
    // wrappers override them. ---

    /// Set (create or overwrite) one or more fields of the hash at `key`
    /// in a single round-trip (`HSET key f1 v1 f2 v2 …`). The hash key is
    /// durable — it never expires. An empty `fields` slice is a no-op.
    async fn hset_multi(&self, _key: &str, _fields: &[(String, Vec<u8>)]) -> Result<()> {
        Ok(())
    }

    /// Remove one or more fields from the hash at `key` (`HDEL`). Absent
    /// fields are silently ignored; an empty slice is a no-op. Used by the
    /// per-entry reset paths (per-IP risk reset, etc.).
    async fn hdel(&self, _key: &str, _fields: &[String]) -> Result<()> {
        Ok(())
    }

    /// Return every `(field, value)` pair of the hash at `key`. Concrete
    /// backends iterate with a cursor (`HSCAN`) so boot hydration of a
    /// large hash never blocks the server on one giant `HGETALL`. Default
    /// returns empty so callers fall back to an empty rehydrate
    /// (single-node / no durable store).
    async fn hscan(&self, _key: &str) -> Result<Vec<(String, Vec<u8>)>> {
        Ok(Vec::new())
    }

    /// Delete an entire key non-blockingly (`UNLINK`, falling back to
    /// `DEL` on older servers). Used by the reset paths to wipe a whole
    /// durable hash in O(1) wall-time. Absent key is not an error.
    async fn unlink(&self, _key: &str) -> Result<()> {
        Ok(())
    }

    /// 2026-05-20 — clear all EPHEMERAL state for
    /// `/__waf_control/reset_state` (committee items 2, 4, 6:
    /// rate-limit counters, challenge nonces, temporary
    /// enforcement state). This wipes: sliding-window /
    /// token-bucket counters, challenge nonces, auto-block
    /// entries, and backend-held risk keys.
    ///
    /// It MUST NOT touch durable operator config (the contract's
    /// §2.4 "long-term static config is preserved"). For
    /// backends whose only contents ARE ephemeral (the current
    /// in-memory + Redis impls store nothing durable), this is a
    /// full flush.
    ///
    /// Default is a no-op so out-of-tree backends keep compiling;
    /// the shipped backends override it. Returns the number of
    /// entries cleared (best-effort; backends that can't count
    /// return 0).
    async fn reset_ephemeral(&self) -> Result<u64> {
        Ok(0)
    }

    /// SC-T1 — backend health for the dashboard's Scaling page.
    ///
    /// Default returns [`BackendHealth::unknown`] so existing impls
    /// keep compiling without code changes; backends that can answer
    /// (Redis, in-memory) override with a real snapshot. Designed to
    /// be called on the dashboard cadence (5s) — concrete impls
    /// should cache aggressively if the answer is expensive.
    async fn health(&self) -> BackendHealth {
        BackendHealth::unknown()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sliding_window_result_fields() {
        let r = SlidingWindowResult {
            count: 5,
            allowed: true,
            retry_after: None,
        };
        assert_eq!(r.count, 5);
        assert!(r.allowed);
        assert!(r.retry_after.is_none());
    }

    #[test]
    fn sliding_window_exceeded() {
        let r = SlidingWindowResult {
            count: 101,
            allowed: false,
            retry_after: Some(Duration::from_secs(30)),
        };
        assert!(!r.allowed);
        assert_eq!(r.retry_after.unwrap().as_secs(), 30);
    }

    // SC-T1 — BackendHealth + LatencyP + CircuitState.

    #[test]
    fn backend_health_unknown_returns_safe_defaults() {
        // 2026-05-11 CORE-06 fix — `connected: true` (was false).
        // The default unknown shape no longer red-flags backends
        // that haven't overridden `health()`. See state.rs::
        // BackendHealth::unknown for the rationale.
        let h = BackendHealth::unknown();
        assert_eq!(h.backend, "unknown");
        assert!(h.connected, "unknown backend is assumed-up by default");
        assert!(h.latency.is_none());
        assert!(h.key_count.is_none());
        assert!(h.replica_lag_ms.is_none());
        assert!(h.server_version.is_none());
        assert_eq!(h.circuit, CircuitState::Closed);
    }

    #[test]
    fn latency_p_empty_returns_none() {
        assert_eq!(LatencyP::from_samples(&[]), None);
    }

    #[test]
    fn latency_p_single_sample_collapses_to_one_value() {
        let lp = LatencyP::from_samples(&[1234]).unwrap();
        assert_eq!(lp.p50_us, 1234);
        assert_eq!(lp.p95_us, 1234);
        assert_eq!(lp.p99_us, 1234);
    }

    #[test]
    fn latency_p_uniform_samples_match_input() {
        // 100 identical samples — every percentile is the same value.
        let samples: Vec<u64> = vec![500; 100];
        let lp = LatencyP::from_samples(&samples).unwrap();
        assert_eq!(lp.p50_us, 500);
        assert_eq!(lp.p95_us, 500);
        assert_eq!(lp.p99_us, 500);
    }

    #[test]
    fn latency_p_picks_correct_ranks_on_sorted_input() {
        // Samples 1..=100 — nearest-rank: p50≈50, p95≈95, p99≈99.
        let samples: Vec<u64> = (1..=100).collect();
        let lp = LatencyP::from_samples(&samples).unwrap();
        assert_eq!(lp.p50_us, 50);
        assert_eq!(lp.p95_us, 95);
        assert_eq!(lp.p99_us, 99);
    }

    #[test]
    fn latency_p_picks_correct_ranks_on_unsorted_input() {
        // Same samples reversed — sort runs internally.
        let samples: Vec<u64> = (1..=100).rev().collect();
        let lp = LatencyP::from_samples(&samples).unwrap();
        assert_eq!(lp.p50_us, 50);
        assert_eq!(lp.p95_us, 95);
        assert_eq!(lp.p99_us, 99);
    }

    #[test]
    fn latency_p_tail_percentiles_capture_outliers() {
        // 50 samples at 100us + 50 spikes at 10ms — by nearest-rank,
        // p50 sits on the boundary (still in the small bucket), p95
        // and p99 land in the outlier tail.
        let mut samples: Vec<u64> = vec![100; 50];
        samples.extend(vec![10_000; 50]);
        let lp = LatencyP::from_samples(&samples).unwrap();
        assert_eq!(lp.p50_us, 100, "median is the 50th-smallest value");
        assert_eq!(
            lp.p95_us, 10_000,
            "p95 must reflect the slow half — operators read this for tail latency",
        );
        assert_eq!(lp.p99_us, 10_000);
    }

    #[test]
    fn circuit_state_open_carries_timestamp() {
        let s = CircuitState::Open {
            last_open_at_unix_ms: 1_700_000_000_000,
        };
        match s {
            CircuitState::Open { last_open_at_unix_ms } => {
                assert_eq!(last_open_at_unix_ms, 1_700_000_000_000);
            }
            _ => panic!("expected Open"),
        }
    }

    #[test]
    fn circuit_state_variants_distinct() {
        // Sanity — three non-equal variants. The dashboard branches on
        // these to render Closed/HalfOpen/Open pills, so equality has
        // to hold.
        assert_eq!(CircuitState::Closed, CircuitState::Closed);
        assert_ne!(CircuitState::Closed, CircuitState::HalfOpen);
        assert_ne!(
            CircuitState::Closed,
            CircuitState::Open { last_open_at_unix_ms: 0 },
        );
    }

    /// Sanity: the trait default `health()` must compile + return
    /// `BackendHealth::unknown()` so existing backends keep working
    /// without code changes.
    #[tokio::test]
    async fn state_backend_default_health_is_unknown() {
        struct DummyBackend;
        #[async_trait::async_trait]
        impl StateBackend for DummyBackend {
            async fn get(&self, _: &str) -> Result<Option<Vec<u8>>> {
                Ok(None)
            }
            async fn set(&self, _: &str, _: &[u8], _: Duration) -> Result<()> {
                Ok(())
            }
            async fn del(&self, _: &str) -> Result<()> {
                Ok(())
            }
            async fn incr_window(
                &self,
                _: &str,
                _: Duration,
                _: u64,
            ) -> Result<SlidingWindowResult> {
                Ok(SlidingWindowResult {
                    count: 0,
                    allowed: true,
                    retry_after: None,
                })
            }
            async fn token_bucket(&self, _: &str, _: u32, _: u32) -> Result<bool> {
                Ok(true)
            }
            async fn get_risk(&self, _: &RiskKey) -> Result<u32> {
                Ok(0)
            }
            async fn add_risk(&self, _: &RiskKey, _: i32, _: u32) -> Result<u32> {
                Ok(0)
            }
            async fn auto_block(&self, _: IpAddr, _: Duration) -> Result<()> {
                Ok(())
            }
            async fn is_auto_blocked(&self, _: IpAddr) -> Result<bool> {
                Ok(false)
            }
            async fn put_nonce(&self, _: &str, _: Duration) -> Result<bool> {
                Ok(true)
            }
            async fn consume_nonce(&self, _: &str) -> Result<bool> {
                Ok(true)
            }
            // Intentionally do NOT override health() — the test verifies
            // the default fires.
        }

        let dummy = DummyBackend;
        let h = dummy.health().await;
        assert_eq!(h.backend, "unknown");
        // 2026-05-11 CORE-06 — default is now `connected: true`.
        assert!(h.connected);

        // 2026-06-24 — the new durable HASH ops also default to inert
        // no-ops on a backend that doesn't override them: writes succeed
        // silently and reads come back empty. This is what keeps every
        // test-stub / out-of-tree backend compiling untouched, and what
        // makes the no-Redis path behave exactly as before A0.
        dummy
            .hset_multi("control:waf:risk", &[("f".into(), b"v".to_vec())])
            .await
            .unwrap();
        dummy.hdel("control:waf:risk", &["f".into()]).await.unwrap();
        dummy.unlink("control:waf:risk").await.unwrap();
        assert!(dummy.hscan("control:waf:risk").await.unwrap().is_empty());
    }
}
