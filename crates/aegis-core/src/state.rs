use std::net::IpAddr;
use std::time::Duration;

use crate::error::Result;
use crate::risk::RiskKey;

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
    pub fn unknown() -> Self {
        Self {
            backend: "unknown",
            connected: false,
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
        let h = BackendHealth::unknown();
        assert_eq!(h.backend, "unknown");
        assert!(!h.connected, "unknown backend is not connected");
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
        assert!(!h.connected);
    }
}
