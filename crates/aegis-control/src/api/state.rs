//! `/api/state` — SC-T1 — Layer-3 (shared state) backend health.
//!
//! Read-only view of the configured `StateBackend`'s current
//! reachability + telemetry. Operators read this to answer
//! "is the data plane's shared state healthy?" without dropping
//! into `redis-cli`.
//!
//! The route mirrors `/api/runtime` (L1) and `/api/cluster` (L2).
//! All three feed the dashboard's Scaling page (SC-T2).
//!
//! ## Cadence
//!
//! Designed for a 5-second dashboard poll. The heavy parts of the
//! snapshot (`INFO server` / `INFO replication` / `DBSIZE` against
//! Redis) are cached server-side inside the Redis backend impl
//! at the same TTL — busy primaries don't pay every dashboard tick.
//!
//! ## What this is NOT
//!
//! - Not a write surface — backends are wired at boot, not via API.
//! - Not a cluster topology view — that's `/api/cluster`.
//! - Not a Redis Cluster-aware view — Cluster slot-hashing changes
//!   the response shape (per-shard health), tracked separately.

use aegis_core::state::{BackendHealth, CircuitState, LatencyP};
use serde::Serialize;

/// Wire shape returned by `GET /api/state`.
#[derive(Clone, Debug, Serialize)]
pub struct StateView {
    /// Stable backend identifier — `"redis"` / `"in_memory"` /
    /// `"reconciling"` / `"unknown"`.
    pub backend: &'static str,
    /// `true` when the backend last responded successfully.
    pub connected: bool,
    /// Recent op latency percentiles in microseconds, when known.
    pub latency: Option<LatencyView>,
    /// Best-effort key count (Redis `DBSIZE` / `DashMap::len`).
    pub key_count: Option<u64>,
    /// Worst-case replica lag in milliseconds (Redis primary →
    /// replicas). `None` for setups without replication.
    pub replica_lag_ms: Option<u64>,
    /// Server version string from `INFO server`. Surfaced for
    /// dashboard troubleshooting only.
    pub server_version: Option<String>,
    /// Circuit-breaker state for this backend's wrapper.
    pub circuit: CircuitView,
}

#[derive(Clone, Debug, Serialize)]
pub struct LatencyView {
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
}

impl From<LatencyP> for LatencyView {
    fn from(p: LatencyP) -> Self {
        Self {
            p50_us: p.p50_us,
            p95_us: p.p95_us,
            p99_us: p.p99_us,
        }
    }
}

/// Wire shape for the circuit-breaker state. Tagged externally so
/// the dashboard can branch on `state` and still reach the
/// timestamp when present.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CircuitView {
    Closed,
    HalfOpen,
    Open {
        last_open_at_unix_ms: u64,
    },
}

impl From<CircuitState> for CircuitView {
    fn from(c: CircuitState) -> Self {
        match c {
            CircuitState::Closed => CircuitView::Closed,
            CircuitState::HalfOpen => CircuitView::HalfOpen,
            CircuitState::Open { last_open_at_unix_ms } => {
                CircuitView::Open { last_open_at_unix_ms }
            }
        }
    }
}

impl StateView {
    /// Render the wire view from a backend's [`BackendHealth`]
    /// snapshot. Pure transformation — no I/O.
    pub fn render(h: BackendHealth) -> Self {
        Self {
            backend: h.backend,
            connected: h.connected,
            latency: h.latency.map(LatencyView::from),
            key_count: h.key_count,
            replica_lag_ms: h.replica_lag_ms,
            server_version: h.server_version,
            circuit: h.circuit.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_health(backend: &'static str, connected: bool) -> BackendHealth {
        BackendHealth {
            backend,
            connected,
            latency: LatencyP::from_samples(&[100, 200, 300, 400, 500]),
            key_count: Some(42),
            replica_lag_ms: Some(50),
            server_version: Some("7.2.4".to_string()),
            circuit: CircuitState::Closed,
        }
    }

    #[test]
    fn render_preserves_field_values() {
        let view = StateView::render(sample_health("redis", true));
        assert_eq!(view.backend, "redis");
        assert!(view.connected);
        assert_eq!(view.key_count, Some(42));
        assert_eq!(view.replica_lag_ms, Some(50));
        assert_eq!(view.server_version.as_deref(), Some("7.2.4"));
        let lat = view.latency.expect("latency present");
        assert_eq!(lat.p50_us, 300);
        assert_eq!(lat.p95_us, 500);
    }

    #[test]
    fn render_propagates_none_fields() {
        let h = BackendHealth {
            backend: "in_memory",
            connected: true,
            latency: None,
            key_count: None,
            replica_lag_ms: None,
            server_version: None,
            circuit: CircuitState::Closed,
        };
        let view = StateView::render(h);
        assert!(view.latency.is_none());
        assert!(view.key_count.is_none());
        assert!(view.replica_lag_ms.is_none());
        assert!(view.server_version.is_none());
    }

    #[test]
    fn render_disconnected_backend_carries_open_circuit() {
        let h = BackendHealth {
            backend: "redis",
            connected: false,
            latency: None,
            key_count: None,
            replica_lag_ms: None,
            server_version: None,
            circuit: CircuitState::Open {
                last_open_at_unix_ms: 1_700_000_000_000,
            },
        };
        let view = StateView::render(h);
        assert!(!view.connected);
        match view.circuit {
            CircuitView::Open { last_open_at_unix_ms } => {
                assert_eq!(last_open_at_unix_ms, 1_700_000_000_000);
            }
            other => panic!("expected Open, got {other:?}"),
        }
    }

    #[test]
    fn view_serialises_to_expected_json_shape() {
        let view = StateView::render(sample_health("redis", true));
        let json = serde_json::to_value(&view).unwrap();

        // Top-level fields the dashboard reads.
        assert_eq!(json["backend"], "redis");
        assert_eq!(json["connected"], true);
        assert_eq!(json["key_count"], 42);
        assert_eq!(json["replica_lag_ms"], 50);
        assert_eq!(json["server_version"], "7.2.4");

        // Latency block.
        assert!(json["latency"].is_object());
        assert_eq!(json["latency"]["p50_us"], 300);
        assert_eq!(json["latency"]["p95_us"], 500);

        // Circuit block — externally tagged on `state`.
        assert_eq!(json["circuit"]["state"], "closed");
    }

    #[test]
    fn open_circuit_serialises_with_timestamp_field() {
        let h = BackendHealth {
            backend: "redis",
            connected: false,
            latency: None,
            key_count: None,
            replica_lag_ms: None,
            server_version: None,
            circuit: CircuitState::Open {
                last_open_at_unix_ms: 1_700_000_000_000,
            },
        };
        let view = StateView::render(h);
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["circuit"]["state"], "open");
        assert_eq!(json["circuit"]["last_open_at_unix_ms"], 1_700_000_000_000u64);
    }

    #[test]
    fn half_open_circuit_serialises_as_snake_case_state() {
        let h = BackendHealth {
            backend: "reconciling",
            connected: true,
            latency: None,
            key_count: None,
            replica_lag_ms: None,
            server_version: None,
            circuit: CircuitState::HalfOpen,
        };
        let view = StateView::render(h);
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["circuit"]["state"], "half_open");
    }

    #[test]
    fn unknown_backend_renders_safely() {
        // The default trait impl returns `BackendHealth::unknown()`;
        // the dashboard must still get a parseable response.
        let view = StateView::render(BackendHealth::unknown());
        assert_eq!(view.backend, "unknown");
        assert!(!view.connected);
        let json = serde_json::to_string(&view).unwrap();
        assert!(json.contains("\"backend\":\"unknown\""));
    }
}
