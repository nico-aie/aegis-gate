//! `/api/upstreams/config` — full upstream-pool configuration view
//! (CC-T1.1 read side) plus validators + route-reference helpers
//! shared with the future audit-mutated PUT / DELETE handlers
//! (CC-T1.1.b).
//!
//! Read-only today. The config the WAF booted with is exposed
//! verbatim — every pool, every member, full health + circuit-
//! breaker + connection-pool tuning. Cached at the dispatch layer
//! (2 s) like the other tracking surfaces.
//!
//! Why this is split from [`crate::api::upstreams`]: that module
//! emits the *summary* (`state` / `healthy_members` / per-pool
//! aggregate) used by the Overview tile. This module emits the
//! *config* the operator can edit. Two distinct purposes, two
//! handlers — keeps each ≤ 50 lines and the wire shapes
//! independent.
//!
//! Validators + reference lookup live alongside the view because
//! the dashboard "delete pool" flow needs the same reference-
//! check the audit-mutated DELETE will eventually run. Surfacing
//! the validators here lets the GET handler echo them in the
//! response (so the UI can pre-flight without a PUT round-trip)
//! and lets the PUT handler import them when it lands.

#![allow(dead_code)]

use std::collections::BTreeMap;

use serde::Serialize;

use aegis_core::config::{
    CircuitBreakerConfig, ConnectionPoolConfig, HealthCheckConfig, LbStrategy, MemberConfig,
    PoolConfig, WafConfig,
};

// ---------------------------------------------------------------------------
// Wire view — full PoolConfig roundtrip shape
// ---------------------------------------------------------------------------

/// `GET /api/upstreams/config` body.
///
/// Pools are emitted in name-sorted order so the JSON is stable
/// across consecutive reads — the dashboard diff preview relies
/// on a deterministic shape.
#[derive(Clone, Debug, Serialize)]
pub struct UpstreamsConfigView {
    pub pools: BTreeMap<String, PoolView>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PoolView {
    pub members: Vec<MemberView>,
    pub lb: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<HealthView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub circuit_breaker: Option<CircuitBreakerView>,
    pub connection: ConnectionView,
    /// Routes whose `upstream` field references this pool. Empty
    /// when nothing routes to the pool — that's the only case
    /// where DELETE will succeed once writes ship.
    pub referenced_by_routes: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct MemberView {
    pub addr: String,
    pub weight: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    /// FIX 2026-05-03 — surfaces `MemberConfig.host_header` so
    /// the dashboard's pool-edit modal can show + roundtrip the
    /// vhost-routing override.
    #[serde(skip_serializing_if = "Option::is_none", rename = "host_header")]
    pub host_header: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct HealthView {
    pub path: String,
    pub interval_ms: u64,
    pub timeout_ms: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct CircuitBreakerView {
    pub error_rate_threshold: f64,
    pub open_duration_ms: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConnectionView {
    pub max_idle_per_host: usize,
    pub idle_timeout_ms: u64,
    pub keep_alive: bool,
    pub tls: bool,
    /// Phase-3 multi-protocol selector. One of
    /// `auto | http | https | h2c | grpc | tcp`. `auto` (default)
    /// preserves the legacy `tls` semantics; explicit values
    /// override.
    pub scheme: &'static str,
}

impl UpstreamsConfigView {
    /// Build the view from the live [`WafConfig`]. Routes that
    /// reference each pool are pre-computed so the dashboard can
    /// render the "in use by" badge without a second fetch.
    pub fn from_config(cfg: &WafConfig) -> Self {
        let pools: BTreeMap<String, PoolView> = cfg
            .upstreams
            .iter()
            .map(|(name, pool)| {
                let view = PoolView {
                    members: pool.members.iter().map(member_view).collect(),
                    lb: lb_name(&pool.lb),
                    health: pool.health.as_ref().map(health_view),
                    circuit_breaker: pool.circuit_breaker.as_ref().map(circuit_view),
                    connection: connection_view(&pool.connection),
                    referenced_by_routes: routes_referencing(cfg, name),
                };
                (name.clone(), view)
            })
            .collect();
        Self { pools }
    }

    /// Render to the JSON body the admin handler returns. Stable
    /// shape — `serde_json` can't fail on these fields.
    pub fn render(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| String::from("{}"))
    }
}

fn member_view(m: &MemberConfig) -> MemberView {
    MemberView {
        addr: m.addr.to_string(),
        weight: m.weight,
        zone: m.zone.clone(),
        host_header: m.host_header.clone(),
    }
}

fn lb_name(lb: &LbStrategy) -> &'static str {
    match lb {
        LbStrategy::RoundRobin => "round_robin",
        LbStrategy::WeightedRoundRobin => "weighted_round_robin",
        LbStrategy::LeastConn => "least_conn",
        LbStrategy::ConsistentHash => "consistent_hash",
        LbStrategy::P2c => "p2c",
    }
}

fn health_view(h: &HealthCheckConfig) -> HealthView {
    HealthView {
        path: h.path.clone(),
        interval_ms: h.interval.as_millis() as u64,
        timeout_ms: h.timeout.as_millis() as u64,
    }
}

fn circuit_view(cb: &CircuitBreakerConfig) -> CircuitBreakerView {
    CircuitBreakerView {
        error_rate_threshold: cb.error_rate_threshold,
        open_duration_ms: cb.open_duration.as_millis() as u64,
    }
}

fn connection_view(c: &ConnectionPoolConfig) -> ConnectionView {
    ConnectionView {
        max_idle_per_host: c.max_idle_per_host,
        idle_timeout_ms: c.idle_timeout.as_millis() as u64,
        keep_alive: c.keep_alive,
        tls: c.tls,
        scheme: c.scheme.as_str(),
    }
}

// ---------------------------------------------------------------------------
// Validators — shared with the future PUT / DELETE handlers
// ---------------------------------------------------------------------------

/// Why a pool config was rejected. Each variant rolls into a
/// stable, machine-readable `reason_code` so the dashboard can
/// surface targeted error messages without parsing free-form
/// strings.
#[derive(Clone, Debug, PartialEq)]
pub enum PoolValidationError {
    /// Pool has zero members. LB algorithms divide by member count;
    /// every algorithm panics or no-ops on an empty list.
    EmptyMembers,
    /// A member declared `weight: 0`. Weighted-round-robin and the
    /// power-of-two-choices algorithms divide by total weight.
    ZeroWeight { addr: String },
    /// `health.timeout >= health.interval` would never finish a
    /// probe before the next one starts.
    InvalidHealthTimeout { interval_ms: u64, timeout_ms: u64 },
    /// `circuit_breaker.error_rate_threshold` outside `[0.0, 1.0]`.
    InvalidCircuitThreshold { value: f64 },
}

impl PoolValidationError {
    /// Stable machine-readable code — the dashboard checks this
    /// to drive the correct error toast / inline hint.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::EmptyMembers => "empty_members",
            Self::ZeroWeight { .. } => "zero_weight",
            Self::InvalidHealthTimeout { .. } => "invalid_health_timeout",
            Self::InvalidCircuitThreshold { .. } => "invalid_circuit_threshold",
        }
    }
}

impl std::fmt::Display for PoolValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyMembers => f.write_str("pool must have at least one member"),
            Self::ZeroWeight { addr } => write!(f, "member {addr} weight must be > 0"),
            Self::InvalidHealthTimeout {
                interval_ms,
                timeout_ms,
            } => write!(
                f,
                "health.timeout ({timeout_ms} ms) must be < health.interval ({interval_ms} ms)"
            ),
            Self::InvalidCircuitThreshold { value } => write!(
                f,
                "circuit_breaker.error_rate_threshold ({value}) must be in [0.0, 1.0]"
            ),
        }
    }
}

impl std::error::Error for PoolValidationError {}

/// Validate a [`PoolConfig`] against the runtime invariants the
/// LB / health / circuit-breaker code paths depend on. Returns
/// the *first* failure — the dashboard re-runs after each fix.
pub fn validate_pool(pool: &PoolConfig) -> Result<(), PoolValidationError> {
    if pool.members.is_empty() {
        return Err(PoolValidationError::EmptyMembers);
    }
    for m in &pool.members {
        if m.weight == 0 {
            return Err(PoolValidationError::ZeroWeight {
                addr: m.addr.to_string(),
            });
        }
    }
    if let Some(h) = &pool.health {
        let interval_ms = h.interval.as_millis() as u64;
        let timeout_ms = h.timeout.as_millis() as u64;
        if timeout_ms >= interval_ms {
            return Err(PoolValidationError::InvalidHealthTimeout {
                interval_ms,
                timeout_ms,
            });
        }
    }
    if let Some(cb) = &pool.circuit_breaker {
        let v = cb.error_rate_threshold;
        if !(0.0..=1.0).contains(&v) {
            return Err(PoolValidationError::InvalidCircuitThreshold { value: v });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Route → pool reference lookup
// ---------------------------------------------------------------------------

/// Return the route ids that name `pool_id` as their upstream.
/// The audit-mutated DELETE handler refuses with 409 when this
/// list is non-empty; the dashboard surfaces the list in the
/// confirm modal so the operator sees what's blocking.
pub fn routes_referencing(cfg: &WafConfig, pool_id: &str) -> Vec<String> {
    cfg.routes
        .iter()
        .filter(|r| r.upstream == pool_id)
        .map(|r| r.id.clone())
        .collect()
}

// ---------------------------------------------------------------------------
// Writer trait — bridges control plane → proxy without circular deps
// ---------------------------------------------------------------------------

/// CC-T1.1.b — typed-erased writer for the live pool registry.
///
/// `aegis-control` can't depend on `aegis-proxy` (the dep flows the
/// other way) but the audit-mutated PUT/DELETE handlers in the
/// proxy need a way to call the registry's `apply` from within
/// `services.mutate.apply`'s closure. This trait is the bridge:
/// the proxy boot path implements it on `PoolRegistry` and stashes
/// an `Arc<dyn UpstreamWriter>` in `DashboardServices`. The
/// dashboard-facing handlers call `services.upstream_writer.as_ref()`
/// without ever needing to name the proxy types.
pub trait UpstreamWriter: Send + Sync {
    /// Atomically replace the live pool table with `new_pools`.
    /// Validates first; on error the registry is untouched.
    fn apply(
        &self,
        new_pools: &std::collections::HashMap<String, PoolConfig>,
    ) -> Result<(), PoolValidationError>;

    /// Live per-pool member health snapshot. Reads each
    /// `Member.is_healthy()` AtomicBool from the proxy's
    /// `PoolRegistry`. The dashboard's `/api/upstreams` endpoint
    /// calls this on every fetch so the "healthy / total" mix
    /// reflects the live state, not the boot-time YAML.
    ///
    /// Default implementation returns an empty snapshot — useful
    /// for tests + bundles built before the live read landed.
    fn live_snapshot(
        &self,
    ) -> crate::api::upstreams::PoolHealthSnapshot {
        crate::api::upstreams::PoolHealthSnapshot {
            pools: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn cfg_yaml(yaml: &str) -> WafConfig {
        serde_yaml::from_str(yaml).expect("test yaml must parse")
    }

    fn three_pool_cfg() -> WafConfig {
        cfg_yaml(
            r#"
listeners:
  data:
    - bind: "0.0.0.0:8080"
  admin:
    bind: "127.0.0.1:9443"
routes:
  - id: api
    path: "/api/"
    match_type: prefix
    upstream: backend-pool
  - id: catch-all
    path: "/"
    match_type: prefix
    upstream: backend-pool
  - id: login
    path: "/login"
    match_type: exact
    methods: [POST]
    upstream: auth-pool
upstreams:
  backend-pool:
    members:
      - addr: "127.0.0.1:3001"
        weight: 3
      - addr: "127.0.0.1:3002"
        weight: 1
        zone: "az-a"
    lb: weighted_round_robin
    health:
      path: "/healthz"
      interval: "10s"
      timeout: "3s"
    circuit_breaker:
      error_rate_threshold: 0.5
      open_duration: "30s"
  auth-pool:
    members:
      - addr: "127.0.0.1:3003"
    lb: round_robin
  static-pool:
    members:
      - addr: "127.0.0.1:3004"
    lb: round_robin
state:
  backend: in_memory
"#,
        )
    }

    // ----- view rendering ----------------------------------------------------

    #[test]
    fn view_lists_every_pool_in_sorted_order() {
        let cfg = three_pool_cfg();
        let view = UpstreamsConfigView::from_config(&cfg);
        let names: Vec<&String> = view.pools.keys().collect();
        // BTreeMap iteration is sorted alphabetically.
        assert_eq!(names, vec!["auth-pool", "backend-pool", "static-pool"]);
    }

    #[test]
    fn view_serialises_member_addr_weight_and_zone() {
        let cfg = three_pool_cfg();
        let view = UpstreamsConfigView::from_config(&cfg);
        let backend = &view.pools["backend-pool"];
        assert_eq!(backend.members.len(), 2);
        assert_eq!(backend.members[0].addr, "127.0.0.1:3001");
        assert_eq!(backend.members[0].weight, 3);
        assert!(backend.members[0].zone.is_none());
        assert_eq!(backend.members[1].addr, "127.0.0.1:3002");
        assert_eq!(backend.members[1].weight, 1);
        assert_eq!(backend.members[1].zone.as_deref(), Some("az-a"));
    }

    #[test]
    fn view_emits_lb_strategy_as_snake_case_string() {
        let cfg = three_pool_cfg();
        let view = UpstreamsConfigView::from_config(&cfg);
        assert_eq!(view.pools["backend-pool"].lb, "weighted_round_robin");
        assert_eq!(view.pools["auth-pool"].lb, "round_robin");
    }

    #[test]
    fn view_includes_health_when_configured() {
        let cfg = three_pool_cfg();
        let view = UpstreamsConfigView::from_config(&cfg);
        let h = view.pools["backend-pool"]
            .health
            .as_ref()
            .expect("health configured");
        assert_eq!(h.path, "/healthz");
        assert_eq!(h.interval_ms, 10_000);
        assert_eq!(h.timeout_ms, 3_000);
    }

    #[test]
    fn view_omits_health_when_absent() {
        let cfg = three_pool_cfg();
        let view = UpstreamsConfigView::from_config(&cfg);
        assert!(view.pools["auth-pool"].health.is_none());
    }

    #[test]
    fn view_includes_circuit_breaker_when_configured() {
        let cfg = three_pool_cfg();
        let view = UpstreamsConfigView::from_config(&cfg);
        let cb = view.pools["backend-pool"]
            .circuit_breaker
            .as_ref()
            .expect("circuit_breaker configured");
        assert!((cb.error_rate_threshold - 0.5).abs() < f64::EPSILON);
        assert_eq!(cb.open_duration_ms, 30_000);
    }

    #[test]
    fn view_emits_connection_pool_defaults() {
        let cfg = three_pool_cfg();
        let view = UpstreamsConfigView::from_config(&cfg);
        let c = &view.pools["auth-pool"].connection;
        // hyper-util defaults from PoolConfig::default().
        assert_eq!(c.max_idle_per_host, 32);
        assert_eq!(c.idle_timeout_ms, 30_000);
        assert!(c.keep_alive);
        assert!(!c.tls);
    }

    #[test]
    fn view_pre_computes_referenced_by_routes() {
        let cfg = three_pool_cfg();
        let view = UpstreamsConfigView::from_config(&cfg);
        let mut backend_refs = view.pools["backend-pool"].referenced_by_routes.clone();
        backend_refs.sort();
        assert_eq!(backend_refs, vec!["api", "catch-all"]);
        assert_eq!(
            view.pools["auth-pool"].referenced_by_routes,
            vec!["login"]
        );
        assert!(view.pools["static-pool"].referenced_by_routes.is_empty());
    }

    #[test]
    fn render_produces_valid_json_with_pools_key() {
        let cfg = three_pool_cfg();
        let body = UpstreamsConfigView::from_config(&cfg).render();
        let v: serde_json::Value = serde_json::from_str(&body).expect("valid json");
        assert!(v["pools"].is_object());
        assert!(v["pools"]["backend-pool"]["lb"].as_str() == Some("weighted_round_robin"));
    }

    #[test]
    fn empty_upstreams_renders_empty_pools_object() {
        let yaml = r#"
listeners:
  data: [{ bind: "0.0.0.0:8080" }]
  admin: { bind: "127.0.0.1:9443" }
routes:
  - id: catch-all
    path: "/"
    match_type: prefix
    upstream: doesnt-exist
upstreams: {}
state: { backend: in_memory }
"#;
        // Note: WafConfig::validate would reject this (route refs
        // unknown pool), but the view itself is purely structural —
        // it doesn't validate semantics. We test the structural
        // shape directly.
        let cfg: aegis_core::config::WafConfig =
            serde_yaml::from_str(yaml).expect("structural yaml parse");
        let body = UpstreamsConfigView::from_config(&cfg).render();
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(v["pools"].as_object().unwrap().is_empty());
    }

    // ----- validators -------------------------------------------------------

    fn ok_pool() -> PoolConfig {
        let yaml = r#"
members:
  - addr: "127.0.0.1:3001"
    weight: 1
lb: round_robin
"#;
        serde_yaml::from_str(yaml).unwrap()
    }

    #[test]
    fn validate_pool_accepts_minimal_well_formed_pool() {
        assert!(validate_pool(&ok_pool()).is_ok());
    }

    #[test]
    fn validate_pool_rejects_empty_members() {
        let mut p = ok_pool();
        p.members.clear();
        let err = validate_pool(&p).unwrap_err();
        assert_eq!(err, PoolValidationError::EmptyMembers);
        assert_eq!(err.reason_code(), "empty_members");
    }

    #[test]
    fn validate_pool_rejects_zero_weight_member() {
        let mut p = ok_pool();
        p.members[0].weight = 0;
        let err = validate_pool(&p).unwrap_err();
        match &err {
            PoolValidationError::ZeroWeight { addr } => {
                assert_eq!(addr, "127.0.0.1:3001");
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert_eq!(err.reason_code(), "zero_weight");
        assert!(err.to_string().contains("must be > 0"));
    }

    #[test]
    fn validate_pool_rejects_health_timeout_geq_interval() {
        let mut p = ok_pool();
        p.health = Some(HealthCheckConfig {
            path: "/healthz".into(),
            interval: Duration::from_millis(1000),
            timeout: Duration::from_millis(1000), // equal → reject
        });
        let err = validate_pool(&p).unwrap_err();
        assert_eq!(err.reason_code(), "invalid_health_timeout");
    }

    #[test]
    fn validate_pool_accepts_health_timeout_lt_interval() {
        let mut p = ok_pool();
        p.health = Some(HealthCheckConfig {
            path: "/healthz".into(),
            interval: Duration::from_secs(10),
            timeout: Duration::from_secs(3),
        });
        assert!(validate_pool(&p).is_ok());
    }

    #[test]
    fn validate_pool_rejects_circuit_threshold_above_one() {
        let mut p = ok_pool();
        p.circuit_breaker = Some(CircuitBreakerConfig {
            error_rate_threshold: 1.5,
            open_duration: Duration::from_secs(30),
        });
        let err = validate_pool(&p).unwrap_err();
        assert_eq!(err.reason_code(), "invalid_circuit_threshold");
    }

    #[test]
    fn validate_pool_rejects_negative_circuit_threshold() {
        let mut p = ok_pool();
        p.circuit_breaker = Some(CircuitBreakerConfig {
            error_rate_threshold: -0.1,
            open_duration: Duration::from_secs(30),
        });
        let err = validate_pool(&p).unwrap_err();
        assert_eq!(err.reason_code(), "invalid_circuit_threshold");
    }

    #[test]
    fn validate_pool_accepts_threshold_at_zero_and_one() {
        let mut p = ok_pool();
        p.circuit_breaker = Some(CircuitBreakerConfig {
            error_rate_threshold: 0.0,
            open_duration: Duration::from_secs(30),
        });
        assert!(validate_pool(&p).is_ok());
        let mut p = ok_pool();
        p.circuit_breaker = Some(CircuitBreakerConfig {
            error_rate_threshold: 1.0,
            open_duration: Duration::from_secs(30),
        });
        assert!(validate_pool(&p).is_ok());
    }

    // ----- route reference lookup -------------------------------------------

    #[test]
    fn routes_referencing_finds_all_routes_for_pool() {
        let cfg = three_pool_cfg();
        let mut refs = routes_referencing(&cfg, "backend-pool");
        refs.sort();
        assert_eq!(refs, vec!["api", "catch-all"]);
    }

    #[test]
    fn routes_referencing_returns_single_route_when_unique() {
        let cfg = three_pool_cfg();
        assert_eq!(routes_referencing(&cfg, "auth-pool"), vec!["login"]);
    }

    #[test]
    fn routes_referencing_returns_empty_for_unused_pool() {
        let cfg = three_pool_cfg();
        let refs = routes_referencing(&cfg, "static-pool");
        assert!(refs.is_empty());
    }

    #[test]
    fn routes_referencing_returns_empty_for_unknown_pool() {
        let cfg = three_pool_cfg();
        let refs = routes_referencing(&cfg, "no-such-pool");
        assert!(refs.is_empty());
    }
}
