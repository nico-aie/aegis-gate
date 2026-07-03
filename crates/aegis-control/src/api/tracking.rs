//! `/api/slo`, `/api/cluster`, `/api/certs`, `/api/gitops/status`,
//! `/api/alerts`, `/api/tracking/snapshot` (D-M5-T5.1..T5.7).
//!
//! Tracking data layers — wrappers around the existing per-feature
//! state in `aegis-control` (slo.rs, gitops.rs, etc.). Where the
//! data source isn't yet runtime-populated (cluster peers, cert
//! store), the module returns the documented JSON shape with empty
//! lists so the page renders cleanly.

#![allow(dead_code)]

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;

const SNAPSHOT_TTL: Duration = Duration::from_secs(2);

// ---------- SLO ---------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
pub struct SliRow {
    pub name: String,
    pub current: f64,
    pub target: f64,
    pub budget_remaining: f64,
    pub burn_1h: f64,
    pub burn_6h: f64,
    pub burn_3d: f64,
}

#[derive(Clone, Debug, Serialize)]
pub struct SloResponse {
    pub slis: Vec<SliRow>,
    /// SLO-P1 — node-local security-enforcement counter
    /// (blocks / challenges / rate-limits). An info series, NOT
    /// an objective: enforcement is the WAF working, so it is
    /// excluded from the availability SLI. `None` when no engine
    /// is wired (key omitted — placeholder shape unchanged).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforcement: Option<crate::slo::EnforcementStats>,
}

impl SloResponse {
    /// 2026-05-17 F-CRITICAL-018 (control audit): pre-fix this
    /// returned two fake SLI rows (`availability=99.99/99.99` +
    /// `overhead_p99=0.0/5.0`) when no SloEngine was wired. The
    /// dashboard then displayed those mock numbers as if they
    /// were live — official rules §9 calls "mock data shipped to
    /// evaluation" a disqualification class. Now returns an
    /// empty `slis` list (honest empty); the dashboard renders
    /// "no data yet" rather than fake 99.99% availability.
    pub fn placeholder() -> Self {
        Self {
            slis: Vec::new(),
            enforcement: None,
        }
    }

    /// CI-T4/T7 — build the response from the live SLO engine's
    /// per-objective `BudgetStatus` snapshot. `burn_1h`, `burn_6h`,
    /// `burn_3d` are populated from `BudgetStatus::burn_rates` —
    /// any windows the SLO objective doesn't declare stay 0.0.
    pub fn from_budget_status(status: Vec<crate::slo::BudgetStatus>) -> Self {
        fn pick(rates: &[crate::slo::BurnRate], hours: u64) -> f64 {
            rates
                .iter()
                .find(|r| r.window_hours == hours)
                .map(|r| r.rate)
                .unwrap_or(0.0)
        }
        let slis = status
            .into_iter()
            .map(|s| SliRow {
                name: format!("{:?}", s.sli)
                    .chars()
                    .flat_map(|c| {
                        // CamelCase → snake_case for friendly display.
                        if c.is_uppercase() {
                            vec!['_', c.to_ascii_lowercase()]
                        } else {
                            vec![c]
                        }
                    })
                    .collect::<String>()
                    .trim_start_matches('_')
                    .to_string(),
                current: s.current * 100.0,
                target: s.target * 100.0,
                budget_remaining: s.budget_remaining_pct / 100.0,
                burn_1h: pick(&s.burn_rates, 1),
                burn_6h: pick(&s.burn_rates, 6),
                burn_3d: pick(&s.burn_rates, 72),
            })
            .collect();
        Self {
            slis,
            enforcement: None,
        }
    }

    /// Attach the engine's enforcement counter (SLO-P1). Kept as
    /// a builder so `from_budget_status` call sites without an
    /// engine handle stay unchanged.
    pub fn with_enforcement(mut self, stats: crate::slo::EnforcementStats) -> Self {
        self.enforcement = Some(stats);
        self
    }
}

// ---------- Cluster ----------------------------------------------------

#[derive(Clone, Debug, Serialize)]
pub struct ClusterPeer {
    pub id: String,
    pub addr: String,
    pub version: String,
    pub last_heartbeat: chrono::DateTime<chrono::Utc>,
    pub leases: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ClusterResponse {
    pub peers: Vec<ClusterPeer>,
    /// `NodeId` of *this* node. The cluster is **leaderless**
    /// (Phase 1) — every node is equal, so the console shows a
    /// flat peer list and correlates panels against `our_node`.
    pub our_node: String,
}

impl ClusterResponse {
    pub fn placeholder() -> Self {
        Self {
            peers: Vec::new(),
            our_node: String::new(),
        }
    }
}

/// Live cluster-roster view, kept in sync by a background
/// polling task that enumerates the `members:*` heartbeat keys
/// every couple of seconds. The admin handler reads it
/// synchronously through `TrackingHandler::render_cluster`.
///
/// The cluster is **leaderless** (Phase 1): this view carries
/// no leader/holder state — singleton side-tasks (ACME, GitOps)
/// coordinate via their own per-task leases, not a global leader.
#[derive(Debug)]
pub struct RosterView {
    /// `NodeId` of this process. Set once at startup; never
    /// changes for the lifetime of the binary.
    pub our_node: String,
    /// Live cluster membership (HA-T4). The polling task
    /// rebuilds this from `lease_store.list_keys_with_prefix("members:")`
    /// every couple of seconds. Empty until the first
    /// successful poll OR when the lease store doesn't
    /// support enumeration.
    pub members: arc_swap::ArcSwap<Vec<ClusterPeer>>,
}

impl RosterView {
    pub fn new(our_node: impl Into<String>) -> Self {
        Self {
            our_node: our_node.into(),
            members: arc_swap::ArcSwap::from_pointee(Vec::new()),
        }
    }

    /// Replace the current membership snapshot. Lock-free
    /// from the reader's perspective. Called by the
    /// `aegis-proxy::run` background poller every couple of
    /// seconds.
    pub fn set_members(&self, peers: Vec<ClusterPeer>) {
        self.members.store(Arc::new(peers));
    }

    /// Latest membership snapshot, cloned out so callers
    /// don't pin the internal `Arc`.
    pub fn members(&self) -> Vec<ClusterPeer> {
        (*self.members.load_full()).clone()
    }
}

// ---------- Certs ------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
pub struct CertEntry {
    pub host: String,
    pub issuer: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub days_to_expiry: i64,
    pub source: String, // "acme" | "static" | "mtls"
}

#[derive(Clone, Debug, Serialize)]
pub struct CertsResponse {
    pub certs: Vec<CertEntry>,
}

impl CertsResponse {
    pub fn placeholder() -> Self {
        Self { certs: Vec::new() }
    }

    /// Build the response from a cert inventory closure. Each
    /// entry carries the parsed `notAfter` and a freshly computed
    /// `days_to_expiry` against `now`. Sorts by `days_to_expiry`
    /// ascending so the dashboard surfaces the most-urgent cert
    /// first.
    pub fn from_inventory(
        entries: impl IntoIterator<Item = CertInventoryEntry>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        let mut certs: Vec<CertEntry> = entries
            .into_iter()
            .map(|e| {
                let days_to_expiry = (e.expires_at - now).num_days();
                CertEntry {
                    host: e.host,
                    issuer: e.issuer,
                    expires_at: e.expires_at,
                    days_to_expiry,
                    source: e.source,
                }
            })
            .collect();
        certs.sort_by(|a, b| a.days_to_expiry.cmp(&b.days_to_expiry));
        Self { certs }
    }
}

/// One row of cert inventory before `days_to_expiry` is computed.
/// Producers (file scanner, ACME manager, mTLS bundle) emit this
/// shape; [`CertsResponse::from_inventory`] computes the diff
/// against `now` once.
#[derive(Clone, Debug)]
pub struct CertInventoryEntry {
    pub host: String,
    pub issuer: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub source: String,
}

// ---------- GitOps -----------------------------------------------------
//
// 2026-05-17 F-CRITICAL-005 (control audit): the `gitops` module was
// deleted because `GitOpsLoader::sync` had zero production callers
// and `set_gitops_loader` was never invoked at boot. The shell
// response type stays so the `/api/gitops/status` endpoint can
// surface a stable empty shape — operators get a predictable null
// payload rather than a 404, which keeps the dashboard's JSON
// parser happy. The `from_loader` constructor is gone (no loader
// to build from); `placeholder()` is now the only constructor.

#[derive(Clone, Debug, Serialize)]
pub struct GitopsStatusResponse {
    pub repo: Option<String>,
    pub branch: Option<String>,
    pub last_sync: Option<chrono::DateTime<chrono::Utc>>,
    pub head_commit: Option<String>,
    pub signature_ok: bool,
    pub drift: bool,
    pub break_glass_active: bool,
}

impl GitopsStatusResponse {
    pub fn placeholder() -> Self {
        Self {
            repo: None,
            branch: None,
            last_sync: None,
            head_commit: None,
            signature_ok: true,
            drift: false,
            break_glass_active: false,
        }
    }
}

// ---------- Alerts -----------------------------------------------------

#[derive(Clone, Debug, Serialize)]
pub struct Alert {
    pub name: String,
    pub severity: String, // "info" | "warn" | "critical"
    pub since: chrono::DateTime<chrono::Utc>,
    pub runbook_url: Option<String>,
    pub receivers: Vec<ReceiverDelivery>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReceiverDelivery {
    pub name: String,
    pub last_status: String, // "delivered" | "failed" | "pending"
}

#[derive(Clone, Debug, Serialize)]
pub struct AlertsResponse {
    pub firing: Vec<Alert>,
    pub pending: Vec<Alert>,
    pub resolved: Vec<Alert>,
}

impl AlertsResponse {
    pub fn placeholder() -> Self {
        Self {
            firing: Vec::new(),
            pending: Vec::new(),
            resolved: Vec::new(),
        }
    }

    /// CI-T4 — pull the engine's active alerts and split them into
    /// `firing` (not yet acked) vs `resolved` (acked-by-id).
    /// `pending` stays empty — the engine doesn't expose a
    /// pre-fire window today.
    pub fn from_engine(
        engine: &crate::slo::SloEngine,
        acked: &std::collections::HashSet<String>,
    ) -> Self {
        let active = engine.active_alerts();
        let mut firing = Vec::with_capacity(active.len());
        let mut resolved = Vec::with_capacity(active.len());
        for a in active {
            let id = format!("{:?}-{}h", a.sli, a.window_hours);
            let alert = Alert {
                name: id.clone(),
                severity: format!("{:?}", a.severity).to_lowercase(),
                since: a.fired_at,
                runbook_url: Some(a.runbook_url),
                receivers: Vec::new(),
            };
            if acked.contains(&id) {
                resolved.push(alert);
            } else {
                firing.push(alert);
            }
        }
        Self { firing, pending: Vec::new(), resolved }
    }
}

// ---------- Snapshot aggregate -----------------------------------------

#[derive(Clone, Debug, Serialize)]
pub struct TrackingSnapshot {
    pub slo: SloResponse,
    pub cluster: ClusterResponse,
    pub certs: CertsResponse,
    pub gitops: GitopsStatusResponse,
    pub alerts: AlertsResponse,
    pub upstream:
        crate::api::upstreams::UpstreamSummaryResponse,
}

/// Closure type for "give me the current cert inventory" — plugged
/// in by the proxy at boot. The dashboard hits this on every
/// `/api/certs` call (no cache; cert files are tiny and parsing
/// happens off the hot path).
pub type CertInventoryProvider =
    Arc<dyn Fn() -> Vec<CertInventoryEntry> + Send + Sync + 'static>;

#[derive(Clone)]
pub struct TrackingHandler {
    upstream_handler: Arc<crate::api::upstreams::UpstreamHandler>,
    cache: Arc<Mutex<Option<(Instant, String)>>>,
    /// Live cluster roster. `None` (the default) keeps the older
    /// "no cluster wired" placeholder behaviour for builds
    /// that don't run with a `LeaseStore`.
    roster_view: Option<Arc<RosterView>>,
    /// CI-T4 — live SLO engine. `None` keeps placeholder shape.
    /// `Mutex<Option<...>>` so the proxy can wire it post-construction
    /// through the existing `Arc<TrackingHandler>` shared with the
    /// admin listener.
    slo_engine: Arc<Mutex<Option<Arc<crate::slo::SloEngine>>>>,
    // 2026-05-17 F-CRITICAL-005 (control audit): `gitops_loader`
    // field removed — the `gitops` module is deleted. The
    // `/api/gitops/status` endpoint now always returns
    // `GitopsStatusResponse::placeholder()` (a stable empty
    // shape) and the dashboard renders "GitOps not configured".
    /// CI-T4 — cert inventory provider.
    cert_provider: Arc<Mutex<Option<CertInventoryProvider>>>,
    /// CI-T4 — acknowledged alert IDs. Survives the process but
    /// not restarts (intentional — alerts re-evaluate on boot).
    ack_store: Arc<Mutex<HashSet<String>>>,
}

impl TrackingHandler {
    pub fn new(upstream_handler: Arc<crate::api::upstreams::UpstreamHandler>) -> Self {
        Self {
            upstream_handler,
            cache: Arc::new(Mutex::new(None)),
            roster_view: None,
            slo_engine: Arc::new(Mutex::new(None)),
            cert_provider: Arc::new(Mutex::new(None)),
            ack_store: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Same as `new`, but plugs in a live `RosterView`. The
    /// view's membership snapshot is refreshed by a background
    /// polling task in `aegis-proxy::run`; this handler reads it
    /// synchronously when the dashboard fetches
    /// `/api/cluster`.
    pub fn with_roster_view(
        upstream_handler: Arc<crate::api::upstreams::UpstreamHandler>,
        roster_view: Arc<RosterView>,
    ) -> Self {
        let mut h = Self::new(upstream_handler);
        h.roster_view = Some(roster_view);
        h
    }

    /// Wire the SLO engine that backs `/api/slo` and `/api/alerts`.
    /// Idempotent — overwrites any previous engine.
    pub fn set_slo_engine(&self, engine: Arc<crate::slo::SloEngine>) {
        *self.slo_engine.lock().expect("slo engine slot poisoned") = Some(engine);
    }

    // 2026-05-17 F-CRITICAL-005: `set_gitops_loader` removed —
    // the gitops module is deleted, and this setter had zero
    // production callers anyway.

    /// Wire a cert inventory provider that backs `/api/certs`.
    pub fn set_cert_provider(&self, provider: CertInventoryProvider) {
        *self.cert_provider.lock().expect("cert provider slot poisoned") = Some(provider);
    }

    /// Acknowledge an alert by id. The next `render_alerts()` call
    /// will exclude this id from the firing list.
    /// Returns `true` if the alert was newly acknowledged.
    pub fn ack(&self, alert_id: &str) -> bool {
        let mut store = self.ack_store.lock().expect("ack store poisoned");
        store.insert(alert_id.to_string())
    }

    /// Returns the set of currently-acked alert ids. Used by
    /// tests + the renderer.
    pub fn acked_ids(&self) -> Vec<String> {
        self.ack_store
            .lock()
            .expect("ack store poisoned")
            .iter()
            .cloned()
            .collect()
    }

    fn slo(&self) -> Option<Arc<crate::slo::SloEngine>> {
        self.slo_engine.lock().ok()?.clone()
    }
    fn certs(&self) -> Option<CertInventoryProvider> {
        self.cert_provider.lock().ok()?.clone()
    }

    /// SLO-P6 — live objective snapshot for the config editor
    /// GET. `None` when no engine is wired.
    pub fn slo_objectives(&self) -> Option<Vec<crate::slo::SloObjective>> {
        self.slo().map(|e| e.objectives())
    }

    /// SLO-P6 — minute-resolution availability series for the
    /// Health page timeline. Empty `points` when no engine is
    /// wired (honest empty, same policy as `render_slo`).
    pub fn render_slo_timeseries(&self, window_secs: i64) -> String {
        let points = match self.slo() {
            None => Vec::new(),
            Some(e) => e.sli_timeseries(
                &crate::slo::SliKind::DataPlaneAvailability,
                chrono::Duration::seconds(window_secs),
                chrono::Utc::now(),
            ),
        };
        serde_json::to_string(&serde_json::json!({
            "window_seconds": window_secs,
            "points": points,
        }))
        .unwrap_or_else(|_| "{}".into())
    }

    pub fn render_slo(&self) -> String {
        let body = match self.slo() {
            None => SloResponse::placeholder(),
            Some(engine) => SloResponse::from_budget_status(engine.budget_status())
                .with_enforcement(engine.enforcement_stats()),
        };
        serde_json::to_string(&body).unwrap_or_else(|_| "{}".into())
    }

    /// 2026-06-02 (copilot P1) — short human labels for the currently
    /// firing SLO alerts, e.g. `DataPlaneAvailability (Page, 977x over
    /// 1h)`. Empty when no engine is wired or nothing is firing. Feeds
    /// the copilot's `TelemetrySnapshot`.
    pub fn active_slo_alert_labels(&self) -> Vec<String> {
        let Some(engine) = self.slo() else {
            return Vec::new();
        };
        engine
            .active_alerts()
            .into_iter()
            .map(|a| {
                format!(
                    "{:?} ({:?}, {:.0}x over {}h)",
                    a.sli, a.severity, a.burn_rate, a.window_hours
                )
            })
            .collect()
    }

    pub fn render_cluster(&self) -> String {
        serde_json::to_string(&self.cluster_response())
            .unwrap_or_else(|_| "{}".into())
    }

    /// Build the live `ClusterResponse`, falling back to the
    /// `ClusterResponse::placeholder()` shape when no
    /// `RosterView` is wired (single-node builds, tests).
    fn cluster_response(&self) -> ClusterResponse {
        match self.roster_view.as_ref() {
            None => ClusterResponse::placeholder(),
            Some(view) => ClusterResponse {
                peers: view.members(),
                our_node: view.our_node.clone(),
            },
        }
    }

    pub fn render_certs(&self) -> String {
        let body = match self.certs() {
            None => CertsResponse::placeholder(),
            Some(p) => CertsResponse::from_inventory(p(), chrono::Utc::now()),
        };
        serde_json::to_string(&body).unwrap_or_else(|_| "{}".into())
    }

    pub fn render_gitops(&self) -> String {
        // 2026-05-17 F-CRITICAL-005: gitops module deleted; this
        // endpoint always returns the empty placeholder so the
        // dashboard's JSON parser stays happy.
        let body = GitopsStatusResponse::placeholder();
        serde_json::to_string(&body).unwrap_or_else(|_| "{}".into())
    }

    pub fn render_alerts(&self) -> String {
        let body = match self.slo() {
            None => AlertsResponse::placeholder(),
            Some(engine) => {
                let acked = self
                    .ack_store
                    .lock()
                    .expect("ack store poisoned")
                    .clone();
                AlertsResponse::from_engine(engine.as_ref(), &acked)
            }
        };
        serde_json::to_string(&body).unwrap_or_else(|_| "{}".into())
    }

    /// MED-SO-04 (2026-05-12) — expose the engine's live firing
    /// alerts so the `/api/incidents` handler can compose them
    /// with the operator overlay (ack / snooze / resolve).
    /// Returns `Vec::new()` when no engine is wired (single-node
    /// boot before `set_slo_engine` runs, tests).
    pub fn active_alerts(&self) -> Vec<crate::slo::SloAlert> {
        match self.slo() {
            None => Vec::new(),
            Some(engine) => engine.active_alerts(),
        }
    }

    /// Aggregate snapshot. Cached for 2s (per the docs spec for the
    /// tracking-snapshot family). Composes upstream summary +
    /// placeholders for the others.
    pub fn render_snapshot(&self) -> String {
        let now = Instant::now();
        {
            let cache = self.cache.lock().expect("tracking cache poisoned");
            if let Some((stamped_at, body)) = cache.as_ref() {
                if now.duration_since(*stamped_at) < SNAPSHOT_TTL {
                    return body.clone();
                }
            }
        }
        let upstream = self.upstream_handler.snapshot();
        let slo = match self.slo() {
            None => SloResponse::placeholder(),
            Some(e) => SloResponse::from_budget_status(e.budget_status())
                .with_enforcement(e.enforcement_stats()),
        };
        let certs = match self.certs() {
            None => CertsResponse::placeholder(),
            Some(p) => CertsResponse::from_inventory(p(), chrono::Utc::now()),
        };
        // 2026-05-17 F-CRITICAL-005: gitops module deleted.
        let gitops = GitopsStatusResponse::placeholder();
        let alerts = match self.slo() {
            None => AlertsResponse::placeholder(),
            Some(e) => {
                let acked = self
                    .ack_store
                    .lock()
                    .expect("ack store poisoned")
                    .clone();
                AlertsResponse::from_engine(e.as_ref(), &acked)
            }
        };
        let snap = TrackingSnapshot {
            slo,
            cluster: self.cluster_response(),
            certs,
            gitops,
            alerts,
            upstream,
        };
        let body = serde_json::to_string(&snap).unwrap_or_else(|_| "{}".into());
        let mut cache = self.cache.lock().expect("tracking cache poisoned");
        *cache = Some((now, body.clone()));
        body
    }

    /// Cert renew action. Returns `(status, body)`. ACME-managed certs
    /// kick off renewal (currently a placeholder); static/mTLS return
    /// 405. v1 always returns 405 because no cert store is wired.
    pub fn render_cert_renew(host: &str) -> (u16, String) {
        let body = serde_json::json!({
            "error": {
                "code": "not_supported",
                "message": format!("cert renewal for {host} is not supported in this build")
            }
        });
        (405, body.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_pool_provider() -> crate::api::upstreams::PoolHealthSnapshot {
        crate::api::upstreams::PoolHealthSnapshot { pools: Vec::new(), ..Default::default() }
    }

    fn handler() -> TrackingHandler {
        let up = Arc::new(crate::api::upstreams::UpstreamHandler::new(|| {
            empty_pool_provider()
        }));
        TrackingHandler::new(up)
    }

    #[test]
    fn slo_response_with_no_engine_is_empty_not_mock() {
        // 2026-05-17 F-CRITICAL-018 regression: pre-fix
        // `SloResponse::placeholder()` returned two fake SLI
        // rows (availability=99.99/99.99, overhead_p99=0/5)
        // when no SloEngine was wired — that's the §9 mock-data
        // disqualification class. Now returns an empty slis
        // list (honest empty); the dashboard renders "no data
        // yet" rather than fake numbers.
        let body = handler().render_slo();
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let slis = v["slis"].as_array().unwrap();
        assert!(slis.is_empty(), "no engine → empty slis (not mock data)");
    }

    #[test]
    fn active_alerts_empty_when_no_engine_wired() {
        let h = handler();
        assert!(h.active_alerts().is_empty());
    }

    // SLO-P1 — with an engine wired, /api/slo carries the
    // enforcement info series; without one the key is omitted
    // entirely (placeholder shape unchanged).
    #[test]
    fn slo_response_surfaces_enforcement_counter() {
        let no_engine: serde_json::Value =
            serde_json::from_str(&handler().render_slo()).unwrap();
        assert!(
            no_engine.get("enforcement").is_none(),
            "no engine → no enforcement key",
        );

        let h = handler();
        let engine =
            Arc::new(crate::slo::SloEngine::new(crate::slo::default_objectives()));
        engine.record_enforcement(chrono::Utc::now());
        engine.record_enforcement(chrono::Utc::now());
        h.set_slo_engine(engine);
        let v: serde_json::Value = serde_json::from_str(&h.render_slo()).unwrap();
        assert_eq!(v["enforcement"]["total"], serde_json::json!(2));
        assert_eq!(v["enforcement"]["last_hour"], serde_json::json!(2));
    }

    #[test]
    fn cluster_certs_alerts_render_empty_lists() {
        let h = handler();
        let cluster: serde_json::Value =
            serde_json::from_str(&h.render_cluster()).unwrap();
        assert!(cluster["peers"].as_array().unwrap().is_empty());
        let certs: serde_json::Value = serde_json::from_str(&h.render_certs()).unwrap();
        assert!(certs["certs"].as_array().unwrap().is_empty());
        let alerts: serde_json::Value =
            serde_json::from_str(&h.render_alerts()).unwrap();
        assert!(alerts["firing"].as_array().unwrap().is_empty());
    }

    // ---- leaderless cluster-roster admin endpoint ----------------

    fn handler_with_roster(view: Arc<RosterView>) -> TrackingHandler {
        let up = Arc::new(crate::api::upstreams::UpstreamHandler::new(|| {
            empty_pool_provider()
        }));
        TrackingHandler::with_roster_view(up, view)
    }

    #[test]
    fn cluster_response_default_is_empty_flat_roster() {
        // Leaderless: no `is_leader`/`leader_node` fields at all;
        // an unwired handler renders an empty peer list.
        let body = handler().render_cluster();
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(v["peers"].as_array().unwrap().is_empty());
        assert_eq!(v["our_node"], serde_json::json!(""));
        assert!(v.get("is_leader").is_none(), "leaderless: no is_leader field");
        assert!(v.get("leader_node").is_none(), "leaderless: no leader_node field");
    }

    #[test]
    fn cluster_response_surfaces_our_node_and_peers() {
        let view = Arc::new(RosterView::new("node-A"));
        view.set_members(vec![
            ClusterPeer {
                id: "node-A".into(),
                addr: String::new(),
                version: "v".into(),
                last_heartbeat: chrono::Utc::now(),
                leases: Vec::new(),
            },
            ClusterPeer {
                id: "node-B".into(),
                addr: String::new(),
                version: "v".into(),
                last_heartbeat: chrono::Utc::now(),
                leases: Vec::new(),
            },
        ]);
        let h = handler_with_roster(view);
        let v: serde_json::Value =
            serde_json::from_str(&h.render_cluster()).unwrap();
        assert_eq!(v["our_node"], serde_json::json!("node-A"));
        assert_eq!(v["peers"].as_array().unwrap().len(), 2);
        assert!(v.get("is_leader").is_none());
    }

    #[test]
    fn cluster_response_round_trips_explicit_node_id() {
        // HA-T3 round-trip — when an operator pins
        // `node.id: "pod-7"`, that string should appear as
        // `our_node` on every node's /api/cluster.
        let view = Arc::new(RosterView::new("pod-7"));
        let h = handler_with_roster(view);
        let v: serde_json::Value =
            serde_json::from_str(&h.render_cluster()).unwrap();
        assert_eq!(v["our_node"], serde_json::json!("pod-7"));
    }

    #[test]
    fn roster_view_set_members_round_trip() {
        let view = RosterView::new("node-A");
        assert!(view.members().is_empty());
        view.set_members(vec![ClusterPeer {
            id: "node-X".into(),
            addr: String::new(),
            version: "v".into(),
            last_heartbeat: chrono::Utc::now(),
            leases: Vec::new(),
        }]);
        assert_eq!(view.members().len(), 1);
        assert_eq!(view.members()[0].id, "node-X");
    }

    #[test]
    fn gitops_response_shape() {
        let body = handler().render_gitops();
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        for k in ["repo", "branch", "last_sync", "head_commit", "signature_ok", "drift", "break_glass_active"] {
            assert!(v.get(k).is_some(), "gitops response missing {k}");
        }
    }

    #[test]
    fn snapshot_contains_six_sections() {
        let body = handler().render_snapshot();
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        for k in ["slo", "cluster", "certs", "gitops", "alerts", "upstream"] {
            assert!(v.get(k).is_some(), "snapshot missing {k}");
        }
    }

    #[test]
    fn snapshot_is_cached() {
        let h = handler();
        let a = h.render_snapshot();
        let b = h.render_snapshot();
        assert_eq!(a, b);
    }

    #[test]
    fn cert_renew_returns_not_supported() {
        let (status, body) = TrackingHandler::render_cert_renew("example.com");
        assert_eq!(status, 405);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["error"]["code"].as_str(), Some("not_supported"));
    }

    // ---------- P5 cert inventory --------------------------------------

    #[test]
    fn certs_from_inventory_computes_days_to_expiry() {
        let now = chrono::Utc::now();
        let r = CertsResponse::from_inventory(
            vec![CertInventoryEntry {
                host: "shop.example.com".into(),
                issuer: "Let's Encrypt".into(),
                expires_at: now + chrono::Duration::days(40),
                source: "acme".into(),
            }],
            now,
        );
        assert_eq!(r.certs.len(), 1);
        assert_eq!(r.certs[0].days_to_expiry, 40);
        assert_eq!(r.certs[0].source, "acme");
    }

    #[test]
    fn certs_from_inventory_sorts_by_urgency() {
        let now = chrono::Utc::now();
        let r = CertsResponse::from_inventory(
            vec![
                CertInventoryEntry {
                    host: "later.example.com".into(),
                    issuer: "L".into(),
                    expires_at: now + chrono::Duration::days(90),
                    source: "static".into(),
                },
                CertInventoryEntry {
                    host: "soon.example.com".into(),
                    issuer: "L".into(),
                    expires_at: now + chrono::Duration::days(5),
                    source: "acme".into(),
                },
                CertInventoryEntry {
                    host: "later2.example.com".into(),
                    issuer: "L".into(),
                    expires_at: now + chrono::Duration::days(45),
                    source: "acme".into(),
                },
            ],
            now,
        );
        let hosts: Vec<&str> = r.certs.iter().map(|e| e.host.as_str()).collect();
        assert_eq!(
            hosts,
            vec!["soon.example.com", "later2.example.com", "later.example.com"]
        );
    }

    #[test]
    fn certs_from_inventory_handles_already_expired() {
        let now = chrono::Utc::now();
        let r = CertsResponse::from_inventory(
            vec![CertInventoryEntry {
                host: "old.example.com".into(),
                issuer: "L".into(),
                expires_at: now - chrono::Duration::days(2),
                source: "static".into(),
            }],
            now,
        );
        assert_eq!(r.certs[0].days_to_expiry, -2);
    }
}
