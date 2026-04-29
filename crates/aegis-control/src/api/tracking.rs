//! `/api/slo`, `/api/cluster`, `/api/certs`, `/api/gitops/status`,
//! `/api/alerts`, `/api/tracking/snapshot` (D-M5-T5.1..T5.7).
//!
//! Tracking data layers — wrappers around the existing per-feature
//! state in `aegis-control` (slo.rs, gitops.rs, etc.). Where the
//! data source isn't yet runtime-populated (cluster peers, cert
//! store), the module returns the documented JSON shape with empty
//! lists so the page renders cleanly.

#![allow(dead_code)]

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
}

impl SloResponse {
    pub fn placeholder() -> Self {
        Self {
            slis: vec![
                SliRow {
                    name: "availability".into(),
                    current: 99.99,
                    target: 99.99,
                    budget_remaining: 1.0,
                    burn_1h: 0.0,
                    burn_6h: 0.0,
                    burn_3d: 0.0,
                },
                SliRow {
                    name: "overhead_p99".into(),
                    current: 0.0,
                    target: 5.0,
                    budget_remaining: 1.0,
                    burn_1h: 0.0,
                    burn_6h: 0.0,
                    burn_3d: 0.0,
                },
            ],
        }
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
    /// True iff this node currently holds the
    /// `leader:cluster` lease. Read by the dashboard's
    /// "this is the leader" badge and by
    /// `tests/cluster/02-leader-failover.sh`.
    pub is_leader: bool,
    /// `NodeId` of the lease holder, or `None` if the
    /// lease is currently unheld / unreachable. Always
    /// populated when `is_leader == true`.
    pub leader_node: Option<String>,
    /// `NodeId` of *this* node. Operators correlate
    /// `is_leader` with this in dashboards that show
    /// multiple node viewpoints.
    pub our_node: String,
}

impl ClusterResponse {
    pub fn placeholder() -> Self {
        Self {
            peers: Vec::new(),
            is_leader: false,
            leader_node: None,
            our_node: String::new(),
        }
    }
}

/// Live leader-state view, kept in sync by a background
/// polling task that reads `lease_store.holder("leader:cluster")`
/// every couple of seconds. The admin handler reads it
/// synchronously through `TrackingHandler::render_cluster`.
#[derive(Debug)]
pub struct LeaderView {
    /// `NodeId` of this process. Set once at startup; never
    /// changes for the lifetime of the binary.
    pub our_node: String,
    /// Latest known holder of `leader:cluster`. `None` while
    /// the first poll is in flight or the store is
    /// unreachable.
    pub current_holder: arc_swap::ArcSwapOption<String>,
}

impl LeaderView {
    pub fn new(our_node: impl Into<String>) -> Self {
        Self {
            our_node: our_node.into(),
            current_holder: arc_swap::ArcSwapOption::from(None),
        }
    }

    /// True iff our node id matches the latest holder. Lock-free.
    pub fn is_leader(&self) -> bool {
        match self.current_holder.load_full() {
            Some(h) => *h == self.our_node,
            None => false,
        }
    }

    /// Latest holder, copied out so callers don't pin the
    /// internal `Arc`.
    pub fn leader_node(&self) -> Option<String> {
        self.current_holder.load_full().map(|h| (*h).clone())
    }

    /// Update the cached holder. The polling task calls this
    /// after each `lease_store.holder(...)` round-trip.
    pub fn set_holder(&self, holder: Option<String>) {
        self.current_holder.store(holder.map(Arc::new));
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

#[derive(Clone)]
pub struct TrackingHandler {
    upstream_handler: Arc<crate::api::upstreams::UpstreamHandler>,
    cache: Arc<Mutex<Option<(Instant, String)>>>,
    /// Live leader view. `None` (the default) keeps the older
    /// "no cluster wired" placeholder behaviour for builds
    /// that don't run with a `LeaseStore`.
    leader_view: Option<Arc<LeaderView>>,
}

impl TrackingHandler {
    pub fn new(upstream_handler: Arc<crate::api::upstreams::UpstreamHandler>) -> Self {
        Self {
            upstream_handler,
            cache: Arc::new(Mutex::new(None)),
            leader_view: None,
        }
    }

    /// Same as `new`, but plugs in a live `LeaderView`. The
    /// view's holder cell is updated by a background polling
    /// task in `aegis-proxy::run`; this handler reads it
    /// synchronously when the dashboard fetches
    /// `/api/cluster`.
    pub fn with_leader_view(
        upstream_handler: Arc<crate::api::upstreams::UpstreamHandler>,
        leader_view: Arc<LeaderView>,
    ) -> Self {
        Self {
            upstream_handler,
            cache: Arc::new(Mutex::new(None)),
            leader_view: Some(leader_view),
        }
    }

    pub fn render_slo(&self) -> String {
        serde_json::to_string(&SloResponse::placeholder()).unwrap_or_else(|_| "{}".into())
    }

    pub fn render_cluster(&self) -> String {
        serde_json::to_string(&self.cluster_response())
            .unwrap_or_else(|_| "{}".into())
    }

    /// Build the live `ClusterResponse`, falling back to the
    /// `ClusterResponse::placeholder()` shape when no
    /// `LeaderView` is wired (single-node builds, tests).
    fn cluster_response(&self) -> ClusterResponse {
        match self.leader_view.as_ref() {
            None => ClusterResponse::placeholder(),
            Some(view) => ClusterResponse {
                peers: Vec::new(),
                is_leader: view.is_leader(),
                leader_node: view.leader_node(),
                our_node: view.our_node.clone(),
            },
        }
    }

    pub fn render_certs(&self) -> String {
        serde_json::to_string(&CertsResponse::placeholder()).unwrap_or_else(|_| "{}".into())
    }

    pub fn render_gitops(&self) -> String {
        serde_json::to_string(&GitopsStatusResponse::placeholder())
            .unwrap_or_else(|_| "{}".into())
    }

    pub fn render_alerts(&self) -> String {
        serde_json::to_string(&AlertsResponse::placeholder())
            .unwrap_or_else(|_| "{}".into())
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
        let snap = TrackingSnapshot {
            slo: SloResponse::placeholder(),
            cluster: self.cluster_response(),
            certs: CertsResponse::placeholder(),
            gitops: GitopsStatusResponse::placeholder(),
            alerts: AlertsResponse::placeholder(),
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
        crate::api::upstreams::PoolHealthSnapshot { pools: Vec::new() }
    }

    fn handler() -> TrackingHandler {
        let up = Arc::new(crate::api::upstreams::UpstreamHandler::new(|| {
            empty_pool_provider()
        }));
        TrackingHandler::new(up)
    }

    #[test]
    fn slo_response_has_documented_shape() {
        let body = handler().render_slo();
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let slis = v["slis"].as_array().unwrap();
        assert!(!slis.is_empty());
        for k in ["name", "current", "target", "budget_remaining"] {
            assert!(slis[0][k].is_number() || slis[0][k].is_string());
        }
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

    // ---- carry-over 3: leader-state admin endpoint ---------------

    fn handler_with_leader(view: Arc<LeaderView>) -> TrackingHandler {
        let up = Arc::new(crate::api::upstreams::UpstreamHandler::new(|| {
            empty_pool_provider()
        }));
        TrackingHandler::with_leader_view(up, view)
    }

    #[test]
    fn cluster_response_default_is_not_leader() {
        let body = handler().render_cluster();
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["is_leader"], serde_json::json!(false));
        assert!(v["leader_node"].is_null());
        assert_eq!(v["our_node"], serde_json::json!(""));
    }

    #[test]
    fn cluster_response_marks_us_as_leader_when_holder_matches() {
        let view = Arc::new(LeaderView::new("node-A"));
        view.set_holder(Some("node-A".to_string()));
        let h = handler_with_leader(Arc::clone(&view));
        let v: serde_json::Value =
            serde_json::from_str(&h.render_cluster()).unwrap();
        assert_eq!(v["is_leader"], serde_json::json!(true));
        assert_eq!(v["leader_node"], serde_json::json!("node-A"));
        assert_eq!(v["our_node"], serde_json::json!("node-A"));
    }

    #[test]
    fn cluster_response_marks_us_as_follower_when_holder_differs() {
        let view = Arc::new(LeaderView::new("node-A"));
        view.set_holder(Some("node-B".to_string()));
        let h = handler_with_leader(view);
        let v: serde_json::Value =
            serde_json::from_str(&h.render_cluster()).unwrap();
        assert_eq!(v["is_leader"], serde_json::json!(false));
        assert_eq!(v["leader_node"], serde_json::json!("node-B"));
        assert_eq!(v["our_node"], serde_json::json!("node-A"));
    }

    #[test]
    fn cluster_response_no_holder_means_no_leader() {
        let view = Arc::new(LeaderView::new("node-A"));
        // First poll hasn't happened yet — holder is None.
        let h = handler_with_leader(view);
        let v: serde_json::Value =
            serde_json::from_str(&h.render_cluster()).unwrap();
        assert_eq!(v["is_leader"], serde_json::json!(false));
        assert!(v["leader_node"].is_null());
    }

    #[test]
    fn leader_view_set_holder_round_trip() {
        let view = LeaderView::new("node-A");
        assert!(view.leader_node().is_none());
        view.set_holder(Some("node-X".to_string()));
        assert_eq!(view.leader_node().as_deref(), Some("node-X"));
        assert!(!view.is_leader());
        view.set_holder(Some("node-A".to_string()));
        assert!(view.is_leader());
        view.set_holder(None);
        assert!(!view.is_leader());
        assert!(view.leader_node().is_none());
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
