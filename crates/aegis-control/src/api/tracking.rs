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
}

impl ClusterResponse {
    pub fn placeholder() -> Self {
        Self { peers: Vec::new() }
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
}

impl TrackingHandler {
    pub fn new(upstream_handler: Arc<crate::api::upstreams::UpstreamHandler>) -> Self {
        Self {
            upstream_handler,
            cache: Arc::new(Mutex::new(None)),
        }
    }

    pub fn render_slo(&self) -> String {
        serde_json::to_string(&SloResponse::placeholder()).unwrap_or_else(|_| "{}".into())
    }

    pub fn render_cluster(&self) -> String {
        serde_json::to_string(&ClusterResponse::placeholder())
            .unwrap_or_else(|_| "{}".into())
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
            cluster: ClusterResponse::placeholder(),
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
}
