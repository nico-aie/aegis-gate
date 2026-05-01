//! MTLS-T6 — read-only `/api/mtls/*` handlers.
//!
//! Four GET endpoints:
//!
//! | Path | Purpose |
//! |---|---|
//! | `/api/mtls` | Current cfg snapshot (mode / ca_bundle / allowed_sans / apply_to / `active`) |
//! | `/api/mtls/connections` | Live identity tracker — sliding-window per-principal counts |
//! | `/api/mtls/failures` | TLS handshake-failure histogram by reason |
//! | `/api/mtls/ca-summary` | Loaded CA bundle metadata (subject / fingerprint / expiry — never raw PEM) |
//!
//! These endpoints work **before MTLS-T2's rustls wiring lands**:
//! the cfg endpoint reads `cfg.tls.client_auth` directly; the
//! tracker / failures endpoints serve empty `[]` until callers
//! start populating `IdentityTracker`. The dashboard
//! `<PageMtls>` (MTLS-T6 frontend) renders an empty-state when
//! the data is empty, so operators see the surface they'll get
//! before the handshake change goes live.

use std::sync::Arc;

use serde::Serialize;

use aegis_core::config::{ClientAuthConfig, ClientAuthMode, ClientAuthScope, WafConfig};

use crate::identity_tracker::{
    CaCertSummary, FailureSnapshot, IdentitySnapshot, IdentityTracker,
};

// ---------------------------------------------------------------------------
// GET /api/mtls — cfg snapshot
// ---------------------------------------------------------------------------

/// Wire shape for `GET /api/mtls`. Mirrors the
/// [`ClientAuthConfig`] field layout but with an `active`
/// boolean that clarifies whether the rustls handshake layer
/// is actually enforcing the policy yet (MTLS-T2). Always
/// returned as 200 — when `cfg.tls.client_auth` is `None` the
/// shape is the all-defaults / `mode: disabled` form so the
/// dashboard doesn't have to handle a 404 path.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct MtlsConfigView {
    pub mode: &'static str,
    pub ca_bundle: Option<String>,
    pub allowed_sans: Vec<String>,
    pub apply_to: Vec<&'static str>,
    /// `true` only after MTLS-T2's rustls wiring lands. Until
    /// then the dashboard shows a "configured but not yet
    /// enforced" pill. Set unconditionally to `false` in this
    /// slice — MTLS-T2 will populate it from the live
    /// `WebPkiClientVerifier` boolean.
    pub active: bool,
}

impl MtlsConfigView {
    /// Build from a [`WafConfig`] reference. The `active` flag
    /// is **always `false` in this slice** because the rustls
    /// handshake still uses `with_no_client_auth()`. MTLS-T2
    /// will replace this constructor with a variant that
    /// takes the live verifier-state handle.
    pub fn from_config(cfg: &WafConfig) -> Self {
        match cfg.tls.as_ref().and_then(|t| t.client_auth.as_ref()) {
            Some(ca) => Self::from_client_auth(ca),
            None => Self::default_disabled(),
        }
    }

    fn from_client_auth(ca: &ClientAuthConfig) -> Self {
        Self {
            mode: mode_label(ca.mode),
            ca_bundle: ca
                .ca_bundle
                .as_ref()
                .map(|p| p.display().to_string()),
            allowed_sans: ca.allowed_sans.clone(),
            apply_to: ca.apply_to.iter().map(|s| scope_label(*s)).collect(),
            active: false,
        }
    }

    fn default_disabled() -> Self {
        Self {
            mode: "disabled",
            ca_bundle: None,
            allowed_sans: Vec::new(),
            apply_to: Vec::new(),
            active: false,
        }
    }

    pub fn render(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| String::from("{}"))
    }
}

fn mode_label(mode: ClientAuthMode) -> &'static str {
    match mode {
        ClientAuthMode::Disabled => "disabled",
        ClientAuthMode::Optional => "optional",
        ClientAuthMode::Required => "required",
    }
}

fn scope_label(scope: ClientAuthScope) -> &'static str {
    match scope {
        ClientAuthScope::Admin => "admin",
        ClientAuthScope::Data => "data",
    }
}

// ---------------------------------------------------------------------------
// GET /api/mtls/connections
// ---------------------------------------------------------------------------

/// Wire shape for `GET /api/mtls/connections`.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ConnectionsView {
    pub connections: Vec<IdentitySnapshot>,
    pub window_seconds: u64,
}

/// Render the connections endpoint from the optional shared
/// [`IdentityTracker`]. `None` produces an empty-state body —
/// matches the alert-receivers / upstreams pattern so the
/// dashboard never has to handle a 404 path on a missing
/// service handle.
pub fn render_connections(tracker: Option<&Arc<IdentityTracker>>) -> String {
    match tracker {
        Some(t) => {
            let view = ConnectionsView {
                connections: t.snapshot_connections(),
                window_seconds: t.window_seconds(),
            };
            serde_json::to_string(&view).unwrap_or_else(|_| String::from("{}"))
        }
        None => String::from("{\"connections\":[],\"window_seconds\":3600}"),
    }
}

// ---------------------------------------------------------------------------
// GET /api/mtls/failures
// ---------------------------------------------------------------------------

/// Wire shape for `GET /api/mtls/failures`.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct FailuresView {
    pub failures: Vec<FailureSnapshot>,
    pub window_seconds: u64,
}

pub fn render_failures(tracker: Option<&Arc<IdentityTracker>>) -> String {
    match tracker {
        Some(t) => {
            let view = FailuresView {
                failures: t.snapshot_failures(),
                window_seconds: t.window_seconds(),
            };
            serde_json::to_string(&view).unwrap_or_else(|_| String::from("{}"))
        }
        None => String::from("{\"failures\":[],\"window_seconds\":3600}"),
    }
}

// ---------------------------------------------------------------------------
// GET /api/mtls/ca-summary
// ---------------------------------------------------------------------------

/// Wire shape for `GET /api/mtls/ca-summary`. Fields
/// deliberately match `CaSummary` 1:1 so the
/// `IdentityTracker::ca_summary` snapshot serialises cleanly.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct CaSummaryView {
    pub bundle_path: Option<String>,
    pub last_loaded_ms: Option<i64>,
    pub certificates: Vec<CaCertSummary>,
}

pub fn render_ca_summary(tracker: Option<&Arc<IdentityTracker>>) -> String {
    let view = match tracker.and_then(|t| t.ca_summary()) {
        Some(summary) => CaSummaryView {
            bundle_path: Some(summary.bundle_path),
            last_loaded_ms: Some(summary.last_loaded_ms),
            certificates: summary.certificates,
        },
        None => CaSummaryView {
            bundle_path: None,
            last_loaded_ms: None,
            certificates: Vec::new(),
        },
    };
    serde_json::to_string(&view).unwrap_or_else(|_| String::from("{}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::config::{ClientAuthMode, TlsConfig};

    fn cfg_with_client_auth(ca: ClientAuthConfig) -> WafConfig {
        let yaml = r#"
listeners:
  data: [{ bind: "127.0.0.1:8080" }]
  admin: { bind: "127.0.0.1:9090" }
routes:
  - { id: catch-all, path: "/", upstream: default }
upstreams:
  default: { members: [{ addr: "127.0.0.1:3000" }] }
state: { backend: in_memory }
"#;
        let mut cfg: WafConfig = serde_yaml::from_str(yaml).unwrap();
        cfg.tls = Some(TlsConfig {
            certificates: Vec::new(),
            min_version: None,
            force_https: false,
            hsts: None,
            acme: None,
            client_auth: Some(ca),
        });
        cfg
    }

    #[test]
    fn cfg_view_no_tls_returns_default_disabled() {
        let yaml = r#"
listeners:
  data: [{ bind: "127.0.0.1:8080" }]
  admin: { bind: "127.0.0.1:9090" }
routes:
  - { id: catch-all, path: "/", upstream: default }
upstreams:
  default: { members: [{ addr: "127.0.0.1:3000" }] }
state: { backend: in_memory }
"#;
        let cfg: WafConfig = serde_yaml::from_str(yaml).unwrap();
        let view = MtlsConfigView::from_config(&cfg);
        assert_eq!(view.mode, "disabled");
        assert!(view.ca_bundle.is_none());
        assert!(view.allowed_sans.is_empty());
        assert!(view.apply_to.is_empty());
        assert!(!view.active);
    }

    #[test]
    fn cfg_view_required_renders_full_state() {
        let cfg = cfg_with_client_auth(ClientAuthConfig {
            mode: ClientAuthMode::Required,
            ca_bundle: Some("/etc/aegis/admin-ca.pem".into()),
            allowed_sans: vec!["admin@aegis.local".into()],
            apply_to: vec![ClientAuthScope::Admin, ClientAuthScope::Data],
        });
        let view = MtlsConfigView::from_config(&cfg);
        assert_eq!(view.mode, "required");
        assert_eq!(view.ca_bundle.as_deref(), Some("/etc/aegis/admin-ca.pem"));
        assert_eq!(view.allowed_sans, vec!["admin@aegis.local".to_string()]);
        assert_eq!(view.apply_to, vec!["admin", "data"]);
        // `active` is always false in this slice — MTLS-T2 will
        // wire the live verifier state.
        assert!(!view.active);
    }

    #[test]
    fn cfg_view_renders_to_json() {
        let cfg = cfg_with_client_auth(ClientAuthConfig {
            mode: ClientAuthMode::Optional,
            ca_bundle: Some("/etc/aegis/ca.pem".into()),
            allowed_sans: Vec::new(),
            apply_to: vec![ClientAuthScope::Admin],
        });
        let view = MtlsConfigView::from_config(&cfg);
        let json = view.render();
        assert!(json.contains("\"mode\":\"optional\""));
        assert!(json.contains("/etc/aegis/ca.pem"));
        assert!(json.contains("\"active\":false"));
    }

    #[test]
    fn render_connections_none_returns_empty_state() {
        let body = render_connections(None);
        assert!(body.contains("\"connections\":[]"));
        assert!(body.contains("\"window_seconds\":3600"));
    }

    #[test]
    fn render_connections_some_returns_tracker_snapshot() {
        let tracker = Arc::new(IdentityTracker::new());
        tracker.record_request("admin@aegis.local", "mtls", "allow");
        tracker.record_request("admin@aegis.local", "mtls", "allow");
        tracker.record_request("admin@aegis.local", "mtls", "block");
        let body = render_connections(Some(&tracker));
        assert!(body.contains("admin@aegis.local"));
        assert!(body.contains("\"request_count\":3"));
    }

    #[test]
    fn render_failures_none_returns_empty_state() {
        let body = render_failures(None);
        assert!(body.contains("\"failures\":[]"));
    }

    #[test]
    fn render_failures_some_returns_tracker_snapshot() {
        let tracker = Arc::new(IdentityTracker::new());
        tracker.record_failure("unknown_ca");
        tracker.record_failure("unknown_ca");
        tracker.record_failure("expired");
        let body = render_failures(Some(&tracker));
        assert!(body.contains("unknown_ca"));
        assert!(body.contains("expired"));
    }

    #[test]
    fn render_ca_summary_none_returns_empty_state() {
        let body = render_ca_summary(None);
        assert!(body.contains("\"certificates\":[]"));
        assert!(body.contains("\"bundle_path\":null"));
    }

    #[test]
    fn render_ca_summary_some_returns_metadata() {
        use crate::identity_tracker::CaSummary;
        let tracker = Arc::new(IdentityTracker::new());
        tracker.set_ca_summary(Some(CaSummary {
            bundle_path: "/etc/aegis/ca.pem".into(),
            last_loaded_ms: 1234567890,
            certificates: vec![CaCertSummary {
                subject: "CN=Test CA,O=Aegis".into(),
                fingerprint_sha256: "ab:cd:ef".into(),
                not_before_ms: 0,
                not_after_ms: 1_000_000,
                days_until_expiry: 365,
            }],
        }));
        let body = render_ca_summary(Some(&tracker));
        assert!(body.contains("CN=Test CA"));
        assert!(body.contains("ab:cd:ef"));
        assert!(body.contains("\"days_until_expiry\":365"));
    }
}
