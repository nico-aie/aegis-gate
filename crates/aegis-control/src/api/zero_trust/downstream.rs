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

use aegis_core::config::{DownstreamMtlsConfig, DownstreamMtlsMode, DownstreamMtlsScope, WafConfig};

use crate::identity_tracker::{
    CaCertSummary, FailureSnapshot, IdentitySnapshot, IdentityTracker,
};

// ---------------------------------------------------------------------------
// GET /api/mtls — cfg snapshot
// ---------------------------------------------------------------------------

/// Wire shape for `GET /api/mtls`. Mirrors the
/// [`DownstreamMtlsConfig`] field layout but with an `active`
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
        match cfg
            .zero_trust
            .as_ref()
            .and_then(|z| z.downstream.as_ref())
        {
            Some(ca) => Self::from_client_auth(ca),
            None => Self::default_disabled(),
        }
    }

    fn from_client_auth(ca: &DownstreamMtlsConfig) -> Self {
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

fn mode_label(mode: DownstreamMtlsMode) -> &'static str {
    match mode {
        DownstreamMtlsMode::Disabled => "disabled",
        DownstreamMtlsMode::Optional => "optional",
        DownstreamMtlsMode::Required => "required",
    }
}

fn scope_label(scope: DownstreamMtlsScope) -> &'static str {
    match scope {
        DownstreamMtlsScope::Admin => "admin",
        DownstreamMtlsScope::Data => "data",
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

/// MTLS-T7 — live, mutable allowed-SAN list.
///
/// Created at boot from `cfg.tls.client_auth.allowed_sans`,
/// then mutated via the audit-mutated `PUT/DELETE/POST-test`
/// handlers. Identity extraction reads through `admits()` /
/// `matched_pattern()` per cert; both are O(n) on a typically
/// small list (single-digit operator entries) so no index is
/// needed.
///
/// Empty list = "no allowlist gate"; any SAN admits. Operators
/// turning the gate on populate the list, then optionally lock
/// it down via `client_auth.mode = Required`.
///
/// Wildcard syntax: `*.example.com` matches a single label
/// (RFC 6125 §6.4.3) — `svc.example.com` admits but neither
/// `example.com` nor `a.b.example.com` does.
#[derive(Debug, Clone)]
pub struct AllowedSansStore {
    inner: Arc<arc_swap::ArcSwap<Vec<String>>>,
}

impl AllowedSansStore {
    /// Snapshot of the current allowlist. Cheap; the
    /// underlying ArcSwap returns an `Arc<Vec<String>>` —
    /// callers `(*snap).clone()` if they want owned strings,
    /// otherwise iterate against the borrowed slice.
    pub fn current(&self) -> Vec<String> {
        (*self.inner.load_full()).clone()
    }

    /// Replace the entire allowlist atomically. Used by the
    /// `PUT /api/mtls/sans` whole-list-replace handler.
    pub fn store(&self, new_list: Vec<String>) {
        self.inner.store(Arc::new(new_list));
    }

    /// Remove one entry. Returns `true` if the entry was
    /// present and removed; `false` if it wasn't there.
    /// Atomic via load → modify → store; concurrent removes
    /// are last-writer-wins.
    pub fn remove(&self, san: &str) -> bool {
        let current = self.inner.load_full();
        let mut next: Vec<String> = (*current).clone();
        let before = next.len();
        next.retain(|s| s != san);
        if next.len() != before {
            self.inner.store(Arc::new(next));
            true
        } else {
            false
        }
    }

    /// Read-side admission check. Empty allowlist → admit
    /// everything (back-compat with operators not opting in).
    /// Non-empty → at least one pattern must match `san`.
    pub fn admits(&self, san: &str) -> bool {
        let snap = self.inner.load_full();
        if snap.is_empty() {
            return true;
        }
        snap.iter().any(|p| san_matches(p, san))
    }

    /// Like `admits` but returns the FIRST matching pattern,
    /// for the `/api/mtls/sans/{san}/test` response. `None`
    /// when nothing matched.
    pub fn matched_pattern(&self, san: &str) -> Option<String> {
        let snap = self.inner.load_full();
        snap.iter().find(|p| san_matches(p, san)).cloned()
    }
}

impl From<Vec<String>> for AllowedSansStore {
    fn from(list: Vec<String>) -> Self {
        Self {
            inner: Arc::new(arc_swap::ArcSwap::from_pointee(list)),
        }
    }
}

/// Pattern → SAN match. `*.example.com` matches one label of
/// `<label>.example.com`; the bare `example.com` does NOT
/// match the wildcard, and nested labels (`a.b.example.com`)
/// are rejected too. Plain patterns require an exact match.
pub fn san_matches(pattern: &str, san: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // The SAN must end with `.<suffix>` (so the wildcard
        // bound has at least one character before the dot)
        // AND have exactly one label before that dot.
        let needle = format!(".{suffix}");
        if !san.ends_with(&needle) {
            return false;
        }
        let prefix_len = san.len() - needle.len();
        if prefix_len == 0 {
            return false;
        }
        let prefix = &san[..prefix_len];
        // Single-label match: no dots in the prefix.
        return !prefix.contains('.');
    }
    pattern == san
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
    use aegis_core::config::{DownstreamMtlsMode, ZeroTrustConfig};

    fn cfg_with_client_auth(ca: DownstreamMtlsConfig) -> WafConfig {
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
        cfg.zero_trust = Some(ZeroTrustConfig {
            downstream: Some(ca),
            upstream_identity: None,
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
        let cfg = cfg_with_client_auth(DownstreamMtlsConfig {
            mode: DownstreamMtlsMode::Required,
            ca_bundle: Some("/etc/aegis/admin-ca.pem".into()),
            allowed_sans: vec!["admin@aegis.local".into()],
            apply_to: vec![DownstreamMtlsScope::Admin, DownstreamMtlsScope::Data],
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
        let cfg = cfg_with_client_auth(DownstreamMtlsConfig {
            mode: DownstreamMtlsMode::Optional,
            ca_bundle: Some("/etc/aegis/ca.pem".into()),
            allowed_sans: Vec::new(),
            apply_to: vec![DownstreamMtlsScope::Admin],
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

    // ---------------- MTLS-T7 — AllowedSansStore ----------------

    #[test]
    fn allowed_sans_store_round_trips() {
        let s = AllowedSansStore::from(vec!["a.example.com".into(), "b@example.com".into()]);
        assert_eq!(s.current().len(), 2);
        s.store(vec!["c.example.com".into()]);
        assert_eq!(s.current().len(), 1);
        assert_eq!(s.current()[0], "c.example.com");
    }

    #[test]
    fn allowed_sans_empty_admits_anything() {
        let s = AllowedSansStore::from(Vec::<String>::new());
        // Empty list = no allowlist gate; any SAN admits.
        assert!(s.admits("anyone"));
        assert!(s.admits("foo.bar.baz"));
    }

    #[test]
    fn allowed_sans_exact_match() {
        let s = AllowedSansStore::from(vec!["svc.example.com".into()]);
        assert!(s.admits("svc.example.com"));
        assert!(!s.admits("other.example.com"));
        assert!(!s.admits(""));
    }

    #[test]
    fn allowed_sans_wildcard_single_label() {
        let s = AllowedSansStore::from(vec!["*.example.com".into()]);
        assert!(s.admits("svc.example.com"));
        assert!(s.admits("api.example.com"));
        // Wildcard does not match the bare domain.
        assert!(!s.admits("example.com"));
        // Wildcard does not match nested labels (RFC 6125 §6.4.3).
        assert!(!s.admits("a.b.example.com"));
        // Different domain — reject.
        assert!(!s.admits("svc.other.com"));
    }

    #[test]
    fn allowed_sans_remove_one_works() {
        let s = AllowedSansStore::from(vec!["a".into(), "b".into(), "c".into()]);
        let removed = s.remove("b");
        assert!(removed);
        let cur = s.current();
        assert_eq!(cur.len(), 2);
        assert!(!cur.contains(&"b".to_string()));
        // Removing again is a no-op.
        let removed_again = s.remove("b");
        assert!(!removed_again);
    }

    #[test]
    fn allowed_sans_match_returns_first_pattern() {
        let s = AllowedSansStore::from(vec![
            "*.example.com".into(),
            "exact@example.com".into(),
        ]);
        assert_eq!(
            s.matched_pattern("svc.example.com"),
            Some("*.example.com".to_string()),
        );
        assert_eq!(
            s.matched_pattern("exact@example.com"),
            Some("exact@example.com".to_string()),
        );
        assert_eq!(s.matched_pattern("nope"), None);
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
