//! Zero Trust — upstream (WAF-as-client) read views (P3 slice 1).
//!
//! Read-only JSON for the Zero Trust console page's **upstream**
//! section:
//!
//! | Path | Purpose |
//! |---|---|
//! | `/api/zero-trust/upstream/identity` | Shared fleet WAF client-cert metadata (subject / fingerprint / expiry — **never** the private key) |
//! | `/api/zero-trust/upstream/config` | Per-pool upstream-mTLS state (off / mutual+verify) |
//!
//! The downstream (WAF-as-server) views still live in [`crate::api::mtls`]
//! and are renamed onto `/api/zero-trust/downstream/*` in the frontend
//! slice. Nothing here ever returns private-key material — the identity
//! view parses only the PUBLIC cert at `cert_path` for display metadata.

use std::path::Path;

use serde::Serialize;

use aegis_core::config::{UpstreamIdentitySource, WafConfig};

use crate::identity_tracker::{parse_ca_bundle, CaCertSummary};

// ---------------------------------------------------------------------------
// GET /api/zero-trust/upstream/identity
// ---------------------------------------------------------------------------

/// Wire shape for the shared fleet WAF client identity. Metadata
/// only — the private key (`key_ref`) is never read or returned.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct UpstreamIdentityView {
    /// `true` when `zero_trust.upstream_identity` is configured.
    pub configured: bool,
    /// `file` | `state` — how the identity is sourced.
    pub source: &'static str,
    /// The PUBLIC cert path (never the key path).
    pub cert_path: Option<String>,
    /// Parsed metadata of the public cert (subject / fingerprint /
    /// expiry). Empty when unconfigured or the cert can't be read.
    pub certificates: Vec<CaCertSummary>,
    /// Human-readable parse error, when the cert couldn't be read.
    pub error: Option<String>,
}

impl UpstreamIdentityView {
    pub fn from_config(cfg: &WafConfig) -> Self {
        let Some(id) = cfg
            .zero_trust
            .as_ref()
            .and_then(|z| z.upstream_identity.as_ref())
        else {
            return Self {
                configured: false,
                source: "file",
                cert_path: None,
                certificates: Vec::new(),
                error: None,
            };
        };
        let source = match id.source {
            UpstreamIdentitySource::File => "file",
            UpstreamIdentitySource::State => "state",
        };
        let cert_path = id.cert_path.as_ref().map(|p| p.display().to_string());
        // Parse the PUBLIC cert for display metadata only.
        let (certificates, error) = match id.cert_path.as_ref() {
            Some(p) => match parse_ca_bundle(Path::new(p)) {
                Ok(summary) => (summary.certificates, None),
                Err(e) => (Vec::new(), Some(e.to_string())),
            },
            None => (Vec::new(), None),
        };
        Self {
            configured: true,
            source,
            cert_path,
            certificates,
            error,
        }
    }

    pub fn render(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| String::from("{}"))
    }
}

// ---------------------------------------------------------------------------
// GET /api/zero-trust/upstream/config
// ---------------------------------------------------------------------------

/// Per-pool upstream-mTLS state for the Zero Trust list.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct UpstreamPoolMtlsView {
    pub pool: String,
    /// `off` | `mutual+verify`. (`client-auth` without verify is a
    /// P5 capability — P2 always verifies, so enabled ⇒ mutual+verify.)
    pub status: &'static str,
    pub enabled: bool,
    pub verify: bool,
    /// Name/path of the custom backend-trust CA, when set (`null` ⇒
    /// public webpki roots).
    pub trust: Option<String>,
    pub allowed_sans: Vec<String>,
}

/// Wire shape for `GET /api/zero-trust/upstream/config`.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct UpstreamConfigView {
    pub pools: Vec<UpstreamPoolMtlsView>,
}

impl UpstreamConfigView {
    pub fn from_config(cfg: &WafConfig) -> Self {
        let mut pools: Vec<UpstreamPoolMtlsView> = cfg
            .upstreams
            .iter()
            .map(|(name, pool)| {
                let m = pool.upstream_mtls.as_ref();
                let enabled = m.map(|m| m.enabled).unwrap_or(false);
                UpstreamPoolMtlsView {
                    pool: name.clone(),
                    status: if enabled { "mutual+verify" } else { "off" },
                    enabled,
                    verify: m.map(|m| m.verify).unwrap_or(true),
                    trust: m
                        .and_then(|m| m.trust.as_ref())
                        .map(|p| p.display().to_string()),
                    allowed_sans: m.map(|m| m.allowed_sans.clone()).unwrap_or_default(),
                }
            })
            .collect();
        // Stable order so the dashboard list doesn't jitter.
        pools.sort_by(|a, b| a.pool.cmp(&b.pool));
        Self { pools }
    }

    pub fn render(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| String::from("{}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(yaml_tail: &str) -> WafConfig {
        let yaml = format!(
            r#"
listeners:
  data: [{{ bind: "0.0.0.0:443" }}]
  admin: {{ bind: "127.0.0.1:9443" }}
routes:
  - {{ id: catch-all, path: "/", upstream: api }}
upstreams:
  api:
    members: [{{ addr: "127.0.0.1:8443" }}]
    connection: {{ tls: true }}
{yaml_tail}
state: {{ backend: in_memory }}
"#
        );
        serde_yaml::from_str(&yaml).unwrap()
    }

    #[test]
    fn identity_view_unconfigured() {
        let v = UpstreamIdentityView::from_config(&cfg(""));
        assert!(!v.configured);
        assert!(v.certificates.is_empty());
        assert!(v.cert_path.is_none());
    }

    #[test]
    fn identity_view_reports_path_never_key() {
        let zt = "zero_trust:\n  upstream_identity:\n    source: file\n    cert_path: /tmp/does-not-exist-waf.pem\n    key_ref: /tmp/secret.key\n";
        let v = UpstreamIdentityView::from_config(&cfg(zt));
        assert!(v.configured);
        assert_eq!(v.source, "file");
        assert_eq!(v.cert_path.as_deref(), Some("/tmp/does-not-exist-waf.pem"));
        // Missing file ⇒ parse error surfaced, no panic, no key leak.
        assert!(v.error.is_some());
        // The rendered JSON must never contain the key path.
        assert!(!v.render().contains("secret.key"));
    }

    #[test]
    fn config_view_off_by_default() {
        let v = UpstreamConfigView::from_config(&cfg(""));
        assert_eq!(v.pools.len(), 1);
        assert_eq!(v.pools[0].pool, "api");
        assert_eq!(v.pools[0].status, "off");
        assert!(!v.pools[0].enabled);
    }

    #[test]
    fn config_view_enabled_pool_is_mutual_verify() {
        let zt = "    upstream_mtls: { enabled: true, trust: /etc/waf/backend-ca.pem }\nzero_trust:\n  upstream_identity:\n    source: file\n    cert_path: /etc/waf/c.pem\n    key_ref: /etc/waf/c.key";
        // pool extra must sit under the pool, before `state:` —
        // rebuild yaml inline for the enabled case.
        let yaml = format!(
            r#"
listeners:
  data: [{{ bind: "0.0.0.0:443" }}]
  admin: {{ bind: "127.0.0.1:9443" }}
routes:
  - {{ id: catch-all, path: "/", upstream: api }}
upstreams:
  api:
    members: [{{ addr: "127.0.0.1:8443" }}]
    connection: {{ tls: true }}
{zt}
state: {{ backend: in_memory }}
"#
        );
        let cfg: WafConfig = serde_yaml::from_str(&yaml).unwrap();
        let v = UpstreamConfigView::from_config(&cfg);
        assert_eq!(v.pools[0].status, "mutual+verify");
        assert!(v.pools[0].enabled);
        assert_eq!(v.pools[0].trust.as_deref(), Some("/etc/waf/backend-ca.pem"));
    }
}
