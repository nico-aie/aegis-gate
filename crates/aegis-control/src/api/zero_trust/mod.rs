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
//! The downstream (WAF-as-server) views live in [`downstream`] (with the
//! CA-bundle preview in [`ca_bundle`] and the mode store in [`mode`]) and
//! are served on `/api/zero-trust/downstream/*`. Nothing here ever returns
//! private-key material — the identity view parses only the PUBLIC cert at
//! `cert_path` for display metadata.

pub mod ca_bundle;
pub mod downstream;
pub mod mode;

use std::path::Path;

use serde::Serialize;

use aegis_core::config::{UpstreamIdentitySource, WafConfig};

use crate::identity_tracker::{parse_ca_bundle, parse_ca_bundle_bytes, CaCertSummary};

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
    /// The PUBLIC cert chain PEM, for the "Download WAF cert" button
    /// (operators install this in their backend client-trust store).
    /// Public material only — the private key (`key_ref`) is never
    /// read. `None` when unconfigured or unreadable.
    pub cert_pem: Option<String>,
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
                cert_pem: None,
                certificates: Vec::new(),
                error: None,
            };
        };
        let source = match id.source {
            UpstreamIdentitySource::File => "file",
            UpstreamIdentitySource::State => "state",
        };
        let cert_path = id.cert_path.as_ref().map(|p| p.display().to_string());
        // PUBLIC cert material + parsed metadata. Two sources:
        //   * file  — read `cert_path` off disk (a missing file
        //             surfaces an Io error so the operator notices).
        //   * state — use the in-memory PEM materialized from the
        //             config plane at boot (`cert_pem`); `cert_path`
        //             is irrelevant. Unmaterialized (e.g. read before
        //             boot folded it in) ⇒ empty, no error.
        // The private key (`key_ref`) is NEVER read in either branch.
        let (certificates, error, cert_pem) = match id.source {
            UpstreamIdentitySource::File => {
                let (certs, err) = match id.cert_path.as_ref() {
                    Some(p) => match parse_ca_bundle(Path::new(p)) {
                        Ok(summary) => (summary.certificates, None),
                        Err(e) => (Vec::new(), Some(e.to_string())),
                    },
                    None => (Vec::new(), None),
                };
                let pem = id
                    .cert_path
                    .as_ref()
                    .and_then(|p| std::fs::read_to_string(p).ok());
                (certs, err, pem)
            }
            UpstreamIdentitySource::State => match id.cert_pem.as_ref() {
                Some(pem) => match parse_ca_bundle_bytes(pem.as_bytes()) {
                    Ok(certs) => (certs, None, Some(pem.clone())),
                    Err(e) => (Vec::new(), Some(e.to_string()), Some(pem.clone())),
                },
                None => (Vec::new(), None, None),
            },
        };
        Self {
            configured: true,
            source,
            cert_path,
            cert_pem,
            certificates,
            error,
        }
    }

    pub fn render(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| String::from("{}"))
    }
}

// ---------------------------------------------------------------------------
// PUT /api/zero-trust/upstream/identity — store the shared fleet identity
// ---------------------------------------------------------------------------

/// Parsed + validated PUT body for storing the shared upstream
/// identity. PUBLIC cert + a *reference* to the private key — the key
/// bytes are never accepted here (reference-only, P4).
#[derive(Debug, serde::Deserialize)]
pub struct IdentityUploadRequest {
    /// PUBLIC client-cert chain PEM (the shared fleet identity).
    pub cert_pem: String,
    /// Reference to the private key (path / `${secret:...}`). Never
    /// the key bytes.
    pub key_ref: String,
}

/// Validate an identity upload before it is persisted: the cert must
/// be parseable PEM with ≥1 certificate, and the key reference must
/// be non-empty. Returns the parsed PUBLIC cert summaries (for the
/// audit `after` projection + the response preview) or a stable error
/// string. Pure — no IO, no key material.
pub fn validate_identity_upload(
    req: &IdentityUploadRequest,
) -> Result<Vec<CaCertSummary>, String> {
    if req.key_ref.trim().is_empty() {
        return Err("key_ref must be a non-empty reference to the private key".into());
    }
    // Defense in depth: a private key block must never ride in on the
    // PUBLIC cert field. Reject loudly rather than persisting it.
    if req.cert_pem.contains("PRIVATE KEY") {
        return Err(
            "cert_pem must contain only the PUBLIC certificate chain — \
             a PRIVATE KEY block was found (the key stays a key_ref, never stored)"
                .into(),
        );
    }
    parse_ca_bundle_bytes(req.cert_pem.as_bytes()).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// POST/DELETE /api/zero-trust/upstream/trust/{bundle} — backend-CA bundles
// ---------------------------------------------------------------------------

/// Whether `name` is a safe trust-bundle identifier. Restricted to a
/// conservative charset so it can't break the config-plane key shape
/// (`aegis:zt:upstream:trust:<name>`) or smuggle path/colon tricks.
pub fn is_valid_bundle_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// Validate a backend-CA trust-bundle upload before it is persisted:
/// the body must be parseable PEM with ≥1 certificate, and must carry
/// no private-key block (a CA bundle is PUBLIC trust material). Returns
/// the parsed cert summaries (for the audit `after` projection +
/// response preview) or a stable error string. Pure — no IO.
pub fn validate_trust_upload(pem: &[u8]) -> Result<Vec<CaCertSummary>, String> {
    // Defense in depth: a trust bundle is PUBLIC — reject a private key.
    if let Ok(s) = std::str::from_utf8(pem) {
        if s.contains("PRIVATE KEY") {
            return Err(
                "a backend-CA trust bundle must contain only PUBLIC certificates — \
                 a PRIVATE KEY block was found"
                    .into(),
            );
        }
    }
    parse_ca_bundle_bytes(pem).map_err(|e| e.to_string())
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

    /// A real self-signed PUBLIC cert (no key) for parse tests.
    /// Generated out of band; PUBLIC material only.
    const TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIUO0nGZ7Wm0Q6kJ8Yk0Y5Q0Z0Q0wwCgYIKoZIzj0EAwIw
-----END CERTIFICATE-----
";

    #[test]
    fn identity_view_state_source_uses_materialized_pem() {
        // Simulate the boot materialization: source: state with the
        // PUBLIC cert folded into `cert_pem` (the config-plane read).
        let mut cfg = cfg("zero_trust:\n  upstream_identity:\n    source: state\n");
        let id = cfg
            .zero_trust
            .as_mut()
            .and_then(|z| z.upstream_identity.as_mut())
            .unwrap();
        id.cert_pem = Some(TEST_CERT_PEM.to_string());
        id.key_ref = Some("/run/secrets/waf-client.key".into());
        let v = UpstreamIdentityView::from_config(&cfg);
        assert!(v.configured);
        assert_eq!(v.source, "state");
        // Surfaces the PUBLIC PEM (for the download button)…
        assert_eq!(v.cert_pem.as_deref(), Some(TEST_CERT_PEM));
        // …and never the key reference.
        assert!(!v.render().contains("waf-client.key"));
    }

    #[test]
    fn identity_view_state_source_unmaterialized_is_empty_no_panic() {
        // source: state but cert_pem not yet folded in ⇒ empty, no error.
        let cfg = cfg("zero_trust:\n  upstream_identity:\n    source: state\n");
        let v = UpstreamIdentityView::from_config(&cfg);
        assert!(v.configured);
        assert_eq!(v.source, "state");
        assert!(v.cert_pem.is_none());
        assert!(v.certificates.is_empty());
        assert!(v.error.is_none());
    }

    #[test]
    fn validate_identity_upload_rejects_empty_key_ref() {
        let req = IdentityUploadRequest {
            cert_pem: TEST_CERT_PEM.into(),
            key_ref: "   ".into(),
        };
        assert!(validate_identity_upload(&req).unwrap_err().contains("key_ref"));
    }

    #[test]
    fn validate_identity_upload_rejects_private_key_in_cert_field() {
        let req = IdentityUploadRequest {
            cert_pem: "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n".into(),
            key_ref: "/run/secrets/waf-client.key".into(),
        };
        assert!(validate_identity_upload(&req)
            .unwrap_err()
            .contains("PRIVATE KEY"));
    }

    #[test]
    fn validate_identity_upload_rejects_garbage_pem() {
        let req = IdentityUploadRequest {
            cert_pem: "not a pem at all".into(),
            key_ref: "/run/secrets/waf-client.key".into(),
        };
        assert!(validate_identity_upload(&req).is_err());
    }

    #[test]
    fn is_valid_bundle_name_accepts_safe_names_rejects_tricks() {
        assert!(is_valid_bundle_name("backend-ca"));
        assert!(is_valid_bundle_name("payments_v2.internal"));
        assert!(!is_valid_bundle_name("")); // empty
        assert!(!is_valid_bundle_name("a/b")); // slash
        assert!(!is_valid_bundle_name("a:b")); // colon (key separator)
        assert!(!is_valid_bundle_name("with space"));
        assert!(!is_valid_bundle_name(&"x".repeat(65))); // too long
    }

    #[test]
    fn validate_trust_upload_rejects_private_key() {
        let err = validate_trust_upload(
            b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
        )
        .unwrap_err();
        assert!(err.contains("PRIVATE KEY"), "got: {err}");
    }

    #[test]
    fn validate_trust_upload_rejects_garbage() {
        assert!(validate_trust_upload(b"not a pem").is_err());
        assert!(validate_trust_upload(b"").is_err());
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
