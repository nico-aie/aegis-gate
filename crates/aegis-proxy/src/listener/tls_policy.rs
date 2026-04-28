//! TLS hardening helpers (P4 of the security-toggle plan).
//!
//! Three concerns: protocol-version enforcement, force-HTTPS
//! redirects, and HSTS header emission. Validation that any of
//! these would reject lives in `aegis_core::config::WafConfig::validate`
//! — this module assumes inputs are already well-formed and
//! focuses on building runtime artefacts.

use std::sync::Arc;

use aegis_core::config::HstsConfig;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Response, StatusCode};
use rustls::version::{TLS12, TLS13};
use rustls::SupportedProtocolVersion;

use crate::listener::tls::DynamicResolver;

// Static slices so `protocol_versions_for` can return `&'static`
// without juggling temporaries.
static VERSIONS_12_13: [&SupportedProtocolVersion; 2] = [&TLS12, &TLS13];
static VERSIONS_13_ONLY: [&SupportedProtocolVersion; 1] = [&TLS13];

/// Map a config-level `min_version` string to the slice of
/// rustls protocol versions to enable. `None` falls back to
/// rustls's "all supported" default, which today is TLS 1.2 + 1.3.
pub fn protocol_versions_for(
    min_version: Option<&str>,
) -> &'static [&'static SupportedProtocolVersion] {
    match min_version {
        Some("1.3") => &VERSIONS_13_ONLY,
        // Default + explicit 1.2: enable both, refuse anything older.
        Some("1.2") | None => &VERSIONS_12_13,
        // Validation should have rejected anything else upstream;
        // fail safe → 1.3-only.
        Some(_) => &VERSIONS_13_ONLY,
    }
}

/// Build a `rustls::ServerConfig` with the configured protocol
/// versions. Mirrors the legacy
/// [`crate::listener::tls::build_server_config`] but enforces the
/// hardened minimum at the rustls layer — older clients will see
/// a handshake failure rather than a silently downgraded session.
pub fn build_hardened_server_config(
    resolver: Arc<DynamicResolver>,
    min_version: Option<&str>,
) -> Result<rustls::ServerConfig, rustls::Error> {
    let versions = protocol_versions_for(min_version);
    let mut config = rustls::ServerConfig::builder_with_protocol_versions(versions)
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

/// Format the `Strict-Transport-Security` header value from the
/// HSTS config. Returns `None` if HSTS is not configured.
pub fn format_hsts_header(hsts: Option<&HstsConfig>) -> Option<String> {
    let h = hsts?;
    let mut out = format!("max-age={}", h.max_age);
    if h.include_subdomains {
        out.push_str("; includeSubDomains");
    }
    if h.preload {
        out.push_str("; preload");
    }
    Some(out)
}

/// Build a force-HTTPS redirect response for an HTTP request.
///
/// `host_header` is the `Host:` header from the inbound request
/// (empty/absent when the request lacked one — uncommon for HTTP/1.1
/// but possible for HTTP/0.9 or malformed clients). `path_and_query`
/// is the request target. `status` is `301` or `308`.
///
/// Strips any explicit port suffix from the host (e.g. `:80`) so the
/// `Location` header points at the canonical HTTPS origin (`:443` is
/// implicit). Custom non-default HTTPS ports are not preserved — the
/// proxy can't infer them from the request alone, and redirecting to
/// `:443` is the right default for force-HTTPS deployments.
pub fn force_https_redirect_response(
    host_header: &str,
    path_and_query: &str,
    status: u16,
) -> Response<Full<Bytes>> {
    let canonical_host = strip_port(host_header);
    let path = if path_and_query.is_empty() {
        "/"
    } else {
        path_and_query
    };
    let location = format!("https://{canonical_host}{path}");

    // Only honour 301 / 308 — anything else fails safe to 301.
    // Validation rejects unsupported codes upstream, but defence
    // in depth.
    let status_code = match status {
        301 => StatusCode::MOVED_PERMANENTLY,
        308 => StatusCode::PERMANENT_REDIRECT,
        _ => StatusCode::MOVED_PERMANENTLY,
    };

    Response::builder()
        .status(status_code)
        .header("location", location.clone())
        .header("cache-control", "no-store")
        .header("content-type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(format!(
            "{status_code} — use HTTPS: {location}\n",
        ))))
        .unwrap()
}

/// Strip a `:port` suffix from a `host:port` literal. Bare hosts
/// (no colon) and IPv6 bracketed forms (`[::1]:8080`) are
/// preserved — IPv6 keeps the brackets without the trailing port.
fn strip_port(host_header: &str) -> &str {
    let trimmed = host_header.trim();
    if trimmed.is_empty() {
        return "localhost";
    }
    // IPv6 literal: [::1]:443
    if let Some(end) = trimmed.find(']') {
        return &trimmed[..=end];
    }
    match trimmed.rsplit_once(':') {
        Some((host, _port)) => host,
        None => trimmed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_versions_default_allows_both() {
        let v = protocol_versions_for(None);
        assert_eq!(v.len(), 2);
        assert!(v.contains(&&TLS12));
        assert!(v.contains(&&TLS13));
    }

    #[test]
    fn protocol_versions_min_12_allows_both() {
        let v = protocol_versions_for(Some("1.2"));
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn protocol_versions_min_13_pins_to_13_only() {
        let v = protocol_versions_for(Some("1.3"));
        assert_eq!(v.len(), 1);
        assert_eq!(v[0] as *const _, &TLS13 as *const _);
    }

    #[test]
    fn protocol_versions_unknown_falls_back_to_13() {
        // Validation rejects this upstream; the helper still
        // fails safe to TLS 1.3 if anything slips through.
        let v = protocol_versions_for(Some("invalid"));
        assert_eq!(v.len(), 1);
        assert_eq!(v[0] as *const _, &TLS13 as *const _);
    }

    #[test]
    fn hsts_header_includes_max_age_only() {
        let cfg = HstsConfig {
            max_age: 3600,
            include_subdomains: false,
            preload: false,
        };
        let header = format_hsts_header(Some(&cfg)).unwrap();
        assert_eq!(header, "max-age=3600");
    }

    #[test]
    fn hsts_header_includes_subdomains_directive() {
        let cfg = HstsConfig {
            max_age: 31_536_000,
            include_subdomains: true,
            preload: false,
        };
        let header = format_hsts_header(Some(&cfg)).unwrap();
        assert_eq!(header, "max-age=31536000; includeSubDomains");
    }

    #[test]
    fn hsts_header_includes_preload_directive() {
        let cfg = HstsConfig {
            max_age: 31_536_000,
            include_subdomains: true,
            preload: true,
        };
        let header = format_hsts_header(Some(&cfg)).unwrap();
        assert_eq!(
            header,
            "max-age=31536000; includeSubDomains; preload"
        );
    }

    #[test]
    fn hsts_header_none_when_no_config() {
        assert!(format_hsts_header(None).is_none());
    }

    #[test]
    fn redirect_returns_configured_status() {
        let resp = force_https_redirect_response("example.com", "/api", 308);
        assert_eq!(resp.status().as_u16(), 308);
    }

    #[test]
    fn redirect_location_is_https_with_path() {
        let resp = force_https_redirect_response("example.com", "/api?x=1", 301);
        let loc = resp.headers().get("location").unwrap().to_str().unwrap();
        assert_eq!(loc, "https://example.com/api?x=1");
    }

    #[test]
    fn redirect_strips_explicit_port_from_host() {
        let resp = force_https_redirect_response("example.com:80", "/foo", 301);
        let loc = resp.headers().get("location").unwrap().to_str().unwrap();
        assert_eq!(loc, "https://example.com/foo");
    }

    #[test]
    fn redirect_preserves_ipv6_brackets() {
        let resp = force_https_redirect_response("[::1]:8080", "/", 301);
        let loc = resp.headers().get("location").unwrap().to_str().unwrap();
        assert_eq!(loc, "https://[::1]/");
    }

    #[test]
    fn redirect_falls_back_for_blank_host() {
        let resp = force_https_redirect_response("", "/", 301);
        let loc = resp.headers().get("location").unwrap().to_str().unwrap();
        assert_eq!(loc, "https://localhost/");
    }

    #[test]
    fn redirect_falls_back_for_blank_path() {
        let resp = force_https_redirect_response("example.com", "", 301);
        let loc = resp.headers().get("location").unwrap().to_str().unwrap();
        assert_eq!(loc, "https://example.com/");
    }

    #[test]
    fn redirect_clamps_invalid_status_to_301() {
        let resp = force_https_redirect_response("example.com", "/", 999);
        assert_eq!(resp.status().as_u16(), 301);
    }

    #[test]
    fn redirect_marks_response_no_store() {
        let resp = force_https_redirect_response("example.com", "/", 301);
        assert_eq!(
            resp.headers().get("cache-control").unwrap(),
            "no-store"
        );
    }
}
