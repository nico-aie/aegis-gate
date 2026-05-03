//! TLS hardening helpers (P4 of the security-toggle plan).
//!
//! Three concerns: protocol-version enforcement, force-HTTPS
//! redirects, and HSTS header emission. Validation that any of
//! these would reject lives in `aegis_core::config::WafConfig::validate`
//! — this module assumes inputs are already well-formed and
//! focuses on building runtime artefacts.

use std::sync::Arc;

use aegis_core::config::{ClientAuthMode, HstsConfig};
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Response, StatusCode};
use rustls::server::WebPkiClientVerifier;
use rustls::version::{TLS12, TLS13};
use rustls::SupportedProtocolVersion;

use crate::listener::client_trust::ClientTrustStore;
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
    // rustls 0.23 requires an explicit CryptoProvider when more
    // than one cipher backend feature is reachable in the
    // dependency graph (HP-T1 added hyper-rustls which enables
    // ring alongside aws-lc-rs). Install the ring provider once
    // per process; idempotent across crates.
    static PROVIDER_INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    PROVIDER_INIT.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });

    let versions = protocol_versions_for(min_version);
    let mut config = rustls::ServerConfig::builder_with_protocol_versions(versions)
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

/// MTLS-T2 — same as [`build_hardened_server_config`] but with
/// inbound client-cert verification wired on.
///
/// `mode` selects the strictness:
/// - [`ClientAuthMode::Disabled`] — caller should use the
///   no-client-auth variant instead. Returns the same shape
///   anyway (with `with_no_client_auth`) so callers don't have
///   to branch when iterating.
/// - [`ClientAuthMode::Optional`] — verifier built with
///   `.allow_unauthenticated()`. Handshake admits both
///   with-cert and without-cert clients; downstream identity
///   extraction (MTLS-T3) marks the latter as `Anonymous`.
/// - [`ClientAuthMode::Required`] — verifier built without
///   `.allow_unauthenticated()`. Handshake fails when the
///   client presents no cert, before any HTTP bytes are
///   exchanged.
///
/// `trust_store` is held by `Arc` clone so the verifier observes
/// the latest swap target. MTLS-T5 will use this for hot-reload.
pub fn build_hardened_server_config_with_client_auth(
    resolver: Arc<DynamicResolver>,
    min_version: Option<&str>,
    trust_store: &ClientTrustStore,
    mode: ClientAuthMode,
) -> Result<rustls::ServerConfig, rustls::Error> {
    static PROVIDER_INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    PROVIDER_INIT.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });

    let versions = protocol_versions_for(min_version);
    let builder = rustls::ServerConfig::builder_with_protocol_versions(versions);

    // MTLS-T9 break-glass — when the boot env var is set, downgrade
    // `Required` to `Optional` so an operator who lost their cert
    // can still complete a TLS handshake and recover. The downgrade
    // is logged + audit-emitted at boot in `run.rs`; we silently
    // apply here on every config build (boot + hot-reload).
    let effective_mode = if aegis_core::break_glass::is_active()
        && mode == ClientAuthMode::Required
    {
        ClientAuthMode::Optional
    } else {
        mode
    };

    let mut config = match effective_mode {
        ClientAuthMode::Disabled => builder
            .with_no_client_auth()
            .with_cert_resolver(resolver),
        ClientAuthMode::Optional => {
            let verifier = WebPkiClientVerifier::builder(trust_store.current())
                .allow_unauthenticated()
                .build()
                .map_err(|e| {
                    rustls::Error::General(format!(
                        "WebPkiClientVerifier (optional) build failed: {e}",
                    ))
                })?;
            builder
                .with_client_cert_verifier(verifier)
                .with_cert_resolver(resolver)
        }
        ClientAuthMode::Required => {
            let verifier = WebPkiClientVerifier::builder(trust_store.current())
                .build()
                .map_err(|e| {
                    rustls::Error::General(format!(
                        "WebPkiClientVerifier (required) build failed: {e}",
                    ))
                })?;
            builder
                .with_client_cert_verifier(verifier)
                .with_cert_resolver(resolver)
        }
    };
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

    // ---------------- MTLS-T2 ----------------

    /// Tests that build a `rustls::ClientConfig` directly need
    /// the same one-shot crypto-provider install the production
    /// path runs in `build_hardened_server_config`. Idempotent.
    fn ensure_crypto_provider() {
        static INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        INIT.get_or_init(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    /// Issue a self-signed CA + server-leaf signed by it +
    /// client-leaf signed by it. Returns PEM bundles + the cert
    /// material the test plumbing needs (DER for rustls,
    /// `PrivateKeyDer` for the server config). Used by the
    /// handshake tests below.
    #[allow(clippy::type_complexity)]
    fn issue_test_pki(
        server_dns: &str,
        client_subject: &str,
    ) -> (
        Vec<u8>, // ca_pem
        Vec<rustls_pki_types::CertificateDer<'static>>, // server cert chain (server leaf only)
        rustls_pki_types::PrivateKeyDer<'static>,       // server key
        Vec<rustls_pki_types::CertificateDer<'static>>, // client cert chain
        rustls_pki_types::PrivateKeyDer<'static>,       // client key
    ) {
        use rustls_pki_types::CertificateDer;

        let mut ca_params =
            rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca =
            rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let srv_params =
            rcgen::CertificateParams::new(vec![server_dns.into()]).unwrap();
        let srv_key = rcgen::KeyPair::generate().unwrap();
        let srv_cert = srv_params.signed_by(&srv_key, &ca_cert, &ca_key).unwrap();

        let cli_params =
            rcgen::CertificateParams::new(vec![client_subject.into()]).unwrap();
        let cli_key = rcgen::KeyPair::generate().unwrap();
        let cli_cert = cli_params.signed_by(&cli_key, &ca_cert, &ca_key).unwrap();

        let ca_pem = ca_cert.pem().into_bytes();
        let server_chain: Vec<CertificateDer<'static>> = vec![srv_cert.der().clone()];
        let server_key = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(srv_key.serialize_der()),
        );
        let client_chain: Vec<CertificateDer<'static>> = vec![cli_cert.der().clone()];
        let client_key = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(cli_key.serialize_der()),
        );

        (ca_pem, server_chain, server_key, client_chain, client_key)
    }

    /// Spin up a tokio TCP listener with the supplied
    /// `ServerConfig` and run one handshake attempt against it.
    /// Returns `Ok(())` if the server side completed a TLS
    /// accept, `Err(...)` with the rustls/io error otherwise.
    /// Used by the handshake tests below to exercise both
    /// success and failure paths.
    async fn drive_handshake(
        server_cfg: rustls::ServerConfig,
        client_cfg: rustls::ClientConfig,
        sni: &str,
    ) -> std::io::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await?;
            let mut tls = acceptor.accept(sock).await?;
            // Drain a probe byte so `Optional` mode actually
            // exchanges encrypted bytes after the handshake.
            let mut buf = [0u8; 4];
            let _ = tls.read(&mut buf).await;
            let _ = tls.write_all(b"ok\n").await;
            Ok::<_, std::io::Error>(())
        });

        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));
        let server_name = rustls_pki_types::ServerName::try_from(sni.to_string())
            .map_err(|e| std::io::Error::other(format!("bad sni: {e}")))?;
        let stream = tokio::net::TcpStream::connect(addr).await?;
        let mut tls = connector.connect(server_name, stream).await?;
        let _ = tls.write_all(b"ping").await;
        let mut buf = [0u8; 4];
        let _ = tls.read(&mut buf).await;

        // Bubble up any error from the server task.
        match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            server,
        )
        .await
        {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(e))) => Err(e),
            Ok(Err(e)) => Err(std::io::Error::other(format!("join: {e}"))),
            Err(_) => Err(std::io::Error::other("server task timed out")),
        }
    }

    #[test]
    fn build_with_client_auth_disabled_returns_noauth_config() {
        // Caller asks for Disabled — we build a config that has
        // no client-cert verifier but still threads the cert
        // resolver. Equivalent to the no-client-auth path.
        let pem = {
            let mut params =
                rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            params.is_ca =
                rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let key = rcgen::KeyPair::generate().unwrap();
            params.self_signed(&key).unwrap().pem().into_bytes()
        };
        let trust = ClientTrustStore::load_from_pem_bytes(&pem).unwrap();
        // Empty CertStore — the disabled-mode test only proves
        // the builder accepts the config shape; we never run a
        // handshake here.
        let empty_store: &[(&str, &str, &[String])] = &[];
        let store = crate::listener::tls::CertStore::load(empty_store).unwrap();
        let resolver = Arc::new(crate::listener::tls::DynamicResolver::new(
            Arc::new(arc_swap::ArcSwap::from_pointee(store)),
        ));
        let cfg = build_hardened_server_config_with_client_auth(
            resolver,
            None,
            &trust,
            ClientAuthMode::Disabled,
        )
        .expect("disabled builds");
        // ALPN list is preserved for the data-plane h2/http1.1
        // negotiation.
        assert!(cfg.alpn_protocols.iter().any(|p| p == b"h2"));
        assert!(cfg.alpn_protocols.iter().any(|p| p == b"http/1.1"));
    }

    #[tokio::test]
    async fn handshake_passes_with_valid_client_cert_when_required() {
        ensure_crypto_provider();
        // Issue a CA + server leaf + client leaf, all rooted in
        // the same CA. Server enforces Required; client presents
        // its leaf. Handshake completes.
        let (ca_pem, srv_chain, srv_key, cli_chain, cli_key) =
            issue_test_pki("localhost", "test-client");
        let trust = ClientTrustStore::load_from_pem_bytes(&ca_pem).unwrap();

        let server_cfg = rustls::ServerConfig::builder()
            .with_client_cert_verifier(
                WebPkiClientVerifier::builder(trust.current())
                    .build()
                    .unwrap(),
            )
            .with_single_cert(srv_chain, srv_key)
            .unwrap();

        let mut roots = rustls::RootCertStore::empty();
        let mut reader = std::io::BufReader::new(ca_pem.as_slice());
        for c in rustls_pemfile::certs(&mut reader) {
            roots.add(c.unwrap()).unwrap();
        }
        let client_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(cli_chain, cli_key)
            .unwrap();

        drive_handshake(server_cfg, client_cfg, "localhost")
            .await
            .expect("handshake should complete with valid client cert");
    }

    #[tokio::test]
    async fn handshake_rejects_missing_client_cert_when_required() {
        ensure_crypto_provider();
        // Required mode + client presents no cert → rustls fails
        // the handshake before any HTTP byte is exchanged.
        let (ca_pem, srv_chain, srv_key, _cli_chain, _cli_key) =
            issue_test_pki("localhost", "test-client");
        let trust = ClientTrustStore::load_from_pem_bytes(&ca_pem).unwrap();

        let server_cfg = rustls::ServerConfig::builder()
            .with_client_cert_verifier(
                WebPkiClientVerifier::builder(trust.current())
                    .build()
                    .unwrap(),
            )
            .with_single_cert(srv_chain, srv_key)
            .unwrap();

        let mut roots = rustls::RootCertStore::empty();
        let mut reader = std::io::BufReader::new(ca_pem.as_slice());
        for c in rustls_pemfile::certs(&mut reader) {
            roots.add(c.unwrap()).unwrap();
        }
        // Note: no `with_client_auth_cert` — bare client config.
        let client_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        let err = drive_handshake(server_cfg, client_cfg, "localhost")
            .await
            .expect_err("handshake must fail when client presents no cert");
        let msg = format!("{err:?}");
        assert!(
            msg.to_lowercase().contains("certificate")
                || msg.to_lowercase().contains("handshake")
                || msg.to_lowercase().contains("reset")
                || msg.to_lowercase().contains("connection")
                || msg.to_lowercase().contains("eof"),
            "expected cert/handshake error, got {msg}",
        );
    }

    #[tokio::test]
    async fn handshake_passes_without_client_cert_when_optional() {
        ensure_crypto_provider();
        // Optional mode + client presents no cert → handshake
        // still completes; downstream identity extraction (T3)
        // marks the connection Anonymous.
        let (ca_pem, srv_chain, srv_key, _cli_chain, _cli_key) =
            issue_test_pki("localhost", "test-client");
        let trust = ClientTrustStore::load_from_pem_bytes(&ca_pem).unwrap();

        let server_cfg = rustls::ServerConfig::builder()
            .with_client_cert_verifier(
                WebPkiClientVerifier::builder(trust.current())
                    .allow_unauthenticated()
                    .build()
                    .unwrap(),
            )
            .with_single_cert(srv_chain, srv_key)
            .unwrap();

        let mut roots = rustls::RootCertStore::empty();
        let mut reader = std::io::BufReader::new(ca_pem.as_slice());
        for c in rustls_pemfile::certs(&mut reader) {
            roots.add(c.unwrap()).unwrap();
        }
        let client_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        drive_handshake(server_cfg, client_cfg, "localhost")
            .await
            .expect("optional mode admits clients without certs");
    }

    #[tokio::test]
    async fn handshake_rejects_untrusted_client_cert_when_required() {
        ensure_crypto_provider();
        // Required mode + client presents a cert signed by a
        // *different* CA than the server trusts → handshake
        // fails. This is the security-critical path: even with
        // a "looks legit" cert, the wrong issuer is rejected.
        let (server_ca_pem, srv_chain, srv_key, _untrusted_chain, _untrusted_key) =
            issue_test_pki("localhost", "test-client-1");
        let trust = ClientTrustStore::load_from_pem_bytes(&server_ca_pem).unwrap();

        // Issue the client leaf from a SECOND, unrelated CA. The
        // server's trust store doesn't know this CA.
        let (_other_ca_pem, _other_srv, _other_srv_key, untrusted_chain, untrusted_key) =
            issue_test_pki("localhost", "rogue-client");

        let server_cfg = rustls::ServerConfig::builder()
            .with_client_cert_verifier(
                WebPkiClientVerifier::builder(trust.current())
                    .build()
                    .unwrap(),
            )
            .with_single_cert(srv_chain, srv_key)
            .unwrap();

        let mut roots = rustls::RootCertStore::empty();
        let mut reader = std::io::BufReader::new(server_ca_pem.as_slice());
        for c in rustls_pemfile::certs(&mut reader) {
            roots.add(c.unwrap()).unwrap();
        }
        let client_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(untrusted_chain, untrusted_key)
            .unwrap();

        let err = drive_handshake(server_cfg, client_cfg, "localhost")
            .await
            .expect_err("untrusted client CA must be rejected");
        let msg = format!("{err:?}");
        assert!(
            msg.to_lowercase().contains("unknown")
                || msg.to_lowercase().contains("issuer")
                || msg.to_lowercase().contains("certificate")
                || msg.to_lowercase().contains("invalid")
                || msg.to_lowercase().contains("handshake")
                || msg.to_lowercase().contains("trust"),
            "expected trust/issuer error, got {msg}",
        );
    }

}
