//! HTTP/3 listener (B5-T1).
//!
//! Terminates QUIC alongside the existing TLS listener. Reuses
//! the operator's `rustls::ServerConfig` (cert resolver, TLS
//! 1.3 enforcement) — `serve_http3` derives a
//! `quinn::ServerConfig` from it and runs the accept loop.
//! HTTP/3 stream bodies + headers are decoded by the `h3`
//! crate, then dispatched through the existing
//! [`crate::proxy::handle_request`] so every request still
//! flows through routing + security + upstream forwarding.
//!
//! # Negotiation
//!
//! Clients learn about HTTP/3 via `Alt-Svc:` headers stamped
//! on the TLS listener's responses — see
//! [`format_alt_svc`] / [`ALT_SVC_HEADER`]. Capable browsers
//! (Chrome, Firefox, Safari) cache that hint and reach the
//! gateway over QUIC on subsequent connections.
//!
//! # Build gating
//!
//! Everything in this module is gated by the `http3` Cargo
//! feature so single-protocol builds don't pull `quinn` /
//! `h3` / `h3-quinn`. Pure helpers (no I/O) below remain
//! callable; the connection loop is feature-gated.

use std::time::Duration;

/// HTTP-header name for the negotiation hint advertised by
/// the TLS listener.
pub const ALT_SVC_HEADER: &str = "alt-svc";

/// Format the `Alt-Svc` header value advertising HTTP/3 on
/// `port`. `max_age` is the cache duration in seconds.
///
/// Format follows RFC 7838 + the `h3` ALPN identifier from
/// RFC 9114. Example output:
/// `h3=":443"; ma=86400`.
pub fn format_alt_svc(port: u16, max_age: u32) -> String {
    format!("h3=\":{port}\"; ma={max_age}")
}

/// Default cache lifetime for the `Alt-Svc` hint — 24 hours.
/// Long enough for clients to remember between sessions,
/// short enough that operators rolling the listener don't
/// strand stale clients indefinitely.
pub const ALT_SVC_DEFAULT_MAX_AGE: u32 = 24 * 60 * 60;

/// Convenience: format the default header value for a port.
pub fn default_alt_svc(port: u16) -> String {
    format_alt_svc(port, ALT_SVC_DEFAULT_MAX_AGE)
}

/// Build the ALPN protocol list to advertise on the QUIC
/// listener. We negotiate strictly `h3` — older HTTP/3
/// drafts (`h3-29`, `h3-32`) are out-of-spec since RFC 9114
/// shipped, and operators wanting them should pin a specific
/// quinn release rather than hide drafts in the default
/// build.
pub fn h3_alpn_protocols() -> Vec<Vec<u8>> {
    vec![b"h3".to_vec()]
}

/// Apply the HTTP/3 ALPN list to a freshly-built rustls
/// server config in place. Returns the same config for
/// chaining.
pub fn with_h3_alpn(mut cfg: rustls::ServerConfig) -> rustls::ServerConfig {
    cfg.alpn_protocols = h3_alpn_protocols();
    cfg
}

/// Pure helper: validate an HTTP/3 listener bind string. We
/// only require it parses as a `SocketAddr` — quinn does
/// IPv4/IPv6 + port range checks at bind time. Returns the
/// parsed address or an error that explains what was wrong.
pub fn parse_http3_bind(s: &str) -> Result<std::net::SocketAddr, Http3ConfigError> {
    s.parse()
        .map_err(|e: std::net::AddrParseError| Http3ConfigError::BadBind(e.to_string()))
}

/// HTTP/3 listener configuration.
#[derive(Clone, Debug)]
pub struct Http3Config {
    /// Bind address — UDP socket the listener opens.
    pub bind: std::net::SocketAddr,
    /// Per-connection idle timeout. Closed connections free
    /// resources — without an explicit timeout quinn defaults
    /// to forever, which is bad for long-running gateways.
    pub idle_timeout: Duration,
    /// Maximum concurrent in-flight streams per QUIC
    /// connection. Bounds memory under burst.
    pub max_concurrent_streams: u32,
}

impl Default for Http3Config {
    fn default() -> Self {
        Self {
            bind: "[::]:443".parse().unwrap(),
            idle_timeout: Duration::from_secs(30),
            max_concurrent_streams: 256,
        }
    }
}

/// Errors raised by HTTP/3 config + start helpers.
#[derive(Debug)]
pub enum Http3ConfigError {
    BadBind(String),
    Tls(String),
    Bind(String),
    Internal(String),
}

impl std::fmt::Display for Http3ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Http3ConfigError::BadBind(m) => write!(f, "http3 bad bind: {m}"),
            Http3ConfigError::Tls(m) => write!(f, "http3 tls config: {m}"),
            Http3ConfigError::Bind(m) => write!(f, "http3 bind failed: {m}"),
            Http3ConfigError::Internal(m) => write!(f, "http3 internal: {m}"),
        }
    }
}

impl std::error::Error for Http3ConfigError {}

// --- Live runtime path (feature-gated) -------------------

#[cfg(feature = "http3")]
mod runtime {
    use super::*;
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::Request;
    use std::sync::Arc;

    /// Build a `quinn::ServerConfig` from a hardened
    /// `rustls::ServerConfig`. Sets HTTP/3-required ALPN +
    /// the configured idle/streams limits.
    pub fn build_quic_server_config(
        rustls_cfg: rustls::ServerConfig,
        cfg: &Http3Config,
    ) -> Result<quinn::ServerConfig, Http3ConfigError> {
        let rustls_cfg = with_h3_alpn(rustls_cfg);
        let qcc = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_cfg)
            .map_err(|e| Http3ConfigError::Tls(e.to_string()))?;
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(qcc));
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_bidi_streams(cfg.max_concurrent_streams.into());
        let idle = quinn::IdleTimeout::try_from(cfg.idle_timeout)
            .map_err(|e| Http3ConfigError::Internal(e.to_string()))?;
        transport.max_idle_timeout(Some(idle));
        server_config.transport = Arc::new(transport);
        Ok(server_config)
    }

    /// Spawn the QUIC accept loop and dispatch each request
    /// through `proxy::handle_request`. Returns the bound
    /// endpoint (so callers can `close` for graceful drain)
    /// and a join handle of the accept task.
    pub fn serve_http3(
        cfg: Http3Config,
        rustls_cfg: rustls::ServerConfig,
        ctx: Arc<crate::proxy::ProxyContext>,
    ) -> Result<
        (
            quinn::Endpoint,
            tokio::task::JoinHandle<()>,
        ),
        Http3ConfigError,
    > {
        let server_config = build_quic_server_config(rustls_cfg, &cfg)?;
        let endpoint = quinn::Endpoint::server(server_config, cfg.bind)
            .map_err(|e| Http3ConfigError::Bind(e.to_string()))?;
        let endpoint_clone = endpoint.clone();
        let handle = tokio::spawn(async move {
            run_accept_loop(endpoint_clone, ctx).await;
        });
        Ok((endpoint, handle))
    }

    async fn run_accept_loop(
        endpoint: quinn::Endpoint,
        ctx: Arc<crate::proxy::ProxyContext>,
    ) {
        while let Some(incoming) = endpoint.accept().await {
            let ctx = Arc::clone(&ctx);
            tokio::spawn(async move {
                match incoming.await {
                    Ok(connection) => {
                        if let Err(e) = handle_quic_connection(connection, ctx).await {
                            tracing::warn!(error = %e, "http3 connection failed");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "http3 accept failed");
                    }
                }
            });
        }
    }

    async fn handle_quic_connection(
        connection: quinn::Connection,
        ctx: Arc<crate::proxy::ProxyContext>,
    ) -> Result<(), Http3ConfigError> {
        let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(connection))
            .await
            .map_err(|e| Http3ConfigError::Internal(format!("h3 handshake: {e}")))?;
        loop {
            match h3_conn.accept().await {
                Ok(Some(req_resolver)) => {
                    let ctx = Arc::clone(&ctx);
                    tokio::spawn(async move {
                        if let Err(e) = handle_h3_request(req_resolver, ctx).await {
                            tracing::warn!(error = %e, "http3 request failed");
                        }
                    });
                }
                Ok(None) => break,
                Err(e) => {
                    tracing::warn!(error = %e, "http3 accept error");
                    break;
                }
            }
        }
        Ok(())
    }

    async fn handle_h3_request(
        req_resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
        ctx: Arc<crate::proxy::ProxyContext>,
    ) -> Result<(), Http3ConfigError> {
        let (req, mut stream) = req_resolver
            .resolve_request()
            .await
            .map_err(|e| Http3ConfigError::Internal(format!("h3 resolve: {e}")))?;

        // Drain the request body. h3's `recv_data` returns
        // chunks until the stream is finished.
        let mut body = bytes::BytesMut::new();
        loop {
            match stream.recv_data().await {
                Ok(Some(mut chunk)) => {
                    while chunk.has_remaining() {
                        let len = chunk.chunk().len();
                        body.extend_from_slice(chunk.chunk());
                        chunk.advance(len);
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    return Err(Http3ConfigError::Internal(format!("h3 recv_data: {e}")));
                }
            }
        }
        let body_bytes = Full::new(body.freeze());

        let (parts, _) = req.into_parts();
        let hyper_req = Request::from_parts(parts, body_bytes);
        let resp = match crate::proxy::handle_request(hyper_req, ctx).await {
            Ok(r) => r,
            Err(e) => {
                return Err(Http3ConfigError::Internal(format!(
                    "handle_request failed: {e}"
                )));
            }
        };

        let (resp_parts, resp_body) = resp.into_parts();
        let resp_no_body: hyper::Response<()> =
            hyper::Response::from_parts(resp_parts.clone(), ());
        stream
            .send_response(resp_no_body)
            .await
            .map_err(|e| Http3ConfigError::Internal(format!("h3 send_response: {e}")))?;

        // Collect the response body into bytes — the proxy
        // surface today is `Full<Bytes>`, so this is one
        // single chunk.
        let body_bytes = resp_body
            .collect()
            .await
            .map_err(|e| Http3ConfigError::Internal(format!("h3 collect body: {e}")))?
            .to_bytes();
        if !body_bytes.is_empty() {
            stream
                .send_data(body_bytes)
                .await
                .map_err(|e| Http3ConfigError::Internal(format!("h3 send_data: {e}")))?;
        }
        stream
            .finish()
            .await
            .map_err(|e| Http3ConfigError::Internal(format!("h3 finish: {e}")))?;
        Ok(())
    }

    use bytes::Buf as _;
}

#[cfg(feature = "http3")]
pub use runtime::{build_quic_server_config, serve_http3};

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Alt-Svc ----

    #[test]
    fn format_alt_svc_default_port_max_age() {
        assert_eq!(format_alt_svc(443, 86400), "h3=\":443\"; ma=86400");
    }

    #[test]
    fn format_alt_svc_custom_port() {
        assert_eq!(format_alt_svc(8443, 3600), "h3=\":8443\"; ma=3600");
    }

    #[test]
    fn default_alt_svc_uses_24h_max_age() {
        let v = default_alt_svc(443);
        assert!(v.contains("ma=86400"), "{v}");
    }

    #[test]
    fn alt_svc_default_max_age_is_24_hours() {
        assert_eq!(ALT_SVC_DEFAULT_MAX_AGE, 86_400);
    }

    #[test]
    fn alt_svc_header_constant_is_lowercase() {
        // Hyper / http header names compare case-insensitively
        // but the canonical constant is lowercase to match the
        // rest of our header strings.
        assert_eq!(ALT_SVC_HEADER, "alt-svc");
    }

    // ---- ALPN ----

    #[test]
    fn h3_alpn_protocols_only_h3() {
        let alpn = h3_alpn_protocols();
        assert_eq!(alpn.len(), 1);
        assert_eq!(alpn[0], b"h3");
    }

    #[test]
    fn with_h3_alpn_replaces_existing() {
        // Build a tiny server config with an h2-style ALPN
        // first, then assert h3 replaces it. We construct
        // the config via the explicit ring provider because
        // multiple crypto features may be enabled and rustls
        // refuses to auto-pick.
        use rustls::ServerConfig;
        #[derive(Debug)]
        struct NoCertResolver;
        impl rustls::server::ResolvesServerCert for NoCertResolver {
            fn resolve(
                &self,
                _: rustls::server::ClientHello<'_>,
            ) -> Option<std::sync::Arc<rustls::sign::CertifiedKey>> {
                None
            }
        }
        // aws-lc-rs is always pulled by the workspace's rustls
        // configuration; ring is only present under
        // `--features http3`. Use the always-available one
        // so the test works in both feature combos.
        let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let builder = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("safe defaults compile");
        let mut cfg = builder
            .with_no_client_auth()
            .with_cert_resolver(std::sync::Arc::new(NoCertResolver));
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let cfg = with_h3_alpn(cfg);
        assert_eq!(cfg.alpn_protocols, vec![b"h3".to_vec()]);
    }

    // ---- parse_http3_bind ----

    #[test]
    fn parse_http3_bind_accepts_ipv4() {
        let a = parse_http3_bind("0.0.0.0:443").unwrap();
        assert_eq!(a.port(), 443);
        assert!(a.is_ipv4());
    }

    #[test]
    fn parse_http3_bind_accepts_ipv6() {
        let a = parse_http3_bind("[::]:443").unwrap();
        assert_eq!(a.port(), 443);
        assert!(a.is_ipv6());
    }

    #[test]
    fn parse_http3_bind_rejects_garbage() {
        let err = parse_http3_bind("not-an-addr").err().unwrap();
        assert!(matches!(err, Http3ConfigError::BadBind(_)));
    }

    #[test]
    fn parse_http3_bind_rejects_missing_port() {
        let err = parse_http3_bind("0.0.0.0").err().unwrap();
        assert!(matches!(err, Http3ConfigError::BadBind(_)));
    }

    // ---- Http3Config defaults ----

    #[test]
    fn http3_config_default_idle_timeout_30s() {
        let c = Http3Config::default();
        assert_eq!(c.idle_timeout, Duration::from_secs(30));
    }

    #[test]
    fn http3_config_default_max_streams_256() {
        let c = Http3Config::default();
        assert_eq!(c.max_concurrent_streams, 256);
    }

    #[test]
    fn http3_config_default_binds_to_quad_zero_443() {
        let c = Http3Config::default();
        assert_eq!(c.bind.port(), 443);
    }

    // ---- error display ----

    #[test]
    fn config_error_display_messages() {
        assert!(
            Http3ConfigError::BadBind("x".into())
                .to_string()
                .contains("bad bind")
        );
        assert!(
            Http3ConfigError::Tls("x".into())
                .to_string()
                .contains("tls")
        );
        assert!(
            Http3ConfigError::Bind("x".into())
                .to_string()
                .contains("bind failed")
        );
        assert!(
            Http3ConfigError::Internal("x".into())
                .to_string()
                .contains("internal")
        );
    }
}
