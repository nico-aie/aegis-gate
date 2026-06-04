//! One-shot upstream connectivity probe (routing-upstream #2, 2026-06-04).
//!
//! Operator-triggered from the Routing & Upstreams pool editor to validate
//! a member **before** traffic depends on it: DNS → TCP → TLS → optional
//! HTTP health-path GET, each timed and reported separately. Read-only —
//! no audit entry, no config change. Backs `GET /api/upstreams/probe`.
//!
//! TLS uses the Mozilla webpki roots so standard public certs validate; a
//! private-CA backend shows "reachable, cert not trusted" — still useful
//! (connectivity OK, trust mismatch), which is the point of a probe.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Per-stage + overall timeout. A probe should fail fast, not hang the
/// admin request.
const STAGE_TIMEOUT: Duration = Duration::from_secs(3);

/// One probe stage result.
#[derive(Serialize, Default)]
pub struct Stage {
    pub ok: bool,
    /// True when the stage didn't apply (e.g. TLS for a plaintext scheme).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub skipped: bool,
    pub ms: u64,
    pub detail: String,
}

impl Stage {
    fn ok(ms: u64, detail: impl Into<String>) -> Self {
        Self { ok: true, skipped: false, ms, detail: detail.into() }
    }
    fn fail(ms: u64, detail: impl Into<String>) -> Self {
        Self { ok: false, skipped: false, ms, detail: detail.into() }
    }
    fn skip(detail: impl Into<String>) -> Self {
        Self { ok: false, skipped: true, ms: 0, detail: detail.into() }
    }
}

/// Result of probing one member.
#[derive(Serialize)]
pub struct ProbeResult {
    pub addr: String,
    /// Overall: true when every non-skipped stage passed.
    pub ok: bool,
    pub dns: Stage,
    pub tcp: Stage,
    pub tls: Stage,
    pub http: Stage,
}

fn elapsed_ms(start: Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

/// Host (for SNI / Host header) — the explicit override, else the host
/// portion of `addr` (everything before the last `:`).
fn sni_host<'a>(addr: &'a str, host_header: Option<&'a str>) -> &'a str {
    if let Some(h) = host_header {
        if !h.trim().is_empty() {
            return h.trim();
        }
    }
    addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr)
}

/// Probe a single upstream member. `scheme` selects whether TLS runs
/// (`https` → yes); `health_path` (when set, for http/https) adds a final
/// HTTP GET reporting the status line.
pub async fn probe_member(
    addr: &str,
    scheme: &str,
    host_header: Option<&str>,
    health_path: Option<&str>,
) -> ProbeResult {
    let tls_wanted = scheme.eq_ignore_ascii_case("https");
    let http_wanted = health_path
        .map(|p| !p.trim().is_empty())
        .unwrap_or(false)
        && matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https" | "auto");
    let host = sni_host(addr, host_header).to_string();

    // ---- DNS ----
    let t = Instant::now();
    let resolved = match tokio::time::timeout(STAGE_TIMEOUT, tokio::net::lookup_host(addr)).await {
        Ok(Ok(mut it)) => it.next(),
        Ok(Err(e)) => {
            return ProbeResult {
                addr: addr.into(),
                ok: false,
                dns: Stage::fail(elapsed_ms(t), format!("resolve failed: {e}")),
                tcp: Stage::skip("dns failed"),
                tls: Stage::skip("dns failed"),
                http: Stage::skip("dns failed"),
            };
        }
        Err(_) => {
            return ProbeResult {
                addr: addr.into(),
                ok: false,
                dns: Stage::fail(elapsed_ms(t), "resolve timed out"),
                tcp: Stage::skip("dns failed"),
                tls: Stage::skip("dns failed"),
                http: Stage::skip("dns failed"),
            };
        }
    };
    let Some(sockaddr) = resolved else {
        return ProbeResult {
            addr: addr.into(),
            ok: false,
            dns: Stage::fail(elapsed_ms(t), "no addresses resolved"),
            tcp: Stage::skip("dns failed"),
            tls: Stage::skip("dns failed"),
            http: Stage::skip("dns failed"),
        };
    };
    let dns = Stage::ok(elapsed_ms(t), format!("resolved → {sockaddr}"));

    // ---- TCP ----
    let t = Instant::now();
    let tcp_stream = match tokio::time::timeout(STAGE_TIMEOUT, TcpStream::connect(sockaddr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return ProbeResult {
                addr: addr.into(),
                ok: false,
                dns,
                tcp: Stage::fail(elapsed_ms(t), format!("connect refused: {e}")),
                tls: Stage::skip("tcp failed"),
                http: Stage::skip("tcp failed"),
            };
        }
        Err(_) => {
            return ProbeResult {
                addr: addr.into(),
                ok: false,
                dns,
                tcp: Stage::fail(elapsed_ms(t), "connect timed out"),
                tls: Stage::skip("tcp failed"),
                http: Stage::skip("tcp failed"),
            };
        }
    };
    let tcp = Stage::ok(elapsed_ms(t), format!("connected to {sockaddr}"));

    // ---- TLS (https only) ----
    if !tls_wanted {
        let http = if http_wanted {
            http_get(tcp_stream, &host, health_path.unwrap_or("/")).await
        } else {
            Stage::skip("no health_path or non-http scheme")
        };
        let ok = dns.ok && tcp.ok && (http.skipped || http.ok);
        return ProbeResult { addr: addr.into(), ok, dns, tcp, tls: Stage::skip("plaintext scheme"), http };
    }

    let t = Instant::now();
    let server_name = match rustls_pki_types::ServerName::try_from(host.clone()) {
        Ok(n) => n,
        Err(e) => {
            return ProbeResult {
                addr: addr.into(),
                ok: false,
                dns,
                tcp,
                tls: Stage::fail(elapsed_ms(t), format!("invalid server name '{host}': {e}")),
                http: Stage::skip("tls failed"),
            };
        }
    };
    let connector = tokio_rustls::TlsConnector::from(Arc::new(probe_client_config()));
    match tokio::time::timeout(STAGE_TIMEOUT, connector.connect(server_name, tcp_stream)).await {
        Ok(Ok(tls_stream)) => {
            let tls = Stage::ok(elapsed_ms(t), format!("handshake ok (SNI {host})"));
            let http = if http_wanted {
                http_get(tls_stream, &host, health_path.unwrap_or("/")).await
            } else {
                Stage::skip("no health_path")
            };
            let ok = dns.ok && tcp.ok && tls.ok && (http.skipped || http.ok);
            ProbeResult { addr: addr.into(), ok, dns, tcp, tls, http }
        }
        Ok(Err(e)) => ProbeResult {
            addr: addr.into(),
            ok: false,
            dns,
            tcp,
            tls: Stage::fail(elapsed_ms(t), format!("handshake failed: {e}")),
            http: Stage::skip("tls failed"),
        },
        Err(_) => ProbeResult {
            addr: addr.into(),
            ok: false,
            dns,
            tcp,
            tls: Stage::fail(elapsed_ms(t), "handshake timed out"),
            http: Stage::skip("tls failed"),
        },
    }
}

/// rustls client config trusting the Mozilla webpki roots (public CAs).
fn probe_client_config() -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// Minimal HTTP/1.1 GET — write the request, read the status line.
async fn http_get<S>(mut stream: S, host: &str, path: &str) -> Stage
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let t = Instant::now();
    let path = if path.starts_with('/') { path.to_string() } else { format!("/{path}") };
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: aegis-probe\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    if let Err(e) = tokio::time::timeout(STAGE_TIMEOUT, stream.write_all(req.as_bytes())).await {
        return Stage::fail(elapsed_ms(t), format!("write timed out: {e}"));
    }
    let mut buf = vec![0u8; 1024];
    let n = match tokio::time::timeout(STAGE_TIMEOUT, stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Stage::fail(elapsed_ms(t), format!("read failed: {e}")),
        Err(_) => return Stage::fail(elapsed_ms(t), "read timed out"),
    };
    let head = String::from_utf8_lossy(&buf[..n]);
    let status_line = head.lines().next().unwrap_or("").trim().to_string();
    // Parse "HTTP/1.1 <code> <reason>".
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok());
    match code {
        Some(c) if (200..400).contains(&c) => Stage::ok(elapsed_ms(t), status_line),
        Some(_) => Stage::fail(elapsed_ms(t), status_line),
        None => Stage::fail(elapsed_ms(t), format!("no status line (got {n} bytes)")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sni_host_prefers_override_then_addr_host() {
        assert_eq!(sni_host("10.0.0.1:80", Some("api.example.com")), "api.example.com");
        assert_eq!(sni_host("10.0.0.1:80", Some("  ")), "10.0.0.1");
        assert_eq!(sni_host("10.0.0.1:80", None), "10.0.0.1");
        assert_eq!(sni_host("backend.local:8443", None), "backend.local");
    }

    #[tokio::test]
    async fn dns_failure_short_circuits_remaining_stages() {
        let r = probe_member("no-such-host.invalid:80", "http", None, None).await;
        assert!(!r.ok);
        assert!(!r.dns.ok);
        assert!(r.tcp.skipped && r.tls.skipped && r.http.skipped);
    }

    #[tokio::test]
    async fn tcp_failure_on_closed_port() {
        // 127.0.0.1:1 — reserved, nothing listens. DNS (literal) ok, TCP fails.
        let r = probe_member("127.0.0.1:1", "http", None, None).await;
        assert!(r.dns.ok, "literal IP resolves");
        assert!(!r.tcp.ok, "nothing listens on :1");
        assert!(r.tls.skipped);
        assert!(!r.ok);
    }
}
