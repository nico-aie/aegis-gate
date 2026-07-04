//! Concrete RFC 3507 ICAP client over plain TCP.
//!
//! Implements the [`super::IcapClient`] trait. One TCP
//! connection per scan — ICAP has a `Keep-Alive` semantic but
//! pooling is left to a future change since most upstream
//! scanners' connection-limit story is per-vendor.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::codec::{
    self, classify_response, decode_head, DecodeError, Verdict,
};
use super::{IcapClient, IcapMode, ScanResult};

/// Configuration for [`IcapTcpClient`].
#[derive(Clone, Debug)]
pub struct IcapTcpOptions {
    /// Hostname or IP of the ICAP server.
    pub host: String,
    /// TCP port. RFC 3507 default is 1344.
    pub port: u16,
    /// Service path the scanner exposes — e.g. `/avscan` for
    /// c-icap REQMOD, `/respmod` for RESPMOD, vendor-specific
    /// paths for Symantec / McAfee / Sophos.
    pub service_path: String,
    /// Upstream Host header to advertise inside the
    /// encapsulated request (REQMOD only). Not the ICAP
    /// server's host. Typically the operator's own service.
    pub upstream_host: String,
    /// Total timeout per scan (connect + write + read). On
    /// timeout, behaviour is governed by [`fail_open`].
    pub scan_timeout: Duration,
    /// Connect timeout. Falls back to `scan_timeout` if
    /// shorter.
    pub connect_timeout: Duration,
    /// `true` (default) → on timeout / network error return
    /// [`ScanResult::Clean`], so a scanner outage does not
    /// take down request-serving. `false` → return
    /// [`ScanResult::Error`] / [`ScanResult::Timeout`] so
    /// the caller can surface to a fail-closed policy.
    pub fail_open: bool,
}

impl Default for IcapTcpOptions {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 1344,
            service_path: "/avscan".into(),
            upstream_host: "upstream.local".into(),
            scan_timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(5),
            fail_open: true,
        }
    }
}

/// Errors raised by the TCP client. Most flow through the
/// fail-open / fail-closed gate before reaching the caller —
/// these surfaces are mostly for tests.
#[derive(Debug)]
pub enum IcapTcpError {
    /// Connection establishment failed.
    Connect(String),
    /// TCP write failed mid-request.
    Write(String),
    /// TCP read failed mid-response.
    Read(String),
    /// Wire-format decode error.
    Decode(DecodeError),
    /// Total scan exceeded `scan_timeout`.
    Timeout,
}

impl std::fmt::Display for IcapTcpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IcapTcpError::Connect(m) => write!(f, "icap connect failed: {m}"),
            IcapTcpError::Write(m) => write!(f, "icap write failed: {m}"),
            IcapTcpError::Read(m) => write!(f, "icap read failed: {m}"),
            IcapTcpError::Decode(e) => write!(f, "icap decode error: {e}"),
            IcapTcpError::Timeout => write!(f, "icap scan timeout"),
        }
    }
}

impl std::error::Error for IcapTcpError {}

impl From<DecodeError> for IcapTcpError {
    fn from(e: DecodeError) -> Self {
        IcapTcpError::Decode(e)
    }
}

/// Concrete RFC 3507 ICAP TCP client.
pub struct IcapTcpClient {
    opts: IcapTcpOptions,
}

impl IcapTcpClient {
    pub fn new(opts: IcapTcpOptions) -> Self {
        Self { opts }
    }

    /// Run one full scan. Internal — exposes the raw
    /// [`Verdict`] so tests can assert on the wire-level
    /// outcome before fail-open mapping.
    pub async fn scan_raw(
        &self,
        mode: IcapMode,
        body: &[u8],
    ) -> Result<Verdict, IcapTcpError> {
        let fut = async {
            let mut stream = TcpStream::connect((
                self.opts.host.as_str(),
                self.opts.port,
            ))
            .await
            .map_err(|e| IcapTcpError::Connect(e.to_string()))?;
            let req = codec::build_request(
                &mode,
                &self.opts.host,
                self.opts.port,
                &self.opts.service_path,
                &self.opts.upstream_host,
                body,
            );
            stream
                .write_all(&req)
                .await
                .map_err(|e| IcapTcpError::Write(e.to_string()))?;
            stream
                .flush()
                .await
                .map_err(|e| IcapTcpError::Write(e.to_string()))?;
            let head = read_head(&mut stream).await?;
            Ok::<_, IcapTcpError>(classify_response(&head))
        };
        match tokio::time::timeout(self.opts.scan_timeout, fut).await {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(IcapTcpError::Timeout),
        }
    }
}

/// Read the ICAP response head, expanding the buffer as
/// needed until we see `\r\n\r\n`. Caps the head at 16 KiB —
/// anything larger is almost certainly a misbehaving scanner.
async fn read_head(stream: &mut TcpStream) -> Result<codec::IcapResponseHead, IcapTcpError> {
    const MAX_HEAD: usize = 16 * 1024;
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 1024];
    loop {
        if buf.len() >= MAX_HEAD {
            return Err(IcapTcpError::Decode(DecodeError::HeadIncomplete));
        }
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| IcapTcpError::Read(e.to_string()))?;
        if n == 0 {
            // EOF before we saw end-of-headers.
            return Err(IcapTcpError::Decode(DecodeError::HeadIncomplete));
        }
        buf.extend_from_slice(&chunk[..n]);
        match decode_head(&buf) {
            Ok((head, _)) => return Ok(head),
            Err(DecodeError::HeadIncomplete) => continue,
            Err(e) => return Err(IcapTcpError::Decode(e)),
        }
    }
}

#[async_trait::async_trait]
impl IcapClient for IcapTcpClient {
    async fn scan(
        &self,
        mode: IcapMode,
        body: &[u8],
    ) -> aegis_core::Result<ScanResult> {
        match self.scan_raw(mode, body).await {
            Ok(Verdict::Clean) => Ok(ScanResult::Clean),
            Ok(Verdict::Infected { threat_name }) => {
                Ok(ScanResult::Infected { threat_name })
            }
            Ok(Verdict::UnexpectedStatus { status }) => {
                if self.opts.fail_open {
                    tracing::warn!(
                        host = %self.opts.host,
                        status,
                        "icap scanner returned unexpected status; failing open"
                    );
                    Ok(ScanResult::Clean)
                } else {
                    Ok(ScanResult::Error {
                        message: format!("unexpected icap status {status}"),
                    })
                }
            }
            Err(IcapTcpError::Timeout) => {
                if self.opts.fail_open {
                    tracing::warn!(
                        host = %self.opts.host,
                        "icap scan timed out; failing open"
                    );
                    Ok(ScanResult::Clean)
                } else {
                    Ok(ScanResult::Timeout)
                }
            }
            Err(e) => {
                if self.opts.fail_open {
                    tracing::warn!(
                        host = %self.opts.host,
                        error = %e,
                        "icap scan failed; failing open"
                    );
                    Ok(ScanResult::Clean)
                } else {
                    Ok(ScanResult::Error {
                        message: e.to_string(),
                    })
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(deprecated)]  // test scaffolding uses NoopPipeline
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU16, Ordering};
    use tokio::net::TcpListener;

    /// Spin up a one-shot TCP server on `127.0.0.1:0` that
    /// reads the request, then writes `response_bytes`.
    /// Returns the bound port.
    async fn one_shot_server(response_bytes: &'static [u8]) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                // Read until client stops sending (best-effort).
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let _ = sock.write_all(response_bytes).await;
                let _ = sock.shutdown().await;
            }
        });
        port
    }

    /// Spin up a server that just stalls — accepts the
    /// connection but never responds. Used for timeout tests.
    async fn stalling_server() -> (u16, std::sync::Arc<AtomicU16>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let counter = std::sync::Arc::new(AtomicU16::new(0));
        let c = counter.clone();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                c.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                tokio::time::sleep(Duration::from_secs(60)).await;
                let _ = sock.shutdown().await;
            }
        });
        (port, counter)
    }

    fn opts(port: u16) -> IcapTcpOptions {
        IcapTcpOptions {
            host: "127.0.0.1".into(),
            port,
            service_path: "/avscan".into(),
            upstream_host: "test.local".into(),
            scan_timeout: Duration::from_millis(500),
            connect_timeout: Duration::from_millis(200),
            fail_open: true,
        }
    }

    // ---- Verdict decoding via real socket ----

    #[tokio::test]
    async fn scan_204_returns_clean() {
        let port = one_shot_server(
            b"ICAP/1.0 204 No Content\r\nISTag: \"x\"\r\n\r\n",
        )
        .await;
        let client = IcapTcpClient::new(opts(port));
        let r = client.scan_raw(IcapMode::Reqmod, b"hello").await.unwrap();
        assert_eq!(r, Verdict::Clean);
    }

    #[tokio::test]
    async fn scan_200_with_eicar_returns_infected() {
        let port = one_shot_server(
            b"ICAP/1.0 200 OK\r\nX-Infection-Found: Type=0; Resolution=2; Threat=EICAR-Test-File;\r\n\r\n",
        )
        .await;
        let client = IcapTcpClient::new(opts(port));
        let r = client.scan_raw(IcapMode::Respmod, b"infected").await.unwrap();
        assert_eq!(
            r,
            Verdict::Infected {
                threat_name: "EICAR-Test-File".into()
            }
        );
    }

    #[tokio::test]
    async fn scan_500_returns_unexpected_status() {
        let port =
            one_shot_server(b"ICAP/1.0 500 Internal Server Error\r\n\r\n").await;
        let client = IcapTcpClient::new(opts(port));
        let r = client.scan_raw(IcapMode::Reqmod, b"x").await.unwrap();
        assert_eq!(r, Verdict::UnexpectedStatus { status: 500 });
    }

    #[tokio::test]
    async fn scan_403_returns_infected_blocked() {
        let port = one_shot_server(b"ICAP/1.0 403 Forbidden\r\n\r\n").await;
        let client = IcapTcpClient::new(opts(port));
        let r = client.scan_raw(IcapMode::Reqmod, b"x").await.unwrap();
        assert_eq!(
            r,
            Verdict::Infected {
                threat_name: "blocked".into()
            }
        );
    }

    // ---- Trait-level fail-open vs. fail-closed ----

    #[tokio::test]
    async fn fail_open_swallows_timeout_as_clean() {
        let (port, _) = stalling_server().await;
        let mut o = opts(port);
        o.fail_open = true;
        o.scan_timeout = Duration::from_millis(100);
        let client = IcapTcpClient::new(o);
        let r = client.scan(IcapMode::Reqmod, b"x").await.unwrap();
        assert_eq!(r, ScanResult::Clean);
    }

    #[tokio::test]
    async fn fail_closed_surfaces_timeout() {
        let (port, _) = stalling_server().await;
        let mut o = opts(port);
        o.fail_open = false;
        o.scan_timeout = Duration::from_millis(100);
        let client = IcapTcpClient::new(o);
        let r = client.scan(IcapMode::Reqmod, b"x").await.unwrap();
        assert_eq!(r, ScanResult::Timeout);
    }

    #[tokio::test]
    async fn fail_closed_surfaces_unexpected_status_as_error() {
        let port = one_shot_server(b"ICAP/1.0 500 oops\r\n\r\n").await;
        let mut o = opts(port);
        o.fail_open = false;
        let client = IcapTcpClient::new(o);
        let r = client.scan(IcapMode::Reqmod, b"x").await.unwrap();
        match r {
            ScanResult::Error { message } => {
                assert!(message.contains("500"), "got {message}");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fail_open_swallows_unexpected_status_as_clean() {
        let port = one_shot_server(b"ICAP/1.0 500 oops\r\n\r\n").await;
        let mut o = opts(port);
        o.fail_open = true;
        let client = IcapTcpClient::new(o);
        let r = client.scan(IcapMode::Reqmod, b"x").await.unwrap();
        assert_eq!(r, ScanResult::Clean);
    }

    #[tokio::test]
    async fn fail_open_swallows_connect_failure_as_clean() {
        // 127.0.0.1:1 should refuse on every dev machine.
        let mut o = opts(1);
        o.fail_open = true;
        o.connect_timeout = Duration::from_millis(50);
        o.scan_timeout = Duration::from_millis(100);
        let client = IcapTcpClient::new(o);
        let r = client.scan(IcapMode::Reqmod, b"x").await.unwrap();
        assert_eq!(r, ScanResult::Clean);
    }

    #[tokio::test]
    async fn fail_closed_surfaces_connect_failure_as_error() {
        let mut o = opts(1);
        o.fail_open = false;
        o.connect_timeout = Duration::from_millis(50);
        o.scan_timeout = Duration::from_millis(100);
        let client = IcapTcpClient::new(o);
        let r = client.scan(IcapMode::Reqmod, b"x").await.unwrap();
        match r {
            ScanResult::Error { .. } | ScanResult::Timeout => {}
            other => panic!("expected Error or Timeout, got {other:?}"),
        }
    }

    // ---- Live integration ----

    /// Live integration test against a real ICAP server.
    ///
    ///   AEGIS_ICAP_INTEGRATION_TEST=1 \
    ///   AEGIS_ICAP_HOST=127.0.0.1 \
    ///   AEGIS_ICAP_PORT=1344 \
    ///   AEGIS_ICAP_SERVICE=/avscan \
    ///   cargo test -p aegis-security --lib \
    ///       content::icap::tcp::tests::live_scan -- --nocapture
    #[tokio::test]
    async fn live_scan() {
        if std::env::var("AEGIS_ICAP_INTEGRATION_TEST").is_err() {
            eprintln!("skipping live_scan — set AEGIS_ICAP_INTEGRATION_TEST=1");
            return;
        }
        let host = std::env::var("AEGIS_ICAP_HOST").unwrap_or_else(|_| "127.0.0.1".into());
        let port: u16 = std::env::var("AEGIS_ICAP_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1344);
        let service = std::env::var("AEGIS_ICAP_SERVICE").unwrap_or_else(|_| "/avscan".into());
        let o = IcapTcpOptions {
            host,
            port,
            service_path: service,
            upstream_host: "live.test".into(),
            scan_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(5),
            fail_open: false,
        };
        let client = IcapTcpClient::new(o);
        // EICAR test string — every conforming AV should
        // flag this.
        let eicar: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let v = client.scan_raw(IcapMode::Respmod, eicar).await.unwrap();
        eprintln!("live: EICAR verdict = {v:?}");
        match v {
            Verdict::Infected { .. } => {}
            other => panic!("EICAR not flagged: {other:?}"),
        }
    }
}
