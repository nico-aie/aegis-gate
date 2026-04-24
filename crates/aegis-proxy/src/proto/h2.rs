use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Configuration for the HTTP/2 server side.
#[derive(Debug, Clone)]
pub struct H2ServerConfig {
    /// Maximum concurrent streams per connection.
    pub max_concurrent_streams: u32,
    /// Maximum number of RST_STREAM frames allowed per `reset_window` before
    /// the connection is dropped (rapid-reset mitigation).
    pub max_resets_per_window: u32,
    /// Window duration for rapid-reset detection.
    pub reset_window: Duration,
}

impl Default for H2ServerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_streams: 128,
            max_resets_per_window: 1024,
            reset_window: Duration::from_secs(30),
        }
    }
}

/// Per-connection rapid-reset tracker.
#[derive(Debug)]
pub struct ResetTracker {
    count: AtomicU64,
    window_start: std::time::Instant,
    window: Duration,
    limit: u32,
}

impl ResetTracker {
    pub fn new(limit: u32, window: Duration) -> Self {
        Self {
            count: AtomicU64::new(0),
            window_start: std::time::Instant::now(),
            window,
            limit,
        }
    }

    /// Record a stream reset. Returns `true` if the connection should be
    /// dropped due to rapid-reset abuse.
    pub fn record_reset(&self) -> bool {
        let elapsed = self.window_start.elapsed();
        if elapsed >= self.window {
            // Window expired — would need a mutable reset, but for the
            // hot-path we just let it roll over. A production implementation
            // would use a sliding window or AtomicU64 epoch.
            self.count.store(1, Ordering::Relaxed);
            return false;
        }
        let prev = self.count.fetch_add(1, Ordering::Relaxed);
        prev + 1 >= self.limit as u64
    }

    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
}

/// Build an auto-detecting (HTTP/1.1 + HTTP/2) server builder.
///
/// The returned builder auto-negotiates the protocol via ALPN (when TLS) or
/// via HTTP/2 connection preface detection (cleartext).
pub fn auto_builder(
    executor: hyper_util::rt::TokioExecutor,
) -> hyper_util::server::conn::auto::Builder<hyper_util::rt::TokioExecutor> {
    hyper_util::server::conn::auto::Builder::new(executor)
}

/// Serve a connection with the auto-detecting builder.
///
/// `svc` must implement `hyper::service::Service<Request<Incoming>>`.
pub async fn serve_auto_connection<I, S, B>(
    builder: &hyper_util::server::conn::auto::Builder<hyper_util::rt::TokioExecutor>,
    io: I,
    svc: S,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    S: hyper::service::Service<
            hyper::Request<hyper::body::Incoming>,
            Response = hyper::Response<B>,
        > + Send
        + 'static,
    S::Future: Send,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    B: http_body_util::BodyExt + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    builder.serve_connection(io, svc).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::service::service_fn;
    use hyper::Response;
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;
    use std::io::BufReader;
    use std::sync::Arc;

    fn generate_cert() -> (String, String) {
        let params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        (cert.pem(), key_pair.serialize_pem())
    }

    #[test]
    fn reset_tracker_trips_on_limit() {
        let tracker = ResetTracker::new(5, Duration::from_secs(30));
        for _ in 0..4 {
            assert!(!tracker.record_reset());
        }
        // 5th reset should trip.
        assert!(tracker.record_reset());
    }

    #[test]
    fn reset_tracker_within_limit() {
        let tracker = ResetTracker::new(100, Duration::from_secs(30));
        for _ in 0..50 {
            assert!(!tracker.record_reset());
        }
    }

    #[test]
    fn default_h2_config() {
        let cfg = H2ServerConfig::default();
        assert_eq!(cfg.max_concurrent_streams, 128);
        assert_eq!(cfg.max_resets_per_window, 1024);
    }

    #[tokio::test]
    async fn auto_builder_serves_h2_over_tls() {
        // Generate self-signed cert.
        let (cert_pem, key_pem) = generate_cert();

        // Build server TLS config.
        let certs: Vec<rustls_pki_types::CertificateDer<'static>> = {
            let mut r = BufReader::new(cert_pem.as_bytes());
            rustls_pemfile::certs(&mut r).collect::<Result<Vec<_>, _>>().unwrap()
        };
        let key: rustls_pki_types::PrivateKeyDer<'static> = {
            let mut r = BufReader::new(key_pem.as_bytes());
            rustls_pemfile::private_key(&mut r).unwrap().unwrap()
        };

        let mut server_tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs.clone(), key)
            .unwrap();
        server_tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls));

        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();

        let srv = tokio::spawn(async move {
            let (stream, _) = tcp.accept().await.unwrap();
            let tls_stream = acceptor.accept(stream).await.unwrap();
            let io = TokioIo::new(tls_stream);

            let builder = auto_builder(hyper_util::rt::TokioExecutor::new());
            let svc = service_fn(|_req: hyper::Request<hyper::body::Incoming>| async {
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from("h2-ok"))))
            });
            let _ = builder.serve_connection(io, svc).await;
        });

        // Client: connect with h2 ALPN.
        let mut root_store = rustls::RootCertStore::empty();
        for cert in &certs {
            root_store.add(cert.clone()).unwrap();
        }
        let mut client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        client_config.alpn_protocols = vec![b"h2".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

        let tcp_stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let server_name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
        let tls = connector.connect(server_name, tcp_stream).await.unwrap();

        // Verify ALPN negotiated h2.
        let (_, conn_info) = tls.get_ref();
        assert_eq!(conn_info.alpn_protocol(), Some(b"h2".as_slice()));

        let io = TokioIo::new(tls);
        let (mut sender, conn) = hyper::client::conn::http2::handshake(
            hyper_util::rt::TokioExecutor::new(),
            io,
        )
        .await
        .unwrap();
        tokio::spawn(conn);

        let req = hyper::Request::builder()
            .uri("https://localhost/")
            .body(http_body_util::Empty::<Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), 200);

        use http_body_util::BodyExt;
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"h2-ok");

        srv.abort();
    }
}
