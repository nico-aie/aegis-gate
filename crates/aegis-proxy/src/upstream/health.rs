use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use aegis_core::audit::{AuditBus, AuditClass, AuditEvent};

use super::Member;

/// Spawn one health-check task per pool.  Each task probes every member's
/// `health_path` at `interval`, flipping `Member::healthy` and emitting
/// `AuditClass::System` on state transitions.
pub fn spawn_health_checker(
    pool_name: String,
    members: Vec<Arc<Member>>,
    health_path: String,
    interval: Duration,
    timeout: Duration,
    bus: AuditBus,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            for member in &members {
                let was_healthy = member.is_healthy();
                let now_healthy = probe(member.addr, &health_path, timeout).await;

                if was_healthy != now_healthy {
                    member.healthy.store(now_healthy, Ordering::Relaxed);
                    let action = if now_healthy {
                        "member_healthy"
                    } else {
                        "member_unhealthy"
                    };
                    tracing::info!(
                        pool = %pool_name,
                        member = %member.addr,
                        "{action}",
                    );
                    bus.emit(AuditEvent {
                        schema_version: 1,
                        ts: chrono::Utc::now(),
                        request_id: String::new(),
                        class: AuditClass::System,
                        tenant_id: None,
                        tier: None,
                        action: action.into(),
                        reason: format!("pool={pool_name} member={}", member.addr),
                        client_ip: String::new(),
                        route_id: None,
                        rule_id: None,
                        risk_score: None,
                        fields: serde_json::json!({
                            "pool": pool_name,
                            "member": member.addr.to_string(),
                        }),
                    });
                }
            }
            tokio::time::sleep(interval).await;
        }
    })
}

/// Probe a member by opening a TCP connection and sending a minimal HTTP/1.1
/// GET.  Returns `true` if a 2xx response is received within `timeout`.
async fn probe(addr: std::net::SocketAddr, path: &str, timeout: Duration) -> bool {
    let result = tokio::time::timeout(timeout, async {
        let stream = tokio::net::TcpStream::connect(addr).await?;
        let io = hyper_util::rt::TokioIo::new(stream);
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(io).await?;
        tokio::spawn(conn);

        let req = hyper::Request::builder()
            .uri(path)
            .header("host", addr.to_string())
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(resp.status())
    })
    .await;

    matches!(result, Ok(Ok(status)) if status.is_success())
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

    /// Start a tiny HTTP server that returns the given status code.
    async fn mock_upstream(status: u16) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            loop {
                let (stream, _) = match tcp.accept().await {
                    Ok(c) => c,
                    Err(_) => break,
                };
                let status = hyper::StatusCode::from_u16(status).unwrap();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |_req: hyper::Request<hyper::body::Incoming>| {
                        let status = status;
                        async move {
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(status)
                                    .body(Full::new(Bytes::from("ok")))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, svc)
                        .await;
                });
            }
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn healthy_member_stays_healthy() {
        let (addr, srv) = mock_upstream(200).await;
        let member = Arc::new(Member::new(addr, 1, None));
        let bus = AuditBus::new(16);

        let handle = spawn_health_checker(
            "test-pool".into(),
            vec![member.clone()],
            "/health".into(),
            Duration::from_millis(100),
            Duration::from_secs(1),
            bus,
        );

        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(member.is_healthy());

        handle.abort();
        srv.abort();
    }

    #[tokio::test]
    async fn unhealthy_member_detected() {
        let (addr, srv) = mock_upstream(503).await;
        let member = Arc::new(Member::new(addr, 1, None));
        let bus = AuditBus::new(16);
        let mut rx = bus.subscribe();

        let handle = spawn_health_checker(
            "test-pool".into(),
            vec![member.clone()],
            "/health".into(),
            Duration::from_millis(100),
            Duration::from_secs(1),
            bus,
        );

        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!member.is_healthy());

        // Should have received an audit event for the transition.
        let ev = rx.try_recv().unwrap();
        assert!(matches!(ev.class, AuditClass::System));
        assert_eq!(ev.action, "member_unhealthy");

        handle.abort();
        srv.abort();
    }

    #[tokio::test]
    async fn member_recovers_after_flap() {
        // Start as 503, then switch to 200.
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let should_be_healthy = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = should_be_healthy.clone();

        let srv = tokio::spawn(async move {
            loop {
                let (stream, _) = match tcp.accept().await {
                    Ok(c) => c,
                    Err(_) => break,
                };
                let flag = flag.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |_req: hyper::Request<hyper::body::Incoming>| {
                        let healthy = flag.load(Ordering::Relaxed);
                        async move {
                            let status = if healthy { 200u16 } else { 503u16 };
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(status)
                                    .body(Full::new(Bytes::from("ok")))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, svc)
                        .await;
                });
            }
        });

        let member = Arc::new(Member::new(addr, 1, None));
        let bus = AuditBus::new(16);

        let handle = spawn_health_checker(
            "test-pool".into(),
            vec![member.clone()],
            "/health".into(),
            Duration::from_millis(100),
            Duration::from_secs(1),
            bus,
        );

        // Wait for unhealthy detection.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!member.is_healthy());

        // Now make it healthy.
        should_be_healthy.store(true, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(member.is_healthy());

        handle.abort();
        srv.abort();
    }
}
