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

                // 2026-06-18 (upstream "up" badge report): mirror the verified
                // result into the display-only `observed` state on every probe
                // so the dashboard badge matches the LB's view for
                // health-checked pools.
                member.set_observed(now_healthy);

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
                        method: None,
                        path: None,
                        mode: None,
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

/// 2026-06-18 (upstream "up" badge report) — display-only TCP liveness
/// observer for pools that have **no** `health:` block configured.
///
/// Without this, such pools never get a probe, so every member kept its
/// optimistic boot-time `healthy = true` and the dashboard reported a
/// permanent `n/n up` for backends nothing ever checked. This loop opens a
/// plain TCP connection to each member and records the result in the
/// member's `observed` state (`Up`/`Down`).
///
/// Crucially it does **not** touch `Member::healthy`, so it can never change
/// load-balancer selection. (And since PREREQ-B, `LbStrategy::pick` fails open
/// anyway — an all-unhealthy pool still routes rather than returning `None`.)
/// It is purely an observability signal for the badge.
pub fn spawn_tcp_observer(
    pool_name: String,
    members: Vec<Arc<Member>>,
    interval: Duration,
    timeout: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            for member in &members {
                let up = tcp_reachable(member.addr, timeout).await;
                member.set_observed(up);
                tracing::trace!(pool = %pool_name, member = %member.addr, up, "tcp liveness observed");
            }
            tokio::time::sleep(interval).await;
        }
    })
}

/// P3 of `plans/future/passive-upstream-health.md` — half-open recovery probe
/// for members that passive accounting marked **down**.
///
/// A passively-downed member receives no real traffic (the LB skips it), so it
/// can never recover on its own. This loop periodically TCP-probes **only the
/// downed members** of a pool and feeds the outcome back through the same
/// hysteretic accounting as the request path: a reachable probe is a
/// [`Member::record_passive_success`] (so `rise_threshold` consecutive probe
/// successes restore it), an unreachable one is a
/// [`Member::record_passive_failure`] (which resets the success streak, so
/// recovery requires *consecutive* successes). Healthy members are skipped
/// entirely — this loop only rotates downed members back in, mirroring the
/// circuit breaker's half-open state.
///
/// A TCP connect is the right trial: passive health counts connection-level
/// failures (connect refused / handshake / timeout), so reachability is the
/// matching recovery signal — no HTTP `health:` path is required (these are
/// exactly the pools without one). Emits `member_recovered`
/// ([`AuditClass::System`]) on the restore transition.
pub fn spawn_passive_recovery_probe(
    pool_name: String,
    members: Vec<Arc<Member>>,
    rise_threshold: u32,
    fail_threshold: u32,
    interval: Duration,
    timeout: Duration,
    bus: AuditBus,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            for member in &members {
                // Only downed members are probed — this loop never touches a
                // healthy member's routing flag or badge.
                if member.is_healthy() {
                    continue;
                }
                let restored = if tcp_reachable(member.addr, timeout).await {
                    member.record_passive_success(rise_threshold)
                } else {
                    // Reset the success streak so recovery needs consecutive
                    // reachable probes; stays down (no-op on routing).
                    member.record_passive_failure(fail_threshold);
                    false
                };
                if restored {
                    tracing::info!(
                        pool = %pool_name,
                        member = %member.addr,
                        "member_recovered",
                    );
                    bus.emit(AuditEvent {
                        schema_version: 1,
                        ts: chrono::Utc::now(),
                        request_id: String::new(),
                        class: AuditClass::System,
                        tenant_id: None,
                        tier: None,
                        action: "member_recovered".into(),
                        reason: format!("pool={pool_name} member={}", member.addr),
                        client_ip: String::new(),
                        route_id: None,
                        rule_id: None,
                        risk_score: None,
                        method: None,
                        path: None,
                        mode: None,
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

/// Open a TCP connection to `addr`, returning `true` if it connects within
/// `timeout`. The handshake alone is the liveness signal — no bytes sent.
async fn tcp_reachable(addr: std::net::SocketAddr, timeout: Duration) -> bool {
    matches!(
        tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await,
        Ok(Ok(_))
    )
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

    // 2026-06-18 (upstream "up" badge report) — observed state.

    #[tokio::test]
    async fn http_checker_sets_observed_status() {
        use aegis_control::api::upstreams::MemberStatus;
        let (addr, srv) = mock_upstream(200).await;
        let member = Arc::new(Member::new(addr, 1, None));
        // Born Unknown — nothing has probed it yet.
        assert_eq!(member.observed_status(), MemberStatus::Unknown);
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
        assert_eq!(member.observed_status(), MemberStatus::Up);
        handle.abort();
        srv.abort();
    }

    #[tokio::test]
    async fn tcp_observer_marks_live_member_up() {
        use aegis_control::api::upstreams::MemberStatus;
        // A bound listener that accepts connections = reachable.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });
        let member = Arc::new(Member::new(addr, 1, None));
        let handle = spawn_tcp_observer(
            "no-health-pool".into(),
            vec![member.clone()],
            Duration::from_millis(50),
            Duration::from_millis(200),
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(member.observed_status(), MemberStatus::Up);
        // Display-only: it must NOT touch the LB routing flag.
        assert!(member.is_healthy());
        handle.abort();
        srv.abort();
    }

    // -----------------------------------------------------------------------
    // P3 — passive-health half-open recovery probe. A member downed by
    // passive accounting gets no real traffic, so it can't recover passively.
    // The recovery probe TCP-probes only downed members and feeds the result
    // back through the same hysteretic accounting (rise_threshold consecutive
    // probe successes → restored).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn passive_recovery_probe_restores_a_reachable_downed_member() {
        // A reachable backend (accepts TCP).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });

        let member = Arc::new(Member::new(addr, 1, None));
        // Drive it down via passive accounting (fail_threshold = 2).
        member.record_passive_failure(2);
        member.record_passive_failure(2);
        assert!(!member.is_healthy());

        let bus = AuditBus::new(16);
        let mut rx = bus.subscribe();
        let handle = spawn_passive_recovery_probe(
            "passive-pool".into(),
            vec![member.clone()],
            1, // rise_threshold — one successful probe restores
            3, // fail_threshold
            Duration::from_millis(50),
            Duration::from_millis(200),
            bus,
        );

        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(member.is_healthy(), "reachable downed member must recover");
        // Routing and badge agree after recovery.
        assert_eq!(
            member.observed_status(),
            aegis_control::api::upstreams::MemberStatus::Up
        );

        // A `member_recovered` audit event fired on the transition.
        let ev = rx.try_recv().unwrap();
        assert!(matches!(ev.class, AuditClass::System));
        assert_eq!(ev.action, "member_recovered");

        handle.abort();
        srv.abort();
    }

    #[tokio::test]
    async fn passive_recovery_probe_leaves_an_unreachable_member_down() {
        // Bind then drop → nothing listening on the port.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let member = Arc::new(Member::new(addr, 1, None));
        member.record_passive_failure(1); // down
        assert!(!member.is_healthy());

        let bus = AuditBus::new(16);
        let handle = spawn_passive_recovery_probe(
            "passive-pool".into(),
            vec![member.clone()],
            1,
            3,
            Duration::from_millis(50),
            Duration::from_millis(150),
            bus,
        );

        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(
            !member.is_healthy(),
            "an unreachable member must stay down — no spurious recovery"
        );

        handle.abort();
    }

    #[tokio::test]
    async fn passive_recovery_probe_never_touches_a_healthy_member() {
        // A reachable backend, but the member starts healthy: the probe must
        // skip it entirely (it only rotates DOWN members back in), so its
        // display badge is never written by this loop and stays Unknown.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });

        let member = Arc::new(Member::new(addr, 1, None));
        assert!(member.is_healthy());

        let bus = AuditBus::new(16);
        let handle = spawn_passive_recovery_probe(
            "passive-pool".into(),
            vec![member.clone()],
            1,
            3,
            Duration::from_millis(50),
            Duration::from_millis(200),
            bus,
        );

        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(member.is_healthy());
        assert_eq!(
            member.observed_status(),
            aegis_control::api::upstreams::MemberStatus::Unknown,
            "healthy members are not probed by the recovery loop"
        );

        handle.abort();
        srv.abort();
    }

    #[tokio::test]
    async fn tcp_observer_marks_dead_member_down() {
        use aegis_control::api::upstreams::MemberStatus;
        // Bind then immediately drop the listener so the port is closed —
        // mirrors the dev `stub-pool -> 127.0.0.1:9999` (nothing listening).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let member = Arc::new(Member::new(addr, 1, None));
        let handle = spawn_tcp_observer(
            "no-health-pool".into(),
            vec![member.clone()],
            Duration::from_millis(50),
            Duration::from_millis(200),
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(member.observed_status(), MemberStatus::Down);
        // LB routing flag stays optimistic (we never fail-close the pool).
        assert!(member.is_healthy());
        handle.abort();
    }
}
