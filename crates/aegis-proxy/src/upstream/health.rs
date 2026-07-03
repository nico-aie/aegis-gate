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
    alert_tx: Option<tokio::sync::mpsc::UnboundedSender<aegis_control::slo::AlertEvent>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // SLO-P5 — per-pool degrade/recover transition memory.
        let mut pool_alerts = aegis_control::slo::producers::PoolAlertState::default();
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
            // SLO-P5 — pool-level degrade/recover alerts, once per
            // transition (the per-member audit events above stay).
            if let Some(tx) = alert_tx.as_ref() {
                observe_pool_health_for_alerts(&pool_name, &members, &mut pool_alerts, tx);
            }
            tokio::time::sleep(interval).await;
        }
    })
}

/// SLO-P5 — fold one sweep's member health into the pool alert
/// transition state, forwarding any degrade/recover events into
/// the alert dispatch channel. Shared by the active checker and
/// the passive monitor.
fn observe_pool_health_for_alerts(
    pool_name: &str,
    members: &[Arc<Member>],
    state: &mut aegis_control::slo::producers::PoolAlertState,
    alert_tx: &tokio::sync::mpsc::UnboundedSender<aegis_control::slo::AlertEvent>,
) {
    let healthy = members.iter().filter(|m| m.is_healthy()).count() as u32;
    let first_down = members
        .iter()
        .find(|m| !m.is_healthy())
        .map(|m| m.addr.to_string());
    let events = state.observe(
        &[aegis_control::slo::producers::PoolHealthObservation {
            pool: pool_name.to_string(),
            healthy,
            total: members.len() as u32,
            first_down,
        }],
        chrono::Utc::now(),
    );
    for event in events {
        // A closed receiver means shutdown — nothing to do.
        let _ = alert_tx.send(event);
    }
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

/// P3+P4 of `plans/future/passive-upstream-health.md` — the passive-health
/// monitor for a pool **without** an active `health:` block. One loop that
/// folds the standalone display-only TCP observer ([`spawn_tcp_observer`]) and
/// the half-open recovery probe into a single per-member pass:
///
/// - **Healthy member** → refresh the display badge ([`Member::set_observed`])
///   from TCP reachability, **without** touching the LB `healthy` flag. Passive
///   down-marking is owned by *real traffic* (the forward-result call sites),
///   not this synthetic probe — a transient probe blip must not evict a member
///   that real requests are still succeeding against.
/// - **Downed member** → half-open recovery: a reachable probe is a
///   [`Member::record_passive_success`] (so `rise_threshold` consecutive probe
///   successes restore it), an unreachable one a
///   [`Member::record_passive_failure`] (resetting the success streak, so
///   recovery requires *consecutive* successes). Mirrors the circuit breaker's
///   half-open state. Emits `member_recovered` ([`AuditClass::System`]) on the
///   restore transition.
///
/// A TCP connect is the right trial: passive health counts connection-level
/// failures (connect refused / handshake / timeout), so reachability is the
/// matching signal — no HTTP `health:` path is required (these are exactly the
/// pools without one).
pub fn spawn_passive_health_monitor(
    pool_name: String,
    members: Vec<Arc<Member>>,
    rise_threshold: u32,
    fail_threshold: u32,
    interval: Duration,
    timeout: Duration,
    bus: AuditBus,
    alert_tx: Option<tokio::sync::mpsc::UnboundedSender<aegis_control::slo::AlertEvent>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // SLO-P5 — per-pool degrade/recover transition memory.
        let mut pool_alerts = aegis_control::slo::producers::PoolAlertState::default();
        loop {
            for member in &members {
                let reachable = tcp_reachable(member.addr, timeout).await;

                // Healthy member: badge-only refresh (folds the TCP observer).
                // Never touch the routing flag — real traffic owns eviction.
                if member.is_healthy() {
                    member.set_observed(reachable);
                    tracing::trace!(
                        pool = %pool_name,
                        member = %member.addr,
                        reachable,
                        "passive monitor: badge refreshed"
                    );
                    continue;
                }

                // Downed member: half-open recovery accounting.
                let restored = if reachable {
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
            // SLO-P5 — pool-level degrade/recover alerts, once per
            // transition.
            if let Some(tx) = alert_tx.as_ref() {
                observe_pool_health_for_alerts(&pool_name, &members, &mut pool_alerts, tx);
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
        None,
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
        None,
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
        None,
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
        None,
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
    // P3+P4 — passive-health monitor. One per-pool loop that (P4) folds the
    // standalone TCP observer: for a HEALTHY member it refreshes the display
    // badge (`observed`) from TCP reachability without ever touching the LB
    // `healthy` flag (real traffic owns down-marking), and for a DOWNED member
    // it runs the (P3) half-open recovery accounting — `rise_threshold`
    // consecutive reachable probes restore it.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn passive_monitor_restores_a_reachable_downed_member() {
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
        let handle = spawn_passive_health_monitor(
            "passive-pool".into(),
            vec![member.clone()],
            1, // rise_threshold — one successful probe restores
            3, // fail_threshold
            Duration::from_millis(50),
            Duration::from_millis(200),
            bus,
            None,
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
    async fn passive_monitor_leaves_an_unreachable_member_down() {
        // Bind then drop → nothing listening on the port.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let member = Arc::new(Member::new(addr, 1, None));
        member.record_passive_failure(1); // down
        assert!(!member.is_healthy());

        let bus = AuditBus::new(16);
        let handle = spawn_passive_health_monitor(
            "passive-pool".into(),
            vec![member.clone()],
            1,
            3,
            Duration::from_millis(50),
            Duration::from_millis(150),
            bus,
            None,
        );

        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(
            !member.is_healthy(),
            "an unreachable member must stay down — no spurious recovery"
        );

        handle.abort();
    }

    #[tokio::test]
    async fn passive_monitor_badges_a_reachable_healthy_member_up() {
        // P4: the monitor folds the TCP observer — it refreshes the display
        // badge for a HEALTHY member from reachability, without touching the
        // routing flag.
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
        // Born Unknown until the monitor verifies it.
        assert_eq!(
            member.observed_status(),
            aegis_control::api::upstreams::MemberStatus::Unknown
        );

        let bus = AuditBus::new(16);
        let handle = spawn_passive_health_monitor(
            "passive-pool".into(),
            vec![member.clone()],
            1,
            3,
            Duration::from_millis(50),
            Duration::from_millis(200),
            bus,
            None,
        );

        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            member.observed_status(),
            aegis_control::api::upstreams::MemberStatus::Up,
            "monitor must refresh a healthy member's badge from reachability"
        );
        assert!(member.is_healthy(), "badge refresh must not touch routing");

        handle.abort();
        srv.abort();
    }

    #[tokio::test]
    async fn passive_monitor_badges_an_unreachable_healthy_member_down_without_evicting() {
        // An unreachable but still-healthy member: the monitor reports Down on
        // the badge (honest) but must NOT flip the LB `healthy` flag — passive
        // down-marking is owned by REAL traffic, not this synthetic probe.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let member = Arc::new(Member::new(addr, 1, None));
        assert!(member.is_healthy());

        let bus = AuditBus::new(16);
        let handle = spawn_passive_health_monitor(
            "passive-pool".into(),
            vec![member.clone()],
            1,
            3,
            Duration::from_millis(50),
            Duration::from_millis(150),
            bus,
            None,
        );

        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            member.observed_status(),
            aegis_control::api::upstreams::MemberStatus::Down,
            "badge must reflect the failed probe"
        );
        assert!(
            member.is_healthy(),
            "the monitor must never evict a healthy member — real traffic does that"
        );

        handle.abort();
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
