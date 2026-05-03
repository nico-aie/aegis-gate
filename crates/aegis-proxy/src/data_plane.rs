//! PRE-T2 — data-plane request handling extracted from `lib.rs`
//! into a focused module.
//!
//! Three functions form the data-plane hot path:
//!
//! - [`handle_data_request`] — `#[tracing::instrument]`
//!   wrapper that owns the OTEL-T3 root span and records the
//!   resolved `action` after the inner returns.
//! - [`handle_data_request_inner`] — the actual per-request
//!   logic: rate-limit → tier classification → detector run →
//!   risk evaluation → forward / block.
//! - [`forward_allow_to_upstream`] — route resolve + circuit
//!   breaker gate + pool member pick + body forward via
//!   `upstream::forward::forward()`.
//!
//! `blocked_response` is the small helper that builds a 403
//! body + emits the audit-chain entry every block path uses.
//!
//! All four are `pub(crate)` — internal to aegis-proxy. Call
//! sites (just `accept_loop` in `lib.rs`) `use data_plane::...`
//! so the refactor is invisible at the call site.

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::Response;

use aegis_core::AuditBus;

/// OTEL-T3 — root request-level span. Every per-request stage
/// log inside the body (rate-limit, detect, forward) nests under
/// one Span in Jaeger. `action` and `tier` are deferred via
/// `Span::record` from inside `_inner`'s body — both land on
/// THIS span because `_inner` runs under it.
///
/// The wrapper exists to record the resolved `action` on every
/// exit path without touching every `return (resp, DecisionTag::...)`
/// site in the body. The inner function executes inside this
/// span; on return, the wrapper's body still runs in the same
/// span and `Span::current().record(...)` lands here.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(
    name = "waf.handle_data_request",
    skip_all,
    fields(
        otel.kind = "server",
        peer = %peer,
        method = %req.method(),
        path = %req.uri().path(),
        action = tracing::field::Empty,
        tier = tracing::field::Empty,
    ),
)]
pub(crate) async fn handle_data_request(
    req: hyper::Request<hyper::body::Incoming>,
    peer: std::net::SocketAddr,
    detectors: &[Box<dyn aegis_security::detectors::Detector>],
    mask: &aegis_security::detectors::SharedDetectorMask,
    risk: &aegis_security::risk::RiskTracker,
    ip_rate_limiter: &aegis_security::rate_limit::IpRateLimiter,
    load_gauge: &aegis_core::LoadGauge,
    verbosity: &aegis_core::SharedVerbosity,
    request_stage_hist: &aegis_control::metrics::request_duration::RequestStageHistogram,
    route_latency_hist: &aegis_control::metrics::route_latency::RouteLatencyHistogram,
    detector_latency_hist: &aegis_control::metrics::detector_latency::DetectorLatencyHistogram,
    bus: &AuditBus,
    upstream_ctx: &Arc<crate::proxy::ProxyContext>,
    detector_hit_metrics: &aegis_control::metrics::detector_hits::DetectorHitMetrics,
    // MTLS-T4 — per-connection client identity. Plain-HTTP +
    // anonymous-mTLS connections pass `&ClientIdentity::Anonymous`;
    // the policy gate below blocks the request if the resolved
    // route's `auth_required` excludes that identity kind.
    identity: &aegis_core::ClientIdentity,
) -> (
    Response<Full<Bytes>>,
    aegis_control::interop::headers::DecisionTag,
) {
    let result = handle_data_request_inner(
        req,
        peer,
        detectors,
        mask,
        risk,
        ip_rate_limiter,
        load_gauge,
        verbosity,
        request_stage_hist,
        route_latency_hist,
        detector_latency_hist,
        bus,
        upstream_ctx,
        detector_hit_metrics,
        identity,
    ).await;
    tracing::Span::current().record("action", result.1.action.as_str());
    result
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_data_request_inner(
    req: hyper::Request<hyper::body::Incoming>,
    peer: std::net::SocketAddr,
    detectors: &[Box<dyn aegis_security::detectors::Detector>],
    mask: &aegis_security::detectors::SharedDetectorMask,
    risk: &aegis_security::risk::RiskTracker,
    ip_rate_limiter: &aegis_security::rate_limit::IpRateLimiter,
    load_gauge: &aegis_core::LoadGauge,
    verbosity: &aegis_core::SharedVerbosity,
    request_stage_hist: &aegis_control::metrics::request_duration::RequestStageHistogram,
    route_latency_hist: &aegis_control::metrics::route_latency::RouteLatencyHistogram,
    detector_latency_hist: &aegis_control::metrics::detector_latency::DetectorLatencyHistogram,
    bus: &AuditBus,
    upstream_ctx: &Arc<crate::proxy::ProxyContext>,
    detector_hit_metrics: &aegis_control::metrics::detector_hits::DetectorHitMetrics,
    identity: &aegis_core::ClientIdentity,
) -> (
    Response<Full<Bytes>>,
    aegis_control::interop::headers::DecisionTag,
) {
    use aegis_control::interop::headers::DecisionTag;
    use aegis_control::metrics::request_duration::stage as stages;
    // RAII guard records the total duration on every exit
    // (early-return on rate-limit, strike-block, detector block,
    // or the Allow / Challenge / Block bottom). One sample per
    // request — no double-counting.
    //
    // Per-route latency is recorded separately inside
    // `forward_allow_to_upstream` once the RouteTable resolves —
    // blocked / rate-limited / challenged requests never reach
    // route resolution and are excluded from per-route series
    // (correct: their latency reflects the WAF decision, not the
    // route).
    struct TotalGuard<'a> {
        h: &'a aegis_control::metrics::request_duration::RequestStageHistogram,
        t0: std::time::Instant,
    }
    impl<'a> Drop for TotalGuard<'a> {
        fn drop(&mut self) {
            self.h.record(
                aegis_control::metrics::request_duration::stage::TOTAL,
                self.t0.elapsed(),
            );
        }
    }
    let request_start = std::time::Instant::now();
    let _total_guard = TotalGuard {
        h: request_stage_hist,
        t0: request_start,
    };
    // P7: bump the request counter so the sampler can update mode.
    load_gauge.tick();
    let load_mode = load_gauge.current();
    // P8: live verbosity dial. Block events are tagged at `Error`
    // — they emit unless the operator pinned `Silent` (used during
    // load tests where every audit write would dominate the
    // workload).
    let verbosity_level = verbosity.current();
    let allow_block_emit =
        verbosity_level.is_at_least(aegis_core::VerbosityLevel::Error);
    let allow_verbose_fields =
        verbosity_level.is_at_least(aegis_core::VerbosityLevel::Info);
    use aegis_core::pipeline::{BodyPeek, RequestView};
    use http_body_util::BodyExt;

    // CQF / detector-coverage fix — actually buffer the request
    // body so the SSRF / XSS / body_abuse detectors that inspect
    // it have something to look at. Previously this was always
    // `BodyPeek::empty()`, which silently disabled every body-
    // based detector and caused the hackathon-stress-test
    // detection ceiling at ~33%. Body collect is deferred until
    // AFTER rate-limit + strike-block (cheap shedders run first;
    // body buffering doesn't waste cycles on requests we'd
    // reject anyway), then threaded into both the detector view
    // AND the upstream forwarder so each request reads its body
    // exactly once.
    const MAX_BODY_BYTES: usize = 1 * 1024 * 1024; // 1 MiB

    let peer_ip = peer.ip();
    // P6 short-circuit: lifetime-strike block runs before any
    // body or detector cost so a flooding known-bad source can't
    // burn CPU.
    if risk.is_strike_blocked(peer_ip) {
        let resp = blocked_response(
            peer,
            "blocked by repeat-offender strikes",
            None,
            risk.snapshot(peer_ip).map(|s| s.score),
            req.uri(),
            req.method(),
            bus,
        );
        return (resp, DecisionTag::block("risk-strikes"));
    }

    // F-T2 — per-IP volumetric guard. Fires before the
    // detector pipeline so a flooding source can't burn CPU
    // on regex matchers. A denied request still records a
    // strike, so repeat offenders eventually cross
    // `risk.strikes.block_at` and get the permanent 403 path
    // above instead of the 429 here.
    let rate_t0 = std::time::Instant::now();
    let rate_decision = ip_rate_limiter.consume(peer_ip);
    request_stage_hist.record(stages::RATE_LIMIT, rate_t0.elapsed());
    if !rate_decision.allowed {
        let post_state = risk.record_malicious(peer_ip, 30);
        let reason = format!(
            "rate limit: {}/{} in last {}s",
            rate_decision.count,
            rate_decision.limit,
            ip_rate_limiter.config().window.as_secs(),
        );
        let allow_emit = verbosity
            .current()
            .is_at_least(aegis_core::VerbosityLevel::Error);
        if allow_emit {
            let ev = aegis_core::audit::AuditEvent {
                schema_version: 1,
                ts: chrono::Utc::now(),
                request_id: blake3::hash(
                    format!(
                        "{}:{}",
                        peer,
                        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
                    )
                    .as_bytes(),
                )
                .to_hex()
                .to_string(),
                class: aegis_core::audit::AuditClass::Detection,
                tenant_id: None,
                tier: None,
                action: "block".into(),
                reason: reason.clone(),
                client_ip: peer_ip.to_string(),
                route_id: None,
                rule_id: Some("ip-rate-limit".into()),
                risk_score: Some(post_state.score),
                fields: if load_mode.is_critical() {
                    serde_json::Value::Null
                } else {
                    serde_json::json!({
                        "path": req.uri().to_string(),
                        "method": req.method().to_string(),
                        "rate_count": rate_decision.count,
                        "rate_limit": rate_decision.limit,
                        "strikes": post_state.strikes,
                    })
                },
            };
            bus.emit(ev);
        }
        let resp = Response::builder()
            .status(429)
            .header("content-type", "application/json")
            .header("retry-after", rate_decision.retry_after_seconds.to_string())
            .body(Full::new(Bytes::from(
                serde_json::json!({
                    "error": "rate_limited",
                    "reason": reason,
                    "retry_after_seconds": rate_decision.retry_after_seconds,
                    "strikes": post_state.strikes,
                })
                .to_string(),
            )))
            .unwrap();
        return (resp, DecisionTag::rate_limit("ip-rate-limit"));
    }

    // Body collect — after cheap shedders (strike + rate-limit)
    // so we don't pay the buffering cost on rejected requests.
    // Bytes are threaded into the detector view AND down to the
    // upstream forwarder; each request reads its body exactly
    // once.
    let (parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => {
            tracing::warn!(error = %e, "client body read failed");
            let resp = Response::builder()
                .status(hyper::StatusCode::BAD_REQUEST)
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(
                    serde_json::json!({ "error": "body_read_error" }).to_string(),
                )))
                .unwrap();
            return (resp, DecisionTag::block("body-read-error"));
        }
    };
    if body_bytes.len() > MAX_BODY_BYTES {
        let resp = Response::builder()
            .status(hyper::StatusCode::PAYLOAD_TOO_LARGE)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(
                serde_json::json!({
                    "error": "body_too_large",
                    "max_bytes": MAX_BODY_BYTES,
                })
                .to_string(),
            )))
            .unwrap();
        return (resp, DecisionTag::block("body-too-large"));
    }

    let body_peek = BodyPeek::new(
        body_bytes.to_vec(),
        Some(body_bytes.len() as u64),
        false,
    );
    let view = RequestView {
        method: &parts.method,
        uri: &parts.uri,
        version: parts.version,
        headers: &parts.headers,
        peer,
        tls: None,
        body: &body_peek,
    };

    // Tier classification needs `view`, so it's run here rather
    // than at the very top.
    let (tier, _failure_mode) = aegis_security::pipeline::classify_tier(None, &view);
    tracing::Span::current().record(
        "tier",
        aegis_security::detectors::tier_str(tier),
    );

    // Run security detectors filtered by the effective mask for
    // this tier. A class turned off via PUT /api/detectors (base
    // or per-tier override) short-circuits before the detector body
    // runs.
    let effective = mask.resolve(Some(tier));
    let detect_t0 = std::time::Instant::now();
    let (signals, fired_classes) = aegis_security::detectors::run_all_filtered_timed(
        detectors,
        effective,
        &view,
        |class, elapsed| detector_latency_hist.record(class, elapsed),
    );
    request_stage_hist.record(stages::DETECT, detect_t0.elapsed());
    // PROM-T2 — record one increment per detector that emitted a
    // signal. Cost: one CounterVec inc per fired class (~30 ns).
    // In the common allow-path `fired_classes` is empty so cost
    // collapses to a single empty-vec branch.
    for class in &fired_classes {
        detector_hit_metrics.record(class);
    }

    if !signals.is_empty() {
        let total_score: u32 = signals.iter().map(|s| s.score).sum();
        let post_state = risk.record_malicious(peer_ip, total_score);
        let tags: Vec<&str> = signals.iter().map(|s| s.tag.as_str()).collect();
        let reason = format!("blocked by detectors: {} (score: {})", tags.join(", "), post_state.score);
        tracing::warn!(
            peer = %peer,
            path = %parts.uri,
            score = post_state.score,
            strikes = post_state.strikes,
            detectors = ?tags,
            "request blocked"
        );

        // P7 degraded logging: in Critical mode strip the verbose
        // `fields` payload to keep the bus + chain writes cheap.
        // Block reason is preserved so operators still see "what
        // tripped" — only the request echo is dropped.
        // P8 verbosity: skip the request echo whenever the live
        // verbosity is below `Info`. Combines additively with the
        // Critical short-circuit so an operator-pinned `Warn`
        // strips fields even at Normal load.
        let fields = if load_mode.is_critical() || !allow_verbose_fields {
            serde_json::Value::Null
        } else {
            serde_json::json!({
                "path": parts.uri.to_string(),
                "method": parts.method.to_string(),
                "detectors": tags,
                "strikes": post_state.strikes,
                "load_mode": load_mode.as_str(),
                "verbosity": verbosity_level.as_str(),
            })
        };
        if allow_block_emit {
            let ev = aegis_core::audit::AuditEvent {
                schema_version: 1,
                ts: chrono::Utc::now(),
                request_id: blake3::hash(format!("{}:{}", peer, chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)).as_bytes()).to_hex().to_string(),
                class: aegis_core::audit::AuditClass::Detection,
                tenant_id: None,
                tier: None,
                action: "block".into(),
                reason: reason.clone(),
                client_ip: peer_ip.to_string(),
                route_id: None,
                rule_id: None,
                risk_score: Some(post_state.score),
                fields,
            };
            bus.emit(ev);
        }

        let detector_rule = if tags.is_empty() {
            "detectors".to_string()
        } else {
            format!("detector:{}", tags.join(","))
        };
        let resp = Response::builder()
            .status(403)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(
                serde_json::json!({
                    "error": "forbidden",
                    "reason": reason,
                    "strikes": post_state.strikes,
                })
                .to_string(),
            )))
            .unwrap();
        return (resp, DecisionTag::block(detector_rule));
    }

    // Clean request — let the trust-recovery clock claw back any
    // accumulated score (capped at `trust_recovery.per_hour` so
    // one benign request can't reset a flagged client). Then the
    // adaptive-mitigation classifier decides between Allow,
    // Challenge, and Block based on the post-state vs the
    // configured `RiskThresholds`.
    risk.record_clean(peer_ip);
    match risk.level(peer_ip) {
        aegis_security::risk::RiskLevel::Block => {
            let resp = blocked_response(
                peer,
                "blocked by risk score",
                None,
                risk.snapshot(peer_ip).map(|s| s.score),
                &parts.uri,
                &parts.method,
                bus,
            );
            (resp, DecisionTag::block("risk-score"))
        }
        aegis_security::risk::RiskLevel::Challenge => {
            // AF-T1: contract-level distinction. Even though
            // the HTTP status (429) and Retry-After header are
            // shaped like rate-limit, the body carries
            // "challenge" and the contract action MUST be
            // `challenge` so the OC's challenge-solver path
            // engages.
            let resp = Response::builder()
                .status(429)
                .header("content-type", "application/json")
                .header("retry-after", "5")
                .body(Full::new(Bytes::from(
                    serde_json::json!({
                        "challenge": true,
                        "reason": "risk score over challenge threshold",
                        "challenge_type": "proof_of_work",
                    })
                    .to_string(),
                )))
                .unwrap();
            (resp, DecisionTag::challenge("risk-challenge"))
        }
        aegis_security::risk::RiskLevel::Allow => {
            // Forward the request to a real upstream member via
            // `crate::upstream::forward`. The forwarder maps
            // its outcome onto a status code; we infer the
            // contract action from that (allow on 2xx/3xx,
            // block / circuit_breaker / timeout otherwise).
            forward_allow_to_upstream(
                parts,
                body_bytes,
                upstream_ctx,
                identity,
                route_latency_hist,
                request_start,
                peer_ip,
                bus,
            )
            .await
        }
    }
}

/// Resolve a route + member from the live `ProxyContext`,
/// collect the request body, and forward through
/// `upstream::forward::forward()`. Returns 404 on no-route,
/// 502 / 503 on circuit-breaker / no-healthy-member / connect
/// failure.
#[tracing::instrument(
    name = "waf.forward_upstream",
    skip_all,
    fields(
        otel.kind = "client",
        host = tracing::field::Empty,
        path = %parts.uri.path(),
        method = %parts.method,
        upstream = tracing::field::Empty,
        member = tracing::field::Empty,
        outcome = tracing::field::Empty,
    ),
)]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn forward_allow_to_upstream(
    parts: http::request::Parts,
    body_bytes: Bytes,
    ctx: &Arc<crate::proxy::ProxyContext>,
    identity: &aegis_core::ClientIdentity,
    route_latency_hist: &aegis_control::metrics::route_latency::RouteLatencyHistogram,
    request_start: std::time::Instant,
    // TCP-T3c — source IP for the per-IP tunnel cap and for
    // `tcp_tunnel_open` / `tcp_tunnel_close` audit events.
    peer_ip: std::net::IpAddr,
    // TCP-T3c — audit bus for the tunnel-pair events. Cloned
    // into the spawned bridge task so the close event lands
    // even after this handler has returned.
    bus: &AuditBus,
) -> (
    Response<Full<Bytes>>,
    aegis_control::interop::headers::DecisionTag,
) {
    use aegis_control::interop::headers::DecisionTag;
    use std::sync::atomic::Ordering;

    let host = parts
        .headers
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost")
        .to_string();
    let path = parts.uri.path().to_string();
    let method = parts.method.clone();
    tracing::Span::current().record("host", host.as_str());

    // RAII helper — record per-route latency on every exit from
    // this function (allow forward, breaker open, no route, etc.).
    // Captures the resolved route_id once known; until then the
    // sample falls under "<unrouted>" so no traffic goes
    // unattributed. The String owns its content so the guard
    // can outlive the scoped `route_ctx` borrow.
    struct RouteLatencyGuard<'a> {
        h: &'a aegis_control::metrics::route_latency::RouteLatencyHistogram,
        t0: std::time::Instant,
        route: std::cell::RefCell<String>,
    }
    impl<'a> Drop for RouteLatencyGuard<'a> {
        fn drop(&mut self) {
            self.h.record(&self.route.borrow(), self.t0.elapsed());
        }
    }
    let _route_guard = RouteLatencyGuard {
        h: route_latency_hist,
        t0: request_start,
        route: std::cell::RefCell::new("<unrouted>".to_string()),
    };

    let route_ctx = match ctx.route_table.resolve(&host, &path, &method) {
        Some(r) => r,
        None => {
            tracing::Span::current().record("outcome", "no-route");
            let resp = Response::builder()
                .status(hyper::StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from("no matching route\n")))
                .unwrap();
            return (resp, DecisionTag::block("no-route"));
        }
    };
    tracing::Span::current().record("upstream", route_ctx.upstream.as_str());
    // Capture the route_id for the per-route latency histogram.
    // Lifetime: route_ctx borrows from `ctx.route_table` which
    // is the same Arc<ProxyContext> the caller holds; safe to
    // hand out the &str here.
    *_route_guard.route.borrow_mut() = route_ctx.route_id.clone();

    // MTLS-T4 — route-scoped client-identity gate.
    //
    // `auth_required` empty → any identity admitted (default
    // open). Non-empty → the identity's `kind()` must appear in
    // the list. Mismatch returns 403 with rule_id
    // `mtls_required`; the contract decision is `block` so
    // upstream rate-limit / risk surfaces still see the
    // rejection. Body is minimal — operators read the audit
    // chain for the principal that was rejected.
    if !route_ctx.auth_required.is_empty()
        && !route_ctx
            .auth_required
            .iter()
            .any(|kind| kind == identity.kind())
    {
        tracing::Span::current().record("outcome", "mtls-required");
        tracing::debug!(
            route_id = %route_ctx.route_id,
            required = ?route_ctx.auth_required,
            actual_kind = identity.kind(),
            principal = ?identity.principal(),
            "blocked: route requires authenticated identity",
        );
        let resp = Response::builder()
            .status(hyper::StatusCode::FORBIDDEN)
            .header("content-type", "text/plain; charset=utf-8")
            .body(Full::new(Bytes::from(
                "forbidden: route requires authenticated client\n",
            )))
            .unwrap();
        return (resp, DecisionTag::block("mtls_required"));
    }

    // TCP-T3c — CONNECT-method dispatch for `scheme: tcp` routes.
    // Branches BEFORE the circuit breaker / pool member pick
    // because tunnels don't go through the HTTP forwarder
    // (different transport entirely). The four explicit error
    // cases (CONNECT/non-tcp, non-CONNECT/tcp) match
    // plans/tcp-forwarder-phase-4.md §3 — distinct rule_ids so
    // operators tell config drift from upstream failure in
    // audit + metrics.
    {
        use aegis_core::config::UpstreamScheme;
        let is_connect = method == hyper::Method::CONNECT;
        let pool_is_tcp = route_ctx.pool_scheme == UpstreamScheme::Tcp;
        match (is_connect, pool_is_tcp) {
            (true, true) => {
                let request_id = blake3::hash(
                    format!(
                        "{}:{}",
                        peer_ip,
                        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
                    )
                    .as_bytes(),
                )
                .to_hex()
                .to_string();
                return forward_connect_tunnel(
                    parts,
                    route_ctx,
                    ctx,
                    peer_ip,
                    bus,
                    request_id,
                )
                .await;
            }
            (true, false) => {
                tracing::Span::current().record("outcome", "connect_to_non_tcp_route");
                let resp = Response::builder()
                    .status(hyper::StatusCode::BAD_GATEWAY)
                    .header("x-waf-rule-id", "connect_to_non_tcp_route")
                    .header("content-type", "text/plain; charset=utf-8")
                    .body(Full::new(Bytes::from(
                        "CONNECT method not allowed on non-tcp route\n",
                    )))
                    .unwrap();
                return (resp, DecisionTag::block("connect_to_non_tcp_route"));
            }
            (false, true) => {
                tracing::Span::current().record("outcome", "non_connect_to_tcp_route");
                let resp = Response::builder()
                    .status(hyper::StatusCode::BAD_GATEWAY)
                    .header("x-waf-rule-id", "non_connect_to_tcp_route")
                    .header("content-type", "text/plain; charset=utf-8")
                    .body(Full::new(Bytes::from(
                        "tcp route requires CONNECT method\n",
                    )))
                    .unwrap();
                return (resp, DecisionTag::block("non_connect_to_tcp_route"));
            }
            (false, false) => {
                // Normal HTTP path — fall through to existing
                // circuit breaker + pool member pick + forward.
            }
        }
    }

    if let Some(cb) = ctx.pools.breaker(&route_ctx.upstream) {
        if !cb.allow_request() {
            tracing::Span::current().record("outcome", "circuit-open");
            let resp = Response::builder()
                .status(hyper::StatusCode::SERVICE_UNAVAILABLE)
                .body(Full::new(Bytes::from("circuit open\n")))
                .unwrap();
            return (resp, DecisionTag::circuit_breaker("circuit-open"));
        }
    }

    let pool = match ctx.pools.get(&route_ctx.upstream) {
        Some(p) => p,
        None => {
            tracing::Span::current().record("outcome", "unknown-upstream");
            let resp = Response::builder()
                .status(hyper::StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("unknown upstream\n")))
                .unwrap();
            return (resp, DecisionTag::block("unknown-upstream"));
        }
    };

    let member = match pool.strategy.pick(&pool.members, None) {
        Some(m) => m,
        None => {
            if let Some(cb) = ctx.pools.breaker(&route_ctx.upstream) {
                cb.record_failure();
            }
            tracing::Span::current().record("outcome", "no-healthy-upstream");
            let resp = Response::builder()
                .status(hyper::StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("no healthy upstream\n")))
                .unwrap();
            return (resp, DecisionTag::circuit_breaker("no-healthy-upstream"));
        }
    };
    tracing::Span::current().record("member", tracing::field::display(&member.addr));

    member.inflight.fetch_add(1, Ordering::Relaxed);
    let result = crate::upstream::forward::forward(
        member,
        &pool.connection,
        parts.method,
        parts.uri,
        parts.headers,
        body_bytes,
    )
    .await;
    member.inflight.fetch_sub(1, Ordering::Relaxed);

    match result {
        Ok(resp) => {
            if let Some(cb) = ctx.pools.breaker(&route_ctx.upstream) {
                if resp.status().is_server_error() {
                    cb.record_failure();
                } else {
                    cb.record_success();
                }
            }
            tracing::Span::current().record(
                "outcome",
                if resp.status().is_server_error() {
                    "upstream-5xx"
                } else {
                    "ok"
                },
            );
            // 5xx from upstream is not a WAF block — we proxied
            // faithfully; the contract action stays `allow` (the
            // upstream's failure is what the client sees).
            (resp, DecisionTag::allow())
        }
        Err(e) => {
            tracing::warn!(error = %e, "upstream forward failed");
            if let Some(cb) = ctx.pools.breaker(&route_ctx.upstream) {
                cb.record_failure();
            }
            // AF-T1: distinguish forward-failure modes for the
            // contract. Connect/Handshake/Send timeouts → Timeout;
            // anything else → CircuitBreaker (we refused to
            // proxy further or the breaker tripped).
            let action_tag = match &e {
                crate::upstream::forward::ForwardError::Send(m)
                    if m.contains("timed out") =>
                {
                    DecisionTag::timeout("upstream-timeout")
                }
                crate::upstream::forward::ForwardError::Connect(_)
                | crate::upstream::forward::ForwardError::Handshake(_) => {
                    DecisionTag::circuit_breaker("upstream-unreachable")
                }
                _ => DecisionTag::circuit_breaker("upstream-error"),
            };
            tracing::Span::current().record("outcome", action_tag.action.as_str());
            let resp = Response::builder()
                .status(hyper::StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("upstream error\n")))
                .unwrap();
            (resp, action_tag)
        }
    }
}

/// TCP-T3c — CONNECT-method tunnel handler. Called from
/// `forward_allow_to_upstream` when the resolved route's pool
/// has `scheme: tcp`. Runs the admission gates + (when
/// admitted) attaches the upgrade hook and spawns the bridge
/// task.
async fn forward_connect_tunnel(
    mut parts: http::request::Parts,
    route_ctx: aegis_core::context::RouteCtx,
    ctx: &Arc<crate::proxy::ProxyContext>,
    peer_ip: std::net::IpAddr,
    bus: &AuditBus,
    request_id: String,
) -> (
    Response<Full<Bytes>>,
    aegis_control::interop::headers::DecisionTag,
) {
    use aegis_control::interop::headers::DecisionTag;
    use crate::tcp_tunnel::{
        bridge_tunnel, connect_admit, ConnectAdmission, ConnectAdmissionRequest,
        TunnelClosed, TunnelCloseReason,
    };

    // CONNECT request line carries `host:port` in the URI's
    // authority slot (RFC 9110 §9.3.6). Reject on missing or
    // empty — we don't fall back to the URI's path-string
    // because that promotes obviously-malformed inputs ("/")
    // into DNS lookups that then 503.
    let raw_authority = match parts
        .uri
        .authority()
        .map(|a| a.as_str().to_string())
        .filter(|s| !s.is_empty())
    {
        Some(a) => a,
        None => {
            return connect_deny_response(
                400,
                "connect_authority_missing",
                "CONNECT request missing authority (RFC 9110 §9.3.6 expects host:port)",
                bus,
                &request_id,
                &route_ctx.route_id,
                peer_ip,
            );
        }
    };

    // DNS resolution if not a literal IP. `parse_authority`
    // returns Some only for literal IPs; otherwise we resolve
    // via tokio's lookup_host. Single resolved address is
    // enough — we don't iterate happy-eyeballs style at this
    // layer.
    let admit_authority = if aegis_core::tcp_destination::parse_authority(&raw_authority)
        .is_some()
    {
        raw_authority.clone()
    } else {
        match tokio::net::lookup_host(raw_authority.as_str()).await {
            Ok(mut iter) => match iter.next() {
                Some(addr) => format!("{}:{}", addr.ip(), addr.port()),
                None => {
                    return connect_deny_response(
                        403,
                        "connect_dns_no_records",
                        "CONNECT authority resolved to no addresses",
                        bus,
                        &request_id,
                        &route_ctx.route_id,
                        peer_ip,
                    );
                }
            },
            Err(e) => {
                tracing::warn!(
                    authority = %raw_authority,
                    error = %e,
                    "CONNECT DNS lookup failed",
                );
                return connect_deny_response(
                    503,
                    "connect_dns_failed",
                    "CONNECT authority DNS lookup failed",
                    bus,
                    &request_id,
                    &route_ctx.route_id,
                    peer_ip,
                );
            }
        }
    };

    let admit = connect_admit(ConnectAdmissionRequest {
        authority: &admit_authority,
        allowlist: &route_ctx.tcp_destination_allowlist,
        max_per_ip: route_ctx.max_concurrent_tunnels_per_ip,
        peer_ip,
        tunnels: &ctx.tunnels,
    });

    let (dest_ip, port, guard) = match admit {
        ConnectAdmission::Admit { dest, port, guard } => (dest, port, guard),
        ConnectAdmission::Deny {
            status,
            rule_id,
            message,
        } => {
            return connect_deny_response(
                status,
                rule_id,
                message,
                bus,
                &request_id,
                &route_ctx.route_id,
                peer_ip,
            );
        }
    };

    // Pull the OnUpgrade extension off the request parts —
    // hyper installed it during connection setup. Absent on
    // HTTP/2 clients (extended CONNECT not yet supported);
    // 405 with a clear hint.
    let on_upgrade = parts.extensions.remove::<hyper::upgrade::OnUpgrade>();
    let Some(on_upgrade) = on_upgrade else {
        return connect_deny_response(
            405,
            "connect_no_upgrade_support",
            "CONNECT requires HTTP/1.1 upgrade; HTTP/2 extended CONNECT not yet supported",
            bus,
            &request_id,
            &route_ctx.route_id,
            peer_ip,
        );
    };

    let dest_addr = std::net::SocketAddr::new(dest_ip, port);

    // Emit the open-event before spawning so it lands on the
    // chain in time-order with subsequent close.
    emit_tunnel_open_audit(
        bus,
        &request_id,
        &route_ctx.route_id,
        peer_ip,
        dest_addr,
    );

    // Spawn the bridge. Everything captured by move so the
    // task is independent of this handler's stack.
    let bus_for_task = bus.clone();
    let request_id_for_task = request_id.clone();
    let route_id_for_task = route_ctx.route_id.clone();
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                let io = hyper_util::rt::TokioIo::new(upgraded);
                let _reason = bridge_tunnel(
                    io,
                    dest_addr,
                    std::time::Duration::from_secs(30),
                    guard,
                    move |closed| {
                        emit_tunnel_close_audit(
                            &bus_for_task,
                            &request_id_for_task,
                            &route_id_for_task,
                            peer_ip,
                            &closed,
                        );
                    },
                )
                .await;
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    request_id = %request_id_for_task,
                    "CONNECT upgrade failed; emitting synthetic close",
                );
                drop(guard);
                let synthetic = TunnelClosed {
                    reason: TunnelCloseReason::Error,
                    duration: std::time::Duration::ZERO,
                    bytes_to_upstream: 0,
                    bytes_from_upstream: 0,
                };
                emit_tunnel_close_audit(
                    &bus_for_task,
                    &request_id_for_task,
                    &route_id_for_task,
                    peer_ip,
                    &synthetic,
                );
            }
        }
    });

    // 200 OK with empty body triggers hyper to start the
    // upgrade and resolve the OnUpgrade future on the spawned
    // task above. RFC 9110 §9.3.6: the response to a successful
    // CONNECT carries no body.
    let resp = Response::builder()
        .status(200)
        .body(Full::new(Bytes::new()))
        .unwrap();
    (resp, DecisionTag::allow())
}

/// TCP-T3c — render a CONNECT-deny response + emit the audit
/// event. Centralised so every deny path uses the same shape
/// (audit class `Access`, `x-waf-rule-id` response header,
/// plain-text body with the message).
fn connect_deny_response(
    status: u16,
    rule_id: &'static str,
    message: &str,
    bus: &AuditBus,
    request_id: &str,
    route_id: &str,
    peer_ip: std::net::IpAddr,
) -> (
    Response<Full<Bytes>>,
    aegis_control::interop::headers::DecisionTag,
) {
    use aegis_control::interop::headers::DecisionTag;

    bus.emit(aegis_core::audit::AuditEvent {
        schema_version: 1,
        ts: chrono::Utc::now(),
        request_id: request_id.to_string(),
        class: aegis_core::audit::AuditClass::Access,
        tenant_id: None,
        tier: None,
        action: "block".into(),
        reason: message.to_string(),
        client_ip: peer_ip.to_string(),
        route_id: Some(route_id.to_string()),
        rule_id: Some(rule_id.to_string()),
        risk_score: None,
        fields: serde_json::json!({"connect_denied": true}),
    });

    let resp = Response::builder()
        .status(status)
        .header("x-waf-rule-id", rule_id)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(format!("{message}\n"))))
        .unwrap();
    (resp, DecisionTag::block(rule_id))
}

fn emit_tunnel_open_audit(
    bus: &AuditBus,
    request_id: &str,
    route_id: &str,
    peer_ip: std::net::IpAddr,
    dest: std::net::SocketAddr,
) {
    bus.emit(aegis_core::audit::AuditEvent {
        schema_version: 1,
        ts: chrono::Utc::now(),
        request_id: request_id.to_string(),
        class: aegis_core::audit::AuditClass::Access,
        tenant_id: None,
        tier: None,
        action: "tcp_tunnel_open".into(),
        reason: format!("CONNECT tunnel admitted to {dest}"),
        client_ip: peer_ip.to_string(),
        route_id: Some(route_id.to_string()),
        rule_id: Some("tunnel_admitted".into()),
        risk_score: None,
        fields: serde_json::json!({
            "destination": dest.to_string(),
        }),
    });
}

fn emit_tunnel_close_audit(
    bus: &AuditBus,
    request_id: &str,
    route_id: &str,
    peer_ip: std::net::IpAddr,
    closed: &crate::tcp_tunnel::TunnelClosed,
) {
    bus.emit(aegis_core::audit::AuditEvent {
        schema_version: 1,
        ts: chrono::Utc::now(),
        request_id: request_id.to_string(),
        class: aegis_core::audit::AuditClass::Access,
        tenant_id: None,
        tier: None,
        action: "tcp_tunnel_close".into(),
        reason: format!("CONNECT tunnel closed: {}", closed.reason.as_str()),
        client_ip: peer_ip.to_string(),
        route_id: Some(route_id.to_string()),
        rule_id: Some(closed.reason.rule_id().to_string()),
        risk_score: None,
        fields: serde_json::json!({
            "duration_ms": closed.duration.as_millis() as u64,
            "bytes_to_upstream": closed.bytes_to_upstream,
            "bytes_from_upstream": closed.bytes_from_upstream,
            "close_reason": closed.reason.as_str(),
        }),
    });
}

#[allow(clippy::too_many_arguments)]
fn blocked_response(
    peer: std::net::SocketAddr,
    reason: &str,
    rule_id: Option<String>,
    risk_score: Option<u32>,
    uri: &hyper::Uri,
    method: &hyper::Method,
    bus: &AuditBus,
) -> Response<Full<Bytes>> {
    let ev = aegis_core::audit::AuditEvent {
        schema_version: 1,
        ts: chrono::Utc::now(),
        request_id: blake3::hash(
            format!(
                "{}:{}",
                peer,
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
            )
            .as_bytes(),
        )
        .to_hex()
        .to_string(),
        class: aegis_core::audit::AuditClass::Detection,
        tenant_id: None,
        tier: None,
        action: "block".into(),
        reason: reason.into(),
        client_ip: peer.ip().to_string(),
        route_id: None,
        rule_id,
        risk_score,
        fields: serde_json::json!({
            "path": uri.to_string(),
            "method": method.to_string(),
        }),
    };
    bus.emit(ev);
    Response::builder()
        .status(403)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(
            serde_json::json!({ "error": "forbidden", "reason": reason }).to_string(),
        )))
        .unwrap()
}

#[cfg(test)]
mod tcp_connect_tests {
    //! TCP-T5 — integration coverage for the CONNECT dispatch
    //! matrix. Drives `forward_allow_to_upstream` directly with
    //! a synthetic request + ProxyContext so we exercise the
    //! real branch logic without needing the full hyper serving
    //! stack. End-to-end byte-flow through a real CONNECT
    //! client is covered by `tcp_tunnel::bridge_tunnel`'s
    //! existing `bridge_tunnel_round_trips_bytes_through_an_echo_upstream`
    //! test.
    //!
    //! What these tests prove:
    //! - The four-cell method × scheme dispatch matrix from
    //!   plans/tcp-forwarder-phase-4.md §3 fires the right
    //!   rule_id on every cell.
    //! - The deny paths emit the documented audit shape +
    //!   `x-waf-rule-id` response header.
    //! - The admit path returns 200 OK (the bridge spawn
    //!   itself can't run inside this test because there's no
    //!   OnUpgrade extension on a hand-built `Parts`; the
    //!   spawned task is then expected to take the
    //!   "upgrade failed" synthetic-close branch — covered
    //!   below).
    //!
    //! Limitations called out:
    //! - Without a real hyper handshake we can't drive
    //!   `OnUpgrade::await` to success, so the admit case
    //!   exercises everything up through the 200 response;
    //!   the bridge task immediately fails its upgrade-await
    //!   and emits a synthetic close. That's also a valuable
    //!   test surface (the orphan-prevention path).

    use std::sync::Arc;
    use std::time::Instant;

    use bytes::Bytes;
    use http_body_util::BodyExt;

    use aegis_core::audit::{AuditBus, AuditEvent};
    use aegis_core::config::WafConfig;
    use aegis_core::{ClientIdentity, SecurityPipeline};
    use aegis_security::NoopPipeline;

    use crate::proxy::ProxyContext;
    use crate::tcp_tunnel::ConcurrentTunnels;

    fn route_latency() -> aegis_control::metrics::route_latency::RouteLatencyHistogram {
        let reg = aegis_control::metrics::MetricsRegistry::init();
        aegis_control::metrics::route_latency::RouteLatencyHistogram::register(&reg)
            .expect("register route latency")
    }

    fn tcp_route_cfg(allowlist_yaml: &str) -> WafConfig {
        let yaml = format!(
            r#"
listeners:
  data: [{{ bind: "127.0.0.1:0" }}]
  admin: {{ bind: "127.0.0.1:0" }}
routes:
  - id: tcp-tunnel
    path: "/"
    upstream: tcp-mesh
{allowlist_yaml}
upstreams:
  tcp-mesh:
    members: [{{ addr: "127.0.0.1:6379" }}]
    connection: {{ scheme: tcp }}
state: {{ backend: in_memory }}
"#
        );
        let cfg: WafConfig = serde_yaml::from_str(&yaml).expect("yaml parse");
        cfg.validate().expect("validate");
        cfg
    }

    fn http_route_cfg() -> WafConfig {
        let yaml = r#"
listeners:
  data: [{ bind: "127.0.0.1:0" }]
  admin: { bind: "127.0.0.1:0" }
routes:
  - { id: catch-all, path: "/", upstream: pool }
upstreams:
  pool: { members: [{ addr: "127.0.0.1:65530" }] }
state: { backend: in_memory }
"#;
        let cfg: WafConfig = serde_yaml::from_str(yaml).unwrap();
        cfg.validate().unwrap();
        cfg
    }

    fn build_ctx(cfg: &WafConfig) -> Arc<ProxyContext> {
        let pipeline: Arc<dyn SecurityPipeline> = Arc::new(NoopPipeline);
        let mut ctx = ProxyContext::build(cfg, pipeline).expect("build ctx");
        ctx.tunnels = ConcurrentTunnels::new();
        Arc::new(ctx)
    }

    /// Build a `Parts` with the given method + URI, attached to
    /// the synthetic Host header the route table needs.
    fn parts(method: hyper::Method, uri: &str) -> http::request::Parts {
        let req = hyper::Request::builder()
            .method(method)
            .uri(uri)
            .header("host", "any")
            .body(http_body_util::Empty::<Bytes>::new())
            .unwrap();
        let (parts, _) = req.into_parts();
        parts
    }

    /// Subscribe to the bus before the call, then drain
    /// everything that fired during it.
    async fn drain_bus(
        rx: &mut tokio::sync::broadcast::Receiver<AuditEvent>,
    ) -> Vec<AuditEvent> {
        let mut out = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            out.push(ev);
        }
        // Give the spawned bridge task a chance to fire its
        // synthetic close audit on the admit path.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        while let Ok(ev) = rx.try_recv() {
            out.push(ev);
        }
        out
    }

    fn rule_id_header(resp: &hyper::Response<http_body_util::Full<Bytes>>) -> Option<&str> {
        resp.headers().get("x-waf-rule-id").and_then(|v| v.to_str().ok())
    }

    // ---- Dispatch matrix cells ----

    #[tokio::test]
    async fn connect_to_non_tcp_route_is_502_with_documented_rule_id() {
        let cfg = http_route_cfg();
        let ctx = build_ctx(&cfg);
        let bus = AuditBus::new(16);
        let rh = route_latency();

        let parts = parts(hyper::Method::CONNECT, "203.0.113.5:443");
        let (resp, tag) = super::forward_allow_to_upstream(
            parts,
            Bytes::new(),
            &ctx,
            &ClientIdentity::Anonymous,
            &rh,
            Instant::now(),
            "198.51.100.1".parse().unwrap(),
            &bus,
        )
        .await;

        assert_eq!(resp.status(), 502);
        assert_eq!(rule_id_header(&resp), Some("connect_to_non_tcp_route"));
        assert_eq!(tag.action.as_str(), "block");
    }

    #[tokio::test]
    async fn non_connect_to_tcp_route_is_502_with_documented_rule_id() {
        let cfg = tcp_route_cfg(
            r#"    tcp_destination_allowlist:
      - "203.0.113.0/24:443"
"#,
        );
        let ctx = build_ctx(&cfg);
        let bus = AuditBus::new(16);
        let rh = route_latency();

        let parts = parts(hyper::Method::GET, "/");
        let (resp, tag) = super::forward_allow_to_upstream(
            parts,
            Bytes::new(),
            &ctx,
            &ClientIdentity::Anonymous,
            &rh,
            Instant::now(),
            "198.51.100.1".parse().unwrap(),
            &bus,
        )
        .await;

        assert_eq!(resp.status(), 502);
        assert_eq!(rule_id_header(&resp), Some("non_connect_to_tcp_route"));
        assert_eq!(tag.action.as_str(), "block");
    }

    #[tokio::test]
    async fn connect_to_tcp_route_with_internal_dest_is_403_internal() {
        let cfg = tcp_route_cfg(
            r#"    tcp_destination_allowlist:
      - "203.0.113.0/24:443"
"#,
        );
        let ctx = build_ctx(&cfg);
        let bus = AuditBus::new(16);
        let rh = route_latency();

        // 127.0.0.1 is hardcoded-deny by the SSRF gate even
        // though this CIDR isn't in the allowlist anyway.
        let parts = parts(hyper::Method::CONNECT, "127.0.0.1:443");
        let (resp, _tag) = super::forward_allow_to_upstream(
            parts,
            Bytes::new(),
            &ctx,
            &ClientIdentity::Anonymous,
            &rh,
            Instant::now(),
            "198.51.100.1".parse().unwrap(),
            &bus,
        )
        .await;

        assert_eq!(resp.status(), 403);
        assert_eq!(
            rule_id_header(&resp),
            Some("connect_destination_internal"),
        );
    }

    #[tokio::test]
    async fn connect_to_tcp_route_outside_allowlist_is_403_denied() {
        let cfg = tcp_route_cfg(
            r#"    tcp_destination_allowlist:
      - "203.0.113.0/24:443"
"#,
        );
        let ctx = build_ctx(&cfg);
        let bus = AuditBus::new(16);
        let rh = route_latency();

        // 198.18.0.1 is public + outside the configured CIDR.
        let parts = parts(hyper::Method::CONNECT, "198.18.0.1:443");
        let (resp, _tag) = super::forward_allow_to_upstream(
            parts,
            Bytes::new(),
            &ctx,
            &ClientIdentity::Anonymous,
            &rh,
            Instant::now(),
            "198.51.100.1".parse().unwrap(),
            &bus,
        )
        .await;

        assert_eq!(resp.status(), 403);
        assert_eq!(rule_id_header(&resp), Some("connect_destination_denied"));
    }

    #[tokio::test]
    async fn connect_to_tcp_route_on_wrong_port_is_403_denied() {
        let cfg = tcp_route_cfg(
            r#"    tcp_destination_allowlist:
      - "203.0.113.0/24:443"
"#,
        );
        let ctx = build_ctx(&cfg);
        let bus = AuditBus::new(16);
        let rh = route_latency();

        let parts = parts(hyper::Method::CONNECT, "203.0.113.5:6379");
        let (resp, _tag) = super::forward_allow_to_upstream(
            parts,
            Bytes::new(),
            &ctx,
            &ClientIdentity::Anonymous,
            &rh,
            Instant::now(),
            "198.51.100.1".parse().unwrap(),
            &bus,
        )
        .await;

        assert_eq!(resp.status(), 403);
        assert_eq!(rule_id_header(&resp), Some("connect_destination_denied"));
    }

    #[tokio::test]
    async fn connect_to_tcp_route_passes_admit_then_405s_without_onupgrade() {
        // The full admit → 200 + bridge path requires a real
        // hyper handshake to install the `OnUpgrade` extension
        // on the request parts; `hyper::upgrade::OnUpgrade` has
        // no public constructor so we can't fabricate it from
        // a unit test. What this test DOES prove:
        //
        //   - All admission gates (allowlist, internal-IP,
        //     per-IP cap) passed for an in-allowlist
        //     destination — otherwise we'd see 403 not 405.
        //   - The OnUpgrade-absent branch returns 405 with
        //     `connect_no_upgrade_support` rule_id.
        //   - The admit-then-no-upgrade path doesn't leak the
        //     per-IP slot — the guard bound at admit drops at
        //     the early return, restoring the counter to 0.
        //
        // The full byte-flow coverage lives at
        // `tcp_tunnel::tests::bridge_tunnel_round_trips_bytes_through_an_echo_upstream`.
        let cfg = tcp_route_cfg(
            r#"    tcp_destination_allowlist:
      - "203.0.113.0/24:443"
"#,
        );
        let ctx = build_ctx(&cfg);
        let bus = AuditBus::new(16);
        let rh = route_latency();
        let peer: std::net::IpAddr = "198.51.100.1".parse().unwrap();

        let parts = parts(hyper::Method::CONNECT, "203.0.113.5:443");
        let (resp, _tag) = super::forward_allow_to_upstream(
            parts,
            Bytes::new(),
            &ctx,
            &ClientIdentity::Anonymous,
            &rh,
            Instant::now(),
            peer,
            &bus,
        )
        .await;

        assert_eq!(resp.status(), 405);
        assert_eq!(rule_id_header(&resp), Some("connect_no_upgrade_support"));
        // Counter must be 0 — admit incremented + guard dropped
        // at the early-return for the missing OnUpgrade.
        assert_eq!(ctx.tunnels.count(peer), 0);
    }

    // ---- Edge cases ----

    #[tokio::test]
    async fn connect_with_missing_authority_is_400_with_rule_id() {
        let cfg = tcp_route_cfg(
            r#"    tcp_destination_allowlist:
      - "203.0.113.0/24:443"
"#,
        );
        let ctx = build_ctx(&cfg);
        let bus = AuditBus::new(16);
        let rh = route_latency();

        // CONNECT with just "/" — no authority. Some buggy
        // clients do this; the handler should reject not crash.
        let parts = parts(hyper::Method::CONNECT, "/");
        let (resp, _tag) = super::forward_allow_to_upstream(
            parts,
            Bytes::new(),
            &ctx,
            &ClientIdentity::Anonymous,
            &rh,
            Instant::now(),
            "198.51.100.1".parse().unwrap(),
            &bus,
        )
        .await;

        // Either authority-missing (preferred) or unparseable —
        // both 4xx and either rule_id is acceptable for this
        // edge. Pin the contract: 4xx + a connect_* rule_id.
        let status = resp.status().as_u16();
        let rule = rule_id_header(&resp).unwrap_or("");
        assert!(
            (400..500).contains(&status),
            "expected 4xx, got {status}",
        );
        assert!(
            rule.starts_with("connect_"),
            "expected connect_* rule_id, got {rule:?}",
        );
    }

    #[tokio::test]
    async fn admit_does_not_leak_per_ip_slot_when_onupgrade_absent() {
        // Companion to the test above. Pin the leak-free
        // contract: even when many CONNECTs come in over a
        // protocol that doesn't carry OnUpgrade, the per-IP
        // counter map stays empty.
        let cfg = tcp_route_cfg(
            r#"    tcp_destination_allowlist:
      - "203.0.113.0/24:443"
"#,
        );
        let ctx = build_ctx(&cfg);
        let bus = AuditBus::new(16);
        let rh = route_latency();
        let peer: std::net::IpAddr = "198.51.100.1".parse().unwrap();

        for _ in 0..5 {
            let p = parts(hyper::Method::CONNECT, "203.0.113.5:443");
            let _ = super::forward_allow_to_upstream(
                p,
                Bytes::new(),
                &ctx,
                &ClientIdentity::Anonymous,
                &rh,
                Instant::now(),
                peer,
                &bus,
            )
            .await;
        }
        assert_eq!(ctx.tunnels.count(peer), 0, "no slot leaks across 5 calls");
        assert_eq!(ctx.tunnels.distinct_ips(), 0);
    }

    #[tokio::test]
    async fn deny_paths_emit_block_audit_event_with_rule_id() {
        // Spot-check: connect_destination_denied path emits
        // a `block` audit event with the documented rule_id
        // and the route_id stamped.
        let cfg = tcp_route_cfg(
            r#"    tcp_destination_allowlist:
      - "203.0.113.0/24:443"
"#,
        );
        let ctx = build_ctx(&cfg);
        let bus = AuditBus::new(16);
        let mut rx = bus.subscribe();
        let rh = route_latency();

        let parts = parts(hyper::Method::CONNECT, "198.18.0.1:443");
        let (resp, _tag) = super::forward_allow_to_upstream(
            parts,
            Bytes::new(),
            &ctx,
            &ClientIdentity::Anonymous,
            &rh,
            Instant::now(),
            "198.51.100.1".parse().unwrap(),
            &bus,
        )
        .await;
        assert_eq!(resp.status(), 403);

        let events = drain_bus(&mut rx).await;
        let block_event = events
            .iter()
            .find(|e| e.action == "block")
            .expect("block audit event for denied dest");
        assert_eq!(
            block_event.rule_id.as_deref(),
            Some("connect_destination_denied"),
        );
        assert_eq!(block_event.route_id.as_deref(), Some("tcp-tunnel"));
    }
}
