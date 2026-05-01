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
    bus: &AuditBus,
    upstream_ctx: &Arc<crate::proxy::ProxyContext>,
    detector_hit_metrics: &aegis_control::metrics::detector_hits::DetectorHitMetrics,
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
        bus,
        upstream_ctx,
        detector_hit_metrics,
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
    bus: &AuditBus,
    upstream_ctx: &Arc<crate::proxy::ProxyContext>,
    detector_hit_metrics: &aegis_control::metrics::detector_hits::DetectorHitMetrics,
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
    let _total_guard = TotalGuard {
        h: request_stage_hist,
        t0: std::time::Instant::now(),
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

    let body_peek = BodyPeek::empty();
    let view = RequestView {
        method: req.method(),
        uri: req.uri(),
        version: req.version(),
        headers: req.headers(),
        peer,
        tls: None,
        body: &body_peek,
    };

    // Classify the request to a tier so per-tier overrides apply.
    // Route context isn't plumbed yet (route table lookup is in
    // aegis-proxy::route, separate work); pass `None` here and rely
    // on the path heuristic in `classify_tier`.
    let (tier, _failure_mode) = aegis_security::pipeline::classify_tier(None, &view);
    // OTEL-T3 — record the resolved tier on the request span so
    // Jaeger filters by tier work without parsing logs.
    tracing::Span::current().record(
        "tier",
        aegis_security::detectors::tier_str(tier),
    );

    // P6 short-circuit: if the client's lifetime strike counter
    // has crossed the configured threshold, refuse before running
    // any detectors. Saves CPU under DDoS from known-bad sources.
    let peer_ip = peer.ip();
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

    // Run security detectors filtered by the effective mask for
    // this tier. A class turned off via PUT /api/detectors (base
    // or per-tier override) short-circuits before the detector body
    // runs.
    let effective = mask.resolve(Some(tier));
    let detect_t0 = std::time::Instant::now();
    let (signals, fired_classes) =
        aegis_security::detectors::run_all_filtered_observed(detectors, effective, &view);
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
            path = %req.uri(),
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
                "path": req.uri().to_string(),
                "method": req.method().to_string(),
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
                req.uri(),
                req.method(),
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
            forward_allow_to_upstream(req, upstream_ctx).await
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
        path = %req.uri().path(),
        method = %req.method(),
        upstream = tracing::field::Empty,
        member = tracing::field::Empty,
        outcome = tracing::field::Empty,
    ),
)]
pub(crate) async fn forward_allow_to_upstream(
    req: hyper::Request<hyper::body::Incoming>,
    ctx: &Arc<crate::proxy::ProxyContext>,
) -> (
    Response<Full<Bytes>>,
    aegis_control::interop::headers::DecisionTag,
) {
    use aegis_control::interop::headers::DecisionTag;
    use http_body_util::BodyExt;
    use std::sync::atomic::Ordering;

    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost")
        .to_string();
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    tracing::Span::current().record("host", host.as_str());

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

    let (parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => {
            tracing::warn!(error = %e, "failed to collect client body");
            tracing::Span::current().record("outcome", "body-read-error");
            let resp = Response::builder()
                .status(hyper::StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::from("body read error\n")))
                .unwrap();
            return (resp, DecisionTag::block("body-read-error"));
        }
    };

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
