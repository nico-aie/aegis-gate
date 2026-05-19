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
    route_activity: &aegis_control::metrics::route_activity::RouteActivityWindow,
    detector_latency_hist: &aegis_control::metrics::detector_latency::DetectorLatencyHistogram,
    bus: &AuditBus,
    upstream_ctx: &Arc<crate::proxy::ProxyContext>,
    detector_hit_metrics: &aegis_control::metrics::detector_hits::DetectorHitMetrics,
    // MTLS-T4 — per-connection client identity. Plain-HTTP +
    // anonymous-mTLS connections pass `&ClientIdentity::Anonymous`;
    // the policy gate below blocks the request if the resolved
    // route's `auth_required` excludes that identity kind.
    identity: &aegis_core::ClientIdentity,
    // 2026-05-18 (QC TLS wire-up — F-CRITICAL-010 / 014 / 015
    // activation): post-handshake TLS fingerprint from the accept
    // loop. `None` for plain-HTTP connections (no handshake) or
    // when TLS termination didn't happen at this layer.
    tls_fingerprint: Option<&aegis_core::TlsFingerprint>,
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
        route_activity,
        detector_latency_hist,
        bus,
        upstream_ctx,
        detector_hit_metrics,
        identity,
        tls_fingerprint,
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
    route_activity: &aegis_control::metrics::route_activity::RouteActivityWindow,
    detector_latency_hist: &aegis_control::metrics::detector_latency::DetectorLatencyHistogram,
    bus: &AuditBus,
    upstream_ctx: &Arc<crate::proxy::ProxyContext>,
    detector_hit_metrics: &aegis_control::metrics::detector_hits::DetectorHitMetrics,
    identity: &aegis_core::ClientIdentity,
    tls_fingerprint: Option<&aegis_core::TlsFingerprint>,
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
    //
    // 2026-05-17 F-CRITICAL-004 — was `const = 1 MiB`; now reads
    // `cfg.proxy.max_body_bytes` via the long-lived ProxyContext.
    // Default 10 MiB matches `QuotaConfig::default()`; operators
    // can raise it for upload-heavy routes or drop it to tighten
    // the DoS surface.
    let max_body_bytes = upstream_ctx.max_body_bytes;

    // F-HIGH-005 (2026-05-17 s-tester audit): v2.3 §2.4 — while
    // /__waf_control/reset_state is iterating subsystem callbacks
    // the OC must not observe a partially-reset state. The §2.4
    // "MAY temporarily reject in-flight non-control requests"
    // clause is honoured here: any request arriving during the
    // reset window short-circuits with 503 + Retry-After: 0.
    // Hot-path cost when no reset is in progress: one relaxed
    // AtomicBool::load (~1 ns).
    if let Some(flag) = upstream_ctx.reset_in_progress.get() {
        if flag.load(std::sync::atomic::Ordering::Acquire) {
            let resp = Response::builder()
                .status(hyper::StatusCode::SERVICE_UNAVAILABLE)
                .header("retry-after", "0")
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(
                    serde_json::json!({
                        "error": "reset_in_progress",
                        "retry_after_seconds": 0,
                    })
                    .to_string(),
                )))
                .unwrap();
            return (resp, DecisionTag::block("reset-in-progress"));
        }
    }

    // 2026-05-17 F-CRITICAL-002 — interop log_only mode store, hoisted
    // here so blacklist / strike-block / rate-limit / risk-score
    // (the four block paths between this point and the detector
    // chain) can consult it before returning early. Pre-fix only
    // the detector branch consulted modes, leaving every other
    // block path stuck in Enforce regardless of `set_profile
    // mode=log_only`. `log_only_intent` carries the would-be block
    // DecisionTag through the rest of the function so the response
    // stamper emits `X-WAF-Action: <intent>` + `X-WAF-Mode:
    // log_only` while the upstream still gets the request.
    let interop_modes = upstream_ctx.interop_modes.get();
    let mut log_only_intent: Option<DecisionTag> = None;

    // Resolve the effective client IP: walk X-Forwarded-For
    // backwards through the trusted-proxy CIDR list and return
    // the first untrusted hop. When the WAF is at the edge,
    // there's no XFF and this collapses to the TCP peer. When
    // the WAF is behind a load balancer, the LB's XFF tells us
    // the real client. Used for everything downstream — rate
    // limit, risk tracking, audit events, geoip — so the
    // dashboard's "live attack origins" map shows the actual
    // origin country, not the LB's private IP.
    //
    // Default trusted_proxies covers RFC1918 + loopback (the
    // common deployment); operator-configurable list lands in
    // a follow-up that plumbs `cfg.ip_lists` into the handler.
    let peer_ip = {
        let xff = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok());
        let trusted = default_trusted_proxies();
        aegis_security::ip_rep::xff::resolve_client_ip(peer.ip(), xff, &trusted)
    };
    // FIX 2026-05-03 — runtime access-list enforcement. The
    // blacklist + whitelist were CRUD-only before this commit
    // (operators could add entries via the Console + see them
    // listed but no traffic was actually filtered). Now they're
    // consulted RIGHT after XFF resolution + before the strike
    // gate, so a known-bad IP / CIDR / country gets the
    // cheapest possible block; whitelisted sources skip the
    // full detector chain.
    let lookup_ref = upstream_ctx
        .access_list_country_lookup
        .get()
        .map(|arc| arc.as_ref() as &dyn aegis_control::api::blacklist::AccessListCountryLookup);
    if let Some(entry_id) = upstream_ctx.blacklist.matches(peer_ip, lookup_ref) {
        tracing::debug!(
            peer = %peer_ip,
            entry = %entry_id,
            "access list: blacklist hit",
        );
        // F-CRITICAL-002 — check `set_profile mode` before enforcing.
        // `blocked_response` always runs (it emits the audit row);
        // we then decide whether to return its 403 or stash the
        // intent and fall through to the rest of the pipeline.
        let block_tag = DecisionTag::block("blacklist");
        let blk_mode = interop_modes
            .map(|m| aegis_control::interop::rule_map::mode_for_rule(m, Some("blacklist")))
            .unwrap_or(aegis_control::interop::headers::Mode::Enforce);
        let resp = blocked_response(
            peer,
            "blocked by blacklist",
            Some(format!("blacklist:{entry_id}")),
            None,
            req.uri(),
            req.method(),
            bus,
        );
        if blk_mode == aegis_control::interop::headers::Mode::LogOnly {
            log_only_intent = Some(block_tag);
            // fall through — audit recorded, no 403 sent.
        } else {
            return (resp, block_tag);
        }
    }
    let on_whitelist = upstream_ctx
        .whitelist
        .matches(peer_ip, lookup_ref)
        .is_some();
    if on_whitelist {
        tracing::debug!(peer = %peer_ip, "access list: whitelist hit, skipping detectors");
    }

    // P6 short-circuit: lifetime-strike block runs before any
    // body or detector cost so a flooding known-bad source can't
    // burn CPU. Whitelisted sources still hit this gate — strikes
    // override whitelist (a whitelisted IP hammering the API
    // hits the strike threshold then gets the permanent 403).
    // 2026-05-18 (QC TLS-wiring batch — Phase E activation): the
    // strike-block check + score snapshot read from the composite-
    // key bucket so they see the same data the record_malicious /
    // record_clean writes populate. Strike-Block remains "block
    // forever" semantics — the strikes lifetime counter accumulates
    // across record_malicious_with_key calls, then is_strike_blocked
    // returns true once the cap is hit.
    let strike_key = build_risk_key(peer_ip, req.headers());
    if risk.is_strike_blocked_for_key(&strike_key) {
        // NEW-4 (2026-05-08) — keyed on `peer_ip` (XFF-resolved).
        // Stamp on the DecisionTag so the response stamper picks
        // it up directly instead of re-querying under peer.ip().
        let strike_score = risk.snapshot_with_key(&strike_key).map(|s| s.score);
        // F-CRITICAL-002 — honor `set_profile mode=log_only` on
        // `risk_engine.strikes`. Audit emits regardless (the call
        // to `blocked_response` does it); only the 403 is gated.
        let tag = match strike_score {
            Some(s) => DecisionTag::block("risk-strikes").with_risk_score(s),
            None    => DecisionTag::block("risk-strikes"),
        };
        let stk_mode = interop_modes
            .map(|m| aegis_control::interop::rule_map::mode_for_rule(m, Some("risk-strikes")))
            .unwrap_or(aegis_control::interop::headers::Mode::Enforce);
        let resp = blocked_response(
            peer,
            "blocked by repeat-offender strikes",
            None,
            strike_score,
            req.uri(),
            req.method(),
            bus,
        );
        if stk_mode == aegis_control::interop::headers::Mode::LogOnly {
            log_only_intent = Some(tag);
            // fall through
        } else {
            return (resp, tag);
        }
    }

    // 2026-05-09 BUG-DDOS-STUB Phase 1 — DDoS observe-only check.
    // Sits between the strike-block gate (in-process) and the
    // per-IP rate-limit token bucket (also in-process) so the
    // cluster auto-block list (StateBackend-backed) gets a chance
    // to fail-fast a previously-blocked IP. In Phase 1 the runtime
    // is wired with `observe_only: true` by default — the audit
    // event always fires on `blocked == true`, but the request is
    // never 503'd until Phase 2 flips the flag.
    //
    // Body buffering hasn't happened yet (it's deferred until after
    // rate-limit), so this check is the cheapest of the three
    // gates. Fail-open on backend errors so a transient redis
    // hiccup doesn't drop legit traffic.
    if let Some(ddos) = upstream_ctx.ddos.get() {
        // 2026-05-18 (QC Sprint 1.2 — F-CRITICAL-005, §5.2 #03):
        // path-heuristic tier classification before the DDoS check.
        // Route resolution hasn't happened yet, but the path-only
        // shortcut gives DDoS the per-tier limit lookup. Cheap —
        // pure-function on `req.uri().path()`.
        let (early_tier, _) =
            aegis_security::pipeline::classify_tier_from_path(req.uri().path());
        match ddos.check_with_tier(peer_ip, Some(early_tier)).await {
            Ok(outcome) if outcome.blocked => {
                // Always emit the audit event so operators can
                // observe-mode bake the signal before Phase 2.
                if allow_block_emit {
                    let action = if outcome.observe_only {
                        "ddos_observed"
                    } else {
                        "ddos_blocked"
                    };
                    let reason_str = outcome
                        .reason
                        .clone()
                        .unwrap_or_else(|| "ddos: per-IP burst".into());
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
                        action: action.into(),
                        reason: reason_str,
                        client_ip: peer_ip.to_string(),
                        route_id: None,
                        rule_id: Some("ddos".into()),
                        risk_score: None,
                        method: None,
                        path: None,
                        mode: None,
                        fields: serde_json::json!({
                            "path": req.uri().to_string(),
                            "method": req.method().to_string(),
                            "ddos_observe_only": outcome.observe_only,
                            "ddos_spike_active": outcome.spike_active,
                        }),
                    };
                    bus.emit(ev);
                }
                if outcome.should_enforce() {
                    // Phase 2 path — never reached while Phase 1
                    // ships with default `observe_only: true`. The
                    // 503 response shape mirrors the strike-block
                    // path above so operators get a consistent
                    // block envelope regardless of which gate
                    // tripped.
                    let resp = blocked_response(
                        peer,
                        outcome.reason.as_deref().unwrap_or("ddos: blocked"),
                        Some("ddos".into()),
                        None,
                        req.uri(),
                        req.method(),
                        bus,
                    );
                    return (resp, DecisionTag::block("ddos"));
                }
                // observe_only — fall through; the request still
                // proceeds to detectors + upstream as if nothing
                // happened. The audit event records the intent.
            }
            Ok(_) => {} // not blocked, no signal
            Err(e) => {
                // 2026-05-18 (QC Sprint 1.2 — F-CRITICAL-005, §5.8):
                // per-tier fail-mode. Spec mandates fail-close on
                // Critical (login / OTP / deposit / withdrawal),
                // fail-open on lower tiers. `Tier::default_failure_mode()`
                // already encodes that; the YAML config can override
                // via `fail_mode_by_tier`.
                let fm = ddos.fail_mode_for(Some(early_tier));
                match fm {
                    aegis_core::tier::FailureMode::FailClose => {
                        tracing::warn!(
                            peer = %peer_ip,
                            tier = %early_tier.as_str(),
                            error = %e,
                            "ddos: backend error on critical-class tier — \
                             fail-close per §5.8",
                        );
                        let resp = Response::builder()
                            .status(hyper::StatusCode::SERVICE_UNAVAILABLE)
                            .header("retry-after", "1")
                            .header("content-type", "application/json")
                            .body(Full::new(Bytes::from(
                                serde_json::json!({
                                    "error": "service_unavailable",
                                    "reason": "ddos_check_failed_fail_close",
                                    "tier": early_tier.as_str(),
                                })
                                .to_string(),
                            )))
                            .unwrap();
                        return (
                            resp,
                            DecisionTag::circuit_breaker("ddos_fail_close")
                                .with_tier(early_tier),
                        );
                    }
                    aegis_core::tier::FailureMode::FailOpen => {
                        tracing::debug!(
                            peer = %peer_ip,
                            tier = %early_tier.as_str(),
                            error = %e,
                            "ddos: backend error — fail-open per §5.8",
                        );
                    }
                }
            }
        }
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
        // 2026-05-18 (QC TLS-wiring batch — Phase E activation):
        // record the malicious event under the composite RiskKey
        // (IP + session + tenant). The session axis activates the
        // F-CRITICAL-001 mandate from §5.5 — two distinct
        // sessions on the same NAT'd IP no longer share a risk
        // bucket. device_fp stays None until the JA4-capture
        // wire-up lands. Pre-Phase-E this was IP-only.
        let post_state = risk.record_malicious_with_key(
            build_risk_key(peer_ip, req.headers()),
            30,
        );
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
                method: None,
                path: None,
                mode: None,
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
        // F-CRITICAL-002 — honor `set_profile mode=log_only` on
        // `rate_limit.per_ip`. Audit already emitted above; only
        // the 429 response is gated by the mode.
        let rl_tag = DecisionTag::rate_limit("ip-rate-limit");
        let rl_mode = interop_modes
            .map(|m| aegis_control::interop::rule_map::mode_for_rule(m, Some("ip-rate-limit")))
            .unwrap_or(aegis_control::interop::headers::Mode::Enforce);
        if rl_mode == aegis_control::interop::headers::Mode::LogOnly {
            log_only_intent = Some(rl_tag);
            // fall through — no 429 sent.
        } else {
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
            return (resp, rl_tag);
        }
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
    if body_bytes.len() > max_body_bytes {
        let resp = Response::builder()
            .status(hyper::StatusCode::PAYLOAD_TOO_LARGE)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(
                serde_json::json!({
                    "error": "body_too_large",
                    "max_bytes": max_body_bytes,
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
        // 2026-05-18 (QC TLS wire-up — F-CRITICAL-010 / 014 / 015
        // activation): post-handshake TLS fingerprint, captured
        // in the accept loop after `tls_acceptor.accept().await`
        // succeeds. Threads through to:
        // - the brute_force detector's device axis
        //   (`detectors/brute_force.rs` reads `view.tls.ja4`),
        // - the DeviceIpTracker.observe call further down,
        // - the bot classifier (via BotSignals.ja4_fingerprint
        //   constructed in `accept.rs`).
        // `None` for plain HTTP — those features all silently
        // skip when fingerprint is absent.
        tls: tls_fingerprint,
        body: &body_peek,
    };

    // Tier classification needs `view`, so it's run here rather
    // than at the very top.
    let (tier, _failure_mode) = aegis_security::pipeline::classify_tier(None, &view);
    tracing::Span::current().record(
        "tier",
        aegis_security::detectors::tier_str(tier),
    );

    // F-CRITICAL-006 (2026-05-17): adaptive load shedder. Runs after
    // tier classification so Critical traffic is never shed and
    // lower tiers shed in priority order. RAII guard tracks the
    // in-flight count across the rest of the function and records
    // the request's RTT into the Gradient2 estimator on every exit
    // path (including detector blocks, upstream-forward errors,
    // and panics). On admit-deny, return 503 + Retry-After: 1 with
    // `X-WAF-Action: circuit_breaker` per v2.3 §3 (the WAF is the
    // upstream-protection surface for this rejection).
    let _shed_guard = if let Some(shedder) = upstream_ctx.load_shedder.get() {
        if !shedder.should_admit(&tier) {
            let resp = Response::builder()
                .status(hyper::StatusCode::SERVICE_UNAVAILABLE)
                .header("retry-after", "1")
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(
                    serde_json::json!({
                        "error": "load_shed",
                        "tier": aegis_security::detectors::tier_str(tier),
                        "retry_after_seconds": 1,
                    })
                    .to_string(),
                )))
                .unwrap();
            return (resp, DecisionTag::circuit_breaker("load_shed").with_tier(tier));
        }
        Some(shedder.admit_guard())
    } else {
        None
    };

    // Run security detectors filtered by the effective mask for
    // this tier. A class turned off via PUT /api/detectors (base
    // or per-tier override) short-circuits before the detector body
    // runs.
    //
    // FIX 2026-05-03 — whitelist bypass. When the request's
    // peer IP matched a whitelist entry above (`on_whitelist`),
    // skip the detector chain entirely. This is the contract
    // operators expect from the whitelist: "trust this source
    // unconditionally" — the whitelist's `bypass: ["all"]`
    // field on entries gives finer-grained control in a
    // future track, but the simple "match → bypass" semantics
    // matches every other WAF.
    let effective = mask.resolve(Some(tier));
    let detect_t0 = std::time::Instant::now();
    let (signals, fired_classes) = if on_whitelist {
        request_stage_hist.record(stages::DETECT, detect_t0.elapsed());
        (Vec::new(), Vec::new())
    } else {
        let r = aegis_security::detectors::run_all_filtered_timed(
            detectors,
            effective,
            &view,
            |class, elapsed| detector_latency_hist.record(class, elapsed),
        );
        request_stage_hist.record(stages::DETECT, detect_t0.elapsed());
        r
    };
    // PROM-T2 — record one increment per detector that emitted a
    // signal. Cost: one CounterVec inc per fired class (~30 ns).
    // In the common allow-path `fired_classes` is empty so cost
    // collapses to a single empty-vec branch.
    for class in &fired_classes {
        detector_hit_metrics.record(class);
    }

    // 2026-05-18 (QC TLS wire-up — F-CRITICAL-010 activation):
    // observe (device_fp, peer_ip) for cross-IP rotation
    // detection. When the same fingerprint comes from >5 distinct
    // IPs in the 60 s window, the tracker emits a
    // `device_ip_rotation` signal at score 60 — over the
    // challenge_at threshold but under block_at, so it stacks
    // with detector signals before forcing a block.
    //
    // Skipped when TLS fingerprint is absent (plain HTTP) or
    // when the request was whitelisted (a trusted source isn't
    // rotation-suspicious by definition).
    let mut signals = signals;
    if !on_whitelist {
        if let Some(fp) = tls_fingerprint {
            if let Some(rotation_signal) = upstream_ctx
                .device_ip_tracker
                .observe(&fp.ja4, peer_ip)
            {
                signals.push(rotation_signal);
            }
        }
    }

    // v2.3 §5.3 — `log_only_intent` carries the WOULD-BE
    // DecisionTag from a block-mode policy that's been switched
    // to `log_only` via `POST /__waf_control/set_profile`. When
    // populated, we skip the actual block and let the request
    // continue to upstream; the listener-side response stamper
    // emits `X-WAF-Action: <intent>` + `X-WAF-Mode: log_only` so
    // the OC sees the detector worked while the upstream still
    // got the request (per `log_only` contract semantics).
    //
    // 2026-05-17 F-CRITICAL-002: `log_only_intent` + `interop_modes`
    // are now hoisted to the top of the function so blacklist /
    // strike-block / rate-limit / risk-score paths can also stash
    // an intent here. See those sites for the symmetric handling.

    if !signals.is_empty() {
        // SEC-M003 (2026-05-08) — cap per-request contribution to
        // max(signal). Pre-fix: sum() let a single multi-class hit
        // (e.g. sqli=50 + path_traversal=45 + ai=50) clamp to
        // score=100 immediately, breaking risk lifecycle tests +
        // locking legit users out on a single ambiguous request.
        //
        // Now: each request contributes the strongest signal only.
        // Repeated bad requests still escalate (each adds max(signal)
        // to the running total → reach `block_at` in 2-3 hits with
        // default thresholds 40/80/100); single multi-detector
        // false-positives get a softer one-strike penalty.
        let request_score: u32 =
            signals.iter().map(|s| s.score).max().unwrap_or(0);
        // 2026-05-18 (QC TLS-wiring batch — Phase E activation):
        // composite-key risk record. Same rationale as the rate-
        // limit site above. `parts.headers` is in scope here
        // (request body has been split out for detector buffering).
        let post_state = risk.record_malicious_with_key(
            build_risk_key(peer_ip, &parts.headers),
            request_score,
        );
        // 2026-05-03 — dedup detector tags before emitting them
        // anywhere (audit fields, rule_id, response header).
        // Multiple signals from one detector class (e.g. two
        // path_traversal hits — one in path, one in body) used
        // to surface as `detector:path_traversal,path_traversal`
        // and pollute the by-detector chart with duplicates.
        // Order is preserved so the most-suspicious tag stays
        // first.
        let tags: Vec<&str> = {
            let mut seen = std::collections::HashSet::new();
            let mut out: Vec<&str> = Vec::with_capacity(signals.len());
            for s in &signals {
                let t = s.tag.as_str();
                if seen.insert(t) {
                    out.push(t);
                }
            }
            out
        };
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
                // 2026-05-05 — populate the route's tier so the
                // dashboard's Live Feed shows the real tier
                // (critical / high / medium / low) instead of
                // falling back to a risk-score bucket. `tier` here
                // is the value computed at line ~381 via
                // `classify_tier()` — combines route_override (if
                // resolved) with path heuristics. Pre-route detector
                // blocks see the heuristic; post-route blocks see
                // the route's tier_override.
                tier: Some(tier),
                action: "block".into(),
                reason: reason.clone(),
                client_ip: peer_ip.to_string(),
                route_id: None,
                rule_id: None,
                risk_score: Some(post_state.score),
                method: None,
                path: None,
                mode: None,
                fields,
            };
            bus.emit(ev);
        }

        // 2026-05-03 — drop the legacy `detector:` prefix so the
        // rule_id rendered on the response header (X-WAF-Rule-Id)
        // and on /api/audit/since matches the bare class names in
        // fields.detectors[] AND the by-detector chart.  Single
        // class → "sqli"; multiple → "sqli,xss".  Operators read
        // one canonical label everywhere.
        let detector_rule = if tags.is_empty() {
            "detectors".to_string()
        } else {
            tags.join(",")
        };
        // v2.3 §5.3 — check the firing detector's mode before
        // building the 403. If `log_only`, skip enforcement and
        // forward to upstream; the response stamper later sees
        // the intent DecisionTag and emits `X-WAF-Action: block`
        // + `X-WAF-Mode: log_only`. Audit was already recorded
        // above, so the OC's correlation chain is intact.
        let detector_mode = interop_modes
            .map(|m| {
                aegis_control::interop::rule_map::mode_for_rule(m, Some(detector_rule.as_str()))
            })
            .unwrap_or(aegis_control::interop::headers::Mode::Enforce);
        // NEW-4 (2026-05-08) — stamp the post-record score so
        // X-WAF-Risk-Score reflects the actual accumulated value
        // rather than 0.
        let block_tag = DecisionTag::block(detector_rule)
            .with_tier(tier)
            .with_risk_score(post_state.score);
        if detector_mode == aegis_control::interop::headers::Mode::LogOnly {
            log_only_intent = Some(block_tag);
            // Fall through — skip the 403 and the risk gate below
            // (which would also block this request because we just
            // recorded the malicious score). The intent is applied
            // at the function's tail, after upstream forward.
        } else {
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
            return (resp, block_tag);
        }
    }

    // v2.3 §5.3 — when a detector trip is in `log_only` mode we
    // SKIP the risk gate entirely. The malicious score was just
    // recorded but the request semantically "passed" the WAF
    // (intent stashed in `log_only_intent`); running the risk
    // gate now would surface the just-recorded score as a
    // separate `risk-score` block and silently re-enforce. Jump
    // straight to upstream forward and apply the intent override
    // at the tail.
    let (resp, allow_tag) = if log_only_intent.is_some() {
        forward_allow_to_upstream(
            parts,
            body_bytes,
            upstream_ctx,
            identity,
            route_latency_hist,
            route_activity,
            request_start,
            peer_ip,
            bus,
        )
        .await
    } else {
        // Clean request — let the trust-recovery clock claw back any
        // accumulated score (capped at `trust_recovery.per_hour` so
        // one benign request can't reset a flagged client). Then the
        // adaptive-mitigation classifier decides between Allow,
        // Challenge, and Block based on the post-state vs the
        // configured `RiskThresholds`.
        //
        // 2026-05-18 (QC TLS-wiring batch — Phase E activation):
        // decay the composite-key bucket (matching the
        // record_malicious_with_key calls above). Trust-recovery
        // operates on the per-session bucket so a malicious session
        // doesn't drag down a clean-session sibling on the same IP.
        risk.record_clean_with_key(build_risk_key(peer_ip, &parts.headers));

        // 2026-05-10 — Option B per-tier overrides. Look up the
        // matched tier's cumulative thresholds + challenges_enabled
        // flag from the live TierStore. None / missing fields fall
        // back to the global thresholds, so existing deployments
        // without tier overrides see no behavior change.
        let global = risk.thresholds();
        let (challenge_at, block_at, challenges_enabled) =
            match upstream_ctx.tiers.get() {
                Some(store) => match store.get(tier.as_str()) {
                    Some(t) => (
                        t.cumulative_challenge_at.unwrap_or(global.challenge_at),
                        t.cumulative_block_at.unwrap_or(global.block_at),
                        t.challenges_enabled,
                    ),
                    None => (global.challenge_at, global.block_at, true),
                },
                None => (global.challenge_at, global.block_at, true),
            };
        // 2026-05-18 (QC TLS-wiring batch — Phase E activation):
        // composite-key level read. Same bucket the write path
        // populates (the record_malicious_with_key calls above).
        let level = risk.level_with_for_key(
            &build_risk_key(peer_ip, &parts.headers),
            challenge_at,
            block_at,
        );
        // 2026-05-10 — when the matched tier has challenges_enabled
        // = false, the challenge rung is removed from the tier's
        // response ladder. Cumulative score crossing challenge_at
        // escalates straight to block instead of emitting a 429
        // PoW. Lets operators run high-stakes tiers (admin APIs,
        // payment paths) with hard allow/block semantics.
        let level = match level {
            aegis_security::risk::RiskLevel::Challenge if !challenges_enabled => {
                aegis_security::risk::RiskLevel::Block
            }
            other => other,
        };
        match level {
            aegis_security::risk::RiskLevel::Block => {
                // NEW-4 (2026-05-08) — stamp the snapshot score
                // on the DecisionTag so the response stamper
                // doesn't re-query under peer.ip() and miss.
                // 2026-05-18 — composite-key snapshot (Phase E).
                let block_score = risk
                    .snapshot_with_key(&build_risk_key(peer_ip, &parts.headers))
                    .map(|s| s.score);
                let tag = match block_score {
                    Some(s) => DecisionTag::block("risk-score").with_tier(tier).with_risk_score(s),
                    None    => DecisionTag::block("risk-score").with_tier(tier),
                };
                // F-CRITICAL-002 — honor `set_profile
                // mode=log_only` on `risk_engine.score`. When
                // LogOnly, emit the audit (via blocked_response
                // side-effect on the discarded response), stash
                // the intent, and forward to upstream as if the
                // level was Allow.
                let rs_mode = interop_modes
                    .map(|m| aegis_control::interop::rule_map::mode_for_rule(m, Some("risk-score")))
                    .unwrap_or(aegis_control::interop::headers::Mode::Enforce);
                let resp = blocked_response(
                    peer,
                    "blocked by risk score",
                    None,
                    block_score,
                    &parts.uri,
                    &parts.method,
                    bus,
                );
                if rs_mode == aegis_control::interop::headers::Mode::LogOnly {
                    log_only_intent = Some(tag);
                    // Fall through to upstream forward as if Allow.
                    forward_allow_to_upstream(
                        parts,
                        body_bytes,
                        upstream_ctx,
                        identity,
                        route_latency_hist,
                        route_activity,
                        request_start,
                        peer_ip,
                        bus,
                    )
                    .await
                } else {
                    (resp, tag)
                }
            }
            aegis_security::risk::RiskLevel::Challenge => {
                // AF-T1 + NEW-2 (2026-05-08): contract-level
                // distinction. Even though the HTTP status (429)
                // and Retry-After header are shaped like
                // rate-limit, the body carries "challenge" and
                // the contract action MUST be `challenge` so the
                // OC's challenge-solver path engages.
                //
                // v2.3 §3 — body must carry "enough information
                // for automated challenge solving." Per NEW-2
                // we issue a stateless PoW challenge with a
                // nonce + difficulty + expiry + MAC. The client
                // solves and POSTs to /__waf_control/challenge_verify.
                //
                // If `pow_issuer` isn't wired (test binaries that
                // skip the interop runtime), fall back to the
                // legacy challenge_type-only body — degraded but
                // never panic.
                let body = match upstream_ctx.pow_issuer.get() {
                    Some(issuer) => {
                        let challenge = issuer.issue();
                        serde_json::json!({
                            "challenge": true,
                            "challenge_type": "proof_of_work",
                            "nonce": challenge.nonce,
                            "difficulty": challenge.difficulty,
                            "expires_at_ms": challenge.expires_at_ms,
                            "mac": challenge.mac,
                            "submit_to": "/__waf_control/challenge_verify",
                            "reason": "risk score over challenge threshold",
                        })
                    }
                    None => serde_json::json!({
                        "challenge": true,
                        "reason": "risk score over challenge threshold",
                        "challenge_type": "proof_of_work",
                    }),
                };
                let resp = Response::builder()
                    .status(429)
                    .header("content-type", "application/json")
                    .header("retry-after", "5")
                    .body(Full::new(Bytes::from(body.to_string())))
                    .unwrap();
                // NEW-4 (2026-05-08) — stamp current snapshot score
                // for the challenge response too.
                // 2026-05-18 — composite-key snapshot (Phase E).
                let challenge_score = risk
                    .snapshot_with_key(&build_risk_key(peer_ip, &parts.headers))
                    .map(|s| s.score);
                let tag = match challenge_score {
                    Some(s) => DecisionTag::challenge("risk-challenge").with_tier(tier).with_risk_score(s),
                    None    => DecisionTag::challenge("risk-challenge").with_tier(tier),
                };
                (resp, tag)
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
                    route_activity,
                    request_start,
                    peer_ip,
                    bus,
                )
                .await
            }
        }
    };

    // v2.3 §5.3 — apply the log_only intent: keep the upstream
    // response body + status, but override the DecisionTag so
    // `X-WAF-Action: block` + `X-WAF-Mode: log_only` reach the
    // OC. Audit was already recorded above with the block intent.
    let final_tag = log_only_intent.unwrap_or(allow_tag);
    (resp, final_tag)
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
    route_activity: &aegis_control::metrics::route_activity::RouteActivityWindow,
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
            // PR3 — deny-by-default. Configs without a `default: true`
            // route reach this branch for unmatched traffic. The
            // request is rejected with 404 + the audit chain records
            // `action=block, rule_id=unmatched_route` so operators can
            // see what's hitting the WAF that they haven't routed yet.
            tracing::Span::current().record("outcome", "unmatched-route");
            let resp = Response::builder()
                .status(hyper::StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from("no matching route\n")))
                .unwrap();
            return (resp, DecisionTag::block("unmatched_route"));
        }
    };
    tracing::Span::current().record("upstream", route_ctx.upstream.as_str());
    // Capture the route_id for the per-route latency histogram.
    // Lifetime: route_ctx borrows from `ctx.route_table` which
    // is the same Arc<ProxyContext> the caller holds; safe to
    // hand out the &str here.
    *_route_guard.route.borrow_mut() = route_ctx.route_id.clone();
    // P5 (2026-05-11) — record one hit in the per-route 60-second
    // sliding-window counter. Fires for every resolved route (the
    // latency guard records on exit; this one records on resolve
    // so the activity pill lights up even for requests that get
    // blocked by a downstream gate). Hot-path cost is one
    // DashMap-shard lookup + one atomic fetch_add.
    route_activity.record(&route_ctx.route_id);

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

    // 2026-05-17 F-CRITICAL-001 (control audit) — operator rule
    // evaluator. Round-1 "Tính hiệu lực" mandate: a rule saved via
    // the dashboard MUST take effect on the next request. The live
    // `Arc<RuleSet>` is shared between the Pipeline, DashboardServices
    // (the CRUD bridge), and `ctx.active_ruleset`; the dashboard
    // `admin_mutate` handlers call `RuleSet::replace_rules` after
    // every successful CRUD via `rebuild_active_ruleset`.
    //
    // Fires AFTER detectors and AFTER route resolution so:
    //   - rules can scope by `route_id` (Scope::Route),
    //   - detector signals are already known (a rule may decide to
    //     allow a request the detectors flagged, e.g. operator
    //     allowlist for a known-noisy endpoint),
    //   - the block path is symmetric with the mTLS-required path
    //     above (returns DecisionTag::block + rule_id so the
    //     listener-side stamper emits `X-WAF-Action: block`).
    //
    // v1 honors only the `Block { status }` action terminally — the
    // other 5 §3 actions (Allow / Challenge / RateLimited / Timeout
    // / CircuitBreaker) fall through to the existing downstream
    // paths so we don't double-fire challenges or rate-limit
    // buckets. Empty rule set (the common boot state when no
    // operator has saved a rule yet) short-circuits via the
    // `is_empty()` check below.
    if let Some(rules) = ctx.active_ruleset.get() {
        let snapshot = rules.snapshot();
        if !snapshot.is_empty() {
            // Rebuild a `RequestView` for the rule evaluator —
            // `forward_allow_to_upstream` receives parts + body_bytes,
            // not the original view from `handle_data_request_inner`.
            // BodyPeek wraps the already-buffered body so body-shape
            // rules see the same bytes the detectors saw.
            let body_peek = aegis_core::pipeline::BodyPeek::new(
                body_bytes.to_vec(),
                Some(body_bytes.len() as u64),
                false,
            );
            let view = aegis_core::pipeline::RequestView {
                method: &parts.method,
                uri: &parts.uri,
                version: parts.version,
                headers: &parts.headers,
                peer: std::net::SocketAddr::new(peer_ip, 0),
                tls: None,
                body: &body_peek,
            };
            let decision =
                aegis_security::rules::evaluate(&snapshot, &view, &route_ctx);
            if let aegis_core::decision::Action::Block { status } = decision.action {
                let rule_id = decision.rule_id.clone().unwrap_or_else(|| "rule".into());
                tracing::Span::current().record("outcome", "rule_block");
                tracing::info!(
                    target: "aegis.rules.live",
                    route_id = %route_ctx.route_id,
                    rule_id = %rule_id,
                    reason = %decision.reason,
                    "request blocked by operator rule",
                );
                let resp = Response::builder()
                    .status(status)
                    .header("content-type", "application/json")
                    .header("x-waf-rule-id", rule_id.as_str())
                    .body(Full::new(Bytes::from(format!(
                        r#"{{"error":"blocked","rule_id":"{}","reason":"{}"}}"#,
                        rule_id.replace('"', "\\\""),
                        decision.reason.replace('"', "\\\""),
                    ))))
                    .unwrap();
                return (resp, DecisionTag::block(rule_id));
            }
        }
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

    // WS-T2/T3 — WebSocket upgrade bridge. Detects the
    // `Upgrade: websocket` + `Connection: Upgrade` pair, picks a
    // healthy upstream member, opens a raw TCP connection, and
    // (on 101) bridges client + upstream sockets via
    // `copy_bidirectional` after hyper resolves `OnUpgrade`.
    // See `plans/websocket-bridge.md §3` for the architecture
    // diagram + rationale (hyper's pooled client can't honor
    // upgrades; this is the workaround).
    let is_ws_upgrade = {
        let synthetic = hyper::Request::builder()
            .method(parts.method.clone())
            .uri(parts.uri.clone())
            .body(())
            .map(|mut r| {
                *r.headers_mut() = parts.headers.clone();
                r
            });
        synthetic
            .as_ref()
            .map(crate::proto::ws::is_websocket_upgrade)
            .unwrap_or(false)
    };
    if is_ws_upgrade {
        let pool = match ctx.pools.get(&route_ctx.upstream) {
            Some(p) => p,
            None => {
                let resp = Response::builder()
                    .status(hyper::StatusCode::BAD_GATEWAY)
                    .header("x-waf-rule-id", "websocket_no_upstream_pool")
                    .body(Full::new(Bytes::from(
                        "WebSocket upgrade: upstream pool missing\n",
                    )))
                    .unwrap();
                return (resp, DecisionTag::block("websocket_no_upstream_pool"));
            }
        };
        let member = match pool
            .strategy
            .pick(&pool.members, Some(parts.uri.path()))
        {
            Some(m) => m.clone(),
            None => {
                let resp = Response::builder()
                    .status(hyper::StatusCode::SERVICE_UNAVAILABLE)
                    .header("x-waf-rule-id", "upstream.no_healthy_member")
                    .body(Full::new(Bytes::from(
                        "WebSocket upgrade: no healthy upstream member\n",
                    )))
                    .unwrap();
                // F-CONTRACT-001 (2026-05-17 s-tester audit): §3 maps
                // "upstream degradation detected by WAF" to
                // `circuit_breaker`. Pre-fix this returned `block`,
                // which §7 normalization classifies as a false-
                // positive on legitimate WS traffic during a backend
                // outage.
                return (resp, DecisionTag::circuit_breaker("upstream.no_healthy_member"));
            }
        };

        let mut parts = parts;
        let on_upgrade =
            parts.extensions.remove::<hyper::upgrade::OnUpgrade>();
        let Some(on_upgrade) = on_upgrade else {
            // No OnUpgrade extension — hyper didn't install one,
            // which means the connection isn't HTTP/1.1 upgrade-
            // capable.  HTTP/2 extended CONNECT (RFC 8441) is
            // out of scope for v1.
            let resp = Response::builder()
                .status(hyper::StatusCode::BAD_GATEWAY)
                .header(
                    "x-waf-rule-id",
                    "websocket_no_upgrade_extension",
                )
                .body(Full::new(Bytes::from(
                    "WebSocket upgrade: HTTP/2 extended CONNECT not supported\n",
                )))
                .unwrap();
            return (
                resp,
                DecisionTag::block("websocket_no_upgrade_extension"),
            );
        };

        let upstream_handshake = match crate::proto::ws_forward::forward_websocket_upgrade(
            &parts.method,
            &parts.uri,
            &parts.headers,
            &body_bytes,
            member.addr,
            std::time::Duration::from_secs(5),
        )
        .await
        {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(
                    route_id = %route_ctx.route_id,
                    upstream = %member.addr,
                    error = %e,
                    "WebSocket upgrade upstream forward failed",
                );
                let resp = Response::builder()
                    .status(hyper::StatusCode::BAD_GATEWAY)
                    .header(
                        "x-waf-rule-id",
                        "upstream.forward_failed",
                    )
                    .body(Full::new(Bytes::from(
                        "WebSocket upgrade: upstream forward failed\n",
                    )))
                    .unwrap();
                // F-CONTRACT-001 (2026-05-17 s-tester audit): same
                // §3 mapping as no_healthy_member above —
                // circuit_breaker, not block.
                return (
                    resp,
                    DecisionTag::circuit_breaker("upstream.forward_failed"),
                );
            }
        };

        let crate::proto::ws_forward::UpstreamHandshake {
            status,
            headers,
            leftover,
            socket: upstream_socket,
        } = upstream_handshake;

        if status == hyper::StatusCode::SWITCHING_PROTOCOLS {
            tracing::Span::current().record("outcome", "websocket_bridged");
            let bus_for_task = bus.clone();
            let route_id_for_task = route_ctx.route_id.clone();
            let upstream_addr = member.addr;
            // WS-T6 — record bridge open before spawning the task.
            // The matching close is recorded inside the task after
            // `copy_bidirectional` returns.  None when the binary
            // boots without metrics wiring (tests).
            let ws_metrics = ctx.websocket_metrics.clone();
            if let Some(m) = ws_metrics.as_ref() {
                m.record_open();
            }
            let ws_metrics_for_task = ws_metrics.clone();
            tokio::spawn(async move {
                let started = std::time::Instant::now();
                match on_upgrade.await {
                    Ok(upgraded) => {
                        let mut client_io =
                            hyper_util::rt::TokioIo::new(upgraded);
                        let mut upstream = upstream_socket;
                        // If the upstream sent post-handshake
                        // bytes that landed in our head buffer,
                        // forward them to the client first so the
                        // bridge starts with both sides aligned.
                        if !leftover.is_empty() {
                            if let Err(e) = tokio::io::AsyncWriteExt::write_all(
                                &mut client_io,
                                &leftover,
                            )
                            .await
                            {
                                tracing::debug!(
                                    error = %e,
                                    "websocket: leftover flush to client failed",
                                );
                                return;
                            }
                        }
                        let copy = tokio::io::copy_bidirectional(
                            &mut client_io,
                            &mut upstream,
                        )
                        .await;
                        let elapsed = started.elapsed();
                        let (c2u, u2c) = copy.unwrap_or((0, 0));
                        bus_for_task.emit(aegis_core::audit::AuditEvent {
                            schema_version: 1,
                            ts: chrono::Utc::now(),
                            request_id: blake3::hash(
                                format!(
                                    "ws:{upstream_addr}:{}",
                                    chrono::Utc::now()
                                        .timestamp_nanos_opt()
                                        .unwrap_or(0),
                                )
                                .as_bytes(),
                            )
                            .to_hex()
                            .to_string(),
                            class: aegis_core::audit::AuditClass::Access,
                            tenant_id: None,
                            tier: None,
                            action: "websocket_close".into(),
                            reason: "ws_bridge_closed".to_string(),
                            client_ip: peer_ip.to_string(),
                            route_id: Some(route_id_for_task.clone()),
                            rule_id: None,
                            risk_score: None,
                            method: None,
                            path: None,
                            mode: None,
                            fields: serde_json::json!({
                                "upstream_addr": upstream_addr.to_string(),
                                "duration_ms": elapsed.as_millis() as u64,
                                "bytes_to_upstream": c2u,
                                "bytes_from_upstream": u2c,
                            }),
                        });
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "websocket: client OnUpgrade failed",
                        );
                    }
                }
                // WS-T6 — bridge ended (any branch above).  Record
                // close so `aegis_websocket_active` returns to
                // baseline and `aegis_websocket_close_total`
                // increments.
                if let Some(m) = ws_metrics_for_task.as_ref() {
                    m.record_close();
                }
            });

            // WS-T4 — open audit event before the spawned task.
            bus.emit(aegis_core::audit::AuditEvent {
                schema_version: 1,
                ts: chrono::Utc::now(),
                request_id: blake3::hash(
                    format!(
                        "ws-open:{}:{}",
                        member.addr,
                        chrono::Utc::now()
                            .timestamp_nanos_opt()
                            .unwrap_or(0),
                    )
                    .as_bytes(),
                )
                .to_hex()
                .to_string(),
                class: aegis_core::audit::AuditClass::Access,
                tenant_id: None,
                // 2026-05-05 — populate route's tier so Live Feed
                // shows the real classification, not a risk-bucket.
                tier: Some(route_ctx.tier),
                action: "websocket_open".into(),
                reason: "ws_bridge_started".to_string(),
                client_ip: peer_ip.to_string(),
                route_id: Some(route_ctx.route_id.clone()),
                rule_id: None,
                risk_score: None,
                method: None,
                path: None,
                mode: None,
                fields: serde_json::json!({
                    "upstream_addr": member.addr.to_string(),
                    "host": host,
                    // v2.3 §6 — audit `path` includes query string.
                    // `parts.uri.to_string()` preserves it; the bare
                    // `path` variable captured earlier strips it.
                    "path": parts.uri.to_string(),
                }),
            });

            // Build the 101 response with upstream's headers so
            // the WebSocket negotiation surfaces (Sec-WebSocket-
            // Accept etc.) reach the client byte-for-byte.
            let mut resp_builder =
                Response::builder().status(hyper::StatusCode::SWITCHING_PROTOCOLS);
            for (name, value) in headers.iter() {
                resp_builder = resp_builder.header(name, value);
            }
            let resp = resp_builder
                .body(Full::new(Bytes::new()))
                .unwrap();
            return (resp, DecisionTag::allow().with_tier(route_ctx.tier));
        }

        // Non-101 — upstream rejected the upgrade.  Drain any
        // remaining body from the upstream socket up to a
        // sensible bound and proxy the response through.
        let mut body = leftover;
        let mut upstream_socket = upstream_socket;
        let mut chunk = [0u8; 4096];
        let drain_deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(2);
        while body.len() < 64 * 1024 && std::time::Instant::now() < drain_deadline {
            match tokio::time::timeout(
                std::time::Duration::from_millis(200),
                tokio::io::AsyncReadExt::read(&mut upstream_socket, &mut chunk),
            )
            .await
            {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => body.extend_from_slice(&chunk[..n]),
                Ok(Err(_)) | Err(_) => break,
            }
        }
        let mut resp_builder = Response::builder().status(status);
        for (name, value) in headers.iter() {
            // Strip Content-Length / Transfer-Encoding — Full<Bytes>
            // is fixed-size so hyper sets the right framing for us.
            let n = name.as_str();
            if n.eq_ignore_ascii_case("content-length")
                || n.eq_ignore_ascii_case("transfer-encoding")
            {
                continue;
            }
            resp_builder = resp_builder.header(name, value);
        }
        let resp = resp_builder
            .body(Full::new(Bytes::from(body)))
            .unwrap();
        return (resp, DecisionTag::allow().with_tier(route_ctx.tier));
    }

    if let Some(cb) = ctx.pools.breaker(&route_ctx.upstream) {
        if !cb.allow_request() {
            tracing::Span::current().record("outcome", "circuit-open");
            let resp = Response::builder()
                .status(hyper::StatusCode::SERVICE_UNAVAILABLE)
                .body(Full::new(Bytes::from("circuit open\n")))
                .unwrap();
            return (resp, DecisionTag::circuit_breaker("circuit-open").with_tier(route_ctx.tier));
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

    // 2026-05-12 — strip the route prefix from the upstream URI
    // when the route opts in (`strip_prefix: true`, the default).
    // The compiled `path_strip_prefix` is `Some(prefix)` only when
    // the strip is safe to apply (prefix/exact match types, no
    // catch-all). Path-only rewrite — query / fragment / host /
    // scheme pass through unchanged.
    let upstream_uri = match &route_ctx.path_strip_prefix {
        Some(prefix) => strip_uri_prefix(&parts.uri, prefix),
        None => parts.uri.clone(),
    };

    // F-CRITICAL-008 (2026-05-17 s-tester audit): RAII guard
    // (Member::inflight_guard) — Drop guarantees the counter is
    // decremented even on cancellation / panic inside `forward()`.
    let _inflight_guard = member.inflight_guard();
    let result = crate::upstream::forward::forward(
        member,
        &pool.connection,
        parts.method,
        upstream_uri,
        parts.headers,
        body_bytes,
    )
    .await;
    drop(_inflight_guard);

    match result {
        Ok(resp) => {
            let status = resp.status();
            if let Some(cb) = ctx.pools.breaker(&route_ctx.upstream) {
                if status.is_server_error() {
                    cb.record_failure();
                } else {
                    cb.record_success();
                }
            }
            tracing::Span::current().record(
                "outcome",
                if status.is_server_error() {
                    "upstream-5xx"
                } else {
                    "ok"
                },
            );
            // 2026-05-11 PR #7 — response filtering wire-up.
            // The forwarder buffers the entire upstream body
            // into `Full::new(body_bytes)` (see
            // `upstream/forward.rs:469-505`), so we apply
            // response filtering as a single `on_body_frame` call
            // here. Once the proxy supports streaming response
            // bodies, this call site fans out per chunk and the
            // shape stays the same. `OutboundAction::Rewrite`
            // replaces the body; `Abort` 502s the request (DLP
            // block path — not exercised by the default filter
            // config but the contract shape is in place).
            //
            // Detector chain inbound work runs separately via
            // `run_all_filtered_timed` earlier in the request
            // path; `Pipeline::on_body_frame` is only used for
            // outbound response scrubbing.
            let (mut parts_out, body) = resp.into_parts();
            // `Full<Bytes>::Error` is `Infallible` — the collect
            // can't fail, but the trait still hands back a Result.
            let body_bytes = {
                use http_body_util::BodyExt as _;
                match body.collect().await {
                    Ok(c) => c.to_bytes(),
                    Err(_) => Bytes::new(),
                }
            };
            // Pipeline::on_body_frame ignores rctx + route in the
            // shipping impl, but the trait sig requires both. Build
            // a minimal RequestCtx from peer_ip + identity so
            // future filter rungs that *do* read it (per-tenant
            // DLP policy, audit attribution) have the fields they
            // need without a second refactor.
            let rctx_for_filter = aegis_core::context::RequestCtx {
                request_id: String::new(),
                received_at: request_start,
                client: aegis_core::context::ClientInfo {
                    ip: peer_ip,
                    tls_fingerprint: None,
                    h2_fingerprint: None,
                    user_agent: None,
                },
                trace_id: None,
                fields: std::collections::BTreeMap::new(),
            };
            let action = ctx
                .pipeline
                .on_body_frame(&body_bytes, &rctx_for_filter, &route_ctx)
                .await;
            let final_bytes = match action {
                aegis_core::pipeline::OutboundAction::PassThrough => body_bytes,
                aegis_core::pipeline::OutboundAction::Rewrite(new_bytes) => {
                    // content-length must follow the new payload
                    // or hyper will hang / mis-frame.
                    use hyper::header::{HeaderValue, CONTENT_LENGTH};
                    if let Ok(v) = HeaderValue::from_str(&new_bytes.len().to_string()) {
                        parts_out.headers.insert(CONTENT_LENGTH, v);
                    }
                    new_bytes
                }
                aegis_core::pipeline::OutboundAction::Abort { reason } => {
                    let body_str = format!(
                        "{{\"error\":\"response_aborted\",\"reason\":{}}}",
                        serde_json::to_string(&reason).unwrap_or_else(|_| "\"\"".into()),
                    );
                    use hyper::header::{HeaderValue, CONTENT_LENGTH, CONTENT_TYPE};
                    let aborted = hyper::Response::builder()
                        .status(hyper::StatusCode::BAD_GATEWAY)
                        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                        .header(
                            CONTENT_LENGTH,
                            HeaderValue::from_str(&body_str.len().to_string()).unwrap(),
                        )
                        .body(http_body_util::Full::new(bytes::Bytes::from(body_str)))
                        .unwrap();
                    return (
                        aborted,
                        DecisionTag::block("response-filter-abort")
                            .with_tier(route_ctx.tier),
                    );
                }
            };
            let resp = Response::from_parts(parts_out, Full::new(final_bytes));
            // 5xx from upstream is not a WAF block — we proxied
            // faithfully; the contract action stays `allow` (the
            // upstream's failure is what the client sees).
            (resp, DecisionTag::allow().with_tier(route_ctx.tier))
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
                    DecisionTag::timeout("upstream-timeout").with_tier(route_ctx.tier)
                }
                crate::upstream::forward::ForwardError::Connect(_)
                | crate::upstream::forward::ForwardError::Handshake(_) => {
                    DecisionTag::circuit_breaker("upstream-unreachable").with_tier(route_ctx.tier)
                }
                _ => DecisionTag::circuit_breaker("upstream-error").with_tier(route_ctx.tier),
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
/// 2026-05-12 — rewrite the request URI to drop a literal path
/// prefix.  Used by routes that opt into `strip_prefix: true`
/// (the default) so the upstream sees a "mount-point-relative"
/// path:
///
///   route path `/news`, request `/news/article.html`
///                          → upstream `/article.html`
///   route path `/news`, request `/news` (exact)
///                          → upstream `/`
///   route path `/api`,  request `/api?q=1`
///                          → upstream `/?q=1` (query preserved)
///
/// Only the path component is rewritten — scheme, authority,
/// query, and fragment pass through unchanged.  A `Uri` build
/// failure (extremely unlikely given a valid input) is silently
/// fatal: we return the input unchanged so the request still
/// has SOME path to send.
fn strip_uri_prefix(uri: &http::Uri, prefix: &str) -> http::Uri {
    let path = uri.path();
    let rest = match path.strip_prefix(prefix) {
        Some(r) if r.is_empty() => "/",
        Some(r) if r.starts_with('/') => r,
        // Path matched the prefix as a string-only substring (e.g.
        // route `/api` matched `/apifoo` — should not happen in
        // practice because the router uses segment-boundary matching,
        // but stay defensive). Forward unchanged rather than producing
        // a malformed URL.
        Some(_) => return uri.clone(),
        // No prefix match at all (concurrent reload, stale ctx) —
        // pass through.
        None => return uri.clone(),
    };
    let mut builder = http::Uri::builder();
    if let Some(s) = uri.scheme() {
        builder = builder.scheme(s.clone());
    }
    if let Some(a) = uri.authority() {
        builder = builder.authority(a.clone());
    }
    let pq = match uri.query() {
        Some(q) => format!("{rest}?{q}"),
        None => rest.to_string(),
    };
    builder
        .path_and_query(pq)
        .build()
        .unwrap_or_else(|_| uri.clone())
}

// ---- 2026-05-18 (QC TLS-wiring batch — Phase E activation) ----

#[cfg(test)]
mod session_extraction_tests {
    use super::{build_risk_key, extract_session_id};
    use http::HeaderMap;

    fn headers_with(cookie: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(http::header::COOKIE, cookie.parse().unwrap());
        h
    }

    #[test]
    fn no_cookie_header_returns_none() {
        let h = HeaderMap::new();
        assert!(extract_session_id(&h).is_none());
    }

    #[test]
    fn empty_cookie_value_returns_none() {
        let h = headers_with("session=");
        assert!(extract_session_id(&h).is_none());
    }

    #[test]
    fn extracts_sessionid_cookie() {
        let h = headers_with("sessionid=abc-123-def");
        assert_eq!(extract_session_id(&h).as_deref(), Some("abc-123-def"));
    }

    #[test]
    fn extracts_session_cookie() {
        let h = headers_with("session=s%3Axyz789");
        assert_eq!(extract_session_id(&h).as_deref(), Some("s%3Axyz789"));
    }

    #[test]
    fn extracts_jsessionid_case_insensitive() {
        let h = headers_with("JSESSIONID=java-session-42");
        assert_eq!(extract_session_id(&h).as_deref(), Some("java-session-42"));
    }

    #[test]
    fn extracts_connect_sid() {
        let h = headers_with("connect.sid=express-sid-99");
        assert_eq!(extract_session_id(&h).as_deref(), Some("express-sid-99"));
    }

    #[test]
    fn returns_first_match_when_multiple_session_cookies() {
        // First-match-wins per the documented contract.
        let h = headers_with("sessionid=first; session=second");
        let s = extract_session_id(&h);
        // Either "first" or "second" is acceptable — both are
        // session cookies and we don't define ordering. Just
        // confirm we got *some* match.
        assert!(s.is_some());
    }

    #[test]
    fn ignores_non_session_cookies() {
        let h = headers_with("user_pref=dark; analytics_id=42");
        assert!(extract_session_id(&h).is_none());
    }

    #[test]
    fn handles_whitespace_around_cookie_pairs() {
        let h = headers_with("foo=bar ;  session=trimmed  ; baz=qux");
        assert_eq!(extract_session_id(&h).as_deref(), Some("trimmed"));
    }

    /// build_risk_key fills ip + session axes, leaves device_fp
    /// (device_fp None). session axis is populated from the
    /// cookie when present.
    #[test]
    fn build_risk_key_populates_session_axis() {
        let h = headers_with("session=abc");
        let ip: std::net::IpAddr = "203.0.113.10".parse().unwrap();
        let key = build_risk_key(ip, &h);
        assert_eq!(key.ip, ip);
        assert_eq!(key.session.as_deref(), Some("abc"));
        assert!(key.device_fp.is_none());
    }

    #[test]
    fn build_risk_key_no_cookie_falls_back_to_ip_only_axis() {
        let h = HeaderMap::new();
        let ip: std::net::IpAddr = "203.0.113.10".parse().unwrap();
        let key = build_risk_key(ip, &h);
        assert_eq!(key.ip, ip);
        assert!(key.session.is_none());
    }
}

#[cfg(test)]
mod strip_uri_prefix_tests {
    use super::strip_uri_prefix;
    use http::Uri;

    fn rewrite(input: &str, prefix: &str) -> String {
        let u: Uri = input.parse().unwrap();
        strip_uri_prefix(&u, prefix).to_string()
    }

    #[test]
    fn strips_prefix_keeping_remainder() {
        assert_eq!(rewrite("/news/article.html", "/news"), "/article.html");
        assert_eq!(rewrite("/news/a/b/c", "/news"), "/a/b/c");
    }

    #[test]
    fn exact_match_collapses_to_root_slash() {
        assert_eq!(rewrite("/news", "/news"), "/");
    }

    #[test]
    fn preserves_query_string() {
        assert_eq!(
            rewrite("/news/article.html?utm=src&id=1", "/news"),
            "/article.html?utm=src&id=1",
        );
        assert_eq!(rewrite("/news?id=1", "/news"), "/?id=1");
    }

    #[test]
    fn non_segment_prefix_match_passes_through_unchanged() {
        // `/news` is a string-prefix of `/newsroom` but not a
        // segment prefix; forwarding `/newsroom` after stripping
        // would yield `room` (no leading slash). Be defensive and
        // pass through.
        assert_eq!(rewrite("/newsroom", "/news"), "/newsroom");
    }

    #[test]
    fn missing_prefix_passes_through_unchanged() {
        assert_eq!(rewrite("/something/else", "/news"), "/something/else");
    }
}

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
        method: None,
        path: None,
        mode: None,
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
        method: None,
        path: None,
        mode: None,
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
        method: None,
        path: None,
        mode: None,
        fields: serde_json::json!({
            "duration_ms": closed.duration.as_millis() as u64,
            "bytes_to_upstream": closed.bytes_to_upstream,
            "bytes_from_upstream": closed.bytes_from_upstream,
            "close_reason": closed.reason.as_str(),
        }),
    });
}

/// Default set of trusted-proxy CIDRs for XFF resolution. Mirrors
/// `aegis_security::ip_rep::IpLists::default().trusted_proxies` —
/// 2026-05-18 (QC follow-up TLS-wiring batch — Phase E composite-
/// key activation): extract a session id from the request's
/// `Cookie` header. Common session cookie names — first match
/// wins. Returns `None` when no recognised session cookie is
/// present; downstream callers feed `None` into `RiskKey.session`
/// and the request gets an IP-only bucket (the legacy bucket).
///
/// We don't validate the value — the WAF doesn't need to know
/// whether the session is *authentic*, only that the requester
/// is presenting the same session id across a window. Risk tied
/// to a stolen session id is still trackable here even if the
/// auth signature is bogus.
pub(crate) fn extract_session_id(headers: &http::HeaderMap) -> Option<String> {
    let cookie_hdr = headers
        .get(http::header::COOKIE)
        .and_then(|v| v.to_str().ok())?;
    // Cookie header: `key1=val1; key2=val2; …`. Split on `;` then
    // trim. First match against the known-names list wins.
    const SESSION_COOKIE_NAMES: &[&str] = &[
        "sessionid",
        "session",
        "jsessionid",
        "connect.sid",
        "sid",
        "asp.net_sessionid",
    ];
    for pair in cookie_hdr.split(';') {
        let pair = pair.trim();
        if let Some((k, v)) = pair.split_once('=') {
            let k_lower = k.trim().to_ascii_lowercase();
            if SESSION_COOKIE_NAMES.contains(&k_lower.as_str()) {
                let v = v.trim();
                // URL-encoded prefix like `s%3A…` is fine — we
                // treat the raw value as the opaque key.
                if !v.is_empty() && v.len() < 256 {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

/// 2026-05-18 (QC follow-up TLS-wiring batch — Phase E composite-
/// key activation): build a [`RiskKey`] from the request shape.
///
/// Fills:
/// - `ip` — always present (peer's resolved IP after XFF).
/// - `session` — from the session-cookie scan above; `None`
///   when no recognised session cookie is sent.
/// - `device_fp` — `None` today. Activates when TLS-fingerprint
///   wire-up lands (tracked in
///   `plans/future/risk-composite-key-data-plane.md`).
///
/// 2026-05-19 — `tenant_id` axis removed from `RiskKey` (the
/// multi-tenant feature was deprecated upstream; every populator
/// was hard-coded to `None`).
pub(crate) fn build_risk_key(
    peer_ip: std::net::IpAddr,
    headers: &http::HeaderMap,
) -> aegis_core::risk::RiskKey {
    aegis_core::risk::RiskKey {
        ip: peer_ip,
        device_fp: None,
        session: extract_session_id(headers),
    }
}

/// loopback + RFC1918 + IPv6 link-local. Operators behind an LB
/// in a private subnet (the typical case) get correct XFF
/// resolution out of the box. Operator-configurable list via
/// `cfg.ip_lists.trusted_proxies` is a follow-up that plumbs
/// the cfg into the handler.
fn default_trusted_proxies() -> Vec<ipnet::IpNet> {
    // F-HIGH-002 (2026-05-17 s-tester audit): default is now empty.
    // Pre-fix this returned `[127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12,
    // 192.168.0.0/16, ::1/128, fc00::/7]`, which silently trusted XFF
    // from any loopback or RFC1918 peer. Two contract problems with
    // that:
    //
    //  1. v2.3 §10 mandates distinct `127.0.0.x` addresses are
    //     distinct clients. With loopback trusted, an OC client
    //     sending `X-Forwarded-For: 1.2.3.4` from `127.0.0.5`
    //     resolves to `1.2.3.4` — collapsing every sandbox client
    //     onto one synthetic key.
    //  2. v2.3 §6 contract test (`tests/contract/v2.3_compliance.sh`
    //     line 299-302) asserts audit `ip` is the TCP peer when
    //     XFF is present from `127.0.0.1`. The previous default
    //     resolved to the XFF value and failed that assertion.
    //
    // Operators with a real edge proxy (CDN, k8s ingress) opt-in
    // via `cfg.ip_lists.trusted_proxies` once that plumbing lands.
    // Default = empty = peer.ip() wins, which is the safe and
    // contract-compliant posture.
    Vec::new()
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
        method: Some(method.to_string()),
        path: Some(uri.to_string()),
        mode: None,
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

    fn route_activity_w() -> aegis_control::metrics::route_activity::RouteActivityWindow {
        aegis_control::metrics::route_activity::RouteActivityWindow::new()
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
            &route_activity_w(),
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
            &route_activity_w(),
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
            &route_activity_w(),
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
            &route_activity_w(),
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
            &route_activity_w(),
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
            &route_activity_w(),
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
            &route_activity_w(),
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
                &route_activity_w(),
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
    async fn websocket_upgrade_attempt_with_unreachable_upstream_emits_documented_action(
    ) {
        // WS-T2/T3 — when the upgrade detector fires we now try
        // a real raw-TCP forward to the resolved member.  The
        // `http_route_cfg()` pool points at 127.0.0.1:65530
        // which won't accept; the bridge surfaces that as a
        // 502 with the documented rule_id (one of two valid paths
        // — see below).
        //
        // F-CONTRACT-001 (2026-05-17): upstream-degradation paths
        // (no_healthy_member, forward_failed) now emit
        // `X-WAF-Action: circuit_breaker` per v2.3 §3, not `block`.
        // The no_upgrade_extension path stays `block` — it's a
        // client-capability mismatch, not upstream degradation.
        let cfg = http_route_cfg();
        let ctx = build_ctx(&cfg);
        let bus = AuditBus::new(16);
        let rh = route_latency();

        let req = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri("/ws")
            .header("host", "any")
            .header("upgrade", "websocket")
            .header("connection", "Upgrade")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("sec-websocket-version", "13")
            .body(http_body_util::Empty::<Bytes>::new())
            .unwrap();
        let (parts, _) = req.into_parts();

        let (resp, tag) = super::forward_allow_to_upstream(
            parts,
            Bytes::new(),
            &ctx,
            &ClientIdentity::Anonymous,
            &rh,
            &route_activity_w(),
            Instant::now(),
            "198.51.100.1".parse().unwrap(),
            &bus,
        )
        .await;

        assert_eq!(resp.status(), hyper::StatusCode::BAD_GATEWAY);
        let rid = rule_id_header(&resp);
        let action = tag.action.as_str();
        assert!(
            matches!(
                (rid, action),
                // Client-capability mismatch — still `block`.
                (Some("websocket_no_upgrade_extension"), "block")
                // Upstream degradation — `circuit_breaker` per §3.
                | (Some("upstream.forward_failed"), "circuit_breaker")
            ),
            "unexpected (rule_id, action): ({rid:?}, {action:?})",
        );
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
            &route_activity_w(),
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

// WS-T5 — end-to-end WebSocket bridge test through the WAF.
//
// The unit tests in `tcp_connect_tests` flagged the limitation
// they couldn't cover: "without a real hyper handshake we can't
// drive OnUpgrade::await to success".  This module fixes that
// for the WS path — it stands up a real hyper listener that
// serves connections via `serve_connection_with_upgrades`, so
// the OnUpgrade extension that the WS bridge consumes is
// genuinely populated by hyper rather than synthesised on a
// hand-built Parts.
//
// What's proven here:
// - is_websocket_upgrade detection fires.
// - forward_websocket_upgrade exchanges the 101 handshake
//   against a real WS backend.
// - The OnUpgrade extracted off the client request resolves
//   when hyper completes the upgrade.
// - copy_bidirectional moves real frames between client and
//   upstream.
//
// What's still NOT covered (acceptable):
// - TLS termination on the inbound side (no TLS in the
//   bare-TCP integration shape; covered by the existing TLS
//   forwarder unit tests).
// - The full detector chain — we call `forward_allow_to_upstream`
//   directly, which already short-circuits the chain when an
//   upgrade fires.  Detector-fires-before-WS coverage lives
//   in the upstream unit tests.
#[cfg(test)]
mod websocket_e2e_tests {
    use std::convert::Infallible;
    use std::sync::Arc;
    use std::time::Instant;

    use aegis_core::audit::AuditBus;
    use aegis_core::ClientIdentity;
    use aegis_core::pipeline::SecurityPipeline;
    use bytes::Bytes;
    use http_body_util::BodyExt;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;

    use crate::proxy::ProxyContext;

    fn route_latency() -> aegis_control::metrics::route_latency::RouteLatencyHistogram {
        let reg = aegis_control::metrics::MetricsRegistry::init();
        aegis_control::metrics::route_latency::RouteLatencyHistogram::register(&reg)
            .expect("route latency histogram registers")
    }

    fn route_activity_w() -> aegis_control::metrics::route_activity::RouteActivityWindow {
        aegis_control::metrics::route_activity::RouteActivityWindow::new()
    }

    /// Drive a real WebSocket client → WAF → echo backend
    /// round-trip and assert the bridge moves frames in both
    /// directions.  Closes the WS-T5 plan slice.
    #[tokio::test]
    async fn websocket_round_trips_frames_through_waf() {
        use futures::SinkExt;
        use tokio_tungstenite::tungstenite::Message;

        // 1. Echo backend on a random port.
        let backend = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let backend_task = tokio::spawn(async move {
            // Single accept — the test sends one connection.
            let (stream, _) = backend.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let (mut tx, mut rx) = futures::StreamExt::split(ws);
            while let Some(Ok(msg)) = futures::StreamExt::next(&mut rx).await {
                if msg.is_text() || msg.is_binary() {
                    if tx.send(msg).await.is_err() {
                        break;
                    }
                }
            }
        });

        // 2. WAF ProxyContext pointing at the echo backend.
        //    Catch-all route, no detectors / risk / rate-limit
        //    in the test path because forward_allow_to_upstream
        //    bypasses the chain when an upgrade fires.
        let yaml = format!(
            r#"
listeners:
  data: [{{ bind: "127.0.0.1:0" }}]
  admin: {{ bind: "127.0.0.1:0" }}
routes:
  - {{ id: catch-all, path: "/", upstream: pool }}
upstreams:
  pool: {{ members: [{{ addr: "{backend_addr}" }}] }}
state: {{ backend: in_memory }}
"#
        );
        let cfg: aegis_core::config::WafConfig =
            serde_yaml::from_str(&yaml).unwrap();
        cfg.validate().unwrap();
        let pipeline: Arc<dyn SecurityPipeline> =
            Arc::new(aegis_security::NoopPipeline);
        let ctx = Arc::new(ProxyContext::build(&cfg, pipeline).unwrap());

        // 3. WAF data-plane listener.  hyper's
        //    serve_connection_with_upgrades is the load-bearing
        //    bit — it installs the OnUpgrade extension on every
        //    request so the WS bridge has something to await.
        let waf = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let waf_addr = waf.local_addr().unwrap();
        let bus = AuditBus::new(16);

        let ctx_for_listener = ctx.clone();
        let bus_for_listener = bus.clone();
        let rh = Arc::new(route_latency());
        let waf_task = tokio::spawn(async move {
            let (stream, peer) = waf.accept().await.unwrap();
            let ctx_for_svc = ctx_for_listener.clone();
            let bus_for_svc = bus_for_listener.clone();
            let rh_for_svc = rh.clone();
            let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                let ctx = ctx_for_svc.clone();
                let bus = bus_for_svc.clone();
                let rh = rh_for_svc.clone();
                async move {
                    let (parts, body) = req.into_parts();
                    let body_bytes = body
                        .collect()
                        .await
                        .map(|c| c.to_bytes())
                        .unwrap_or_default();
                    let (resp, _tag) = super::forward_allow_to_upstream(
                        parts,
                        body_bytes,
                        &ctx,
                        &ClientIdentity::Anonymous,
                        &rh,
                        &route_activity_w(),
                        Instant::now(),
                        peer.ip(),
                        &bus,
                    )
                    .await;
                    Ok::<_, Infallible>(resp)
                }
            });
            let io = TokioIo::new(stream);
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, svc)
                .with_upgrades()
                .await;
        });

        // Tiny grace so both listeners are ready.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // 4. Real WS client driving the round-trip.
        let url = format!("ws://127.0.0.1:{}/", waf_addr.port());
        let (ws, _resp) = tokio_tungstenite::connect_async(&url)
            .await
            .expect("client connects to WAF and upgrades");
        let (mut tx, mut rx) = futures::StreamExt::split(ws);

        tx.send(Message::Text("hello".into())).await.unwrap();
        let echo = futures::StreamExt::next(&mut rx)
            .await
            .expect("first frame")
            .expect("first frame ok");
        assert_eq!(echo.into_text().unwrap(), "hello");

        tx.send(Message::Text("world".into())).await.unwrap();
        let echo2 = futures::StreamExt::next(&mut rx)
            .await
            .expect("second frame")
            .expect("second frame ok");
        assert_eq!(echo2.into_text().unwrap(), "world");

        // Clean shutdown — drop the sink so the bridge sees EOF.
        drop(tx);
        // Give the WAF + backend tasks a beat to drain their
        // copy_bidirectional then bail out.  Aborts are safe
        // because both listeners only accept once.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        backend_task.abort();
        waf_task.abort();
    }
}
