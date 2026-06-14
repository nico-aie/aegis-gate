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
use hyper::Response;

use aegis_core::AuditBus;

/// PROXY-T3 — additively stamp the real load-balancer transport hop
/// (`proxy_via`) onto an audit event's `fields` object. `proxy_via` is
/// `Some` only when a trusted PROXY-protocol header overrode the
/// effective peer for this connection (the audit `ip` is then the
/// asserted client; `proxy_via` is the LB that fronted it). `None` (the
/// default / no-PROXY case) and a non-object `fields` (e.g. `Null` under
/// critical load) are left untouched, so the wire shape is unchanged for
/// every existing deployment. Design §3.4.
fn with_proxy_via(
    mut fields: serde_json::Value,
    proxy_via: Option<std::net::IpAddr>,
) -> serde_json::Value {
    if let Some(via) = proxy_via {
        if let Some(obj) = fields.as_object_mut() {
            obj.insert(
                "proxy_via".to_string(),
                serde_json::Value::String(via.to_string()),
            );
        }
    }
    fields
}

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
    // PROXY-T3 — real LB transport hop when a trusted PROXY header
    // overrode `peer` to the asserted client; `None` otherwise. Surfaced
    // as the additive `proxy_via` audit field. Cosmetic for risk/RL
    // (they key on `peer`); kept for operator forensics.
    proxy_via: Option<std::net::IpAddr>,
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
    // Per-connection client identity (mTLS principal or Anonymous).
    // 2026-06-12 — the per-route `auth_required` gate that read this was
    // removed; client mTLS is now enforced plane-level by Zero Trust.
    // Threaded for audit + future per-request zero-trust use.
    identity: &aegis_core::ClientIdentity,
    // 2026-05-18 (QC TLS wire-up — F-CRITICAL-010 / 014 / 015
    // activation): post-handshake TLS fingerprint from the accept
    // loop. `None` for plain-HTTP connections (no handshake) or
    // when TLS termination didn't happen at this layer.
    tls_fingerprint: Option<&aegis_core::TlsFingerprint>,
) -> (
    // The whole inner chain now carries the unified DataBody (buffered
    // or streamed), so this wrapper just passes it through.
    Response<crate::body::DataBody>,
    aegis_control::interop::headers::DecisionTag,
) {
    let (resp, tag) = handle_data_request_inner(
        req,
        peer,
        proxy_via,
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
    tracing::Span::current().record("action", tag.action.as_str());
    (resp, tag)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_data_request_inner(
    req: hyper::Request<hyper::body::Incoming>,
    peer: std::net::SocketAddr,
    // PROXY-T3 — see `handle_data_request`. Threaded to the audit sites
    // via `with_proxy_via`.
    proxy_via: Option<std::net::IpAddr>,
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
    Response<crate::body::DataBody>,
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
        // WAF-only elapsed (µs), set right before the upstream forward.
        // 0 means the request never forwarded (blocked / early exit), so
        // `waf_overhead` == `total` — the whole request was WAF work.
        overhead_us: &'a std::sync::atomic::AtomicU64,
    }
    impl<'a> Drop for TotalGuard<'a> {
        fn drop(&mut self) {
            use aegis_control::metrics::request_duration::stage;
            let total = self.t0.elapsed();
            self.h.record(stage::TOTAL, total);
            // `waf_overhead` excludes the upstream backend round-trip:
            // the WAF's own cost. Falls back to `total` when no forward
            // happened (those requests have no upstream wait to exclude).
            let ov = self.overhead_us.load(std::sync::atomic::Ordering::Relaxed);
            let overhead = if ov == 0 {
                total
            } else {
                std::time::Duration::from_micros(ov)
            };
            self.h.record(stage::WAF_OVERHEAD, overhead);
        }
    }
    let request_start = std::time::Instant::now();
    // Captured just before the upstream forward (see the forward sites
    // below); stays 0 for requests that block/exit before forwarding.
    let waf_overhead_us = std::sync::atomic::AtomicU64::new(0);
    let _total_guard = TotalGuard {
        h: request_stage_hist,
        t0: request_start,
        overhead_us: &waf_overhead_us,
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
                .body(crate::body::full(Bytes::from(
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
    // 2026-05-20 (Option B) — set to the accumulated risk score when
    // detectors fired but this request's combined score was under
    // the tier's per-request block threshold. Routes the request to
    // the upstream-forward path (no decay) and stamps the score on
    // the allow response.
    let mut detected_under_threshold: Option<u32> = None;
    // 2026-05-21 — comma-joined detector tags that fired but stayed
    // under the tier block threshold. Attached to the forwarded
    // `allow` decision so the listener-side audit records
    // `fields.detectors` instead of `detectors: null`.
    let mut detected_detectors: Option<String> = None;
    // 2026-05-21 — per-request detector score (sum of this request's
    // signals) for the under-threshold allow path. Carried out to the
    // listener so the audit records `fields.request_score` (distinct
    // from the cumulative `risk_score`).
    let mut detected_request_score: Option<u32> = None;

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
    // C-5 — trusted_proxies comes from `cfg.proxy.trusted_proxies`,
    // parsed once into the long-lived ProxyContext (same pattern as
    // max_body_bytes). Empty (the default) ⇒ the TCP peer always wins
    // and XFF is ignored, which is the F-HIGH-002-safe posture.
    // Operators fronting the fleet with a *trusted* L7/SNAT LB set the
    // LB's CIDRs so `resolve_client_ip` walks XFF to the real client.
    let peer_ip = {
        let xff = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok());
        aegis_security::ip_rep::xff::resolve_client_ip(
            peer.ip(),
            xff,
            &upstream_ctx.trusted_proxies,
        )
    };
    // 2026-05-24 — resolve the route's tier ONCE here (read-only trie
    // walk) so EVERY block path labels its audit event with the real
    // route tier (`tier_override`), not the legacy path heuristic. A
    // catch-all `/` route at tier=high previously showed cumulative
    // `risk-score` blocks as Low because `blocked_response` hard-coded
    // `classify_tier_from_path` (always Low) while per-request detector
    // blocks on the SAME route correctly showed high. Unmatched paths
    // fall back to Low (and still 404 in the forward path as before).
    let route_tier = upstream_ctx
        .route_table
        .resolve(
            req.headers()
                .get(hyper::header::HOST)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("localhost"),
            req.uri().path(),
            req.method(),
        )
        .map(|rc| rc.tier)
        .unwrap_or(aegis_core::tier::Tier::Low);
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
            route_tier,
            req.uri(),
            req.method(),
            bus,
            None,
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
    let strike_key = build_risk_key(peer_ip, req.headers(), tls_fingerprint);
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
        // 2026-05-19 — stamp `risk-strikes` on the audit event so
        // the AttacksAggregator's detector_name() can map it to
        // "ip-strikes" instead of falling through to "unknown".
        // Pre-fix the Attack Distribution donut showed a mystery
        // "unknown" slice for every Strike-Block 403.
        let resp = blocked_response(
            peer,
            "blocked by repeat-offender strikes",
            Some("risk-strikes".into()),
            strike_score,
            route_tier,
            req.uri(),
            req.method(),
            bus,
            None,
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
                        fields: with_proxy_via(
                            serde_json::json!({
                                "path": req.uri().to_string(),
                                "method": req.method().to_string(),
                                "ddos_observe_only": outcome.observe_only,
                                "ddos_spike_active": outcome.spike_active,
                            }),
                            proxy_via,
                        ),
                    };
                    bus.emit(ev);
                }
                if outcome.should_enforce() {
                    // 2026-05-22 — honor `set_profile mode=log_only` on the
                    // `ddos` feature (in addition to the config-level
                    // `ddos.observe_only` flag). In log_only, report the
                    // intended block but forward upstream — the audit event
                    // above already recorded the intent; the response stamper
                    // emits X-WAF-Action: block + X-WAF-Mode: log_only.
                    let ddos_mode = interop_modes
                        .map(|m| aegis_control::interop::rule_map::mode_for_rule(m, Some("ddos")))
                        .unwrap_or(aegis_control::interop::headers::Mode::Enforce);
                    if ddos_mode == aegis_control::interop::headers::Mode::LogOnly {
                        log_only_intent = Some(DecisionTag::block("ddos"));
                        // fall through to detectors + upstream
                    } else {
                        // Enforce — 503. The response shape mirrors the
                        // strike-block path above so operators get a
                        // consistent block envelope regardless of which
                        // gate tripped.
                        let resp = blocked_response(
                            peer,
                            outcome.reason.as_deref().unwrap_or("ddos: blocked"),
                            Some("ddos".into()),
                            None,
                            route_tier,
                            req.uri(),
                            req.method(),
                            bus,
                            None,
                        );
                        return (resp, DecisionTag::block("ddos"));
                    }
                }
                // observe_only OR log_only-forward — fall through; the
                // request still proceeds to detectors + upstream. The
                // audit event above records the intent either way.
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
                            .body(crate::body::full(Bytes::from(
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
    //
    // 2026-05-19 Phase E completion — the per-IP guard now keys
    // on the composite `RiskKey`. Two TLS sessions from the same
    // NAT'd IP with different (JA4, UA, session-cookie) shapes
    // get independent buckets, so legit user B isn't penalised
    // for attacker A's flood when they share an egress proxy.
    let rate_t0 = std::time::Instant::now();
    let rate_decision = ip_rate_limiter
        .consume_with_key(build_risk_key(peer_ip, req.headers(), tls_fingerprint));
    request_stage_hist.record(stages::RATE_LIMIT, rate_t0.elapsed());
    if !rate_decision.allowed {
        // 2026-05-18 (QC TLS-wiring batch — Phase E activation):
        // record the malicious event under the composite RiskKey
        // (IP + session + device_fp). The session axis activates the
        // F-CRITICAL-001 mandate from §5.5 — two distinct sessions on
        // the same NAT'd IP no longer share a risk bucket. device_fp
        // is the JA4-derived TLS fingerprint hash (None on plain HTTP);
        // see build_risk_key. Pre-Phase-E this was IP-only.
        let post_state = risk.record_malicious_with_key(
            build_risk_key(peer_ip, req.headers(), tls_fingerprint),
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
                    with_proxy_via(
                        serde_json::json!({
                            "path": req.uri().to_string(),
                            "method": req.method().to_string(),
                            "rate_count": rate_decision.count,
                            "rate_limit": rate_decision.limit,
                            "strikes": post_state.strikes,
                        }),
                        proxy_via,
                    )
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
                .body(crate::body::full(Bytes::from(
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
                .body(crate::body::full(Bytes::from(
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
            .body(crate::body::full(Bytes::from(
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

    // 2026-05-23 — resolve the route's tier UP FRONT so the per-request
    // block gate, the per-tier detector mask, and the load shedder all
    // key off the route's `tier_override`. Previously this stage used
    // `classify_tier(None, …)`, which ALWAYS returns Low since the
    // path→tier heuristic was removed — so a route's tier_override never
    // affected per-request blocking / shedding / the mask. Only the
    // allow-path audit label (resolved later in the forward path) picked
    // up the route tier, so the dashboard showed the new tier while the
    // blocking behaviour stayed on Low: "changed the tier but it doesn't
    // take effect, score still by the old tier".
    //
    // The forward path re-resolves the route for upstream selection +
    // circuit breaking; here we only read the tier (a cheap ArcSwap trie
    // walk). Unmatched routes fall back to Low and still 404 in the
    // forward path exactly as before.
    // Reuse the route tier resolved up front (line ~290, same request,
    // before the early gates) — drives the per-request block gate, the
    // per-tier detector mask, and the load shedder.
    let tier = route_tier;
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
                .body(crate::body::full(Bytes::from(
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
            build_risk_key(peer_ip, &parts.headers, tls_fingerprint),
            request_score,
        );
        // 2026-05-20 (Option B) — per-request tier gate. Block this
        // request ONLY when its COMBINED detector score reaches the
        // matched tier's per-request threshold (TierStore
        // `risk_threshold` defaults: critical 50 / high 60 / medium 70 /
        // low 80 — 2026-05-23 clean 10-apart ladder; configurable via
        // the `tiers:` config block + dashboard PUT /api/tiers). The malicious score was already
        // recorded above, so a single under-threshold hit still
        // accumulates and a repeat offender escalates via the
        // cumulative gate below. Falls back to 50 (critical default)
        // when the TierStore has no entry for the classified tier.
        // SUM (not max) here per the dashboard's documented
        // semantics — `max` stays the cumulative-record contribution
        // (SEC-M003); the per-request gate sums this request's
        // signals so multiple weak indicators can combine.
        let per_request_sum: u32 = signals.iter().map(|s| s.score).sum::<u32>().min(100);
        let per_request_block_at = upstream_ctx
            .tiers
            .get()
            .and_then(|store| store.get(tier.as_str()))
            .map(|t| t.risk_threshold)
            .unwrap_or(50);
        let detector_blocks = per_request_sum >= per_request_block_at;
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
            let mut f = serde_json::json!({
                "path": parts.uri.to_string(),
                "method": parts.method.to_string(),
                "detectors": tags,
                // 2026-05-21 — per-request detector score: the sum of
                // THIS request's signals (capped at 100). Distinct from
                // the top-level `risk_score`, which is the cumulative
                // composite-key score. Surfaced so the dashboard can
                // show "this request scored N" vs "this source's
                // accumulated risk is M".
                "request_score": per_request_sum,
                "strikes": post_state.strikes,
                "load_mode": load_mode.as_str(),
                "verbosity": verbosity_level.as_str(),
            });
            // 2026-05-20 — attach the redacted request echo (headers
            // + bounded body preview) so the dashboard detail drawer
            // can show what tripped the detector. Body is in scope
            // here (post-buffer); rides the same verbosity gate above.
            if let serde_json::Value::Object(ref mut map) = f {
                map.extend(request_echo_fields(&parts.headers, Some(&body_bytes)));
            }
            f
        };
        if detector_blocks && allow_block_emit {
            let ev = aegis_core::audit::AuditEvent {
                schema_version: 1,
                ts: chrono::Utc::now(),
                request_id: blake3::hash(format!("{}:{}", peer, chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)).as_bytes()).to_hex().to_string(),
                class: aegis_core::audit::AuditClass::Detection,
                tenant_id: None,
                // 2026-05-05 — populate the tier so the dashboard's Live
                // Feed shows it. 2026-05-24 — `tier` is the route-resolved
                // tier (`route_tier`, resolved up front at line ~290), so a
                // per-request detector block on a high-tier route is
                // labelled high — matching the cumulative `risk-score`
                // path, which now passes the same `tier` to
                // `blocked_response`.
                tier: Some(tier),
                action: "block".into(),
                reason: reason.clone(),
                client_ip: peer_ip.to_string(),
                route_id: None,
                // 2026-05-21 — populate the audit `rule_id` with the
                // joined detector tags so it matches the
                // `X-WAF-Rule-Id` response header (set from
                // `DecisionTag::block(detector_rule)` below) and is
                // queryable the same way as the allow-detected path.
                // Was `None`, which left blocks with `rule_id: null`
                // even though the header carried the tags.
                rule_id: Some(if tags.is_empty() {
                    "detectors".to_string()
                } else {
                    tags.join(",")
                }),
                risk_score: Some(post_state.score),
                method: None,
                path: None,
                mode: None,
                fields: with_proxy_via(fields, proxy_via),
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
        if !detector_blocks {
            // 2026-05-20 (Option B) — detectors fired but this
            // request's combined score is under the tier's
            // per-request threshold. Don't block per-request: the
            // malicious score was recorded above (so it accumulates
            // toward the cumulative gate), and we route to the
            // upstream-forward path WITHOUT decaying it. Reported as
            // `allow` with the elevated X-WAF-Risk-Score so the
            // benchmarker still sees risk on the response.
            detected_under_threshold = Some(post_state.score);
            // Carry the fired detector tags onto the allow decision so
            // the audit log records them (otherwise the forwarded
            // request logs as a plain allow with `detectors: null`).
            detected_detectors = Some(tags.join(","));
            // Carry this request's detector score (sum of signals) so
            // the audit records `fields.request_score` distinct from
            // the cumulative `risk_score`.
            detected_request_score = Some(per_request_sum);
        } else if detector_mode == aegis_control::interop::headers::Mode::LogOnly {
            log_only_intent = Some(block_tag);
            // Fall through — skip the 403 and the risk gate below
            // (which would also block this request because we just
            // recorded the malicious score). The intent is applied
            // at the function's tail, after upstream forward.
        } else {
            let resp = Response::builder()
                .status(403)
                .header("content-type", "application/json")
                .body(crate::body::full(Bytes::from(
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
    //
    // 2026-05-24 — evaluate the cumulative IP-risk level UP FRONT so it
    // applies to every non-log_only request, including under-tier-
    // threshold detections. Decay (trust recovery) runs only for a
    // genuinely clean request: a detection that just recorded a malicious
    // score (even one under the per-request threshold) must NOT claw it
    // back here. Same condition as the old clean-path branch.
    if detected_under_threshold.is_none() && log_only_intent.is_none() {
        risk.record_clean_with_key(build_risk_key(peer_ip, &parts.headers, tls_fingerprint));
    }
    // Per-tier cumulative thresholds, falling back to the global values
    // when the matched tier has no override (Option B).
    let global = risk.thresholds();
    let (challenge_at, block_at, challenges_enabled) = match upstream_ctx.tiers.get() {
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
    // Composite-key cumulative level. 2026-05-24 — when the matched tier
    // disables challenges, the challenge rung is SKIPPED (treated as
    // Allow), NOT escalated to Block. Disabling challenges means "don't
    // run the PoW gate", not "lower the block threshold to challenge_at":
    // a challenge-band score (challenge_at..block_at) passes through, and
    // only block_at blocks. (Previously this escalated to Block, which
    // surprised operators by effectively blocking at challenge_at — e.g.
    // a cumulative 60 blocking when block_at is 70.) A tier that wants a
    // hard block earlier should lower its `cumulative_block_at` instead.
    let level = {
        let lvl = risk.level_with_for_key(
            &build_risk_key(peer_ip, &parts.headers, tls_fingerprint),
            challenge_at,
            block_at,
        );
        match lvl {
            aegis_security::risk::RiskLevel::Challenge if !challenges_enabled => {
                aegis_security::risk::RiskLevel::Allow
            }
            other => other,
        }
    };

    // WAF detection is done; from here it's the upstream forward (or a
    // small block/challenge response build). Capture the WAF-only
    // elapsed now so the `waf_overhead` stage excludes the backend
    // round-trip. Requests that blocked/exited before this point left
    // `waf_overhead_us` at 0, so the guard reports their `total` (they
    // have no upstream wait to strip).
    waf_overhead_us.store(
        request_start.elapsed().as_micros() as u64,
        std::sync::atomic::Ordering::Relaxed,
    );
    // 2026-05-24 — the cumulative IP-risk gate is authoritative. An
    // under-tier-threshold detection forwards (allow + watch) ONLY while
    // the IP's cumulative level is still `Allow`; once it crosses into
    // Challenge or Block it falls through to the match below and gets the
    // 429 challenge / risk-score block. Without this a recon scanner that
    // only ever trips under-threshold detector paths accumulates to the
    // block threshold yet keeps sailing through. `log_only` stays exempt:
    // it deliberately never enforces.
    let (resp, allow_tag) = if log_only_intent.is_some()
        || (detected_under_threshold.is_some()
            && matches!(level, aegis_security::risk::RiskLevel::Allow))
    {
        // log_only OR under-tier-threshold detection: forward to
        // upstream WITHOUT running the clean-decay path (the
        // malicious score was already recorded and must accumulate).
        let (resp, tag) = forward_allow_to_upstream(
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
        .await;
        // Surface the accumulated risk on the allow response so the
        // benchmarker sees the elevated score for an under-threshold
        // detection (the log_only case stamps its own intent at the
        // tail).
        match detected_under_threshold {
            Some(score) if log_only_intent.is_none() => {
                let mut t = tag.with_risk_score(score);
                // Label the forwarded `allow` with the fired detector
                // tags so X-WAF-Rule-Id (stamped from `rule_id`) AND
                // the audit `rule_id` both carry the detectors and
                // match — even though the request was allowed.
                if let Some(d) = detected_detectors.take() {
                    t = t.with_rule_id(d);
                }
                if let Some(rs) = detected_request_score.take() {
                    t = t.with_detector_score(rs);
                }
                (resp, t)
            }
            _ => (resp, tag),
        }
    } else {
        // Cumulative-risk gate (authoritative). Reached for genuinely
        // clean requests AND for under-threshold detections whose IP has
        // accumulated to Block — `level` (and the decay for clean
        // requests) was computed up front above. The adaptive-mitigation
        // classifier maps the cumulative level to Allow / Challenge /
        // Block.
        match level {
            aegis_security::risk::RiskLevel::Block => {
                // NEW-4 (2026-05-08) — stamp the snapshot score
                // on the DecisionTag so the response stamper
                // doesn't re-query under peer.ip() and miss.
                // 2026-05-18 — composite-key snapshot (Phase E).
                let block_score = risk
                    .snapshot_with_key(&build_risk_key(peer_ip, &parts.headers, tls_fingerprint))
                    .map(|s| s.score);
                let mut tag = match block_score {
                    Some(s) => DecisionTag::block("risk-score").with_tier(tier).with_risk_score(s),
                    None => DecisionTag::block("risk-score").with_tier(tier),
                };
                // 2026-05-24 — if THIS request's own detectors fired but
                // stayed under the per-request tier threshold, it routes
                // through the cumulative gate and blocks as `risk-score`.
                // Stamp the per-request detector score onto the tag so
                // `X-WAF-Detector-Score` matches the detector-block path.
                // `rule_id` stays `risk-score` (the enforcing gate); the
                // contributing detector is surfaced in the audit fields below.
                if let Some(rs) = detected_request_score {
                    tag = tag.with_detector_score(rs);
                }
                // F-CRITICAL-002 — honor `set_profile
                // mode=log_only` on `risk_engine.score`. When
                // LogOnly, emit the audit (via blocked_response
                // side-effect on the discarded response), stash
                // the intent, and forward to upstream as if the
                // level was Allow.
                let rs_mode = interop_modes
                    .map(|m| aegis_control::interop::rule_map::mode_for_rule(m, Some("risk-score")))
                    .unwrap_or(aegis_control::interop::headers::Mode::Enforce);
                // 2026-05-19 — stamp `risk-score` on the audit event
                // so the AttacksAggregator can map it to "ip-risk"
                // instead of falling through to "unknown". See the
                // matching stamp on the Strike-Block path above.
                // 2026-05-22 — attach the redacted request echo so a
                // risk-score block shows headers + body + cookies in the
                // detail drawer, like detector blocks do. Same verbosity
                // gate as the detector-block echo.
                // 2026-05-24 — carry the per-request detector score + fired
                // detector tags into the audit `fields` so the detail drawer
                // attributes a risk-score block to the detector that drove it
                // (e.g. path_traversal=70, under the LOW per-request 80 but
                // >= the cumulative block_at 70) instead of rendering a
                // scoreless reputation block. A genuinely clean cumulative
                // block leaves both None → fields stay slim → drawer shows `—`.
                let mut rs_fields = if !load_mode.is_critical() && allow_verbose_fields {
                    request_echo_fields(&parts.headers, Some(&body_bytes))
                } else {
                    serde_json::Map::new()
                };
                if let Some(rs) = detected_request_score {
                    rs_fields.insert("request_score".into(), serde_json::json!(rs));
                }
                if let Some(d) = detected_detectors.as_ref() {
                    rs_fields.insert("detectors".into(), serde_json::Value::String(d.clone()));
                }
                let rs_echo = if rs_fields.is_empty() { None } else { Some(rs_fields) };
                let resp = blocked_response(
                    peer,
                    "blocked by risk score",
                    Some("risk-score".into()),
                    block_score,
                    tier,
                    &parts.uri,
                    &parts.method,
                    bus,
                    rs_echo,
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
                // v2.5 contract §4 Format A — fields the benchmarker
                // reads to solve: `challenge_token`, `difficulty`,
                // `submit_url`, `submit_method`. Submit body is
                // `{"challenge_token":"<echo>","nonce":"<work>"}`.
                // The token packs (nonce, difficulty, expires_at_ms,
                // mac) so the server can verify statelessly.
                let body = match upstream_ctx.pow_issuer.get() {
                    Some(issuer) => {
                        let challenge = issuer.issue();
                        serde_json::json!({
                            "challenge": true,
                            "challenge_type": "proof_of_work",
                            "challenge_token": challenge.challenge_token(),
                            "difficulty": challenge.difficulty,
                            "submit_url": "/challenge/verify",
                            "submit_method": "POST",
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
                    .body(crate::body::full(Bytes::from(body.to_string())))
                    .unwrap();
                // NEW-4 (2026-05-08) — stamp current snapshot score
                // for the challenge response too.
                // 2026-05-18 — composite-key snapshot (Phase E).
                let challenge_score = risk
                    .snapshot_with_key(&build_risk_key(peer_ip, &parts.headers, tls_fingerprint))
                    .map(|s| s.score);
                let tag = match challenge_score {
                    Some(s) => DecisionTag::challenge("risk-challenge").with_tier(tier).with_risk_score(s),
                    None    => DecisionTag::challenge("risk-challenge").with_tier(tier),
                };
                // 2026-05-25 — emit a Detection audit for the CHALLENGE
                // action. The Block path audits via `blocked_response` and
                // the Allow path audits inside `forward_allow_to_upstream`,
                // but this rung previously built the 429 and returned WITHOUT
                // emitting — so `action: challenge` never reached the audit
                // log / dashboard Live Feed (only the live `X-WAF-Action`
                // header carried it). Mirrors the `blocked_response` shape
                // with `action: "challenge"` + `rule_id: risk-challenge`, and
                // is emitted UNCONDITIONALLY (before the log_only branch)
                // exactly like the block path — so the OC's correlation chain
                // sees the challenge even when `risk_engine.score` is
                // `log_only` (the response stamper still marks `X-WAF-Mode`).
                // Honors the same load-shed `allow_block_emit` gate as the
                // detector-block audit.
                if allow_block_emit {
                    let echo = if !load_mode.is_critical() && allow_verbose_fields {
                        Some(request_echo_fields(&parts.headers, Some(&body_bytes)))
                    } else {
                        None
                    };
                    emit_challenge_audit(
                        peer,
                        peer_ip,
                        tier,
                        challenge_score,
                        detected_request_score,
                        detected_detectors.as_deref(),
                        &parts.uri,
                        &parts.method,
                        bus,
                        echo,
                    );
                }
                // Contract §2.7 — honor `set_profile mode=log_only` on
                // `risk_engine.score` for the CHALLENGE action too (not
                // just block). In log_only the WAF MUST report the
                // intended `X-WAF-Action: challenge` + `X-WAF-Mode:
                // log_only` but MUST NOT apply enforcement — so we
                // stash the intent and forward upstream instead of
                // issuing the 429 PoW. Mirrors the Block arm above.
                let rc_mode = interop_modes
                    .map(|m| aegis_control::interop::rule_map::mode_for_rule(m, Some("risk-challenge")))
                    .unwrap_or(aegis_control::interop::headers::Mode::Enforce);
                if rc_mode == aegis_control::interop::headers::Mode::LogOnly {
                    log_only_intent = Some(tag);
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
    // 2026-06-12 — the per-route `auth_required` gate that consumed the
    // client identity here was removed (client mTLS is now Zero Trust,
    // plane-level). Kept threaded through the chain for future per-request
    // zero-trust needs; currently unused at this leaf.
    _identity: &aegis_core::ClientIdentity,
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
    Response<crate::body::DataBody>,
    aegis_control::interop::headers::DecisionTag,
) {
    use aegis_control::interop::headers::DecisionTag;

    // Load shedder gradient signal — feed WAF-inspection latency ONLY.
    // We are at the allow path *before* the upstream connect, so
    // `request_start.elapsed()` is the time spent inside the WAF
    // (parse + detectors + gates) with zero upstream round-trip mixed
    // in. Recording here keeps the shedder from treating a slow backend
    // as WAF overload — see shed.rs `record_rtt`.
    if let Some(shedder) = ctx.load_shedder.get() {
        shedder.record_rtt(request_start.elapsed());
    }

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
                .body(crate::body::full(Bytes::from("no matching route\n")))
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

    // 2026-06-12 — the MTLS-T4 route-scoped client-identity gate
    // (`route.auth_required`) was removed. Client mTLS is now enforced by
    // the unified Zero Trust downstream config at the listener-plane level
    // (`zero_trust.downstream.mode` + `apply_to`), not per route.

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
                    .body(crate::body::full(Bytes::from(format!(
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
                    .body(crate::body::full(Bytes::from(
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
                    .body(crate::body::full(Bytes::from(
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
                    .body(crate::body::full(Bytes::from(
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
                    .body(crate::body::full(Bytes::from(
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
                .body(crate::body::full(Bytes::from(
                    "WebSocket upgrade: HTTP/2 extended CONNECT not supported\n",
                )))
                .unwrap();
            return (
                resp,
                DecisionTag::block("websocket_no_upgrade_extension"),
            );
        };

        // 2026-06-12 — WS frame inspection is ON BY DEFAULT: every WS
        // connection is inspected (enforce) unless the route explicitly
        // opted out with `ws_inspect: { enabled: false }`. `resolve`
        // returns the default-on posture when there's no per-route block.
        let effective_ws_inspect =
            aegis_core::config::WsInspectConfig::resolve(route_ctx.ws_inspect.as_ref());
        // WS-MSG5 — strip `permessage-deflate` from the forwarded
        // handshake when this connection inspects frames, so the
        // negotiated connection is uncompressed (compressed frames can't
        // be decoded for inspection in v1).
        let strip_ws_extensions = effective_ws_inspect.is_active();
        let upstream_handshake = match crate::proto::ws_forward::forward_websocket_upgrade(
            &parts.method,
            &parts.uri,
            &parts.headers,
            &body_bytes,
            member.addr,
            std::time::Duration::from_secs(5),
            strip_ws_extensions,
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
                    .body(crate::body::full(Bytes::from(
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
            // WS-MSG2 — effective (default-on) frame-inspection config
            // moved into the bridge task. `enabled: false` ⇒ the zero-copy
            // path below; otherwise the inspecting bridge runs.
            let ws_inspect_for_task = effective_ws_inspect.clone();
            // WS-MSG3 — detector handles + the synthetic-view context for
            // the inspecting bridge, all moved into the spawned task.
            // `ws_detectors`/`ws_mask` are `None` on builds that don't
            // wire detectors (tests) → the bridge forwards un-inspected.
            let ws_detectors = ctx.ws_detectors.clone();
            let ws_mask = ctx
                .ws_detector_mask
                .as_ref()
                .map(|m| m.resolve(Some(route_ctx.tier)));
            let ws_block_at = ctx
                .tiers
                .get()
                .and_then(|store| store.get(route_ctx.tier.as_str()))
                .map(|t| t.risk_threshold)
                .unwrap_or(50);
            let ws_method = parts.method.clone();
            let ws_uri = parts.uri.clone();
            // A WS text frame is UTF-8 text by RFC 6455; stamp a
            // `text/plain` Content-Type onto the synthetic view so the
            // body-class detectors (which gate on a scannable
            // Content-Type) actually scan the reassembled message.
            let mut ws_headers = parts.headers.clone();
            ws_headers.insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("text/plain"),
            );
            let ws_peer_ip = peer_ip;
            // WS-MSG4 — audit + metric emission context for blocked
            // (and would-block) frames.
            let ws_bus = bus.clone();
            let ws_route_id = route_ctx.route_id.clone();
            let ws_tier = route_ctx.tier;
            let ws_metrics_for_inspect = ctx.websocket_metrics.clone();
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
                        // WS-MSG2 — inspect every WS connection by default
                        // (the parsing bridge); a route that opted out
                        // (`enabled: false`) falls back to the original
                        // zero-copy tunnel, byte-for-byte.
                        let (c2u, u2c) = if ws_inspect_for_task.is_active() {
                            let ws_cfg = &ws_inspect_for_task;
                            // WS-MSG3 — per-message inspector: build a
                            // synthetic RequestView from the handshake
                            // context, run the body detectors over the
                            // reassembled text, and block on `enforce`
                            // when the summed score crosses the route
                            // tier's per-request threshold. `log_only`
                            // forwards (WS-MSG4 emits the would-block
                            // audit). No detectors wired ⇒ allow.
                            let enforce = matches!(
                                ws_cfg.mode,
                                aegis_core::config::WsInspectMode::Enforce
                            );
                            let bridge_cfg = crate::proto::ws_inspect::WsBridgeConfig {
                                max_message_bytes: ws_cfg.max_message_bytes,
                                // 2026-06-12 — fail-closed (WS 1009) over the
                                // inspection cap in enforce; forward + meter
                                // the skip in log_only.
                                over_cap_close: enforce,
                            };
                            let inspector = move |payload: &[u8]| {
                                use crate::proto::ws_inspect::WsVerdict;
                                let (Some(detectors), Some(mask)) =
                                    (ws_detectors.as_ref(), ws_mask)
                                else {
                                    return WsVerdict::Allow;
                                };
                                let body = aegis_core::pipeline::BodyPeek::new(
                                    payload.to_vec(),
                                    Some(payload.len() as u64),
                                    false,
                                );
                                let view = aegis_core::pipeline::RequestView {
                                    method: &ws_method,
                                    uri: &ws_uri,
                                    version: http::Version::HTTP_11,
                                    headers: &ws_headers,
                                    peer: std::net::SocketAddr::new(ws_peer_ip, 0),
                                    tls: None,
                                    body: &body,
                                };
                                let signals = aegis_security::detectors::run_all_filtered(
                                    &detectors[..],
                                    mask,
                                    &view,
                                );
                                let sum: u32 = signals
                                    .iter()
                                    .map(|s| s.score)
                                    .sum::<u32>()
                                    .min(100);
                                if sum < ws_block_at {
                                    return WsVerdict::Allow;
                                }
                                // Over threshold — emit the
                                // websocket_frame_block audit + metric for
                                // both enforce and log_only; `mode`
                                // distinguishes them (see memory:
                                // X-WAF-Action vs Mode).
                                let top = signals.iter().max_by_key(|s| s.score);
                                let tag = top
                                    .map(|s| s.tag.clone())
                                    .unwrap_or_else(|| "detectors".to_string());
                                let matched_field =
                                    top.map(|s| s.field.clone()).unwrap_or_default();
                                let mode_str = if enforce { "enforce" } else { "log_only" };
                                if let Some(m) = ws_metrics_for_inspect.as_ref() {
                                    m.record_frame_block(&ws_route_id, &tag);
                                }
                                ws_bus.emit(aegis_core::audit::AuditEvent {
                                    schema_version: 1,
                                    ts: chrono::Utc::now(),
                                    request_id: blake3::hash(
                                        format!(
                                            "wsframe:{}:{}",
                                            ws_route_id,
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
                                    tier: Some(ws_tier),
                                    action: "websocket_frame_block".into(),
                                    reason: format!(
                                        "websocket text frame blocked by detectors: {tag} \
                                         (score: {sum})"
                                    ),
                                    client_ip: ws_peer_ip.to_string(),
                                    route_id: Some(ws_route_id.clone()),
                                    rule_id: Some(tag),
                                    risk_score: Some(sum),
                                    method: None,
                                    path: None,
                                    mode: Some(mode_str.to_string()),
                                    fields: serde_json::json!({
                                        "matched_field": matched_field,
                                        "message_bytes": payload.len(),
                                    }),
                                });
                                if enforce {
                                    WsVerdict::Block
                                } else {
                                    WsVerdict::Allow
                                }
                            };
                            match crate::proto::ws_inspect::run_bridge(
                                client_io,
                                upstream,
                                bridge_cfg,
                                inspector,
                            )
                            .await
                            {
                                Ok(stats) => {
                                    (stats.client_to_upstream, stats.upstream_to_client)
                                }
                                Err(e) => {
                                    tracing::debug!(
                                        error = %e,
                                        "websocket inspecting bridge ended with io error",
                                    );
                                    (0, 0)
                                }
                            }
                        } else {
                            let copy = tokio::io::copy_bidirectional(
                                &mut client_io,
                                &mut upstream,
                            )
                            .await;
                            copy.unwrap_or((0, 0))
                        };
                        let elapsed = started.elapsed();
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
                .body(crate::body::full(Bytes::new()))
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
            .body(crate::body::full(Bytes::from(body)))
            .unwrap();
        return (resp, DecisionTag::allow().with_tier(route_ctx.tier));
    }

    // SC-1 — smart cache lookup (L1, in-process). Runs AFTER the auth +
    // operator-rule gates and the WebSocket-upgrade path, BEFORE dialing
    // upstream. CRITICAL tier is never cached (hard invariant). On a HIT we
    // serve the stored response and skip the upstream entirely; on a MISS we
    // remember the key + rule so the success path below can store the
    // upstream response.
    let mut cache_pending: Option<(
        std::sync::Arc<crate::cache::PoolCache>,
        crate::cache::CacheKey,
        usize,
    )> = None;
    if route_ctx.tier != aegis_core::tier::Tier::Critical {
        if let Some(pc) = ctx.cache.pool(&route_ctx.upstream) {
            let pc = pc.clone();
            match pc
                .lookup(&method, &path, parts.uri.query(), &parts.headers)
                .await
            {
                crate::cache::CacheLookup::Hit(entry) => {
                    tracing::Span::current().record("outcome", "cache-hit");
                    let mut rb = Response::builder().status(entry.status);
                    for (n, v) in &entry.headers {
                        rb = rb.header(n, v);
                    }
                    let resp = rb
                        .body(crate::body::full(entry.body.clone()))
                        .unwrap_or_else(|_| Response::new(crate::body::full(entry.body.clone())));
                    return (
                        resp,
                        DecisionTag::allow().with_tier(route_ctx.tier).with_cache(
                            aegis_control::interop::headers::CacheState::Hit,
                        ),
                    );
                }
                crate::cache::CacheLookup::Miss { key, rule_idx } => {
                    cache_pending = Some((pc, key, rule_idx));
                }
                crate::cache::CacheLookup::Bypass(_reason) => {}
            }
        }
    }

    if let Some(cb) = ctx.pools.breaker(&route_ctx.upstream) {
        if !cb.allow_request() {
            tracing::Span::current().record("outcome", "circuit-open");
            let resp = Response::builder()
                .status(hyper::StatusCode::SERVICE_UNAVAILABLE)
                .body(crate::body::full(Bytes::from("circuit open\n")))
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
                .body(crate::body::full(Bytes::from("unknown upstream\n")))
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
                .body(crate::body::full(Bytes::from("no healthy upstream\n")))
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
        &ctx.streaming,
        &ctx.streaming_permits,
    )
    .await;
    drop(_inflight_guard);

    match result {
        // Phase 2 staging: `forward()` now returns the classified
        // ResponseMode, but the body is still buffered here (the
        // streaming bypass that skips this collect/filter/cache path is
        // the next increment, once the inner chain carries DataBody).
        Ok((resp, mode)) => {
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
            // SSE plan Phase 3 — streaming bypass. A streamed response is
            // header-inspected only: its body can't be re-read, so we skip
            // the response-filter pipeline AND the response cache and pass
            // the live stream straight through. The decision was made once
            // in forward() (decision 2a); we act on the carried mode here
            // and never re-parse Content-Type. Request-side + response-
            // header inspection already ran. (Phase 5 stamps the
            // `streamed` / `response_inspection_skipped` audit fields.)
            if mode.is_streaming() {
                tracing::Span::current().record("outcome", "streamed");
                // Phase 5 — attach streaming observability (active gauge,
                // duration + bytes histograms, streamed counter). The
                // metric guard rides the body and records on drop (stream
                // end / client disconnect). No-op when metrics aren't wired.
                let resp = match ctx.stream_metrics.as_ref() {
                    Some(m) => resp.map(|body| {
                        crate::upstream::streaming::meter(body, m.clone())
                    }),
                    None => resp,
                };
                return (
                    resp,
                    DecisionTag::allow()
                        .with_tier(route_ctx.tier)
                        .with_streamed(true),
                );
            }
            // 2026-05-11 PR #7 — response filtering wire-up.
            // The forwarder buffers the entire upstream body
            // into `crate::body::full(body_bytes)` (see
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
                        .body(crate::body::full(bytes::Bytes::from(body_str)))
                        .unwrap();
                    return (
                        aborted,
                        DecisionTag::block("response-filter-abort")
                            .with_tier(route_ctx.tier),
                    );
                }
            };
            // SC-1 — store on the upstream success path, BEFORE moving
            // `parts_out` / `final_bytes` into the response. `store` enforces
            // the rest of the admission rules (200-only, no Set-Cookie, no
            // no-store, content-type/deception armor, per-entry size cap);
            // a refusal still reports MISS on the wire (forwarded, not stored).
            let mut allow_tag = DecisionTag::allow().with_tier(route_ctx.tier);
            if let Some((pc, key, rule_idx)) = cache_pending.take() {
                pc.store(
                    key,
                    rule_idx,
                    parts_out.status.as_u16(),
                    &parts_out.headers,
                    &final_bytes,
                )
                .await;
                allow_tag = allow_tag
                    .with_cache(aegis_control::interop::headers::CacheState::Miss);
            }
            let resp = Response::from_parts(parts_out, crate::body::full(final_bytes));
            // 5xx from upstream is not a WAF block — we proxied
            // faithfully; the contract action stays `allow` (the
            // upstream's failure is what the client sees).
            (resp, allow_tag)
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
                    // P4 — surface upstream mTLS handshake failures on
                    // the Zero Trust page (classified by reason). Only
                    // record handshake errors for pools that actually
                    // opted into upstream mTLS, so a plain TLS/connect
                    // failure on a non-mTLS pool doesn't masquerade as
                    // a client-auth problem.
                    if let crate::upstream::forward::ForwardError::Handshake(m) = &e {
                        let is_mtls = ctx
                            .pools
                            .get(&route_ctx.upstream)
                            .map(|p| p.connection.upstream_mtls.is_some())
                            .unwrap_or(false);
                        if is_mtls {
                            crate::upstream::mtls_failures::global()
                                .record(&route_ctx.upstream, m);
                        }
                    }
                    DecisionTag::circuit_breaker("upstream-unreachable").with_tier(route_ctx.tier)
                }
                _ => DecisionTag::circuit_breaker("upstream-error").with_tier(route_ctx.tier),
            };
            tracing::Span::current().record("outcome", action_tag.action.as_str());
            let resp = Response::builder()
                .status(hyper::StatusCode::BAD_GATEWAY)
                .body(crate::body::full(Bytes::from("upstream error\n")))
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
    Response<crate::body::DataBody>,
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
        .body(crate::body::full(Bytes::new()))
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
mod proxy_via_tests {
    use super::with_proxy_via;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn stamps_proxy_via_into_object_fields() {
        let lb = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let out = with_proxy_via(serde_json::json!({"path": "/x"}), Some(lb));
        assert_eq!(out["proxy_via"], serde_json::json!("10.0.0.5"));
        assert_eq!(out["path"], serde_json::json!("/x"));
    }

    #[test]
    fn none_proxy_via_leaves_fields_untouched() {
        let base = serde_json::json!({"path": "/x"});
        let out = with_proxy_via(base.clone(), None);
        assert_eq!(out, base, "no override → wire shape unchanged");
    }

    #[test]
    fn null_fields_under_critical_load_are_left_null() {
        // Rate-limit audit sets `fields: Null` in critical mode; the
        // helper must not coerce it into an object.
        let lb = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let out = with_proxy_via(serde_json::Value::Null, Some(lb));
        assert!(out.is_null());
    }
}

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

    /// build_risk_key fills ip + session axes. device_fp stays
    /// `None` on the plain-HTTP path (no TLS fingerprint
    /// available), `Some(16 hex chars)` on the TLS path.
    #[test]
    fn build_risk_key_populates_session_axis() {
        let h = headers_with("session=abc");
        let ip: std::net::IpAddr = "203.0.113.10".parse().unwrap();
        let key = build_risk_key(ip, &h, None);
        assert_eq!(key.ip, ip);
        assert_eq!(key.session.as_deref(), Some("abc"));
        assert!(key.device_fp.is_none(), "plain HTTP leaves device_fp None");
    }

    #[test]
    fn build_risk_key_no_cookie_falls_back_to_ip_only_axis() {
        let h = HeaderMap::new();
        let ip: std::net::IpAddr = "203.0.113.10".parse().unwrap();
        let key = build_risk_key(ip, &h, None);
        assert_eq!(key.ip, ip);
        assert!(key.session.is_none());
    }

    /// 2026-05-19 — TLS fingerprint produces a stable device_fp axis.
    /// Two requests with the same JA4 + UA hash to the same bucket;
    /// two requests with the same JA4 but different UA bucket apart.
    #[test]
    fn build_risk_key_populates_device_fp_from_tls() {
        use http::HeaderValue;
        let mut h = HeaderMap::new();
        h.insert(
            http::header::USER_AGENT,
            HeaderValue::from_static("Mozilla/5.0 (Macintosh)"),
        );
        let ip: std::net::IpAddr = "203.0.113.10".parse().unwrap();
        let fp = aegis_core::TlsFingerprint {
            ja3: "abc".into(),
            ja4: "t13d1516h2_8daaf6152771_b0da82dd1658".into(),
        };

        let a = build_risk_key(ip, &h, Some(&fp));
        let b = build_risk_key(ip, &h, Some(&fp));
        assert_eq!(a.device_fp, b.device_fp, "same JA4 + UA → same hash");
        assert_eq!(a.device_fp.as_ref().map(|s| s.len()), Some(16));

        // Different UA on the same JA4 → different bucket.
        let mut h2 = HeaderMap::new();
        h2.insert(
            http::header::USER_AGENT,
            HeaderValue::from_static("curl/8.0"),
        );
        let c = build_risk_key(ip, &h2, Some(&fp));
        assert_ne!(a.device_fp, c.device_fp, "different UA → different hash");
    }

    /// Same IP + same UA (+ no session) but a DIFFERENT JA4 must land
    /// on a different composite key — the device_fp axis is what
    /// separates two TLS clients NAT'd behind one address. Holds every
    /// other axis constant so only the JA4 varies.
    #[test]
    fn build_risk_key_different_ja4_same_ip_buckets_apart() {
        use http::HeaderValue;
        let ip: std::net::IpAddr = "203.0.113.10".parse().unwrap();
        let mut h = HeaderMap::new();
        h.insert(
            http::header::USER_AGENT,
            HeaderValue::from_static("Mozilla/5.0 (Macintosh)"),
        );
        let fp_a = aegis_core::TlsFingerprint {
            ja3: "abc".into(),
            ja4: "t13d1516h2_8daaf6152771_b0da82dd1658".into(),
        };
        let fp_b = aegis_core::TlsFingerprint {
            ja3: "abc".into(),
            ja4: "t13d1517h2_8daaf6152771_deadbeef0000".into(),
        };

        let a = build_risk_key(ip, &h, Some(&fp_a));
        let b = build_risk_key(ip, &h, Some(&fp_b));
        assert_eq!(a.ip, b.ip, "same IP");
        assert_eq!(a.session, b.session, "no session cookie on either");
        assert_ne!(a.device_fp, b.device_fp, "different JA4 → different device_fp");
        assert_ne!(a, b, "composite keys differ on the device_fp axis alone");
    }

    /// Same IP + same JA4 + same UA but different session cookies
    /// must give us TWO distinct keys — the whole point of the
    /// composite migration.
    #[test]
    fn build_risk_key_two_sessions_on_same_ip_bucket_apart() {
        use http::HeaderValue;
        let ip: std::net::IpAddr = "203.0.113.10".parse().unwrap();
        let fp = aegis_core::TlsFingerprint {
            ja3: "abc".into(),
            ja4: "ja4-shared".into(),
        };
        let ua = HeaderValue::from_static("Mozilla/5.0");
        let mut h1 = HeaderMap::new();
        h1.insert(http::header::USER_AGENT, ua.clone());
        h1.insert(http::header::COOKIE, HeaderValue::from_static("session=alice"));
        let mut h2 = HeaderMap::new();
        h2.insert(http::header::USER_AGENT, ua);
        h2.insert(http::header::COOKIE, HeaderValue::from_static("session=bob"));

        let alice = build_risk_key(ip, &h1, Some(&fp));
        let bob = build_risk_key(ip, &h2, Some(&fp));
        assert_eq!(alice.ip, bob.ip, "same IP");
        assert_eq!(alice.device_fp, bob.device_fp, "same TLS device");
        assert_ne!(alice.session, bob.session, "session axis splits the bucket");
        assert_ne!(alice, bob);
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

#[cfg(test)]
mod request_echo_tests {
    use super::{is_sensitive_header, request_echo_fields};
    use http::HeaderMap;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                http::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                http::header::HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn sensitive_header_values_are_masked() {
        let h = headers(&[
            ("user-agent", "curl/8.0"),
            ("authorization", "Bearer sk-secret"),
            ("cookie", "session=abc"),
            ("x-api-key", "deadbeef"),
        ]);
        let echo = request_echo_fields(&h, None);
        let hdrs = echo["request_headers"].as_object().unwrap();
        assert_eq!(hdrs["user-agent"], "curl/8.0");
        assert_eq!(hdrs["authorization"], "[redacted]");
        // cookie is now shown with per-pair redaction; `session` is sensitive.
        assert_eq!(hdrs["cookie"], "session=[redacted]");
        assert_eq!(hdrs["x-api-key"], "[redacted]");
    }

    #[test]
    fn cookie_shows_pairs_but_masks_sensitive_values() {
        let h = headers(&[(
            "cookie",
            "_ga=GA1.2.3; sessionid=abc123; consent=yes; auth_token=xyz; ab_test=onerror=1",
        )]);
        let echo = request_echo_fields(&h, None);
        let c = echo["request_headers"]["cookie"].as_str().unwrap();
        // non-credential cookies stay visible (this is the FP-debugging value)
        assert!(c.contains("_ga=GA1.2.3"), "analytics cookie shown: {c}");
        assert!(c.contains("consent=yes"), "consent cookie shown: {c}");
        assert!(c.contains("ab_test=onerror=1"), "state cookie shown: {c}");
        // credential cookies are masked
        assert!(c.contains("sessionid=[redacted]"), "session masked: {c}");
        assert!(c.contains("auth_token=[redacted]"), "auth masked: {c}");
        // the secret values themselves never appear
        assert!(!c.contains("abc123") && !c.contains("xyz"), "no secret leak: {c}");
    }

    #[test]
    fn body_preview_is_bounded_and_flags_truncation() {
        let small = b"id=1&q=hello";
        let echo = request_echo_fields(&HeaderMap::new(), Some(small));
        assert_eq!(echo["request_body_preview"], "id=1&q=hello");
        assert_eq!(echo["request_body_bytes"], 12);
        assert_eq!(echo["request_body_truncated"], false);

        let big = vec![b'a'; 5000];
        let echo = request_echo_fields(&HeaderMap::new(), Some(&big));
        assert_eq!(echo["request_body_bytes"], 5000);
        assert_eq!(echo["request_body_truncated"], true);
        assert_eq!(echo["request_body_preview"].as_str().unwrap().len(), 2048);
    }

    #[test]
    fn no_body_keys_when_body_is_none() {
        let echo = request_echo_fields(&HeaderMap::new(), None);
        assert!(echo.contains_key("request_headers"));
        assert!(!echo.contains_key("request_body_preview"));
        assert!(!echo.contains_key("request_body_bytes"));
    }

    #[test]
    fn sensitive_header_classifier_catches_substrings() {
        assert!(is_sensitive_header("authorization"));
        assert!(is_sensitive_header("x-refresh-token"));
        assert!(is_sensitive_header("my-password-field"));
        assert!(is_sensitive_header("x-some-apikey"));
        assert!(!is_sensitive_header("user-agent"));
        assert!(!is_sensitive_header("content-type"));
        assert!(!is_sensitive_header("accept"));
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
    Response<crate::body::DataBody>,
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
        .body(crate::body::full(Bytes::from(format!("{message}\n"))))
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
/// - `device_fp` — `Some(blake3-16hex(ja4 ‖ ua))` when the TLS
///   handshake produced a fingerprint (HTTPS data plane); `None`
///   on plain HTTP. See
///   [`aegis_security::fingerprint::device_fp_hash`] for the
///   exact construction. Two TLS sessions from the same NAT'd IP
///   with different JA4 / User-Agent shapes now bucket
///   independently — that's the whole point of the composite key.
///
/// 2026-05-19 — `tenant_id` axis removed from `RiskKey` (the
/// multi-tenant feature was deprecated upstream; every populator
/// was hard-coded to `None`).
pub(crate) fn build_risk_key(
    peer_ip: std::net::IpAddr,
    headers: &http::HeaderMap,
    tls_fp: Option<&aegis_core::TlsFingerprint>,
) -> aegis_core::risk::RiskKey {
    let device_fp = tls_fp.map(|fp| {
        let ua = headers
            .get(http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok());
        aegis_security::fingerprint::device_fp_hash(&fp.ja4, ua)
    });
    aegis_core::risk::RiskKey {
        ip: peer_ip,
        device_fp,
        session: extract_session_id(headers),
    }
}

/// 2026-05-20 — bounded, redacted request echo for the audit
/// `fields` bag so the dashboard's request-detail drawer can show
/// the headers + payload that tripped a detector. Only invoked on
/// detection / block paths (not every request) and behind the same
/// load-mode + verbosity gate as the rest of `fields`, so the
/// volume + audit-log disk cost stays bounded.
///
/// Security: header values for auth / cookie / token / API-key
/// names are masked to `[redacted]` (the key is kept so operators
/// know the header was present); the body is capped to a small
/// UTF-8-lossy preview with a `truncated` flag. `body = None` for
/// the early IP-reputation block paths that fire before the body
/// is buffered.
fn request_echo_fields(
    headers: &http::HeaderMap,
    body: Option<&[u8]>,
) -> serde_json::Map<String, serde_json::Value> {
    const MAX_HEADERS: usize = 64;
    const MAX_BODY_PREVIEW: usize = 2048;

    let mut hdrs = serde_json::Map::new();
    for (name, value) in headers.iter().take(MAX_HEADERS) {
        let key = name.as_str().to_ascii_lowercase();
        let val_str = value.to_str().unwrap_or("[binary]");
        // 2026-05-22 — the `cookie` header is shown for blocked-request
        // forensics (which cookie tripped a detector?), but the VALUES of
        // sensitive-named cookie pairs (session / auth / token / csrf / …)
        // are masked so session credentials never reach the audit chain or
        // dashboard. Other sensitive headers (authorization, x-*-token, …)
        // stay fully masked.
        let rendered = if key == "cookie" {
            redact_cookie(val_str)
        } else if is_sensitive_header(&key) {
            "[redacted]".to_string()
        } else {
            val_str.to_string()
        };
        // Last value wins for repeated header names — multi-valued
        // request headers are rare and the preview is forensic, not
        // authoritative.
        hdrs.insert(key, serde_json::Value::String(rendered));
    }

    let mut out = serde_json::Map::new();
    out.insert(
        "request_headers".to_string(),
        serde_json::Value::Object(hdrs),
    );

    if let Some(b) = body {
        let total = b.len();
        let slice = &b[..total.min(MAX_BODY_PREVIEW)];
        out.insert(
            "request_body_preview".to_string(),
            serde_json::Value::String(String::from_utf8_lossy(slice).into_owned()),
        );
        out.insert(
            "request_body_bytes".to_string(),
            serde_json::Value::from(total),
        );
        out.insert(
            "request_body_truncated".to_string(),
            serde_json::Value::Bool(total > MAX_BODY_PREVIEW),
        );
    }
    out
}

/// Header names whose VALUES carry secrets and must never reach the
/// audit log / dashboard. The name itself is still surfaced so an
/// operator can see the header was present.
/// Render a `Cookie` header value for the forensic echo: each
/// `name=value` pair is preserved so operators can see which cookie
/// tripped a detector, but the value is masked when the cookie NAME
/// looks sensitive (session / auth / token / csrf / …). Session
/// credentials therefore never reach the audit chain or dashboard,
/// while analytics / consent / state cookies stay visible for
/// false-positive debugging.
fn redact_cookie(raw: &str) -> String {
    raw.split(';')
        .map(|pair| {
            let pair = pair.trim();
            match pair.split_once('=') {
                Some((name, _)) if is_sensitive_cookie_name(name.trim()) => {
                    format!("{}=[redacted]", name.trim())
                }
                _ => pair.to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Cookie names whose VALUES carry credentials / CSRF tokens / session
/// identifiers and must be masked even in a blocked-request echo.
fn is_sensitive_cookie_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.ends_with("sid")          // sid / jsessionid / phpsessid / asp.net_sessionid
        || n.contains("session")
        || n.contains("token")
        || n.contains("auth")
        || n.contains("jwt")
        || n.contains("csrf")
        || n.contains("xsrf")
        || n.contains("secret")
        || n.contains("password")
        || n.contains("apikey")
        || n.contains("api-key")
}

fn is_sensitive_header(lower_name: &str) -> bool {
    const EXACT: &[&str] = &[
        "authorization",
        "proxy-authorization",
        // `cookie` is intentionally NOT here — it's rendered with
        // per-pair redaction by `redact_cookie` so blocked-request
        // forensics can see non-credential cookies.
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
        "x-xsrf-token",
        "x-amz-security-token",
        "x-aegis-actor",
    ];
    EXACT.contains(&lower_name)
        || lower_name.contains("secret")
        || lower_name.contains("token")
        || lower_name.contains("password")
        || lower_name.contains("apikey")
        || lower_name.contains("api-key")
}

// C-5 (2026-06-10): the hard-coded `default_trusted_proxies()` (which
// always returned an empty Vec with no way to configure it) was retired
// in favour of `cfg.proxy.trusted_proxies`, parsed once into
// `ProxyContext.trusted_proxies` and read by the data-plane handler.
// The F-HIGH-002 default is preserved: an empty `trusted_proxies` means
// the TCP peer always wins and XFF is ignored. Operators fronting the
// fleet with a *trusted* L7/SNAT LB set the LB CIDRs so
// `resolve_client_ip` walks XFF right-to-left to the real client; the
// v2.3 §6/§10 contract assertions hold because the default stays empty.

/// 2026-05-25 — emit a Detection audit for the CHALLENGE action.
/// Mirrors [`blocked_response`]'s audit shape (`action: "challenge"`,
/// `rule_id: risk-challenge`) so the dashboard Live Feed + AttacksAggregator
/// surface challenges the same way they surface blocks. The cumulative-gate
/// challenge rung previously built the 429 and returned WITHOUT auditing, so
/// `action: challenge` never reached the audit log / UI (only the live
/// `X-WAF-Action` response header carried it). Unlike `blocked_response` this
/// builds no HTTP response — the 429 PoW body is shaped by the caller.
/// 2026-05-25 — `detector_score` + `detectors` mirror the risk-score
/// block path: when THIS request tripped a detector under the per-request
/// threshold and then the cumulative gate challenged it, the audit records
/// `fields.request_score` + `fields.detectors` so the feed can show the
/// detector that raised the score (`risk-challenge · recon_path`) and the
/// per-request score — instead of a scoreless `risk-challenge` row. Both
/// `None` (this request scored 0 → challenged purely on the IP's accumulated
/// history) leaves the fields slim, which the UI renders as `· cumulative`.
#[allow(clippy::too_many_arguments)]
fn emit_challenge_audit(
    peer: std::net::SocketAddr,
    peer_ip: std::net::IpAddr,
    tier: aegis_core::tier::Tier,
    risk_score: Option<u32>,
    detector_score: Option<u32>,
    detectors: Option<&str>,
    uri: &hyper::Uri,
    method: &hyper::Method,
    bus: &AuditBus,
    echo: Option<serde_json::Map<String, serde_json::Value>>,
) {
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
        tier: Some(tier),
        action: "challenge".into(),
        reason: "risk score over challenge threshold".into(),
        client_ip: peer_ip.to_string(),
        route_id: None,
        rule_id: Some("risk-challenge".to_string()),
        risk_score,
        method: Some(method.to_string()),
        path: Some(uri.to_string()),
        mode: None,
        fields: {
            let mut f = serde_json::Map::new();
            f.insert("path".to_string(), serde_json::Value::String(uri.to_string()));
            f.insert("method".to_string(), serde_json::Value::String(method.to_string()));
            // The challenge response is always 429 (PoW). Stamp it so the
            // feed's Status column matches blocks/allows (the listener emit
            // that used to carry this is now skipped for challenge).
            f.insert("status".to_string(), serde_json::json!(429));
            if let Some(rs) = detector_score {
                f.insert("request_score".to_string(), serde_json::json!(rs));
            }
            if let Some(d) = detectors {
                f.insert("detectors".to_string(), serde_json::Value::String(d.to_string()));
            }
            if let Some(echo) = echo {
                f.extend(echo);
            }
            serde_json::Value::Object(f)
        },
    };
    bus.emit(ev);
}

#[allow(clippy::too_many_arguments)]
fn blocked_response(
    peer: std::net::SocketAddr,
    reason: &str,
    rule_id: Option<String>,
    risk_score: Option<u32>,
    // 2026-05-24 — route-resolved tier passed by the caller (each block
    // path resolves it once up front). Replaces the old internal
    // `classify_tier_from_path` call.
    tier: aegis_core::tier::Tier,
    uri: &hyper::Uri,
    method: &hyper::Method,
    bus: &AuditBus,
    // 2026-05-22 — optional redacted request echo (headers + body
    // preview, cookie pairs masked) merged into the audit `fields` so
    // gate blocks (e.g. risk-score) surface the same detail drawer the
    // detector blocks already do. `None` keeps the slim shape.
    echo: Option<serde_json::Map<String, serde_json::Value>>,
) -> Response<crate::body::DataBody> {
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
        // 2026-05-24 — use the route-resolved tier the caller passed
        // (the matched route's `tier_override`, e.g. a catch-all `/`
        // route at tier=high). Previously this hard-coded
        // `classify_tier_from_path(uri.path())`, which ALWAYS returns
        // Low since the path heuristic was removed — so a cumulative
        // `risk-score` block on a high-tier route rendered as Low in the
        // Live Feed while a per-request detector block on the SAME route
        // correctly showed high. Now both agree.
        tier: Some(tier),
        action: "block".into(),
        reason: reason.into(),
        client_ip: peer.ip().to_string(),
        route_id: None,
        rule_id,
        risk_score,
        method: Some(method.to_string()),
        path: Some(uri.to_string()),
        mode: None,
        fields: {
            let mut f = serde_json::Map::new();
            f.insert("path".to_string(), serde_json::Value::String(uri.to_string()));
            f.insert("method".to_string(), serde_json::Value::String(method.to_string()));
            if let Some(echo) = echo {
                f.extend(echo);
            }
            serde_json::Value::Object(f)
        },
    };
    bus.emit(ev);
    Response::builder()
        .status(403)
        .header("content-type", "application/json")
        .body(crate::body::full(Bytes::from(
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

    fn rule_id_header<B>(resp: &hyper::Response<B>) -> Option<&str> {
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

    /// WS-MSG2 — with `ws_inspect.enabled`, text **and** binary frames
    /// still round-trip through the *inspecting* bridge (binary verbatim,
    /// text reassembled-then-forwarded). Proves the parsing bridge is
    /// transparent before any detector is wired (WS-MSG3).
    #[tokio::test]
    async fn websocket_round_trips_with_inspection_enabled() {
        use futures::SinkExt;
        use tokio_tungstenite::tungstenite::Message;

        let backend = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let backend_task = tokio::spawn(async move {
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

        // Same fixture, but the route opts into frame inspection.
        let yaml = format!(
            r#"
listeners:
  data: [{{ bind: "127.0.0.1:0" }}]
  admin: {{ bind: "127.0.0.1:0" }}
routes:
  - {{ id: chat, path: "/", upstream: pool, ws_inspect: {{ enabled: true }} }}
upstreams:
  pool: {{ members: [{{ addr: "{backend_addr}" }}] }}
state: {{ backend: in_memory }}
"#
        );
        let cfg: aegis_core::config::WafConfig = serde_yaml::from_str(&yaml).unwrap();
        cfg.validate().unwrap();
        let pipeline: Arc<dyn SecurityPipeline> = Arc::new(aegis_security::NoopPipeline);
        let ctx = Arc::new(ProxyContext::build(&cfg, pipeline).unwrap());

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

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let url = format!("ws://127.0.0.1:{}/", waf_addr.port());
        let (ws, _resp) = tokio_tungstenite::connect_async(&url)
            .await
            .expect("client connects + upgrades through the inspecting bridge");
        let (mut tx, mut rx) = futures::StreamExt::split(ws);

        // Text message round-trips (reassembled + forwarded).
        tx.send(Message::Text("benign chat text".into()))
            .await
            .unwrap();
        let echo = futures::StreamExt::next(&mut rx)
            .await
            .expect("text echo")
            .expect("text echo ok");
        assert_eq!(echo.into_text().unwrap(), "benign chat text");

        // Binary message round-trips byte-identical (never inspected).
        let payload = vec![0x00, 0x01, 0x02, 0xFF, 0xFE];
        tx.send(Message::Binary(payload.clone().into()))
            .await
            .unwrap();
        let echo2 = futures::StreamExt::next(&mut rx)
            .await
            .expect("binary echo")
            .expect("binary echo ok");
        assert_eq!(echo2.into_data().to_vec(), payload);

        drop(tx);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        backend_task.abort();
        waf_task.abort();
    }

    /// WS-MSG3 — with real detectors wired and `mode: enforce`, a text
    /// frame carrying SQLi is blocked: it never reaches the upstream and
    /// the client's socket is closed. The detector chain runs over the
    /// reassembled message via the synthetic `RequestView`.
    #[tokio::test]
    async fn sqli_text_frame_is_blocked_and_never_reaches_upstream() {
        use futures::SinkExt;
        use tokio_tungstenite::tungstenite::Message;

        // Echo backend that records whether it ever received a message.
        let backend = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let got_message = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let got_message_be = got_message.clone();
        let backend_task = tokio::spawn(async move {
            let (stream, _) = backend.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let (mut tx, mut rx) = futures::StreamExt::split(ws);
            while let Some(Ok(msg)) = futures::StreamExt::next(&mut rx).await {
                if msg.is_text() || msg.is_binary() {
                    got_message_be.store(true, std::sync::atomic::Ordering::SeqCst);
                    let _ = tx.send(msg).await;
                }
            }
        });

        let yaml = format!(
            r#"
listeners:
  data: [{{ bind: "127.0.0.1:0" }}]
  admin: {{ bind: "127.0.0.1:0" }}
routes:
  - {{ id: chat, path: "/", upstream: pool, ws_inspect: {{ enabled: true, mode: enforce }} }}
upstreams:
  pool: {{ members: [{{ addr: "{backend_addr}" }}] }}
state: {{ backend: in_memory }}
"#
        );
        let cfg: aegis_core::config::WafConfig = serde_yaml::from_str(&yaml).unwrap();
        cfg.validate().unwrap();
        let pipeline: Arc<dyn SecurityPipeline> = Arc::new(aegis_security::NoopPipeline);
        let mut ctx_inner = ProxyContext::build(&cfg, pipeline).unwrap();
        // Wire the real detector chain into the WS bridge.
        ctx_inner.ws_detectors =
            Some(Arc::new(aegis_security::detectors::default_detectors()));
        ctx_inner.ws_detector_mask =
            Some(aegis_security::detectors::SharedDetectorMask::default());
        let ctx = Arc::new(ctx_inner);

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

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let url = format!("ws://127.0.0.1:{}/", waf_addr.port());
        let (ws, _resp) = tokio_tungstenite::connect_async(&url).await.unwrap();
        let (mut tx, mut rx) = futures::StreamExt::split(ws);

        // Malicious text frame → blocked by the SQLi detector.
        tx.send(Message::Text("' OR 1=1--".into())).await.unwrap();

        // The bridge closes the socket; the client sees a Close (or the
        // stream ends) and never an echo of the payload.
        let mut echoed_back = false;
        while let Some(item) = futures::StreamExt::next(&mut rx).await {
            match item {
                Ok(Message::Text(_)) | Ok(Message::Binary(_)) => {
                    echoed_back = true;
                    break;
                }
                Ok(Message::Close(_)) | Err(_) => break,
                _ => {}
            }
        }
        assert!(!echoed_back, "blocked SQLi message must not be echoed back");

        // Let the backend task observe (it should never have).
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            !got_message.load(std::sync::atomic::Ordering::SeqCst),
            "blocked SQLi message must never reach the upstream",
        );

        drop(tx);
        backend_task.abort();
        waf_task.abort();
    }

    /// WS-MSG4 — `mode: log_only` forwards the malicious frame to the
    /// upstream **and** emits a `websocket_frame_block` audit event with
    /// `mode: log_only`. The socket is NOT closed.
    #[tokio::test]
    async fn sqli_log_only_forwards_and_audits() {
        use futures::SinkExt;
        use tokio_tungstenite::tungstenite::Message;

        let backend = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let got_message = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let got_message_be = got_message.clone();
        let backend_task = tokio::spawn(async move {
            let (stream, _) = backend.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let (mut tx, mut rx) = futures::StreamExt::split(ws);
            while let Some(Ok(msg)) = futures::StreamExt::next(&mut rx).await {
                if msg.is_text() || msg.is_binary() {
                    got_message_be.store(true, std::sync::atomic::Ordering::SeqCst);
                    let _ = tx.send(msg).await;
                }
            }
        });

        let yaml = format!(
            r#"
listeners:
  data: [{{ bind: "127.0.0.1:0" }}]
  admin: {{ bind: "127.0.0.1:0" }}
routes:
  - {{ id: chat, path: "/", upstream: pool, ws_inspect: {{ enabled: true, mode: log_only }} }}
upstreams:
  pool: {{ members: [{{ addr: "{backend_addr}" }}] }}
state: {{ backend: in_memory }}
"#
        );
        let cfg: aegis_core::config::WafConfig = serde_yaml::from_str(&yaml).unwrap();
        cfg.validate().unwrap();
        let pipeline: Arc<dyn SecurityPipeline> = Arc::new(aegis_security::NoopPipeline);
        let mut ctx_inner = ProxyContext::build(&cfg, pipeline).unwrap();
        ctx_inner.ws_detectors =
            Some(Arc::new(aegis_security::detectors::default_detectors()));
        ctx_inner.ws_detector_mask =
            Some(aegis_security::detectors::SharedDetectorMask::default());
        let ctx = Arc::new(ctx_inner);

        let waf = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let waf_addr = waf.local_addr().unwrap();
        let bus = AuditBus::new(16);
        let mut audit_rx = bus.subscribe();
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

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let url = format!("ws://127.0.0.1:{}/", waf_addr.port());
        let (ws, _resp) = tokio_tungstenite::connect_async(&url).await.unwrap();
        let (mut tx, mut rx) = futures::StreamExt::split(ws);

        tx.send(Message::Text("' OR 1=1--".into())).await.unwrap();

        // log_only forwards → the backend echoes it back.
        let echo = futures::StreamExt::next(&mut rx)
            .await
            .expect("log_only forwards the frame → echo")
            .expect("echo ok");
        assert_eq!(echo.into_text().unwrap(), "' OR 1=1--");
        assert!(
            got_message.load(std::sync::atomic::Ordering::SeqCst),
            "log_only must forward the frame to the upstream",
        );

        // …and a websocket_frame_block audit with mode log_only fired.
        let mut found = false;
        while let Ok(ev) = audit_rx.try_recv() {
            if ev.action.as_str() == "websocket_frame_block" {
                found = true;
                assert_eq!(ev.mode.as_deref(), Some("log_only"));
                assert_eq!(ev.rule_id.as_deref(), Some("sqli"));
                assert_eq!(ev.route_id.as_deref(), Some("chat"));
                break;
            }
        }
        assert!(found, "log_only must emit a websocket_frame_block audit");

        drop(tx);
        backend_task.abort();
        waf_task.abort();
    }
}

#[cfg(test)]
mod log_only_enforce_tests {
    //! 2026-05-24 regression guard for the v2.x interop contract:
    //! `set_profile` `log_only` MUST actually forward a would-be-blocked
    //! request (HTTP 200), and `enforce` MUST block it (HTTP 403). This
    //! exercises the real data-plane mode gate (`interop_modes` →
    //! `mode_for_rule` → forward-on-LogOnly) end to end through
    //! `handle_data_request`, not just the `X-WAF-Mode` header — a review
    //! nearly mis-diagnosed this because the header reports the *would-be*
    //! action while the status code reports what actually happened.

    use std::convert::Infallible;
    use std::sync::Arc;

    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use aegis_control::interop::headers::Mode;
    use aegis_control::interop::mode::ModeStore;
    use aegis_core::audit::AuditBus;
    use aegis_core::{ClientIdentity, SecurityPipeline};
    use aegis_security::detectors::Detector;

    use crate::proxy::ProxyContext;

    /// Everything `handle_data_request` needs, bundled so the serve
    /// closure clones one `Arc` instead of 13.
    struct Args {
        detectors: Vec<Box<dyn Detector>>,
        mask: aegis_security::detectors::SharedDetectorMask,
        risk: aegis_security::risk::RiskTracker,
        ip_rl: aegis_security::rate_limit::IpRateLimiter,
        load_gauge: aegis_core::LoadGauge,
        verbosity: aegis_core::SharedVerbosity,
        rsh: aegis_control::metrics::request_duration::RequestStageHistogram,
        rlh: aegis_control::metrics::route_latency::RouteLatencyHistogram,
        ra: aegis_control::metrics::route_activity::RouteActivityWindow,
        dlh: aegis_control::metrics::detector_latency::DetectorLatencyHistogram,
        dhm: aegis_control::metrics::detector_hits::DetectorHitMetrics,
        bus: AuditBus,
        ctx: Arc<ProxyContext>,
    }

    /// Mock upstream that 200s everything, so a *forwarded* request is
    /// distinguishable from a 403 block by status code.
    async fn spawn_upstream() -> std::net::SocketAddr {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let svc = service_fn(|_r: hyper::Request<hyper::body::Incoming>| async {
                        Ok::<_, Infallible>(hyper::Response::new(crate::body::full(Bytes::from(
                            "upstream-ok",
                        ))))
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(s), svc)
                        .await;
                });
            }
        });
        addr
    }

    /// Send one GET and return the HTTP status code (raw to avoid a
    /// client dep; the WAF closes the conn after the response).
    async fn get_status(waf: std::net::SocketAddr, path: &str) -> u16 {
        let mut s = tokio::net::TcpStream::connect(waf).await.unwrap();
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: any\r\nConnection: close\r\n\r\n"
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf).await;
        let head = String::from_utf8_lossy(&buf);
        head.lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|c| c.parse().ok())
            .unwrap_or(0)
    }

    /// Like [`get_status`] but also returns the response body, so a 429
    /// challenge envelope can be inspected for the v2.5 contract fields.
    async fn get_response(waf: std::net::SocketAddr, path: &str) -> (u16, String) {
        let mut s = tokio::net::TcpStream::connect(waf).await.unwrap();
        let req = format!("GET {path} HTTP/1.1\r\nHost: any\r\nConnection: close\r\n\r\n");
        s.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf).await;
        let raw = String::from_utf8_lossy(&buf).to_string();
        let status = raw
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        let body = raw
            .split_once("\r\n\r\n")
            .map(|(_, b)| b.to_string())
            .unwrap_or_default();
        (status, body)
    }

    #[tokio::test]
    async fn set_profile_log_only_forwards_enforce_blocks() {
        let backend = spawn_upstream().await;
        let yaml = format!(
            r#"
listeners:
  data: [{{ bind: "127.0.0.1:0" }}]
  admin: {{ bind: "127.0.0.1:0" }}
routes:
  - {{ id: catch-all, path: "/", upstream: pool }}
upstreams:
  pool: {{ members: [{{ addr: "{backend}" }}] }}
state: {{ backend: in_memory }}
"#
        );
        let cfg: aegis_core::config::WafConfig = serde_yaml::from_str(&yaml).unwrap();
        cfg.validate().unwrap();
        let pipeline: Arc<dyn SecurityPipeline> = Arc::new(aegis_security::NoopPipeline);
        let ctx = Arc::new(ProxyContext::build(&cfg, pipeline).unwrap());

        // Shared ModeStore wired into the data plane exactly like run.rs.
        let modes = Arc::new(ModeStore::new(Mode::Enforce));
        ctx.interop_modes.set(modes.clone()).ok();

        let metrics = aegis_control::metrics::MetricsRegistry::init();
        let args = Arc::new(Args {
            detectors: aegis_security::detectors::default_detectors(),
            mask: aegis_security::detectors::SharedDetectorMask::from_config(&cfg.detectors),
            risk: aegis_security::risk::RiskTracker::new(&cfg.risk),
            ip_rl: aegis_security::rate_limit::IpRateLimiter::new(
                crate::config_source::reload::derive_ip_rate_cfg(&cfg),
            ),
            load_gauge: aegis_core::LoadGauge::new(cfg.load_mode.clone()),
            verbosity: aegis_core::SharedVerbosity::from_config(&cfg.logging),
            rsh: aegis_control::metrics::request_duration::RequestStageHistogram::register(&metrics)
                .unwrap(),
            rlh: aegis_control::metrics::route_latency::RouteLatencyHistogram::register(&metrics)
                .unwrap(),
            ra: aegis_control::metrics::route_activity::RouteActivityWindow::new(),
            dlh: aegis_control::metrics::detector_latency::DetectorLatencyHistogram::register(
                &metrics,
            )
            .unwrap(),
            dhm: aegis_control::metrics::detector_hits::DetectorHitMetrics::register(&metrics)
                .unwrap(),
            bus: AuditBus::new(64),
            ctx: ctx.clone(),
        });

        let waf = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let waf_addr = waf.local_addr().unwrap();
        let args_l = args.clone();
        tokio::spawn(async move {
            while let Ok((stream, peer)) = waf.accept().await {
                let args_c = args_l.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                        let a = args_c.clone();
                        async move {
                            let (resp, _tag) = super::handle_data_request(
                                req,
                                peer,
                                None, // PROXY-T3 — no PROXY override in this test harness
                                &a.detectors,
                                &a.mask,
                                &a.risk,
                                &a.ip_rl,
                                &a.load_gauge,
                                &a.verbosity,
                                &a.rsh,
                                &a.rlh,
                                &a.ra,
                                &a.dlh,
                                &a.bus,
                                &a.ctx,
                                &a.dhm,
                                &ClientIdentity::Anonymous,
                                None,
                            )
                            .await;
                            Ok::<_, Infallible>(resp)
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Multi-vector payload: sqli + path_traversal in the query →
        // per-request score well over any tier threshold → would block.
        let atk = "/?q=1%27%20OR%201=1%20UNION%20SELECT%20pw%20FROM%20users&p=..%2F..%2F..%2Fetc%2Fpasswd";

        // ENFORCE → real 403 block.
        modes.set_all(Mode::Enforce);
        let enforced = get_status(waf_addr, atk).await;
        assert_eq!(enforced, 403, "enforce must block the attack with 403");

        // LOG_ONLY → forwarded to upstream (200), NOT blocked.
        modes.set_all(Mode::LogOnly);
        let logged = get_status(waf_addr, atk).await;
        assert_eq!(
            logged, 200,
            "log_only must FORWARD the would-be-blocked request (got {logged}); \
             the data-plane mode gate is not honoring set_profile",
        );

        // Granular: rules_engine=log_only (feature-level) also forwards.
        modes.set_all(Mode::Enforce);
        modes.set_feature("rules_engine", Mode::LogOnly);
        let feat = get_status(waf_addr, atk).await;
        assert_eq!(feat, 200, "rules_engine=log_only must forward");
    }

    // 2026-05-24 — a block routed through `blocked_response` (cumulative
    // risk-score, blacklist, strike, ddos) must audit the ROUTE tier the
    // caller passes, NOT the legacy path-heuristic Low. Regression guard
    // for: a high-tier catch-all `/` route showed risk-score blocks as
    // Low in the Live Feed while per-request detector blocks showed high.
    #[tokio::test]
    async fn blocked_response_audits_caller_tier_not_low() {
        let bus = AuditBus::new(16);
        let mut rx = bus.subscribe();
        let uri: hyper::Uri = "/anything.php".parse().unwrap();
        let _ = super::blocked_response(
            "1.2.3.4:5".parse().unwrap(),
            "blocked by risk score",
            Some("risk-score".into()),
            Some(100),
            aegis_core::tier::Tier::High,
            &uri,
            &hyper::Method::GET,
            &bus,
            None,
        );
        let ev = rx.try_recv().expect("audit event emitted");
        assert_eq!(
            ev.tier,
            Some(aegis_core::tier::Tier::High),
            "risk-score block on a HIGH route must audit as High, not Low",
        );
    }

    /// 2026-05-25 — the cumulative-gate CHALLENGE rung must emit an audit
    /// (action "challenge", rule_id "risk-challenge") so it appears in the
    /// audit log / dashboard Live Feed. Previously the rung built the 429 and
    /// returned without auditing, so operators never saw `challenge` actions
    /// (only the live X-WAF-Action header carried it).
    #[tokio::test]
    async fn challenge_audit_emits_challenge_action_with_tier_and_score() {
        let bus = AuditBus::new(16);
        let mut rx = bus.subscribe();
        let uri: hyper::Uri = "/login".parse().unwrap();
        super::emit_challenge_audit(
            "9.9.9.9:443".parse().unwrap(),
            "9.9.9.9".parse().unwrap(),
            aegis_core::tier::Tier::High,
            Some(45),
            Some(25),
            Some("recon_path"),
            &uri,
            &hyper::Method::GET,
            &bus,
            None,
        );
        let ev = rx.try_recv().expect("challenge audit event emitted");
        assert_eq!(ev.action, "challenge", "challenge rung must audit action=challenge");
        assert_eq!(ev.rule_id.as_deref(), Some("risk-challenge"));
        assert_eq!(ev.tier, Some(aegis_core::tier::Tier::High));
        assert_eq!(ev.risk_score, Some(45), "audit carries the cumulative score");
        assert_eq!(ev.client_ip, "9.9.9.9");
        // 2026-05-25 — the contributing detector + per-request score ride in
        // `fields` so the feed can show `risk-challenge · recon_path` + Req.
        assert_eq!(
            ev.fields.get("detectors").and_then(|v| v.as_str()),
            Some("recon_path"),
            "challenge audit must carry the detector that raised the score"
        );
        assert_eq!(
            ev.fields.get("request_score").and_then(|v| v.as_u64()),
            Some(25),
            "challenge audit must carry this request's detector score"
        );
        assert_eq!(
            ev.fields.get("status").and_then(|v| v.as_u64()),
            Some(429),
            "challenge audit stamps the 429 status (listener emit is skipped for challenge)"
        );
    }

    /// 2026-05-25 — end-to-end + CONTRACT proof that a per-tier
    /// `challenges_enabled` toggle drives the cumulative-IP-risk challenge
    /// rung through `handle_data_request`:
    ///   • enabled  → a cumulative score in the band `[challenge_at,block_at)`
    ///                returns 429 with the v2.5 §4 Format-A PoW envelope
    ///                (`challenge_token` / `difficulty` / `submit_url` /
    ///                `submit_method`) AND emits an `action: challenge` audit.
    ///   • disabled → the SAME band score passes through as allow (200,
    ///                forwarded upstream) — no PoW.
    /// The PoW solve/verify round trip itself is covered by the
    /// `challenge::pow` tests (`verify_accepts_correct_solution`, …).
    #[tokio::test]
    async fn challenges_enabled_tier_issues_pow_challenge_for_band_score() {
        let backend = spawn_upstream().await;
        let yaml = format!(
            r#"
listeners:
  data: [{{ bind: "127.0.0.1:0" }}]
  admin: {{ bind: "127.0.0.1:0" }}
routes:
  - {{ id: catch-all, path: "/", upstream: pool }}
upstreams:
  pool: {{ members: [{{ addr: "{backend}" }}] }}
state: {{ backend: in_memory }}
"#
        );
        let cfg: aegis_core::config::WafConfig = serde_yaml::from_str(&yaml).unwrap();
        cfg.validate().unwrap();
        let pipeline: Arc<dyn SecurityPipeline> = Arc::new(aegis_security::NoopPipeline);
        let ctx = Arc::new(ProxyContext::build(&cfg, pipeline).unwrap());

        // Catch-all `/` resolves to the LOW tier. Seed low.challenges_enabled
        // exactly as the boot path does from `challenges_enabled_overrides()`.
        let tiers = Arc::new(aegis_control::api::tiers::TierStore::new());
        tiers.apply_challenges_enabled([("low", true)]);
        ctx.tiers.set(tiers.clone()).ok();

        // PoW issuer so the 429 envelope carries a real challenge_token.
        let issuer = Arc::new(aegis_security::challenge::PowIssuer::new(
            [7u8; 32],
            8,
            std::time::Duration::from_secs(60),
        ));
        ctx.pow_issuer.set(issuer).ok();
        ctx.interop_modes.set(Arc::new(ModeStore::new(Mode::Enforce))).ok();

        let metrics = aegis_control::metrics::MetricsRegistry::init();
        let risk = aegis_security::risk::RiskTracker::new(&cfg.risk);
        // Pre-seed the loopback composite key (no cookie/TLS → IP-only) into
        // the challenge band: score 50 ∈ [challenge_at 30, block_at 70).
        risk.record_malicious("127.0.0.1".parse().unwrap(), 50);

        let args = Arc::new(Args {
            detectors: aegis_security::detectors::default_detectors(),
            mask: aegis_security::detectors::SharedDetectorMask::from_config(&cfg.detectors),
            risk,
            ip_rl: aegis_security::rate_limit::IpRateLimiter::new(
                crate::config_source::reload::derive_ip_rate_cfg(&cfg),
            ),
            load_gauge: aegis_core::LoadGauge::new(cfg.load_mode.clone()),
            verbosity: aegis_core::SharedVerbosity::from_config(&cfg.logging),
            rsh: aegis_control::metrics::request_duration::RequestStageHistogram::register(&metrics)
                .unwrap(),
            rlh: aegis_control::metrics::route_latency::RouteLatencyHistogram::register(&metrics)
                .unwrap(),
            ra: aegis_control::metrics::route_activity::RouteActivityWindow::new(),
            dlh: aegis_control::metrics::detector_latency::DetectorLatencyHistogram::register(
                &metrics,
            )
            .unwrap(),
            dhm: aegis_control::metrics::detector_hits::DetectorHitMetrics::register(&metrics)
                .unwrap(),
            bus: AuditBus::new(64),
            ctx: ctx.clone(),
        });
        let mut rx = args.bus.subscribe();

        let waf = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let waf_addr = waf.local_addr().unwrap();
        let args_l = args.clone();
        tokio::spawn(async move {
            while let Ok((stream, peer)) = waf.accept().await {
                let args_c = args_l.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                        let a = args_c.clone();
                        async move {
                            let (resp, _tag) = super::handle_data_request(
                                req,
                                peer,
                                None, // PROXY-T3 — no PROXY override in this test harness
                                &a.detectors,
                                &a.mask,
                                &a.risk,
                                &a.ip_rl,
                                &a.load_gauge,
                                &a.verbosity,
                                &a.rsh,
                                &a.rlh,
                                &a.ra,
                                &a.dlh,
                                &a.bus,
                                &a.ctx,
                                &a.dhm,
                                &ClientIdentity::Anonymous,
                                None,
                            )
                            .await;
                            Ok::<_, Infallible>(resp)
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // ENABLED → 429 with the v2.5 §4 Format-A PoW envelope.
        let (status, body) = get_response(waf_addr, "/").await;
        assert_eq!(status, 429, "band score on a challenges-enabled tier must 429");
        let v: serde_json::Value = serde_json::from_str(&body)
            .unwrap_or_else(|_| panic!("challenge body must be JSON, got: {body}"));
        assert_eq!(v["challenge"], serde_json::json!(true));
        assert_eq!(v["challenge_type"], serde_json::json!("proof_of_work"));
        assert!(
            v["challenge_token"].as_str().map(|t| !t.is_empty()).unwrap_or(false),
            "v2.5 §4 requires a non-empty challenge_token, got: {body}"
        );
        assert!(v["difficulty"].is_number(), "envelope must carry difficulty");
        assert_eq!(v["submit_url"], serde_json::json!("/challenge/verify"));
        assert_eq!(v["submit_method"], serde_json::json!("POST"));

        // … and the challenge must be audited (drain all events, find it).
        let mut saw_challenge = false;
        while let Ok(ev) = rx.try_recv() {
            if ev.action == "challenge" {
                saw_challenge = true;
                assert_eq!(ev.rule_id.as_deref(), Some("risk-challenge"));
                assert_eq!(ev.client_ip, "127.0.0.1");
            }
        }
        assert!(saw_challenge, "challenge action must reach the audit bus");

        // DISABLED → same band score now passes through as allow (forwarded).
        tiers.apply_challenges_enabled([("low", false)]);
        let (status_off, _body) = get_response(waf_addr, "/").await;
        assert_eq!(
            status_off, 200,
            "challenges off → band score must pass through as allow (forwarded), got {status_off}"
        );
    }
}

// SC-1 — end-to-end smart-cache tests through `forward_allow_to_upstream`
// against a real mock HTTP backend. Proves: MISS-then-HIT on identical GETs
// (and that a HIT does NOT re-dial the backend), and that a CRITICAL-tier
// route is never cached (BYPASS, backend hit every time).
#[cfg(test)]
mod smart_cache_e2e_tests {
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    use aegis_core::audit::AuditBus;
    use aegis_core::pipeline::SecurityPipeline;
    use aegis_core::ClientIdentity;
    use bytes::Bytes;
    use http_body_util::BodyExt;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;

    use crate::proxy::ProxyContext;
    use aegis_control::interop::headers::CacheState;

    fn route_latency() -> aegis_control::metrics::route_latency::RouteLatencyHistogram {
        let reg = aegis_control::metrics::MetricsRegistry::init();
        aegis_control::metrics::route_latency::RouteLatencyHistogram::register(&reg)
            .expect("route latency histogram registers")
    }
    fn route_activity_w() -> aegis_control::metrics::route_activity::RouteActivityWindow {
        aegis_control::metrics::route_activity::RouteActivityWindow::new()
    }
    fn get_parts(uri: &str) -> http::request::Parts {
        let req = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri(uri)
            .header("host", "any")
            .body(http_body_util::Empty::<Bytes>::new())
            .unwrap();
        req.into_parts().0
    }

    /// Spawn a mock HTTP/1.1 backend that counts requests and returns
    /// `200 text/css` with a fixed body. Returns `(addr, hit_counter)`.
    async fn spawn_backend() -> (std::net::SocketAddr, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_for_task = hits.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(c) => c,
                    Err(_) => break,
                };
                let hits = hits_for_task.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |_req: hyper::Request<hyper::body::Incoming>| {
                        let hits = hits.clone();
                        async move {
                            hits.fetch_add(1, Ordering::SeqCst);
                            Ok::<_, Infallible>(
                                hyper::Response::builder()
                                    .status(200)
                                    .header("content-type", "text/css")
                                    .body(http_body_util::Full::new(Bytes::from_static(
                                        b"cached-css-body",
                                    )))
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
        (addr, hits)
    }

    fn ctx_for(addr: std::net::SocketAddr, tier_override: Option<&str>) -> Arc<ProxyContext> {
        let route_line = match tier_override {
            Some(t) => format!(
                "  - {{ id: assets, path: \"/\", upstream: pool, tier_override: {t} }}"
            ),
            None => "  - { id: assets, path: \"/\", upstream: pool }".to_string(),
        };
        let yaml = format!(
            r#"
listeners:
  data: [{{ bind: "127.0.0.1:0" }}]
  admin: {{ bind: "127.0.0.1:0" }}
routes:
{route_line}
upstreams:
  pool:
    members: [{{ addr: "{addr}" }}]
    cache:
      enabled: true
      default_ttl: "60s"
      rules:
        - prefix: "/static/"
          content_types: ["text/css"]
state: {{ backend: in_memory }}
"#
        );
        let cfg: aegis_core::config::WafConfig = serde_yaml::from_str(&yaml).unwrap();
        cfg.validate().unwrap();
        let pipeline: Arc<dyn SecurityPipeline> = Arc::new(aegis_security::NoopPipeline);
        Arc::new(ProxyContext::build(&cfg, pipeline).unwrap())
    }

    async fn forward(
        ctx: &Arc<ProxyContext>,
        uri: &str,
        rh: &aegis_control::metrics::route_latency::RouteLatencyHistogram,
        bus: &AuditBus,
    ) -> (hyper::StatusCode, CacheState, Bytes) {
        let (resp, tag) = super::forward_allow_to_upstream(
            get_parts(uri),
            Bytes::new(),
            ctx,
            &ClientIdentity::Anonymous,
            rh,
            &route_activity_w(),
            Instant::now(),
            "198.51.100.7".parse().unwrap(),
            bus,
        )
        .await;
        let status = resp.status();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, tag.cache, body)
    }

    #[tokio::test]
    async fn miss_then_hit_does_not_redial_backend() {
        let (addr, hits) = spawn_backend().await;
        let ctx = ctx_for(addr, None);
        let rh = route_latency();
        let bus = AuditBus::new(16);

        // 1st GET — MISS, forwarded + stored.
        let (s1, c1, b1) = forward(&ctx, "/static/app.css", &rh, &bus).await;
        assert_eq!(s1, 200);
        assert!(matches!(c1, CacheState::Miss), "1st should be MISS, got {c1:?}");
        assert_eq!(&b1[..], b"cached-css-body");
        assert_eq!(hits.load(Ordering::SeqCst), 1, "backend hit once on miss");

        // 2nd identical GET — HIT, served from cache, backend NOT re-dialed.
        let (s2, c2, b2) = forward(&ctx, "/static/app.css", &rh, &bus).await;
        assert_eq!(s2, 200);
        assert!(matches!(c2, CacheState::Hit), "2nd should be HIT, got {c2:?}");
        assert_eq!(&b2[..], b"cached-css-body");
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "HIT must not re-dial the backend"
        );
    }

    #[tokio::test]
    async fn critical_tier_is_never_cached() {
        let (addr, hits) = spawn_backend().await;
        let ctx = ctx_for(addr, Some("critical"));
        let rh = route_latency();
        let bus = AuditBus::new(16);

        // Even with a matching cache rule, a CRITICAL-tier route bypasses.
        let (_s1, c1, _b1) = forward(&ctx, "/static/app.css", &rh, &bus).await;
        assert!(matches!(c1, CacheState::Bypass), "critical → BYPASS, got {c1:?}");
        let (_s2, c2, _b2) = forward(&ctx, "/static/app.css", &rh, &bus).await;
        assert!(matches!(c2, CacheState::Bypass), "critical → BYPASS, got {c2:?}");
        assert_eq!(
            hits.load(Ordering::SeqCst),
            2,
            "critical never caches → backend hit every request"
        );
    }
}
