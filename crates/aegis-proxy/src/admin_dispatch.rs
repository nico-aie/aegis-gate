//! PRE-T7 (part of) — admin / interop / force-https request
//! dispatch extracted from `lib.rs`.
//!
//! ## Scope
//!
//! - [`handle_admin_request`] — method+path dispatch for the
//!   admin listener. Routes `/admin/login` /
//!   `/admin/logout` / `/admin/drain` / mutation-handler
//!   paths / `/__waf_control/*` then falls through to
//!   [`crate::admin_get::admin_router`] for everything else.
//! - [`handle_interop_control`] — `/__waf_control/*` body for
//!   the interop contract (HK-T3). Authenticates via
//!   `X-Benchmark-Secret`; routes the four interop endpoints
//!   to `aegis_control::interop::control::ControlContext`.
//! - [`stamp_interop_response`] — adds the always-on
//!   `X-WAF-*` response headers (request-id, decision,
//!   risk-score, mode, cache, rule-id) before any response
//!   leaves the data-plane accept loop.
//! - [`handle_force_https_request`] — body for the optional
//!   plain-HTTP `force_https` listener. Either returns the
//!   ACME-01 challenge or a 301/308 redirect.
//!
//! Visibility: `pub(crate)` for all four. Single call sites in
//! `accept.rs` (the listener loops).

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::Response;

use aegis_core::config::WafConfig;
use aegis_core::ReadinessSignal;

const ACME_CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";

use crate::admin_get::admin_router;
use crate::admin_login::{handle_admin_login, handle_admin_logout};
use crate::admin_mutate::{
    handle_access_list_delete, handle_access_list_post, handle_admin_drain,
    handle_alert_ack, handle_alert_receiver_delete, handle_alert_receiver_test,
    handle_alert_receivers_put, handle_detectors_put, handle_loadmode_put,
    handle_logging_put, handle_mode_put, handle_mtls_sans_delete,
    handle_mtls_sans_put, handle_mtls_sans_test, handle_pool_delete,
    handle_pool_upsert, handle_risk_reset, handle_risk_thresholds_put,
    handle_rules_delete, handle_rules_post, handle_rules_put,
    handle_rules_toggle, handle_upstreams_config_put,
};
use crate::responses::{json_body_response, json_response};

pub(crate) async fn handle_admin_request(
    req: hyper::Request<hyper::body::Incoming>,
    peer: std::net::SocketAddr,
    cfg: &WafConfig,
    readiness: &ReadinessSignal,
    startup: &aegis_control::health::StartupProbe,
    metrics: &aegis_control::metrics::MetricsRegistry,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();

    // F-T1 — auth front door. Login is open (rate-limited);
    // logout reads the session cookie. Both bypass the regular
    // admin_router because they need access to the auth runtime.
    if method == hyper::Method::POST && path == "/admin/login" {
        return handle_admin_login(req, peer, services).await;
    }
    if method == hyper::Method::POST && path == "/admin/logout" {
        return handle_admin_logout(req, services);
    }

    // HA-T5 — operator-initiated drain. Flips
    // `readiness.draining` so subsequent `/healthz/ready` probes
    // return 503; LBs (HAProxy / Nginx / k8s endpoints) stop
    // routing new traffic to this node within the next health
    // check interval. In-flight requests continue.
    if method == hyper::Method::POST && path == "/admin/drain" {
        return handle_admin_drain(req, readiness, services).await;
    }

    // external interop contract control plane .
    // Always under `/__waf_control/*`; auth via `X-Benchmark-Secret`.
    // No-op (404) when the binary was built without the
    // interop surface.
    if path.starts_with("/__waf_control/") {
        return handle_interop_control(req, services).await;
    }

    // P2 mutating endpoint: PUT /api/detectors. Reads body
    // asynchronously, runs through AuditedMutate.
    if method == hyper::Method::PUT && path == "/api/detectors" {
        return handle_detectors_put(req, cfg, services).await;
    }

    // P6 mutating endpoint: PUT /api/risk/{ip}/reset. Audit-mutated
    // operator override that clears strikes + score for one client.
    if method == hyper::Method::PUT && path.starts_with("/api/risk/") {
        if let Some(ip_seg) = path
            .strip_prefix("/api/risk/")
            .and_then(|s| s.strip_suffix("/reset"))
        {
            return handle_risk_reset(req, ip_seg, services).await;
        }
    }

    // CI-T12 — PUT /api/risk/thresholds — audit-mutated;
    // hot-applies new challenge_at / block_at / max via
    // RiskTracker::set_thresholds.
    if method == hyper::Method::PUT && path == "/api/risk/thresholds" {
        return handle_risk_thresholds_put(req, services).await;
    }

    // P7 mutating endpoint: PUT /api/loadmode. Audit-mutated
    // operator override that pins / clears the live LoadMode.
    if method == hyper::Method::PUT && path == "/api/loadmode" {
        return handle_loadmode_put(req, services).await;
    }

    // P8 mutating endpoint: PUT /api/logging. Audit-mutated
    // verbosity level change.
    if method == hyper::Method::PUT && path == "/api/logging" {
        return handle_logging_put(req, services).await;
    }

    // DD-T6 — rule CRUD. Audit-mutated; CSRF-gated; writes the
    // before / after state into the audit chain.
    if method == hyper::Method::POST && path == "/api/rules" {
        return handle_rules_post(req, services).await;
    }
    if method == hyper::Method::PUT && path.starts_with("/api/rules/") {
        let suffix = &path["/api/rules/".len()..];
        if let Some(rule_id) = suffix.strip_suffix("/toggle") {
            return handle_rules_toggle(req, rule_id, services).await;
        }
        if !suffix.is_empty() && !suffix.contains('/') {
            return handle_rules_put(req, suffix, services).await;
        }
    }
    if method == hyper::Method::DELETE && path.starts_with("/api/rules/") {
        let id = &path["/api/rules/".len()..];
        if !id.is_empty() && !id.contains('/') {
            return handle_rules_delete(req, id, services).await;
        }
    }

    // CI-T4 — alert ack. Audit-mutated; CSRF-gated. The ack
    // store lives on `services.tracking`; render_alerts() then
    // moves the alert from `firing` to `resolved`.
    if method == hyper::Method::POST && path.starts_with("/api/alerts/") {
        let suffix = &path["/api/alerts/".len()..];
        if let Some(alert_id) = suffix.strip_suffix("/ack") {
            if !alert_id.is_empty() && !alert_id.contains('/') {
                return handle_alert_ack(req, alert_id, services).await;
            }
        }
    }

    // CI-T6 — global enforce / log_only toggle (shadow mode).
    // Wraps the interop ModeStore so dashboard mutations and the
    // /__waf_control mutations route through the same global
    // mode plane. Audit-mutated; CSRF-gated.
    if method == hyper::Method::PUT && path == "/api/mode" {
        return handle_mode_put(req, services).await;
    }

    // CC-T2.1.b — alert-receivers writes. Audit-mutated; CSRF-
    // gated. Three handlers:
    //   PUT    /api/alert-receivers           whole-list replace
    //   DELETE /api/alert-receivers/{name}    single remove
    //   POST   /api/alert-receivers/{name}/test  synthetic delivery
    if method == hyper::Method::PUT && path == "/api/alert-receivers" {
        return handle_alert_receivers_put(req, services).await;
    }
    if let Some(suffix) = path.strip_prefix("/api/alert-receivers/") {
        if method == hyper::Method::POST {
            if let Some(name) = suffix.strip_suffix("/test") {
                if !name.is_empty() && !name.contains('/') {
                    return handle_alert_receiver_test(req, name, services).await;
                }
            }
        }
        if method == hyper::Method::DELETE
            && !suffix.is_empty()
            && !suffix.contains('/')
        {
            return handle_alert_receiver_delete(req, suffix, services).await;
        }
    }

    // CC-T1.1.b — upstream pool writes. Audit-mutated; CSRF-gated.
    //   PUT    /api/upstreams/config           whole-map replace
    //   PUT    /api/upstreams/pool/{id}        single-pool upsert
    //   DELETE /api/upstreams/pool/{id}        single-pool delete (route-ref guarded)
    if method == hyper::Method::PUT && path == "/api/upstreams/config" {
        return handle_upstreams_config_put(req, cfg, services).await;
    }
    if let Some(suffix) = path.strip_prefix("/api/upstreams/pool/") {
        if !suffix.is_empty() && !suffix.contains('/') {
            if method == hyper::Method::PUT {
                return handle_pool_upsert(req, suffix, cfg, services).await;
            }
            if method == hyper::Method::DELETE {
                return handle_pool_delete(req, suffix, cfg, services).await;
            }
        }
    }

    // SC-T1 — Layer-3 backend health. Async because the Redis
    // backend's `health()` runs `INFO` / `DBSIZE` (cached 5s
    // server-side) — can't be called from the sync `admin_router`.
    // Falls back to `BackendHealth::unknown()` when the proxy
    // boot path didn't wire a backend (test bundles).
    if method == hyper::Method::GET && path == "/api/state" {
        return handle_state_get(services).await;
    }

    // HACK-T3 — Tier-A bonus: rule simulator. POST
    // `/api/rules/simulate { method, path, headers, body }`
    // runs the supplied request through the live detector
    // chain (and live mask) and returns the decision +
    // matched detector ids without any side effect.
    if method == hyper::Method::POST && path == "/api/rules/simulate" {
        return handle_simulate(req, services).await;
    }

    // HACK-T4 rollback (deferred follow-up): re-applies the
    // captured `before` state of an audit-mutated change.
    // POST /api/config/versions/{seq}/rollback. v1 supports
    // `mode_set` only — see `aegis-control::api::rollback`.
    if method == hyper::Method::POST {
        if let Some(rest) = path.strip_prefix("/api/config/versions/") {
            if let Some(seq_str) = rest.strip_suffix("/rollback") {
                if let Ok(seq) = seq_str.parse::<u64>() {
                    return handle_rollback(req, seq, services).await;
                }
            }
        }
    }

    // CQF-T2 — Blacklist + Whitelist CRUD. Audit-mutated;
    // CSRF-gated.
    //   POST   /api/{blacklist,whitelist}        add a single entry
    //   DELETE /api/{blacklist,whitelist}/{id}   remove a single entry
    if method == hyper::Method::POST
        && (path == "/api/blacklist" || path == "/api/whitelist")
    {
        let kind = if path == "/api/blacklist" { "blacklist" } else { "whitelist" };
        return handle_access_list_post(req, kind, services).await;
    }
    if method == hyper::Method::DELETE {
        if let Some(rest) = path.strip_prefix("/api/blacklist/") {
            if !rest.is_empty() && !rest.contains('/') {
                return handle_access_list_delete(req, "blacklist", rest, services).await;
            }
        }
        if let Some(rest) = path.strip_prefix("/api/whitelist/") {
            if !rest.is_empty() && !rest.contains('/') {
                return handle_access_list_delete(req, "whitelist", rest, services).await;
            }
        }
    }

    // MTLS-T7 — Allowed SAN allowlist mutations. Audit-mutated;
    // CSRF-gated. Three handlers:
    //   PUT    /api/mtls/sans              whole-list replace
    //   DELETE /api/mtls/sans/{san}        single remove
    //   POST   /api/mtls/sans/{san}/test   synthetic admit check
    if method == hyper::Method::PUT && path == "/api/mtls/sans" {
        return handle_mtls_sans_put(req, services).await;
    }
    if let Some(suffix) = path.strip_prefix("/api/mtls/sans/") {
        if method == hyper::Method::POST {
            if let Some(san) = suffix.strip_suffix("/test") {
                if !san.is_empty() && !san.contains('/') {
                    return handle_mtls_sans_test(req, san, services).await;
                }
            }
        }
        if method == hyper::Method::DELETE
            && !suffix.is_empty()
            && !suffix.contains('/')
        {
            return handle_mtls_sans_delete(req, suffix, services).await;
        }
    }

    admin_router(req, cfg, readiness, startup, metrics, services)
}

/// HACK-T4 rollback — body for
/// `POST /api/config/versions/{seq}/rollback`.
///
/// Calls into `aegis-control::api::rollback` to re-apply the
/// captured `before` state, then emits a new Admin audit event
/// (`<orig>_rollback`) so the chain records the rollback.
/// Errors map to HTTP statuses: NotFound → 404; the rest
/// (NotAdminClass / NotRollbackable / MissingBefore /
/// ApplyFailed) → 422 with an operator-readable body.
async fn handle_rollback(
    _req: hyper::Request<hyper::body::Incoming>,
    seq: u64,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use aegis_control::api::rollback::{rollback_for_seq, RollbackError, RollbackTargets};

    let Some(rt) = services.interop.as_ref() else {
        return json_response(
            503,
            &serde_json::json!({
                "error": "rollback unavailable — interop runtime not wired",
            }),
        );
    };

    // Wire every live store the dispatcher might need. Each is
    // optional (None = NotApplicable / ApplyFailed) so a partial
    // wiring still functions for v1 mode_set rollbacks.
    let targets = RollbackTargets {
        mode_store: &rt.modes,
        risk: Some(&services.risk),
        allowed_sans: services.allowed_sans.as_ref(),
        blacklist: Some(&services.blacklist),
        whitelist: Some(&services.whitelist),
        detector_mask: Some(&services.detector_mask),
    };

    match rollback_for_seq(&services.audit_ring, seq, &targets) {
        Ok(outcome) => {
            // Audit-emit the rollback itself so the chain captures
            // it. The new event is `<orig>_rollback` with
            // `before` / `after` carrying the diff that was
            // applied (NOT the original event's diff —
            // operators reading the chain see the rollback
            // direction, not the original change direction).
            let rollback_action = format!("{}_rollback", outcome.action);
            services.bus.emit(aegis_core::audit::AuditEvent {
                schema_version: 1,
                ts: chrono::Utc::now(),
                request_id: String::new(),
                class: aegis_core::audit::AuditClass::Admin,
                tenant_id: None,
                tier: None,
                action: rollback_action,
                reason: format!(
                    "operator rolled back to audit version {}",
                    outcome.rolled_back_to_seq,
                ),
                client_ip: String::new(),
                route_id: None,
                rule_id: None,
                risk_score: None,
                fields: serde_json::json!({
                    "actor": "admin",
                    "rollback_to_seq": outcome.rolled_back_to_seq,
                    "diff": {
                        "before": outcome.before.clone(),
                        "after":  outcome.after.clone(),
                    },
                    "resource": "/api/config/versions",
                    "source": "dashboard",
                }),
            });

            let body = serde_json::to_string(&serde_json::json!({
                "ok": true,
                "rolled_back_to_seq": outcome.rolled_back_to_seq,
                "action": outcome.action,
                "before": outcome.before,
                "after": outcome.after,
            }))
            .unwrap_or_else(|_| "{}".into());
            json_body_response(200, body, "private, no-store")
        }
        Err(RollbackError::NotFound(s)) => json_response(
            404,
            &serde_json::json!({
                "error": format!("audit version {s} not found"),
            }),
        ),
        Err(e) => json_response(
            422,
            &serde_json::json!({
                "error": e.to_string(),
            }),
        ),
    }
}

/// HACK-T3 — body for `POST /api/rules/simulate`.
async fn handle_simulate(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let Some(detectors) = services.detectors.as_ref() else {
        return json_response(
            503,
            &serde_json::json!({
                "error": "simulator unavailable — detector list not wired (test bundle?)",
            }),
        );
    };

    // Read body — capped at 64 KiB to keep the simulator from
    // becoming a body-buffering DoS surface.
    let body_bytes = match req.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            return json_response(
                400,
                &serde_json::json!({ "error": format!("body read failed: {e}") }),
            );
        }
    };
    if body_bytes.len() > 64 * 1024 {
        return json_response(
            413,
            &serde_json::json!({ "error": "request body too large (max 64 KiB)" }),
        );
    }

    let parsed: aegis_control::api::simulator::SimulateRequest =
        match serde_json::from_slice(&body_bytes) {
            Ok(p) => p,
            Err(e) => {
                return json_response(
                    400,
                    &serde_json::json!({ "error": format!("invalid simulate body: {e}") }),
                );
            }
        };

    let resp = aegis_control::api::simulator::simulate(
        &parsed,
        detectors.as_ref(),
        &services.detector_mask,
    );
    let body = serde_json::to_string(&resp).unwrap_or_else(|_| "{}".into());
    json_body_response(200, body, "private, no-store")
}

/// SC-T1 — render the live state-backend health snapshot as
/// JSON. Cached server-side at 5s by the Redis backend; reads
/// here are cheap (one `Mutex` lock + clone).
async fn handle_state_get(
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let health = match services.state_backend.as_ref() {
        Some(sb) => sb.health().await,
        None => aegis_core::state::BackendHealth::unknown(),
    };
    let view = aegis_control::api::state::StateView::render(health);
    let body = serde_json::to_string(&view).unwrap_or_else(|_| "{}".into());
    json_body_response(200, body, "private, max-age=2")
}

pub(crate) async fn handle_interop_control(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use aegis_control::interop::{control, CONTROL_SECRET_HEADER};
    use http_body_util::BodyExt;

    let Some(rt) = services.interop.as_ref() else {
        return json_response(
            404,
            &serde_json::json!({"error": "interop surface disabled"}),
        );
    };

    let method = req.method().clone();
    let path = req.uri().path().to_owned();

    let secret = req
        .headers()
        .get(CONTROL_SECRET_HEADER)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    if let Err(e) = rt.control.check_auth(secret.as_deref()) {
        return json_response(
            e.status(),
            &serde_json::json!({"ok": false, "error": e.to_string()}),
        );
    }

    match (method, path.as_str()) {
        (hyper::Method::GET, "/__waf_control/capabilities") => {
            let body = serde_json::to_string(&rt.control.capabilities())
                .unwrap_or_else(|_| "{}".into());
            json_body_response(200, body, "no-store")
        }
        (hyper::Method::POST, "/__waf_control/reset_state") => {
            let body = serde_json::to_string(&rt.control.reset_state())
                .unwrap_or_else(|_| "{}".into());
            json_body_response(200, body, "no-store")
        }
        (hyper::Method::POST, "/__waf_control/set_profile") => {
            let bytes = match req.into_body().collect().await {
                Ok(c) => c.to_bytes(),
                Err(_) => {
                    return json_response(
                        400,
                        &serde_json::json!({"ok": false, "error": "body read error"}),
                    );
                }
            };
            let parsed: control::SetProfileRequest =
                match serde_json::from_slice(&bytes) {
                    Ok(p) => p,
                    Err(e) => {
                        return json_response(
                            400,
                            &serde_json::json!({
                                "ok": false,
                                "error": format!("invalid body: {e}"),
                            }),
                        );
                    }
                };
            match rt.control.set_profile(&parsed) {
                Ok(resp) => {
                    let body = serde_json::to_string(&resp)
                        .unwrap_or_else(|_| "{}".into());
                    json_body_response(200, body, "no-store")
                }
                Err(e) => json_response(
                    e.status(),
                    &serde_json::json!({"ok": false, "error": e.to_string()}),
                ),
            }
        }
        (hyper::Method::POST, "/__waf_control/flush_cache") => {
            let body = serde_json::to_string(&rt.control.flush_cache())
                .unwrap_or_else(|_| "{}".into());
            json_body_response(200, body, "no-store")
        }
        _ => json_response(
            404,
            &serde_json::json!({
                "ok": false,
                "error": "unknown control endpoint",
            }),
        ),
    }
}



/// CI-T4 — parse one configured cert into the dashboard's
/// inventory shape. Returns `None` when the file is missing or
/// can't be parsed as PEM (the cert provider is best-effort —
/// the real cert loader in `listener::tls` already failed loudly
/// at boot if certs are bad, so silent skips are safe here).
pub(crate) fn read_cert_inventory(
    cfg: &aegis_core::config::CertConfig,
) -> Option<aegis_control::api::tracking::CertInventoryEntry> {
    use std::io::BufReader;
    use x509_parser::prelude::FromDer;

    let pem_bytes = std::fs::read(&cfg.cert_path).ok()?;
    let mut reader = BufReader::new(pem_bytes.as_slice());
    let first = rustls_pemfile::certs(&mut reader)
        .next()
        .and_then(|r| r.ok())?;
    let (_rest, parsed) = x509_parser::certificate::X509Certificate::from_der(&first).ok()?;

    let issuer = parsed
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| parsed.issuer().to_string());

    let host = cfg
        .hosts
        .first()
        .cloned()
        .unwrap_or_else(|| cfg.cert_path.display().to_string());

    let not_after_secs = parsed.validity().not_after.timestamp();
    let expires_at = chrono::DateTime::<chrono::Utc>::from_timestamp(not_after_secs, 0)?;

    Some(aegis_control::api::tracking::CertInventoryEntry {
        host,
        issuer,
        expires_at,
        source: "static".into(),
    })
}

pub(crate) fn stamp_interop_response(
    mut resp: Response<Full<Bytes>>,
    decision_tag: aegis_control::interop::headers::DecisionTag,
    interop: Option<&Arc<aegis_control::interop::InteropRuntime>>,
    peer: std::net::SocketAddr,
    method: &hyper::Method,
    path: &str,
    risk_score: u32,
) -> Response<Full<Bytes>> {
    use aegis_control::interop::audit::MinimalAuditEntry;
    use aegis_control::interop::headers::{CacheState, Decision};

    let Some(rt) = interop else {
        return resp;
    };

    // Generate a request id. UUID v4 isn't on our crate list yet,
    // so build a 36-char hyphenated hex from blake3 (still
    // RFC-4122-shaped, deterministic per request, distinct enough
    // to satisfy the OC's "MUST match audit log" constraint).
    let raw = blake3::hash(
        format!(
            "{peer}:{}:{path}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
        )
        .as_bytes(),
    );
    let h = raw.to_hex();
    let h = h.as_str();
    let request_id = format!(
        "{}-{}-4{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[13..16],
        &h[16..20],
        &h[20..32],
    );

    let mode = rt.modes.resolve("rules_engine", None);
    let decision = Decision {
        request_id: request_id.clone(),
        risk_score,
        action: decision_tag.action,
        rule_id: decision_tag.rule_id.clone(),
        cache: CacheState::Bypass,
        mode,
    };
    decision.stamp(resp.headers_mut());

    if let Some(sink) = rt.audit.as_ref() {
        let entry = MinimalAuditEntry {
            request_id,
            ts_ms: chrono::Utc::now().timestamp_millis(),
            ip: peer.ip().to_string(),
            method: method.as_str().to_string(),
            path: path.to_string(),
            action: decision_tag.action.as_str().to_string(),
            risk_score,
            mode: mode.as_str().to_string(),
            rule_id: decision_tag.rule_id,
        };
        if let Err(e) = sink.append(&entry) {
            tracing::warn!(error = %e, "interop audit write failed");
        }
    }

    resp
}

pub(crate) fn handle_force_https_request(
    req: hyper::Request<hyper::body::Incoming>,
    status: u16,
    challenges: &crate::acme::ChallengeStore,
) -> Response<Full<Bytes>> {
    let path_owned = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".into());

    // ACME HTTP-01 short-circuit: if this request is for a token
    // we know about, serve the key authorisation as text/plain.
    if let Some(token) = req.uri().path().strip_prefix(ACME_CHALLENGE_PREFIX) {
        if let Some(key_auth) = challenges.lookup(token) {
            return Response::builder()
                .status(200)
                .header("content-type", "application/octet-stream")
                .header("cache-control", "no-store")
                .body(Full::new(Bytes::from(key_auth)))
                .unwrap();
        }
        // Unknown token → 404 (don't redirect, the directory
        // expects a definitive answer).
        return Response::builder()
            .status(404)
            .header("content-type", "text/plain")
            .header("cache-control", "no-store")
            .body(Full::new(Bytes::from("acme challenge token not found")))
            .unwrap();
    }

    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    crate::listener::tls_policy::force_https_redirect_response(host, &path_owned, status)
}
