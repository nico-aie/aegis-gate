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
    handle_alert_receivers_put, handle_config_put, handle_config_rollback,
    handle_detectors_put, handle_loadmode_put,
    handle_logging_put, handle_mode_put, handle_mtls_sans_delete,
    handle_mtls_sans_put, handle_mtls_sans_test, handle_pool_delete,
    handle_ai_enabled_get, handle_ai_enabled_put, handle_response_filter_get,
    handle_response_filter_put, handle_pool_upsert,
    handle_risk_canary_paths_put, handle_risk_reset, handle_risk_reset_key,
    handle_risk_thresholds_put, handle_route_delete,
    handle_route_upsert, handle_rules_delete, handle_rules_post,
    handle_rules_put, handle_rules_toggle, handle_tier_put,
    handle_upstreams_config_put,
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
    // FIX 2026-05-03 — GET /admin/login renders the standalone
    // login page (the SPA's CSRF interceptor + logout button both
    // navigate here).  GET /admin/login.js serves the form-submit
    // client.  Both go through the dashboard CSP.
    if method == hyper::Method::GET && path == "/admin/login" {
        return crate::admin_login::handle_admin_login_page();
    }
    if method == hyper::Method::GET && path == "/admin/login.js" {
        return crate::admin_login::handle_admin_login_js();
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
    //
    // 2026-05-19 committee bind contract: even when the admin
    // listener is exposed on a routable interface (dev profile
    // pins `0.0.0.0:9443` so docker-host Prometheus can scrape
    // `/metrics`), the control plane MUST stay local-only. Gate
    // on `peer.ip().is_loopback()` so the surface is invisible
    // to any non-loopback caller — request falls through to the
    // 404 path below, indistinguishable from any unknown route.
    // X-Benchmark-Secret is still enforced inside the handler.
    if path.starts_with("/__waf_control/") && peer.ip().is_loopback() {
        return handle_interop_control(req, services).await;
    }

    // P2 mutating endpoint: PUT /api/detectors. Reads body
    // asynchronously, runs through AuditedMutate.
    if method == hyper::Method::PUT && path == "/api/detectors" {
        return handle_detectors_put(req, services).await;
    }

    // 2026-05-27 — cluster config plane. Audit-mutated + CSRF-gated via
    // the async AuditedMutate path; activation is a StateBackend CAS that
    // every node's shared-store watcher then converges on.
    if method == hyper::Method::PUT && path == "/api/config" {
        return handle_config_put(req, services).await;
    }
    if method == hyper::Method::POST && path == "/api/config/rollback" {
        return handle_config_rollback(req, services).await;
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

    // 2026-05-19 — POST /api/risk/reset_key. Surgical reset that
    // wipes ONE composite-key bucket (IP + optional device_fp +
    // optional session). Distinct from PUT /api/risk/{ip}/reset
    // which wipes every bucket sharing that IP. Audit-mutated;
    // CSRF-gated; admin-only via the auth middleware that runs
    // before this dispatcher.
    if method == hyper::Method::POST && path == "/api/risk/reset_key" {
        return handle_risk_reset_key(req, services).await;
    }

    // CI-T12 — PUT /api/risk/thresholds — audit-mutated;
    // hot-applies new challenge_at / block_at / max via
    // RiskTracker::set_thresholds.
    if method == hyper::Method::PUT && path == "/api/risk/thresholds" {
        return handle_risk_thresholds_put(req, services).await;
    }

    // 2026-05-20 — PUT /api/risk/canary-paths — audit-mutated;
    // hot-applies the operator's honeypot path set via the shared
    // CanaryPaths handle (no chain rebuild). GET is served on the
    // admin read path (admin_get.rs).
    if method == hyper::Method::PUT && path == "/api/risk/canary-paths" {
        return handle_risk_canary_paths_put(req, services).await;
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
    //
    // MED-ADM-01 (2026-05-12) — `req.uri().path()` returns the
    // percent-encoded path, so ids like `<sli>-<Nh>:<ts>` arrive
    // as `<sli>-<Nh>%3A<ts>`.  Decode here before handing to the
    // handler so the overlay-store key matches what `enrich()`
    // looks up via `alert_id(&a)`.  Apply exactly once at this
    // layer; the handler MUST NOT decode again.
    if method == hyper::Method::POST && path.starts_with("/api/alerts/") {
        let suffix = &path["/api/alerts/".len()..];
        if let Some(raw_id) = suffix.strip_suffix("/ack") {
            if !raw_id.is_empty() && !raw_id.contains('/') {
                let alert_id = crate::admin_get::percent_decode(raw_id);
                return handle_alert_ack(req, &alert_id, services).await;
            }
        }
    }

    // Phase-3 Incidents — operator overlay (ack/snooze/resolve)
    // on top of the SLO engine's firing alerts. Each handler is
    // audit-mutated + CSRF-gated. The `/ack` path also forwards
    // to the legacy `services.tracking.ack` store so existing
    // /api/alerts consumers see the same view.
    if method == hyper::Method::POST && path.starts_with("/api/incidents/") {
        let suffix = &path["/api/incidents/".len()..];
        if let Some(raw_id) = suffix.strip_suffix("/ack") {
            if !raw_id.is_empty() && !raw_id.contains('/') {
                let id = crate::admin_get::percent_decode(raw_id);
                return crate::admin_mutate::handle_incident_ack(req, &id, services).await;
            }
        }
        if let Some(raw_id) = suffix.strip_suffix("/snooze") {
            if !raw_id.is_empty() && !raw_id.contains('/') {
                let id = crate::admin_get::percent_decode(raw_id);
                return crate::admin_mutate::handle_incident_snooze(req, &id, services).await;
            }
        }
        if let Some(raw_id) = suffix.strip_suffix("/resolve") {
            if !raw_id.is_empty() && !raw_id.contains('/') {
                let id = crate::admin_get::percent_decode(raw_id);
                return crate::admin_mutate::handle_incident_resolve(req, &id, services).await;
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

    // 2026-05-09 — Traffic Gates audit-mutated PUTs. Both hot-reload
    // the corresponding live runtime config without restart;
    // per-IP state (StateBackend window for DDoS, in-process
    // timestamp map for rate-limit) is preserved across the swap
    // so flooding sources don't get a free reset.
    if method == hyper::Method::PUT && path == "/api/gates/ddos" {
        return crate::admin_mutate::handle_ddos_put(req, services).await;
    }
    if method == hyper::Method::PUT && path == "/api/rate-limit" {
        return crate::admin_mutate::handle_rate_limit_put(req, services).await;
    }
    if method == hyper::Method::PUT && path == "/api/gates/bots" {
        return crate::admin_mutate::handle_bots_put(req, services).await;
    }
    if method == hyper::Method::PUT && path == "/api/gates/strikes" {
        return crate::admin_mutate::handle_strikes_put(req, services).await;
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
        return handle_upstreams_config_put(req, services).await;
    }
    if let Some(suffix) = path.strip_prefix("/api/upstreams/pool/") {
        if !suffix.is_empty() && !suffix.contains('/') {
            if method == hyper::Method::PUT {
                return handle_pool_upsert(req, suffix, services).await;
            }
            if method == hyper::Method::DELETE {
                return handle_pool_delete(req, suffix, services).await;
            }
        }
    }

    // RT-T4 — route writes. Audit-mutated; CSRF-gated. Mirrors
    // the pool path so the dashboard's RouteEditModal +
    // DeleteRouteModal flow has the same shape.
    //   PUT    /api/routes/{id}    upsert (create or replace)
    //   DELETE /api/routes/{id}    delete (last-catch-all guarded)
    if let Some(suffix) = path.strip_prefix("/api/routes/") {
        if !suffix.is_empty() && !suffix.contains('/') {
            if method == hyper::Method::PUT {
                return handle_route_upsert(req, suffix, cfg, services).await;
            }
            if method == hyper::Method::DELETE {
                return handle_route_delete(req, suffix, cfg, services).await;
            }
        }
    }

    // PR3 — Test route tool. Lets operators paste host + method
    // + path and see which route the live config would resolve to
    // (with priority breakdown) without sending real traffic.
    // Read-only — no audit chain entry — but session-gated so
    // only admins can run it.
    if method == hyper::Method::POST && path == "/api/routes/test" {
        return handle_route_test(req, services).await;
    }

    // AI-T10 — runtime on/off for the AI detector. Audit-mutated
    // PUT; CSRF-gated. GET is open-on-session so the dashboard's
    // Detectors page can render the toggle state without a write.
    if path == "/api/ai/enabled" {
        if method == hyper::Method::GET {
            return handle_ai_enabled_get(services).await;
        }
        if method == hyper::Method::PUT {
            return handle_ai_enabled_put(req, services).await;
        }
    }

    // 2026-05-11 PR #7 — response-filter rung toggles. Audit-mutated
    // PUT; CSRF-gated. GET is open-on-session so the dashboard's
    // Security Engine tile can render the toggle state. Defaults are
    // all-on; this endpoint lets operators flip a rung off without
    // restart when an environment proves problematic (e.g. a JSON
    // service that legitimately contains an internal-shaped IP).
    if path == "/api/response-filter" {
        if method == hyper::Method::GET {
            return handle_response_filter_get(services).await;
        }
        if method == hyper::Method::PUT {
            return handle_response_filter_put(req, services).await;
        }
    }

    // TI-T — audit-mutated tier edits. Tier names are constrained
    // (`critical | high | medium | low`); the handler rejects
    // anything else with a `validation` reason.
    if let Some(suffix) = path.strip_prefix("/api/tiers/") {
        if !suffix.is_empty() && !suffix.contains('/') {
            if method == hyper::Method::PUT {
                return handle_tier_put(req, suffix, services).await;
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
    // MTLS-T8 — runtime mode override.
    if method == hyper::Method::PUT && path == "/api/mtls/mode" {
        return crate::admin_mutate::handle_mtls_mode_put(req, services).await;
    }
    // MTLS-T10 — CA bundle validation + audit-emit (Phase 1).
    if method == hyper::Method::PUT && path == "/api/mtls/ca-bundle" {
        return crate::admin_mutate::handle_mtls_ca_bundle_put(req, services).await;
    }
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

    // 2026-05-27 — cluster config-plane read. Intercepted here on the
    // async path (the GET `admin_router` is synchronous and the store
    // reads are async): current activated version + per-node applied
    // versions for the console drift view.
    if method == hyper::Method::GET && path == "/api/config" {
        return handle_config_get(services).await;
    }

    admin_router(req, cfg, readiness, startup, metrics, services)
}

/// 2026-05-27 — render the cluster config-plane status: the current
/// activated version + each live node's applied version (drift view).
/// Reads through a `ConfigStore` built from the runtime state backend;
/// empty/zero when no config has been activated or no backend is wired.
async fn handle_config_get(
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let Some(backend) = services.state_backend.as_ref() else {
        return json_body_response(
            200,
            serde_json::json!({ "version": 0, "applied": [], "backend": false }).to_string(),
            "private, max-age=2",
        );
    };
    let store = crate::config_source::config_store::ConfigStore::new(backend.clone());
    let version = store.current_version().await.unwrap_or(0);
    let applied: Vec<serde_json::Value> = store
        .applied_map()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|(node, v)| serde_json::json!({ "node": node, "version": v }))
        .collect();
    let body = serde_json::json!({
        "version": version,
        "applied": applied,
        "backend": true,
    })
    .to_string();
    json_body_response(200, body, "private, max-age=2")
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
        verbosity: Some(&services.verbosity),
        load_gauge: Some(&services.load_gauge),
        rules: Some(&services.rules),
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
                action: rollback_action.into(),
                reason: format!(
                    "operator rolled back to audit version {}",
                    outcome.rolled_back_to_seq,
                ),
                client_ip: String::new(),
                route_id: None,
                rule_id: None,
                risk_score: None,
                method: None,
                path: None,
                mode: None,
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

/// PR3 — `POST /api/routes/test`. Lets operators paste a synthetic
/// `(host, method, path)` and see which route the live config would
/// resolve to, with the priority tuple breakdown. Read-only; no
/// audit entry; session-gated by the dispatcher.
///
/// Request body: `{ "host": "...", "method": "GET", "path": "/foo" }`.
/// Response body: `{ "matched": { route_id, host, path, method, tier,
/// upstream, priority } | null, "reason": "matched" | "unmatched" }`.
async fn handle_route_test(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    #[derive(serde::Deserialize)]
    struct TestRequest {
        #[serde(default)]
        host: String,
        method: String,
        path: String,
    }

    let Some(writer) = services.route_writer.as_ref().cloned() else {
        return json_response(
            503,
            &serde_json::json!({ "error": "route writer not wired (test bundle?)" }),
        );
    };

    let body_bytes = match req.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            return json_response(
                400,
                &serde_json::json!({ "error": format!("body read failed: {e}") }),
            );
        }
    };
    if body_bytes.len() > 4 * 1024 {
        return json_response(
            413,
            &serde_json::json!({ "error": "request body too large (max 4 KiB)" }),
        );
    }

    let parsed: TestRequest = match serde_json::from_slice(&body_bytes) {
        Ok(p) => p,
        Err(e) => {
            return json_response(
                400,
                &serde_json::json!({ "error": format!("invalid test body: {e}") }),
            );
        }
    };

    // Validate the method early so a typo gets a clear error.
    if parsed.method.parse::<hyper::Method>().is_err() {
        return json_response(
            400,
            &serde_json::json!({ "error": format!("invalid HTTP method: {}", parsed.method) }),
        );
    }

    let body = match writer.resolve_for_test(&parsed.host, &parsed.path, &parsed.method) {
        Some(r) => serde_json::json!({
            "matched": {
                "route_id": r.route_id,
                "host":     r.host,
                "path":     r.path,
                "methods":  r.methods,
                "tier":     r.tier,
                "upstream": r.upstream,
                "priority": r.priority,
                "default":  r.default,
                "enabled":  r.enabled,
            },
            "reason": "matched",
        }),
        None => serde_json::json!({
            "matched": null,
            "reason": "unmatched — would 404 (deny-by-default; configure a `default: true` route to catch unmatched traffic)",
        }),
    };

    json_response(200, &body)
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
    let Some(rt) = services.interop.as_ref() else {
        return json_response(
            404,
            &serde_json::json!({"error": "interop surface disabled"}),
        );
    };
    handle_interop_control_with_rt(req, rt.as_ref()).await
}

/// Same dispatcher as [`handle_interop_control`] but takes an
/// `InteropRuntime` directly. Used by the data-plane request path
/// for the loopback-gated `/__waf_control/*` short-circuit
/// (see deploy/STAGING-BENCHMARK.md §7.5).
///
/// 2026-05-19 v2.5 — challenge verify moved out of this namespace
/// to the public `/challenge/verify` data-plane mount, so this
/// dispatcher no longer needs `pow_issuer` / `state`.
pub(crate) async fn handle_interop_control_with_rt(
    req: hyper::Request<hyper::body::Incoming>,
    rt: &aegis_control::interop::InteropRuntime,
) -> Response<Full<Bytes>> {
    use aegis_control::interop::{control, CONTROL_SECRET_HEADER};
    use http_body_util::BodyExt;

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
        // RUN3-NEW-2 (2026-05-08) — liveness endpoint for the
        // automated interop harness. Returns 200 + minimal body
        // as soon as the data-plane dispatcher can respond.
        // Auth via X-Benchmark-Secret stays enforced (already
        // checked above before the match), so this isn't an
        // unauthenticated probe surface.
        //
        // Deeper readiness (Redis reachable, audit sink open,
        // upstream pools registered) lives at the admin port's
        // /healthz/ready — that endpoint exposes the actual
        // /api/state probes. This one is just "the WAF process
        // is alive and serving requests on this listener."
        (hyper::Method::GET, "/__waf_control/healthz") => {
            json_body_response(
                200,
                serde_json::json!({"ok": true, "status": "alive"}).to_string(),
                "no-store",
            )
        }
        (hyper::Method::POST, "/__waf_control/reset_state") => {
            // F-HIGH-005 (2026-05-17 s-tester audit): v2.3 §2.4 —
            // reset_state must look atomic to the benchmarker.
            // Setting `reset_in_progress = true` causes the data
            // plane to short-circuit incoming requests with
            // 503 + Retry-After: 0 ("MAY temporarily reject in-
            // flight non-control requests"). RAII guard clears the
            // flag on every exit, including panic.
            use std::sync::atomic::Ordering;
            struct ResetGuard<'a>(&'a std::sync::atomic::AtomicBool);
            impl<'a> Drop for ResetGuard<'a> {
                fn drop(&mut self) {
                    self.0.store(false, Ordering::Release);
                }
            }
            rt.reset_in_progress.store(true, Ordering::Release);
            let _g = ResetGuard(&rt.reset_in_progress);
            // 2026-05-20 — async variant awaits the StateBackend
            // ephemeral wipe (nonces, rate windows, auto-block,
            // backend risk keys) so the reset is complete before
            // the 200 lands (§2.4 atomicity).
            let body = serde_json::to_string(&rt.control.reset_state_async().await)
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
        // v2.5 contract §4: challenge verify is now a PUBLIC
        // benchmarker-facing endpoint at `/challenge/verify` on the
        // data plane (not under /__waf_control/*, which is local-
        // only). The data plane mounts it directly; this control-
        // namespace branch was removed alongside the loopback gate.
        _ => json_response(
            404,
            &serde_json::json!({
                "ok": false,
                "error": "unknown control endpoint",
            }),
        ),
    }
}

/// 2026-05-08 NEW-2 / 2026-05-19 v2.5 — verify a PoW solution
/// submitted by the benchmarker. Mounted at the PUBLIC path
/// `/challenge/verify` on the data plane (per v2.5 contract §4).
/// Body shape: `{"challenge_token":"<echo>","nonce":"<work>"}`.
pub(crate) async fn handle_challenge_verify(
    req: hyper::Request<hyper::body::Incoming>,
    pow_issuer: Option<&Arc<aegis_security::challenge::PowIssuer>>,
    state: Option<&Arc<dyn aegis_core::state::StateBackend>>,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let issuer = match pow_issuer {
        Some(i) => i,
        None => {
            return json_response(
                503,
                &serde_json::json!({
                    "ok": false,
                    "error": "pow issuer not wired",
                }),
            );
        }
    };
    let state_ref = match state {
        Some(s) => s.as_ref(),
        None => {
            return json_response(
                503,
                &serde_json::json!({
                    "ok": false,
                    "error": "state backend not wired",
                }),
            );
        }
    };

    // v2.5 contract §4 — benchmarker submits
    // `{"challenge_token":"<echo>","nonce":"<work>"}`.
    // `challenge_token` packs (nonce, difficulty, expires_at_ms,
    // mac); `nonce` is the work-discovered counter.
    #[derive(serde::Deserialize)]
    struct VerifyBody {
        challenge_token: String,
        nonce: String,
    }

    let bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return json_response(
                400,
                &serde_json::json!({"ok": false, "error": "body read error"}),
            );
        }
    };
    let body: VerifyBody = match serde_json::from_slice(&bytes) {
        Ok(b) => b,
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

    let unpacked = match aegis_security::challenge::PowChallenge::unpack_token(&body.challenge_token) {
        Some(u) => u,
        None => {
            return json_response(
                400,
                &serde_json::json!({
                    "ok": false,
                    "error": "malformed challenge_token",
                }),
            );
        }
    };

    let result = issuer.verify(
        state_ref,
        &unpacked.nonce,
        unpacked.difficulty,
        unpacked.expires_at_ms,
        &unpacked.mac,
        &body.nonce,
    ).await;

    use aegis_security::challenge::PowError;
    match result {
        // v2.5 contract §4: "WAF should return 200 with a session
        // cookie or token that allows the original request to
        // proceed." We honour the 200 + JSON body shape; the
        // session-token cookie path is wired by the data-plane
        // risk-bucket clear (separate concern).
        Ok(()) => json_response(
            200,
            &serde_json::json!({
                "ok": true,
                "action": "challenge_verified",
            }),
        ),
        Err(PowError::InvalidMac) => json_response(
            403,
            &serde_json::json!({"ok": false, "error": "invalid_mac"}),
        ),
        Err(PowError::Expired) => json_response(
            403,
            &serde_json::json!({"ok": false, "error": "expired"}),
        ),
        Err(PowError::InsufficientDifficulty) => json_response(
            403,
            &serde_json::json!({"ok": false, "error": "insufficient_difficulty"}),
        ),
        Err(PowError::Replay) => json_response(
            403,
            &serde_json::json!({"ok": false, "error": "replay"}),
        ),
        Err(PowError::StateError(msg)) => json_response(
            500,
            &serde_json::json!({"ok": false, "error": format!("state: {msg}")}),
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
    // 2026-05-08 — `Instant` captured at the listener service_fn
    // entry. Used to stamp `X-WAF-Overhead-Latency`. Computed
    // here (after Decision::stamp) so the header reflects the
    // actual time-on-wire from the WAF's perspective.
    request_start: std::time::Instant,
) -> Response<Full<Bytes>> {
    use aegis_control::interop::audit::MinimalAuditEntry;
    use aegis_control::interop::headers::{CacheState, Decision};

    let Some(rt) = interop else {
        // No interop runtime → skip the v2.3 mandatory headers,
        // but still stamp the overhead-latency telemetry so
        // operators in non-interop builds get the same
        // observability hint.
        aegis_control::interop::headers::stamp_overhead_latency(
            resp.headers_mut(),
            request_start.elapsed(),
        );
        return resp;
    };

    // v2.3 §5.1 — UUID v4. The pre-2026-05-17 implementation used
    // `blake3(peer:nanos:path)` because `uuid` wasn't on the crate
    // list; that's deterministic on `(peer, nanos, path)` and
    // collides when two requests share a nanosecond timestamp.
    // `getrandom` (via `uuid::Uuid::new_v4`) gives 122 bits of
    // entropy per ID, collision-free under any realistic load.
    let request_id = uuid::Uuid::new_v4().to_string();

    // v2.3 §2.7 — `X-WAF-Mode` MUST reflect the mode of the
    // policy that produced the final reported `X-WAF-Action`,
    // not a hardcoded global feature. Map the firing `rule_id`
    // to its (feature, policy) and resolve there. Pre-fix,
    // every response stamped the mode of the `rules_engine`
    // feature regardless of which detector or rate-limit /
    // risk gate actually decided the request.
    let mode = aegis_control::interop::rule_map::mode_for_rule(
        &rt.modes,
        decision_tag.rule_id.as_deref(),
    );
    // NEW-4 (2026-05-08) — prefer the score the data plane stamped
    // at decision time (keyed on the XFF-resolved client IP, same
    // key as the risk accumulator). The peer.ip()-keyed snapshot
    // (the fallback) only matches the tracker for direct-connect
    // clients; behind a trusted proxy or with operator-injected
    // X-Forwarded-For, the keys differ and the snapshot returns
    // None → 0.
    let effective_risk_score = decision_tag.risk_score.unwrap_or(risk_score);
    let decision = Decision {
        request_id: request_id.clone(),
        risk_score: effective_risk_score,
        action: decision_tag.action,
        rule_id: decision_tag.rule_id.clone(),
        cache: CacheState::Bypass,
        mode,
    };
    decision.stamp(resp.headers_mut());

    // 2026-05-08 — bonus telemetry. Captures elapsed at the
    // last possible moment so the value reflects the full
    // WAF-side processing cost (received → response stamped),
    // including the stamper itself. Two `Instant::now()` calls
    // and an integer format — sub-microsecond cost.
    aegis_control::interop::headers::stamp_overhead_latency(
        resp.headers_mut(),
        request_start.elapsed(),
    );

    if let Some(sink) = rt.audit.as_ref() {
        let entry = MinimalAuditEntry {
            request_id,
            ts_ms: chrono::Utc::now().timestamp_millis(),
            ip: peer.ip().to_string(),
            method: method.as_str().to_string(),
            path: path.to_string(),
            action: decision_tag.action.as_str().to_string(),
            // NEW-4 (2026-05-08) — same effective score that was
            // stamped on the X-WAF-Risk-Score header, so audit log
            // and headers agree.
            risk_score: effective_risk_score,
            mode: mode.as_str().to_string(),
            rule_id: decision_tag.rule_id,
            // 2026-05-05 — surface the resolved tier so the
            // dashboard's Live Feed shows the route's real tier
            // instead of a risk-score bucket. snake_case form
            // matches the canonical Tier enum serde variants
            // (`critical | high | medium | low`).
            tier: decision_tag.tier.map(|t| match t {
                aegis_core::tier::Tier::Critical => "critical",
                aegis_core::tier::Tier::High => "high",
                aegis_core::tier::Tier::Medium => "medium",
                aegis_core::tier::Tier::Low => "low",
            }.to_string()),
        };
        // F-CRITICAL-012 (2026-05-17 control audit): pre-fix
        // `sink.append` ran inline on the request-stamping path,
        // doing sync `Mutex::lock` + `File::write_all` +
        // `File::flush` on the tokio worker thread. Every request
        // stalled a worker until the page cache + dirent traversal
        // completed (microseconds typical, milliseconds under
        // contention or slow disks). Hot-path latency budget
        // blown.
        //
        // Now: offload to a `spawn_blocking` task. The hot path
        // returns immediately; the audit-write completes on the
        // blocking pool. Audit ordering is preserved per `Arc<
        // MinimalJsonlSink>` because the sink's internal Mutex
        // serialises writes. On error, the spawned task logs at
        // warn level (the caller can no longer see the Result —
        // acceptable trade-off for the latency win; the previous
        // inline error path also only emitted a warn).
        let sink = sink.clone();
        tokio::task::spawn_blocking(move || {
            if let Err(e) = sink.append(&entry) {
                tracing::warn!(error = %e, "interop audit write failed");
            }
        });
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

#[cfg(test)]
mod tests {
    #[test]
    fn request_id_is_uuid_v4_shape() {
        // Sanity that the new uuid::Uuid::new_v4 form is the
        // expected 8-4-4-4-12 with version=4, variant=10xxxxxx,
        // and produces distinct IDs on consecutive calls (no
        // determinism, no nanosecond collision).
        let a = uuid::Uuid::new_v4().to_string();
        let b = uuid::Uuid::new_v4().to_string();
        let groups: Vec<&str> = a.split('-').collect();
        assert_eq!(groups.len(), 5);
        assert_eq!(groups[0].len(), 8);
        assert_eq!(groups[1].len(), 4);
        assert_eq!(groups[2].len(), 4);
        assert_eq!(groups[3].len(), 4);
        assert_eq!(groups[4].len(), 12);
        assert_eq!(groups[2].chars().next(), Some('4'));
        let variant = groups[3].chars().next().unwrap();
        assert!(matches!(variant, '8' | '9' | 'a' | 'b'));
        assert_ne!(a, b);
    }
}
