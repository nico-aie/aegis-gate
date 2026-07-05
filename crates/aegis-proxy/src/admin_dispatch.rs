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
    handle_admin_undrain, handle_node_drain_get,
    handle_alert_ack, handle_alert_receiver_delete, handle_alert_receiver_test,
    handle_alert_receivers_put, handle_config_put, handle_config_rollback,
    handle_slo_config_put,
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

/// AM-P2b — a `/api/admin/accounts/{user}` path segment must be a single
/// username, not a nested path, so `{user}/password` can't be misread as
/// user = `x/password`.
fn is_account_segment(seg: &str) -> bool {
    !seg.is_empty() && !seg.contains('/')
}

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
        return handle_admin_logout(req, peer, services).await;
    }
    // FIX 2026-05-03 — GET /admin/login renders the standalone
    // login page (the SPA's CSRF interceptor + logout button both
    // navigate here).  GET /admin/login.js serves the form-submit
    // client.  Both go through the dashboard CSP.
    if method == hyper::Method::GET && path == "/admin/login" {
        return crate::admin_login::handle_admin_login_page();
    }
    // TOTP-7 — `/login` guess-path alias → the real login page.
    if method == hyper::Method::GET && path == "/login" {
        return crate::admin_login::handle_login_alias();
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

    // Reverse of drain — clear `readiness.draining` so `/healthz/ready`
    // returns 200 again and the LB routes this node back in. Lets an
    // operator undo a drain from the console without a restart.
    if method == hyper::Method::POST && path == "/admin/undrain" {
        return handle_admin_undrain(req, readiness, services).await;
    }

    // Live drain state for this node, so the dashboard renders a truthful
    // Serving/Draining toggle (survives reload; reflects SIGTERM/automation
    // drains).
    if method == hyper::Method::GET && path == "/api/node/drain" {
        return handle_node_drain_get(readiness, services);
    }

    // TOTP-3 (TF-1a) — Google Authenticator enrollment. Session-gated by
    // the upstream middleware; these two are also the ONLY endpoints an
    // enrollment-only session (require_totp, no factor yet) may reach.
    if method == hyper::Method::POST && path == "/api/admin/totp/enroll" {
        return crate::admin_totp::handle_totp_enroll(req, peer, cfg, services).await;
    }
    if method == hyper::Method::POST && path == "/api/admin/totp/confirm" {
        return crate::admin_totp::handle_totp_confirm(req, peer, services).await;
    }

    // AM-P2b — admin account management. Session-gated + CSRF + write scope by
    // the upstream middleware; the acting admin is the injected `x-aegis-actor`.
    // Equal-privilege v1 (any admin manages accounts); the last-admin / no-self
    // guards live in `aegis_control::api::admin_accounts`.
    // AM-P2d — self-service: rotate your own password (verifies the current
    // one; keeps this session, revokes your others).
    if method == hyper::Method::POST && path == "/api/admin/self/password" {
        return crate::admin_accounts::handle_self_password(req, peer, services).await;
    }
    if path == "/api/admin/accounts" {
        if method == hyper::Method::GET {
            let actor = req
                .headers()
                .get("x-aegis-actor")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("admin")
                .to_string();
            return crate::admin_accounts::handle_accounts_list(&actor, services).await;
        }
        if method == hyper::Method::POST {
            return crate::admin_accounts::handle_accounts_create(req, peer, services).await;
        }
    }
    if let Some(rest) = path.strip_prefix("/api/admin/accounts/") {
        // `{user}` | `{user}/password` | `{user}/totp/reset`
        if method == hyper::Method::POST {
            if let Some(user) = rest.strip_suffix("/password") {
                if is_account_segment(user) {
                    let user = user.to_string();
                    return crate::admin_accounts::handle_account_reset_password(
                        req, peer, &user, services,
                    )
                    .await;
                }
            }
            if let Some(user) = rest.strip_suffix("/totp/reset") {
                if is_account_segment(user) {
                    let user = user.to_string();
                    return crate::admin_accounts::handle_account_reset_totp(
                        req, peer, &user, services,
                    )
                    .await;
                }
            }
        }
        if method == hyper::Method::DELETE && is_account_segment(rest) {
            let user = rest.to_string();
            return crate::admin_accounts::handle_account_delete(req, peer, &user, services).await;
        }
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
            // 2026-06-21 — percent-decode the id so non-ASCII / special-char
            // rule ids (e.g. `ádasd` → `%C3%A1dasd`) match the stored key.
            // Previously the raw encoded segment was used, so toggle/edit/
            // delete silently no-op'd on any id the browser URL-encoded.
            let id = crate::admin_get::percent_decode(rule_id);
            return handle_rules_toggle(req, &id, services).await;
        }
        if !suffix.is_empty() && !suffix.contains('/') {
            let id = crate::admin_get::percent_decode(suffix);
            return handle_rules_put(req, &id, services).await;
        }
    }
    if method == hyper::Method::DELETE && path.starts_with("/api/rules/") {
        let raw = &path["/api/rules/".len()..];
        if !raw.is_empty() && !raw.contains('/') {
            let id = crate::admin_get::percent_decode(raw);
            return handle_rules_delete(req, &id, services).await;
        }
    }

    // CI-T4 — alert ack. Audit-mutated; CSRF-gated. The ack
    // store lives on `services.tracking`; render_alerts() then
    // moves the alert from `firing` to `resolved`.
    //
    // MED-ADM-01 (2026-05-12) — `req.uri().path()` returns the
    // percent-encoded path; decode here before handing to the handler so
    // the overlay-store key matches what `enrich()` looks up via
    // `incident_uid(&a)`.  Apply exactly once at this layer; the handler
    // MUST NOT decode again. IF-P1a — the uid is now node-independent
    // (`<sli>-<Nh>`, no `:<ts>`), so it no longer contains a `%3A`, but
    // the decode stays defensive.
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
    // 2026-07-02 — flip the DDoS gate's interop mode (enforce/log_only)
    // from the dashboard so a set_profile log_only is reversible in the UI.
    if method == hyper::Method::PUT && path == "/api/gates/ddos/mode" {
        return crate::admin_mutate::handle_ddos_mode_put(req, services).await;
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
    // SLO-P6 (P4b) — objective editor write. Audit-mutated;
    // CSRF-gated; folds `slo:` into the shared config doc.
    if method == hyper::Method::PUT && path == "/api/slo/config" {
        return handle_slo_config_put(req, services).await;
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

    // 2026-05-29 — runtime `confidence_threshold` adjustment for the AI
    // detector. Same shape as `/api/ai/enabled`: audit-mutated PUT
    // through the cluster config plane; GET is open-on-session so the
    // dashboard can render current + the cfg-loaded default.
    if path == "/api/ai/confidence" {
        if method == hyper::Method::GET {
            return crate::admin_mutate::handle_ai_confidence_get(services).await;
        }
        if method == hyper::Method::PUT {
            return crate::admin_mutate::handle_ai_confidence_put(req, services).await;
        }
    }

    // Hot-reload the AI model from its on-disk path. POST is audit-mutated +
    // CSRF-gated; it re-reads `cfg.ai.model_path` and atomically swaps the new
    // model into the live detector (per-node, local — not a config-plane
    // change). GET reports whether a reloadable model exists and from where.
    if path == "/api/ai/reload" {
        if method == hyper::Method::GET {
            return crate::admin_mutate::handle_ai_reload_get(services).await;
        }
        if method == hyper::Method::POST {
            return crate::admin_mutate::handle_ai_reload_post(req, services).await;
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

    // P4 (2026-07-02) — pre-save rule validation. Same checks the
    // POST/PUT save path enforces (DSL parse + lint + id shape +
    // form-id/body-id match), exposed read-only so the editor can
    // surface errors inline BEFORE the modal closes instead of a
    // failed-save toast after the draft is gone. Always 200 with
    // `{ok, errors[], warnings[]}` — an invalid rule is a successful
    // validation, not an HTTP error.
    if method == hyper::Method::POST && path == "/api/rules/validate" {
        return handle_rules_validate(req).await;
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
    //   PUT    /api/zero-trust/downstream/sans              whole-list replace
    //   DELETE /api/zero-trust/downstream/sans/{san}        single remove
    //   POST   /api/zero-trust/downstream/sans/{san}/test   synthetic admit check
    // MTLS-T8 — runtime mode override.
    if method == hyper::Method::PUT && path == "/api/zero-trust/downstream/mode" {
        return crate::admin_mutate::handle_mtls_mode_put(req, services).await;
    }
    // MTLS-T10 — CA bundle validation + audit-emit (Phase 1).
    if method == hyper::Method::PUT && path == "/api/zero-trust/downstream/ca-bundle" {
        return crate::admin_mutate::handle_mtls_ca_bundle_put(req, services).await;
    }
    if method == hyper::Method::PUT && path == "/api/zero-trust/downstream/sans" {
        return handle_mtls_sans_put(req, services).await;
    }
    // P4 4a-ii — store the shared fleet WAF client identity (upstream
    // mTLS, source: state) in the config plane. Audit-mutated,
    // CSRF-gated, gated behind allow_ca_upload. PUBLIC cert + key
    // reference only (never the key bytes).
    if method == hyper::Method::PUT && path == "/api/zero-trust/upstream/identity" {
        return crate::admin_mutate::handle_zt_upstream_identity_put(req, services).await;
    }
    // P4 trust bundles — upload (POST) / list (GET) / remove (DELETE)
    // PUBLIC backend-CA bundles a pool's `upstream_mtls.trust`
    // references. POST/DELETE audit-mutated + CSRF + allow_ca_upload.
    if method == hyper::Method::GET && path == "/api/zero-trust/upstream/trust" {
        return crate::admin_mutate::handle_zt_upstream_trust_list(services).await;
    }
    if let Some(bundle) = path.strip_prefix("/api/zero-trust/upstream/trust/") {
        if !bundle.is_empty() && !bundle.contains('/') {
            if method == hyper::Method::POST {
                return crate::admin_mutate::handle_zt_upstream_trust_put(req, bundle, services)
                    .await;
            }
            if method == hyper::Method::DELETE {
                return crate::admin_mutate::handle_zt_upstream_trust_delete(req, bundle, services)
                    .await;
            }
        }
    }
    if let Some(suffix) = path.strip_prefix("/api/zero-trust/downstream/sans/") {
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

    // F7 (2026-06-11 cluster QC) — detector mask read, intercepted on
    // the async path so it can stamp the config version THIS node has
    // applied (the version that produced the in-process mask). The
    // dashboard echoes it back in `If-Match` on `PUT /api/detectors`
    // so the CAS rejects a stale write (412) instead of silently
    // clobbering a concurrent toggle. Falls through to the sync
    // `admin_router` arm (no version) when there's no config plane.
    if method == hyper::Method::GET && path == "/api/detectors" {
        return handle_detectors_get(cfg, services).await;
    }

    // 2026-06-02 (copilot P1) — GET /api/copilot/summary. Async because
    // it calls the LLM provider, so it can't run on the sync
    // `admin_router`. Admin-auth gated by the upstream middleware.
    if method == hyper::Method::GET && path == "/api/copilot/summary" {
        return crate::admin_get::handle_copilot_summary(req, services).await;
    }
    if method == hyper::Method::GET && path == "/api/copilot/ask" {
        return crate::admin_get::handle_copilot_ask(req, services).await;
    }
    // MED-3 (2026-06-14): the spec/contract + any programmatic client POST
    // a JSON body ({question, minutes}) rather than a query string. Only
    // GET was wired, so POST /api/copilot/ask fell through to admin_router
    // and 404'd (the dashboard's own Ask box uses the GET form, masking
    // it). CSRF-gated by the upstream middleware like every other POST.
    if method == hyper::Method::POST && path == "/api/copilot/ask" {
        return crate::admin_get::handle_copilot_ask_post(req, services).await;
    }
    // 2026-06-21 — AI rule generation for the New-rule editor (advisory).
    if method == hyper::Method::POST && path == "/api/copilot/rule" {
        return crate::admin_get::handle_copilot_generate_rule(req, services).await;
    }
    if method == hyper::Method::GET && path == "/api/copilot/suggestions" {
        return crate::admin_get::handle_copilot_suggestions(req, services).await;
    }
    // routing-upstream #2 — one-shot member connectivity probe. Async
    // (DNS/TCP/TLS/HTTP I/O), read-only, admin-auth gated upstream.
    if method == hyper::Method::GET && path == "/api/upstreams/probe" {
        return crate::admin_get::handle_upstream_probe(req, services).await;
    }
    // PE-2 (2026-07-04) — allow-listed PromQL proxy to
    // `admin.prometheus_url`. Async (HTTP I/O), read-only,
    // admin-auth gated upstream.
    if method == hyper::Method::GET && path == "/api/analytics/query" {
        return crate::admin_get::handle_analytics_query(req, cfg).await;
    }
    // Async so it can read this node's applied config-doc version from
    // the state backend (the convergence signal the dashboard polls
    // after a pool/route edit). Shadows the synchronous no-backend
    // fallback arm in `admin_router`.
    if method == hyper::Method::GET && path == "/api/config/version" {
        return handle_config_version_get(services).await;
    }

    admin_router(req, cfg, readiness, startup, metrics, services)
}

/// 2026-05-27 — render the cluster config-plane status: the current
/// activated version + each live node's applied version (drift view).
/// Reads through a `ConfigStore` built from the runtime state backend;
/// empty/zero when no config has been activated or no backend is wired.
/// Build the read-side `ConfigStore` from the **same** backend the write side
/// activates on: `services.config_backend` (the store selected by
/// `config_plane.store` — etcd under `store: etcd`) when present, else the
/// data-plane `state_backend` (the `shared_state` default + test bundles).
///
/// Read/write asymmetry was the etcd config-plane bug: the read helpers stamped
/// `config_version` from `state_backend` (Redis) while `activate()` read the
/// real version from etcd, so every `If-Match` mutation 412'd. Mirrors the
/// write-side `admin_mutate::config_plane_store`. `None` ⇒ no backend wired.
fn config_store_for(
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Option<crate::config_source::config_store::ConfigStore> {
    use crate::config_source::config_store::ConfigStore;
    if let Some(cb) = services.config_backend.as_ref() {
        return Some(ConfigStore::with_config_backend(cb.clone()));
    }
    services
        .state_backend
        .as_ref()
        .map(|b| ConfigStore::new(b.clone()))
}

async fn handle_config_get(
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    // A5 — this node's current global mode (enforce / log_only), so the
    // console drift view can show "applied vN · mode" per node and an
    // operator can spot a node lagging on either axis. `None` ⇒ interop
    // not wired (the field is omitted).
    let mode = services
        .interop
        .as_ref()
        .map(|rt| rt.modes.current().default.as_str());
    let Some(store) = config_store_for(services) else {
        return json_body_response(
            200,
            serde_json::json!({ "version": 0, "applied": [], "backend": false, "mode": mode })
                .to_string(),
            "private, max-age=2",
        );
    };
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
        "mode": mode,
    })
    .to_string();
    json_body_response(200, body, "private, max-age=2")
}

/// Build the `/api/config/version` response body.
///
/// `audit_chain_len` is this node's local audit-chain counter — it
/// increments *synchronously* when a mutation's PUT returns, so it is a
/// progress ping, NOT a "config applied" signal. `applied_version` is
/// this node's config-plane ACK: the config-doc version the watcher has
/// actually applied in-process via `writer.apply()` (read from
/// `config:waf:applied:<node>`). After a pool/route edit the dashboard
/// must wait until `applied_version` reaches the doc version the PUT
/// returned before reloading — otherwise it re-reads the live registry
/// before the async watcher has swapped it in and the edit looks lost
/// until a manual refresh.
///
/// `applied_version` is omitted (not zeroed) when no state backend /
/// roster is wired (single-node, test bundles); the client then falls
/// back to the legacy audit-chain wait. `now_ms` is injected so the
/// body shape stays unit-testable.
pub(crate) fn config_version_body(
    audit_chain_len: u64,
    applied_version: Option<u64>,
    node: &str,
    now_ms: i64,
) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert("audit_chain_len".into(), audit_chain_len.into());
    obj.insert("applied_at_ms".into(), now_ms.into());
    obj.insert("applied_on_node".into(), node.into());
    if let Some(v) = applied_version {
        obj.insert("applied_version".into(), v.into());
    }
    obj.insert(
        "note".into(),
        serde_json::Value::String(
            "audit_chain_len = this node's local audit-chain length \
             (increments per audit-mutation, synchronous with the PUT). \
             applied_version = the cluster config-doc version this node has \
             applied in-process; wait for it to reach the version a \
             pool/route mutation returned before reloading. Full per-node \
             applied roster: GET /api/config."
                .into(),
        ),
    );
    obj.insert(
        "cluster_config_version_endpoint".into(),
        "/api/config".into(),
    );
    serde_json::Value::Object(obj)
}

/// This node's applied config-doc version: the version the config-plane
/// watcher last recorded after `writer.apply()` (`config:waf:applied:<node>`).
/// `None` when no state backend / roster is wired (single-node, test
/// bundles). Shared by `GET /api/config/version` and `GET /api/detectors`.
async fn this_node_applied_version(
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Option<u64> {
    match (config_store_for(services), services.roster_view.as_ref()) {
        (Some(store), Some(rv)) if !rv.our_node.is_empty() => {
            store.applied_version(&rv.our_node).await.ok()
        }
        _ => None,
    }
}

/// `GET /api/config/version` — this node's audit-chain length plus its
/// applied config-doc version (the async-apply convergence signal the
/// dashboard polls after a pool/route mutation). `applied_version` field
/// omitted when no backend/roster is wired.
async fn handle_config_version_get(
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let node = services
        .roster_view
        .as_ref()
        .map(|lv| lv.our_node.clone())
        .unwrap_or_default();
    let applied_version = this_node_applied_version(services).await;
    let body = config_version_body(
        services.mutate.chain_len() as u64,
        applied_version,
        &node,
        chrono::Utc::now().timestamp_millis(),
    );
    json_body_response(200, body.to_string(), "private, no-store")
}

/// F7 (2026-06-11) — `GET /api/detectors` with the applied config
/// version stamped on. The version is read from this node's ACK key
/// (`config:waf:applied:<node>`), which the config-plane watcher
/// keeps fresh on every poll — so it reflects the version that
/// produced the mask we render, not a racing latest-doc read. `None`
/// (field omitted) when there's no state backend or no roster
/// (single-node / test bundles); the client then PUTs without an
/// `If-Match` and the handler takes the legacy unconditional path.
async fn handle_detectors_get(
    cfg: &WafConfig,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let modes: Vec<aegis_core::config::ComplianceMode> = cfg
        .compliance
        .as_ref()
        .map(|c| c.modes.clone())
        .unwrap_or_default();
    let config_version = this_node_applied_version(services).await;
    let body = aegis_control::api::detectors::render_get_versioned(
        &services.detector_mask,
        &modes,
        config_version,
    );
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
async fn handle_rollback<B>(
    _req: hyper::Request<B>,
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

            // A1 — same bug class as A0: a `mode_set` rollback mutated
            // the node-local `ModeStore`; propagate the resulting
            // snapshot to peers so the fleet converges. Best-effort;
            // no-op single-node. (Access-list / config-plane rollbacks
            // ride their own convergence path and are out of scope here.)
            if outcome.action == "mode_set" {
                rt.control.publish_modes().await;
            }

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
        Err(RollbackError::NotRollbackable(action)) => {
            // 2026-05-30 (QC R2-004): point operators at the
            // config-plane rollback path for folded actions. The
            // audit-ring whitelist only covers in-process state
            // mutations (mode_set, risk_thresholds_set, …); folded
            // toggles (response_filter_put, ai_confidence_put, …)
            // ride the versioned config doc and roll back via
            // ConfigStore::rollback, which is what
            // POST /api/config/rollback exposes.
            json_response(
                422,
                &serde_json::json!({
                    "error": format!(
                        "action `{action}` is not rollback-able via the audit-ring path"
                    ),
                    "hint": "this action rides the cluster config plane — \
                             use POST /api/config/rollback with `{\"target_version\": N}` to \
                             re-activate an earlier version of the cluster config",
                    "config_plane_endpoint": "POST /api/config/rollback",
                }),
            )
        }
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

    // P1 (2026-07-02) — evaluate the operator ruleset too. Same
    // live handle the data plane reads (`accept.rs` wires it), so
    // the simulator verdict reflects rule CRUD immediately. `None`
    // (test bundles) degrades to detectors-only, matching a
    // no-rules deployment.
    let rules_snapshot = services.active_ruleset.as_ref().map(|rs| rs.snapshot());
    let rules: &[aegis_security::rules::ast::Rule] = rules_snapshot
        .as_deref()
        .map(|v| v.as_slice())
        .unwrap_or(&[]);

    let resp = aegis_control::api::simulator::simulate(
        &parsed,
        detectors.as_ref(),
        &services.detector_mask,
        &services.tiers,
        rules,
        // AC-P2-c — same GeoIP reader the data plane uses, so a
        // Country/Asn rule previews the identical verdict.
        services.attacks.geo_lookup(),
    );
    let body = serde_json::to_string(&resp).unwrap_or_else(|_| "{}".into());
    json_body_response(200, body, "private, no-store")
}

/// P4 (2026-07-02) — `POST /api/rules/validate {id?, body}`.
/// Read-only pre-save validation running the exact checks the
/// save path (`handle_rules_post` / `handle_rules_put`) enforces,
/// so "validate ok → save rejected" can't happen. The id checks
/// only run when an `id` is supplied — the editor may validate a
/// body before the operator has picked an id.
async fn handle_rules_validate(
    req: hyper::Request<hyper::body::Incoming>,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    #[derive(serde::Deserialize)]
    struct ValidateBody {
        #[serde(default)]
        id: Option<String>,
        body: String,
    }

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
    let parsed: ValidateBody = match serde_json::from_slice(&body_bytes) {
        Ok(p) => p,
        Err(e) => {
            return json_response(
                400,
                &serde_json::json!({ "error": format!("invalid validate body: {e}") }),
            );
        }
    };

    let mut v = aegis_control::api::rules::validate_rule_body(&parsed.body);
    if let Some(id) = parsed.id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        if let Some(id_err) = aegis_control::api::rules::validate_rule_id(id) {
            v.errors.push(id_err);
            v.ok = false;
        }
        if let Some(mismatch) =
            aegis_control::api::rules::validate_rule_id_matches_body(id, &parsed.body)
        {
            v.errors.push(mismatch);
            v.ok = false;
        }
    }
    let body = serde_json::to_string(&v).unwrap_or_else(|_| "{}".into());
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
            let resp = rt.control.reset_state_async().await;
            // C-1 — bump the cluster reset epoch so every OTHER node
            // flushes its LOCAL trackers too (the shared-backend wipe
            // above already fanned out fleet-wide). No-op single-node.
            rt.control.publish_reset_epoch().await;
            let body =
                serde_json::to_string(&resp).unwrap_or_else(|_| "{}".into());
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
                    // C-1 — when cluster-scoped (the default), publish
                    // the new mode map so peers converge. Best-effort;
                    // no-op on single-node / in-memory deployments.
                    if parsed.cluster {
                        rt.control.publish_modes().await;
                    }
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
/// How long a solved-challenge pass is honoured before the client
/// must solve again. Short enough to bound replay of a leaked token,
/// long enough for the benchmarker to replay the original request.
const CHALLENGE_PASS_TTL_SECS: u64 = 300;

/// `/challenge/verify` on the data plane (per v2.6 contract §4).
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
        // v2.6 contract §4: "On success, the WAF returns 200 with a
        // session cookie or token that allows the original request to
        // proceed." We mint a short-lived signed `waf_challenge_pass`
        // cookie; the data-plane challenge gate honours it so the
        // replayed original request is forwarded instead of
        // re-challenged (enables the `allowed_after_challenge`
        // outcome). The token is also returned in the body for
        // header-less clients.
        Ok(()) => {
            let pass = issuer.issue_pass(std::time::Duration::from_secs(
                CHALLENGE_PASS_TTL_SECS,
            ));
            let cookie = format!(
                "waf_challenge_pass={pass}; Path=/; Max-Age={CHALLENGE_PASS_TTL_SECS}; \
                 HttpOnly; SameSite=Strict"
            );
            let body = serde_json::to_string(&serde_json::json!({
                "ok": true,
                "action": "challenge_verified",
                "pass_token": pass,
            }))
            .unwrap_or_else(|_| "{}".into());
            Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .header("set-cookie", cookie)
                .body(Full::new(Bytes::from(body)))
                .unwrap()
        }
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

// Phase 1 (SSE): generic over the body type — this only stamps response
// headers, never touches the body — so it works for both the buffered
// `Full<Bytes>` admin responses and the data plane's unified `DataBody`.
pub(crate) fn stamp_interop_response<B>(
    mut resp: Response<B>,
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
) -> Response<B> {
    use aegis_control::interop::audit::MinimalAuditEntry;
    use aegis_control::interop::headers::Decision;

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
    //
    // HIGH-1 (2026-06-19) — a per-route monitor decision forwards the
    // request under a route-level `log_only` downgrade that the GLOBAL
    // `ModeStore` knows nothing about. The data plane stamps
    // `route_log_only` onto the tail tag for exactly those forwarded
    // paths, so honour it here (OR semantics: route forces log_only;
    // otherwise the global per-policy resolution stands). This fixes BOTH
    // the `X-WAF-Mode` response header AND the audit row below, since they
    // share this single `mode`.
    let mode = if decision_tag.route_log_only {
        aegis_control::interop::headers::Mode::LogOnly
    } else {
        aegis_control::interop::rule_map::mode_for_rule(
            &rt.modes,
            decision_tag.rule_id.as_deref(),
        )
    };
    // NEW-4 (2026-05-08) — prefer the score the data plane stamped
    // at decision time (keyed on the XFF-resolved client IP, same
    // key as the risk accumulator). The peer.ip()-keyed snapshot
    // (the fallback) only matches the tracker for direct-connect
    // clients; behind a trusted proxy or with operator-injected
    // X-Forwarded-For, the keys differ and the snapshot returns
    // None → 0.
    // §5.1 / §6 — risk_score is an integer 0–100. The per-request sum
    // is already clamped, but the cumulative tracker clamps to the
    // operator-configurable `risk.max` (default 100, but can be set
    // higher), so clamp here at the shared stamp site to bound BOTH the
    // X-WAF-Risk-Score header and the audit `risk_score`. See F-V26-003.
    let effective_risk_score = decision_tag.risk_score.unwrap_or(risk_score).min(100);
    let decision = Decision {
        request_id: request_id.clone(),
        risk_score: effective_risk_score,
        action: decision_tag.action,
        rule_id: decision_tag.rule_id.clone(),
        // SC-1 — carry the smart-cache decision (Hit/Miss/Bypass) through.
        cache: decision_tag.cache,
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
            // §5.1 — keep the audit `rule_id` byte-identical to the
            // sanitized, singular X-WAF-Rule-Id header (F-V26-001): the
            // primary detector only. The full multi-detector list lives
            // on the X-WAF-Detectors header + the forensic AuditEvent.
            rule_id: decision_tag
                .rule_id
                .as_deref()
                .map(aegis_control::interop::headers::sanitize_primary_rule_id),
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
    use super::config_version_body;

    // BUG (etcd config plane) — the admin read-side that stamps `config_version`
    // must follow the SAME backend the write side activates on
    // (`services.config_backend` when set, e.g. etcd), not the data-plane
    // `state_backend` (Redis). Otherwise every `If-Match`-guarded mutation 412s
    // under `config_plane.store: etcd`. This pins `config_store_for`'s
    // selection: config_backend wins, state_backend is the fallback.
    #[tokio::test]
    async fn config_store_for_follows_config_backend_when_set() {
        use crate::config_source::config_store::ConfigStore;
        use std::sync::Arc;

        // state_backend (Redis stand-in) holds version 1; config_backend (etcd
        // stand-in) holds a DIFFERENT version 2.
        let state_be: Arc<dyn aegis_core::state::StateBackend> =
            Arc::new(crate::state::in_memory::InMemoryBackend::new());
        ConfigStore::new(state_be.clone())
            .activate(0, "state-doc".into(), "t", "")
            .await
            .unwrap();

        let cfg_be: Arc<dyn aegis_core::config_backend::ConfigBackend> =
            aegis_core::config_backend::SharedStateConfigBackend::arc(Arc::new(
                crate::state::in_memory::InMemoryBackend::new(),
            ));
        let cfg_store = ConfigStore::with_config_backend(cfg_be.clone());
        cfg_store.activate(0, "cfg-doc-a".into(), "t", "").await.unwrap();
        cfg_store.activate(1, "cfg-doc-b".into(), "t", "").await.unwrap();

        let bus = aegis_core::audit::AuditBus::new(8);
        let pools: aegis_control::dashboard_services::PoolSnapshotProvider =
            Arc::new(|| aegis_control::api::upstreams::PoolHealthSnapshot {
                pools: Vec::new(),
                ..Default::default()
            });
        let (mut services, _drain) =
            aegis_control::dashboard_services::DashboardServices::spawn(bus, pools, None);
        services.state_backend = Some(state_be.clone());
        services.config_backend = Some(cfg_be.clone());

        // With a config_backend set, the read store follows it → version 2.
        let v = super::config_store_for(&services)
            .expect("store")
            .current_version()
            .await
            .unwrap();
        assert_eq!(v, 2, "read side must follow config_backend (etcd), not state_backend");

        // Fallback: no config_backend → state_backend → version 1.
        services.config_backend = None;
        let v = super::config_store_for(&services)
            .expect("store")
            .current_version()
            .await
            .unwrap();
        assert_eq!(v, 1, "without a config_backend the read side falls back to state_backend");
    }

    // Pool/route edits land via the async apply pipeline, so the
    // dashboard must wait on this node's *applied* config-doc version
    // (the ACK the watcher records after `writer.apply()`), NOT the
    // audit-chain length (which increments synchronously with the PUT
    // and so races the apply). `config_version_body` carries both; these
    // pin the contract the UI's `waitForApplied` polls against.
    #[test]
    fn config_version_body_includes_applied_version_when_known() {
        let v = config_version_body(7, Some(42), "node-a", 1_700_000_000_000);
        assert_eq!(v["audit_chain_len"], 7);
        assert_eq!(v["applied_version"], 42);
        assert_eq!(v["applied_on_node"], "node-a");
        assert_eq!(v["applied_at_ms"], 1_700_000_000_000_i64);
        assert_eq!(v["cluster_config_version_endpoint"], "/api/config");
        assert!(v["note"].is_string());
    }

    #[test]
    fn config_version_body_omits_applied_version_when_unknown() {
        // No state backend / roster (single-node, test bundles): the
        // field is omitted rather than emitted as a misleading 0, so the
        // client falls back to the legacy audit-chain wait.
        let v = config_version_body(3, None, "", 0);
        assert_eq!(v["audit_chain_len"], 3);
        assert!(v.get("applied_version").is_none());
    }

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

    // A1 — same bug class as A0: the audit-ring rollback path
    // (`POST /api/config/versions/{seq}/rollback`) re-applies a
    // `mode_set` to the node-local `ModeStore` but, pre-fix, never
    // published the resulting snapshot to the cluster. A rollback in
    // the console therefore drifted the fleet just like the Dry-Run
    // toggle did (A0). Drives the real `handle_rollback` so the missing
    // publish is caught.
    #[tokio::test]
    async fn mode_rollback_publishes_to_cluster_so_peer_converges() {
        use aegis_control::interop::cluster_sync;
        use aegis_control::interop::headers::Mode;
        use aegis_control::interop::mode::ModeStore;
        use aegis_core::audit::{AuditClass, AuditEvent};
        use aegis_core::audit::AuditBus;
        use bytes::Bytes;
        use http_body_util::Full;
        use std::sync::Arc;

        // H2b — the control plane rides the ConfigBackend seam; wrap an
        // in-memory state backend (shared_state) for the test.
        let backend: Arc<dyn aegis_core::config_backend::ConfigBackend> =
            aegis_core::config_backend::SharedStateConfigBackend::arc(Arc::new(
                crate::state::in_memory::InMemoryBackend::new(),
            ));

        let cfg = aegis_core::load_config_str(concat!(
            "listeners:\n  data: [{ bind: \"0.0.0.0:443\" }]\n",
            "  admin: { bind: \"127.0.0.1:9443\" }\n",
            "routes:\n  - { id: catch-all, path: \"/\", upstream: api }\n",
            "upstreams:\n  api: { members: [{ addr: \"127.0.0.1:8443\" }] }\n",
            "state: { backend: in_memory }\n",
        ))
        .unwrap();
        let risk = aegis_security::risk::RiskTracker::new(
            &aegis_core::config::RiskConfig::default(),
        );
        let iprl = Arc::new(aegis_security::rate_limit::IpRateLimiter::new(
            Default::default(),
        ));
        let rt = crate::run::build_interop_runtime(&cfg, &risk, &iprl)
            .expect("interop surface is on by default");
        rt.control.set_cluster_state(backend.clone());

        let bus = AuditBus::new(64);
        let pools: aegis_control::dashboard_services::PoolSnapshotProvider =
            Arc::new(|| aegis_control::api::upstreams::PoolHealthSnapshot {
                pools: Vec::new(),
                ..Default::default()
            });
        let (mut services, _drain) =
            aegis_control::dashboard_services::DashboardServices::spawn(bus, pools, None);
        services.interop = Some(rt.clone());

        // Live store is enforce; a recorded `mode_set` whose captured
        // `before.mode` is log_only is what the operator rolls back to.
        rt.modes.set_all(Mode::Enforce);
        let seq = services.audit_ring.record(AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: String::new(),
            class: AuditClass::Admin,
            tenant_id: None,
            tier: None,
            action: "mode_set".into(),
            reason: String::new(),
            client_ip: String::new(),
            route_id: None,
            rule_id: None,
            risk_score: None,
            method: None,
            path: None,
            mode: None,
            fields: serde_json::json!({
                "diff": { "before": { "mode": "log_only" }, "after": { "mode": "enforce" } },
            }),
        });

        let req = hyper::Request::builder()
            .method("POST")
            .uri(format!("/api/config/versions/{seq}/rollback"))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = super::handle_rollback(req, seq, &services).await;
        assert_eq!(resp.status(), 200, "rollback must succeed");
        assert_eq!(
            rt.modes.resolve("rules_engine", None),
            Mode::LogOnly,
            "local store rolled back to log_only",
        );

        // Peer converges on the rolled-back mode via the published doc.
        let doc = cluster_sync::read_modes(&backend)
            .await
            .expect("rollback must publish a modes doc to the cluster plane");
        let node_b = ModeStore::new(Mode::Enforce);
        node_b.set_snapshot(doc.to_snapshot());
        assert_eq!(
            node_b.resolve("rules_engine", None),
            Mode::LogOnly,
            "peer converges on the rolled-back global mode",
        );
    }

    /// HIGH-1 (2026-06-19) — a per-route monitor decision is forwarded
    /// (action=block) but MUST report `X-WAF-Mode: log_only`, even though
    /// the GLOBAL ModeStore is `enforce`. Pre-fix the stamper re-derived
    /// the mode from the global store via `mode_for_rule` and stamped
    /// `enforce`, contradicting the forwarded behaviour (§5.3).
    fn stamp_mode_for(route_log_only: bool) -> String {
        use aegis_control::interop::headers::{DecisionTag, Mode, MODE};
        use bytes::Bytes;
        use http_body_util::Full;
        use std::sync::Arc;

        let cfg = aegis_core::load_config_str(concat!(
            "listeners:\n  data: [{ bind: \"0.0.0.0:443\" }]\n",
            "  admin: { bind: \"127.0.0.1:9443\" }\n",
            "routes:\n  - { id: catch-all, path: \"/\", upstream: api }\n",
            "upstreams:\n  api: { members: [{ addr: \"127.0.0.1:8443\" }] }\n",
            "state: { backend: in_memory }\n",
        ))
        .unwrap();
        let risk =
            aegis_security::risk::RiskTracker::new(&aegis_core::config::RiskConfig::default());
        let iprl = Arc::new(aegis_security::rate_limit::IpRateLimiter::new(
            Default::default(),
        ));
        let rt = crate::run::build_interop_runtime(&cfg, &risk, &iprl)
            .expect("interop surface is on by default");
        // Global store stays ENFORCE — the route flag must win on its own.
        rt.modes.set_all(Mode::Enforce);

        let mut tag = DecisionTag::block("xss");
        if route_log_only {
            tag = tag.with_route_log_only(true);
        }
        let resp: hyper::Response<Full<Bytes>> =
            hyper::Response::builder().status(200).body(Full::new(Bytes::new())).unwrap();
        let stamped = super::stamp_interop_response(
            resp,
            tag,
            Some(&rt),
            "127.0.0.1:1234".parse().unwrap(),
            &hyper::Method::GET,
            "/",
            0,
            std::time::Instant::now(),
        );
        stamped
            .headers()
            .get(MODE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("<missing>")
            .to_string()
    }

    // `#[tokio::test]` — the stamper offloads the audit write via
    // `spawn_blocking`, which needs an active reactor.
    #[tokio::test]
    async fn monitored_route_block_stamps_x_waf_mode_log_only() {
        assert_eq!(
            stamp_mode_for(true),
            "log_only",
            "a forwarded monitor-route block must report X-WAF-Mode: log_only",
        );
    }

    #[tokio::test]
    async fn enforce_route_block_stamps_x_waf_mode_enforce() {
        assert_eq!(
            stamp_mode_for(false),
            "enforce",
            "a real enforce block keeps X-WAF-Mode: enforce (global store)",
        );
    }
}
