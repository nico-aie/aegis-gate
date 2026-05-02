//! PRE-T5 — `admin_router` + query parsers extracted from
//! `lib.rs` into a focused module.
//!
//! ## Scope
//!
//! - [`admin_router`] — the GET-side dispatcher every admin /
//!   dashboard / health / metrics request flows through. ~430
//!   lines of `match path { ... }` arms covering health probes,
//!   `/metrics`, `/api/about`, `/api/stats`, `/api/timeseries`,
//!   `/api/audit/since`, `/api/rules*`, `/api/upstreams*`,
//!   `/api/risk*`, `/api/mode`, `/api/loadmode`, `/api/runtime`,
//!   `/api/detectors`, `/api/blacklist`, `/api/whitelist`,
//!   `/api/alerts`, `/api/slo`, `/api/certs`, `/api/cluster`,
//!   `/api/gitops/*`, `/api/mtls*` (MTLS-T6), `/api/filters`,
//!   `/api/integrations`, `/api/admin/*`, `/api/cold-tier`,
//!   `/api/logging`, `/api/analytics/*`, `/api/threat-intel/*`,
//!   `/api/bots/*`, `/api/audit/witness`, `/api/tracking/*`,
//!   `/api/upstreams/config` (CC-T1.1).
//! - [`parse_query_u32`], [`parse_query_str`],
//!   [`parse_query_u64`] — small `?key=value` helpers used by
//!   the dispatch arms to honour `?window=` / `?step=` /
//!   `?limit=` / `?cursor=` query parameters.
//!
//! ## Visibility
//!
//! `pub(crate)` for everything — internal to aegis-proxy. The
//! single call site in `lib.rs` (`admin_listener`'s service_fn)
//! invokes `admin_router(...)` via `use admin_get::admin_router;`.
//! Mutation handlers are NOT in this file — they live in `lib.rs`
//! (until PRE-T6 extracts them) and are invoked from
//! `admin_router` for paths that don't match a GET arm.

use bytes::Bytes;
use http_body_util::Full;
use hyper::Response;

use aegis_core::config::WafConfig;
use aegis_core::ReadinessSignal;

use crate::responses::{
    dashboard_response, dashboard_shell_response, json_body_response, json_response,
};

pub(crate) fn admin_router(
    req: hyper::Request<hyper::body::Incoming>,
    cfg: &WafConfig,
    readiness: &ReadinessSignal,
    startup: &aegis_control::health::StartupProbe,
    metrics: &aegis_control::metrics::MetricsRegistry,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let path = req.uri().path();
    let query = req.uri().query().unwrap_or("");

    let use_legacy = cfg.admin.dashboard.legacy_shell;

    // Root → dashboard for convenience (existing behaviour).
    if path == "/" {
        return dashboard_shell_response(use_legacy);
    }

    // Dashboard surface (SPA shell + embedded assets) is owned by
    // aegis-control::dashboard::dispatch. SSE returns None and falls
    // through to the streaming handler below.
    if let Some(resp) = aegis_control::dashboard::dispatch::dispatch(path) {
        return dashboard_response(resp, use_legacy);
    }

    match path {
        // `/dashboard/sse` is intercepted at the listener
        // service_fn (B4-T4) and returns a streaming body.
        // If a request reaches `admin_router` with that path
        // (for example via tests that bypass the listener),
        // surface a 404 — the buffered router can no longer
        // serve SSE.

        // Health probes.
        "/healthz/live" => {
            let (code, msg) = aegis_control::health::check_live(readiness);
            json_response(code, &serde_json::json!({"status": msg}))
        }
        "/healthz/ready" => {
            // HA-T5 — `?strict=1` returns 503 unless this node also
            // holds the cluster lease. Lets active/standby LB
            // topologies route singleton traffic to one node only.
            let strict = matches!(parse_query_str(query, "strict"), Some("1"));
            let (code, resp) = if strict {
                let is_leader = services
                    .leader_view
                    .as_ref()
                    .map(|lv| lv.is_leader());
                aegis_control::health::check_ready_strict(readiness, is_leader)
            } else {
                aegis_control::health::check_ready(readiness)
            };
            json_response(code, &serde_json::json!(resp))
        }
        "/healthz/startup" => {
            let (code, msg) = aegis_control::health::check_startup(startup);
            json_response(code, &serde_json::json!({"status": msg}))
        }

        // Prometheus metrics.
        "/metrics" => {
            let body = aegis_control::metrics::exporter::render(metrics);
            Response::builder()
                .status(200)
                .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
                .body(Full::new(Bytes::from(body)))
                .unwrap()
        }

        // Config API.
        "/api/config" => {
            json_response(200, &serde_json::json!({
                "status": "running",
                "admin": cfg.listeners.admin.bind.to_string(),
                "data_listeners": cfg.listeners.data.len(),
                "routes": cfg.routes.len(),
                "upstreams": cfg.upstreams.len(),
            }))
        }

        // DD-T7 — config-version visibility for hot-reload UI.
        // Returns the current rules-store revision so the dashboard
        // can poll after a mutation and surface "Applied in X.Xs".
        // The version increments on every successful audit-mutation
        // (rule CRUD, detector toggle, loadmode pin, etc.) — every
        // surface that flows through `services.mutate.apply()` is
        // counted automatically, so adding a new mutating endpoint
        // doesn't need a parallel version bump.
        "/api/config/version" => {
            let v = services.mutate.chain_len();
            let body = serde_json::json!({
                "version": v,
                "applied_at_ms": chrono::Utc::now().timestamp_millis(),
                "applied_on_node": services
                    .leader_view
                    .as_ref()
                    .map(|lv| lv.our_node.clone())
                    .unwrap_or_default(),
            });
            json_body_response(200, body.to_string(), "private, no-store")
        }

        // Dashboard data endpoints (D-M2). All read-only, JSON,
        // sourced from `aegis-control::dashboard_services`.
        "/api/about" => {
            json_body_response(
                200,
                aegis_control::api::about::render(services.environment.clone()),
                "private, max-age=10",
            )
        }
        "/api/stats" => {
            json_body_response(200, services.stats.render(), "private, max-age=1")
        }
        "/api/stats/timeseries" => {
            let window = parse_query_u32(query, "window", 900);
            let step = parse_query_u32(query, "step", 5);
            let resp = services.stats_agg.timeseries(window, step);
            let body = serde_json::to_string(&resp).unwrap_or_else(|_| "{}".into());
            json_body_response(200, body, "private, max-age=1")
        }
        "/api/upstreams/summary" => {
            json_body_response(200, services.upstreams.render(), "private, max-age=2")
        }
        "/api/attacks/distribution" => {
            let window = parse_query_u32(query, "window", 900);
            json_body_response(
                200,
                services.attacks.render(window),
                "private, max-age=10",
            )
        }
        "/api/attacks/top" => {
            let window = parse_query_u32(query, "window", 900);
            let limit = parse_query_u32(query, "limit", 5);
            json_body_response(
                200,
                services.attacks.render_top(window, limit),
                "private, max-age=10",
            )
        }
        "/api/audit/since" => {
            let cursor = parse_query_u64(query, "cursor", 0);
            let limit = parse_query_u32(query, "limit", 200);
            json_body_response(
                200,
                services.audit.render_since(cursor, limit),
                "private, no-store",
            )
        }
        "/api/attacks/by-detector" => {
            let window = parse_query_u32(query, "window", 900);
            json_body_response(
                200,
                services.attacks.render_by_detector(window),
                "private, max-age=10",
            )
        }
        "/api/threat-intel/hits" => {
            let window = parse_query_u32(query, "window", 3600);
            let limit = parse_query_u32(query, "limit", 20);
            json_body_response(
                200,
                services.attacks.render_threat_intel(window, limit),
                "private, max-age=10",
            )
        }
        "/api/bots/mix" => {
            let window = parse_query_u32(query, "window", 3600);
            json_body_response(
                200,
                services.attacks.render_bot_mix(window),
                "private, max-age=10",
            )
        }
        "/api/audit/witness" => {
            json_body_response(200, services.witness.render(), "private, max-age=2")
        }
        // HACK-T4 — Tier-B bonus: config-change timeline.
        // Filters the audit ring to `class = Admin` events
        // (every audit-mutated PUT/POST/DELETE) and returns
        // them newest-first. The dashboard renders a
        // browse-able history of "who changed what when?"
        // on the Settings page.
        "/api/config/versions" => {
            let limit = parse_query_u32(query, "limit", 50);
            json_body_response(
                200,
                aegis_control::api::config_versions::render(
                    &services.audit_ring,
                    limit,
                ),
                "private, max-age=2",
            )
        }
        "/api/filters" => {
            json_body_response(200, services.filters.render(), "private, max-age=30")
        }
        "/api/analytics/query" => {
            let expr = parse_query_str(query, "expr").unwrap_or("");
            let start = parse_query_u64(query, "start", 0);
            let end = parse_query_u64(query, "end", 0);
            let step = parse_query_u32(query, "step", 60);
            let r = aegis_control::api::analytics::render_query(
                expr, start, end, step, None,
            );
            json_body_response(r.status, r.body, "private, max-age=30")
        }
        // Phase-1: per-stage p50/p95/p99 from the in-process
        // `RequestStageHistogram`. Returns `{stages: {total: {p50_ms,
        // p95_ms, p99_ms, samples}, detect: {...}, ...}}` so the
        // Analytics page can render them without scraping
        // `/metrics` itself.
        "/api/analytics/latency" => {
            use aegis_control::metrics::request_duration::stage;
            let body = match services.request_stage_hist.as_ref() {
                None => serde_json::json!({"stages": {}}).to_string(),
                Some(h) => {
                    let stages = [stage::TOTAL, stage::DETECT, stage::RATE_LIMIT, stage::RESPOND];
                    let mut out = serde_json::Map::new();
                    for s in stages {
                        if let Some(p) = h.percentiles_ms(s) {
                            out.insert(
                                s.to_string(),
                                serde_json::to_value(p).unwrap_or(serde_json::Value::Null),
                            );
                        }
                    }
                    serde_json::json!({"stages": out}).to_string()
                }
            };
            json_body_response(200, body, "private, max-age=2")
        }

        // D-M4 read endpoints. Mutating endpoints (POST / PUT /
        // DELETE) are deferred until the M3 audit-mutation
        // pipeline is integrated; the in-process stores still
        // round-trip through these reads for the dashboard pages
        // to render the empty initial state.
        "/api/rules" => {
            let body = serde_json::json!({"rules": services.rules.list()});
            json_body_response(200, body.to_string(), "private, max-age=2")
        }
        "/api/rules/top" => {
            let window = parse_query_u32(query, "window", 3600);
            let limit = parse_query_u32(query, "limit", 10);
            let body = serde_json::to_string(&services.rule_stats.top(window, limit))
                .unwrap_or_else(|_| "{}".into());
            json_body_response(200, body, "private, max-age=10")
        }
        "/api/tiers" => {
            let body = serde_json::json!({"tiers": services.tiers.list()});
            json_body_response(200, body.to_string(), "private, max-age=5")
        }
        "/api/routes" => {
            // Read-only view of the routing trie seeded from
            // `cfg.routes` at boot. Cached 30 s — config is
            // hot-reloadable but doesn't change on every request.
            json_body_response(200, services.routes.render(), "private, max-age=30")
        }
        "/api/blacklist" => {
            let body = serde_json::json!({"entries": services.blacklist.list()});
            json_body_response(200, body.to_string(), "private, max-age=2")
        }
        "/api/whitelist" => {
            let body = serde_json::json!({"entries": services.whitelist.list()});
            json_body_response(200, body.to_string(), "private, max-age=2")
        }
        "/api/admin/sessions" => {
            let body = serde_json::json!({"sessions": services.sessions.list()});
            json_body_response(200, body.to_string(), "private, no-store")
        }
        "/api/admin/break-glass" => {
            let body = serde_json::to_string(&services.break_glass.snapshot())
                .unwrap_or_else(|_| "{}".into());
            json_body_response(200, body, "private, no-store")
        }
        "/api/integrations" => {
            let resp = aegis_control::api::admin::IntegrationsResponse::from_config(cfg);
            let body = serde_json::to_string(&resp).unwrap_or_else(|_| "{}".into());
            json_body_response(200, body, "private, max-age=30")
        }

        // P8 verbosity. GET returns the live level + ladder; PUT
        // (audit-mutated) sets a new level. Cold-tier mirror at
        // `/api/cold-tier` lists configured sinks.
        "/api/logging" => {
            let body = aegis_control::api::logging::render_logging_get(&services.verbosity);
            json_body_response(200, body, "private, max-age=2")
        }
        "/api/cold-tier" => {
            let sinks = &cfg.audit.sinks;
            let body = aegis_control::api::logging::render_cold_tier(sinks);
            json_body_response(200, body, "private, max-age=10")
        }

        // P7 load-mode snapshot. GET returns the live mode +
        // RPS + threshold config + override state. PUT is async
        // (handled in `handle_admin_request`).
        "/api/loadmode" => {
            let body = aegis_control::api::load_mode::render_get(&services.load_gauge);
            json_body_response(200, body, "private, max-age=2")
        }

        // CI-T6 — current global enforce / log_only mode (interop
        // ModeStore). Mirror surface of `/__waf_control/mode`
        // gated behind dashboard auth. PUT lands at the matching
        // mutation handler in dispatch.
        "/api/mode" => {
            let mode = services
                .interop
                .as_ref()
                .map(|rt| rt.modes.current().default.as_str())
                .unwrap_or("enforce");
            let body = serde_json::json!({"mode": mode}).to_string();
            json_body_response(200, body, "private, max-age=2")
        }

        // P6 risk inventory. Top-N high-risk clients ordered by
        // strike count then score. The dashboard polls this to
        // render the Tracking page risk widget.
        "/api/risk" => {
            let limit = parse_query_u32(query, "limit", 50);
            let body = aegis_control::api::risk::render_list(&services.risk, limit);
            json_body_response(200, body, "private, max-age=2")
        }

        // CI-T12 — current risk thresholds. Mirrors the PUT body
        // shape so a roundtrip {GET → modify → PUT} works.
        "/api/risk/thresholds" => {
            let t = services.risk.thresholds();
            let body = serde_json::json!({
                "challenge_at": t.challenge_at,
                "block_at":     t.block_at,
                "max":          t.max,
            })
            .to_string();
            json_body_response(200, body, "private, max-age=2")
        }

        // P2: detector class mask — read returns the live mask
        // plus compliance lock-list. PUT is handled in
        // `handle_admin_request` (async — needs to read body).
        "/api/detectors" => {
            let modes: Vec<aegis_core::config::ComplianceMode> = cfg
                .compliance
                .as_ref()
                .map(|c| c.modes.clone())
                .unwrap_or_default();
            let body = aegis_control::api::detectors::render_get(
                &services.detector_mask,
                &modes,
            );
            json_body_response(200, body, "private, max-age=2")
        }

        // D-M5: tracking
        "/api/slo" => json_body_response(200, services.tracking.render_slo(), "private, max-age=2"),
        "/api/cluster" => json_body_response(200, services.tracking.render_cluster(), "private, max-age=2"),
        "/api/runtime" => {
            // Layer-1 — in-node runtime sizing snapshot. Stable
            // across the process lifetime (tokio runtime is fixed
            // at boot), so cache aggressively.
            let view = aegis_control::api::runtime::RuntimeView::render(
                &cfg.runtime,
                cfg!(feature = "affinity"),
            );
            let body = serde_json::to_string(&view).unwrap_or_else(|_| "{}".into());
            json_body_response(200, body, "private, max-age=60")
        }
        "/api/certs" => json_body_response(200, services.tracking.render_certs(), "private, max-age=10"),
        "/api/gitops/status" => json_body_response(200, services.tracking.render_gitops(), "private, max-age=5"),
        "/api/alerts" => json_body_response(200, services.tracking.render_alerts(), "private, max-age=2"),
        // CC-T2.1 — alert-channel management surface. Returns
        // every configured `slo::AlertReceiver` with secrets
        // redacted to last-4 chars, plus per-receiver
        // last-delivery state. Empty body when the proxy hasn't
        // wired the handler (e.g. tests that boot DashboardServices
        // standalone) — keeps the dashboard's empty-state path
        // working without a 404.
        "/api/alert-receivers" => match services.alert_receivers.as_ref() {
            Some(h) => json_body_response(200, h.render(), "private, max-age=2"),
            None => json_body_response(
                200,
                String::from("{\"receivers\":[]}"),
                "private, max-age=2",
            ),
        },
        // MTLS-T6 — read-only mTLS observability surface. Four
        // endpoints. Each works with `identity_tracker: None`
        // (returns empty-state body) so the dashboard renders
        // before MTLS-T2's rustls wiring lands.
        "/api/mtls" => json_body_response(
            200,
            aegis_control::api::mtls::MtlsConfigView::from_config(cfg).render(),
            "private, max-age=2",
        ),
        "/api/mtls/connections" => json_body_response(
            200,
            aegis_control::api::mtls::render_connections(
                services.identity_tracker.as_ref(),
            ),
            "private, max-age=2",
        ),
        "/api/mtls/failures" => json_body_response(
            200,
            aegis_control::api::mtls::render_failures(
                services.identity_tracker.as_ref(),
            ),
            "private, max-age=2",
        ),
        "/api/mtls/ca-summary" => json_body_response(
            200,
            aegis_control::api::mtls::render_ca_summary(
                services.identity_tracker.as_ref(),
            ),
            "private, max-age=2",
        ),
        // MTLS-T7 — live allowed-SAN list. Empty array when
        // no allowlist is wired (test bundles or operators
        // who haven't opted in).
        "/api/mtls/sans" => {
            let body = match services.allowed_sans.as_ref() {
                Some(store) => serde_json::json!({ "allowed": store.current() }),
                None => serde_json::json!({ "allowed": [] }),
            };
            json_body_response(
                200,
                serde_json::to_string(&body).unwrap_or_else(|_| "{}".into()),
                "private, max-age=2",
            )
        }
        "/api/upstreams" => json_body_response(200, services.upstreams.render(), "private, max-age=2"),
        // CC-T1.1 — full upstream-pool configuration view. Reads
        // `cfg.upstreams` plus pre-computed route references so
        // the dashboard's edit page renders without a second
        // fetch. Read-only today; the audit-mutated PUT / DELETE
        // handlers ship in CC-T1.1.b once the proxy hot-swap of
        // `ProxyContext.pools` lands.
        "/api/upstreams/config" => {
            let view = aegis_control::api::upstreams_config::UpstreamsConfigView::from_config(cfg);
            json_body_response(200, view.render(), "private, max-age=2")
        }
        "/api/tracking/snapshot" => json_body_response(
            200,
            services.tracking.render_snapshot(),
            "private, max-age=2",
        ),

        // P6 single-client detail. Path is `/api/risk/<ip>`.
        path if path.starts_with("/api/risk/") => {
            let segment = &path["/api/risk/".len()..];
            // `/api/risk/<ip>/reset` is a PUT — leave it to the
            // async wrapper. Anything else GETs the detail.
            if let Some(ip_seg) = segment.strip_suffix("/reset") {
                let _ = ip_seg; // PUT path handled in handle_admin_request
                json_response(
                    405,
                    &serde_json::json!({
                        "error": "method_not_allowed",
                        "allow": "PUT",
                    }),
                )
            } else if let Some(ip) = aegis_control::api::risk::parse_ip_segment(segment) {
                let (status, body) =
                    aegis_control::api::risk::render_detail(&services.risk, ip);
                json_body_response(status, body, "private, no-store")
            } else {
                json_response(
                    400,
                    &serde_json::json!({
                        "error": "invalid_ip",
                        "segment": segment,
                    }),
                )
            }
        }

        // 404 for everything else.
        _ => {
            json_response(404, &serde_json::json!({"error": "not found", "path": path}))
        }
    }
}

/// Parse a `?key=value` integer from a raw query string. Used by
/// the dashboard API endpoints to honour their `?window=` /
/// `?step=` / `?limit=` parameters. Falls back to `default` on
/// missing key, parse failure, or trailing `s` suffix
/// (the api spec writes `15m` / `5s` in examples but accepts
/// integer seconds in the URL).
fn parse_query_u32(query: &str, key: &str, default: u32) -> u32 {
    for pair in query.split('&') {
        if let Some(rest) = pair.strip_prefix(key) {
            if let Some(value) = rest.strip_prefix('=') {
                let trimmed = value.trim_end_matches('s');
                if let Ok(n) = trimmed.parse::<u32>() {
                    return n;
                }
            }
        }
    }
    default
}

/// Same shape as `parse_query_u32` but returns the raw string slice.
/// Useful for keys whose values aren't numeric (e.g. `?expr=`).
fn parse_query_str<'q>(query: &'q str, key: &str) -> Option<&'q str> {
    for pair in query.split('&') {
        if let Some(rest) = pair.strip_prefix(key) {
            if let Some(value) = rest.strip_prefix('=') {
                return Some(value);
            }
        }
    }
    None
}

/// Same shape as `parse_query_u32` but for u64 — used by audit cursor
/// values that may exceed `u32::MAX` in long-running deployments.
fn parse_query_u64(query: &str, key: &str, default: u64) -> u64 {
    for pair in query.split('&') {
        if let Some(rest) = pair.strip_prefix(key) {
            if let Some(value) = rest.strip_prefix('=') {
                if let Ok(n) = value.parse::<u64>() {
                    return n;
                }
            }
        }
    }
    default
}
