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
//!   `/api/gitops/*`, `/api/zero-trust/downstream*` (MTLS-T6), `/api/filters`,
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

/// F14 (2026-06-11) — log `/api/audit/since` renders slower than this.
/// The in-process render (in-memory ring + 1 s cache) is normally
/// sub-millisecond, so anything past this points outside the handler
/// (TLS/connection churn, lock contention) — the source the cluster
/// QC's remote-Chrome timing (~260 ms floor) couldn't pin down.
const AUDIT_RENDER_SLOW_MS: u128 = 25;

/// 2026-05-27 (Phase C) — wall-clock seconds for windowing the cached
/// cluster-wide metric aggregates.
fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Cluster Phase 3 (§2a) — the merged fleet metrics view, if the
/// snapshot publish/merge task is wired (`cluster.fleet_view` enabled +
/// shared backend) AND it has produced at least one merge. `None` ⇒ the
/// traffic GET handlers fall back to this node's local aggregators.
fn fleet_view(
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Option<aegis_control::metrics::fleet_snapshot::MergedFleet> {
    services.fleet_cache.as_ref().and_then(|c| c.load())
}

/// SCOPE-P1b — the fleet view scoped by an optional `?node=<id>` query
/// param. With `node` present, re-merges just that node's snapshot so any
/// fleet renderer serves a single node; absent (or empty) ⇒ the full
/// merge. An unknown/TTL'd node yields `None`, so the handler falls back
/// to this node's local aggregators (same as fleet-off).
fn fleet_view_scoped(
    services: &aegis_control::dashboard_services::DashboardServices,
    query: &str,
) -> Option<aegis_control::metrics::fleet_snapshot::MergedFleet> {
    let merged = fleet_view(services)?;
    match parse_query_str(query, "node") {
        Some(node) if !node.is_empty() => merged.view_for_node(node),
        _ => Some(merged),
    }
}

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
            // Phase 1 (leaderless): readiness is purely node-local —
            // state rehydrated + listeners bound + not draining. The
            // old `?strict=1` "503 unless leader" mode was removed
            // with the global leader concept.
            let (code, resp) = aegis_control::health::check_ready(readiness);
            // F-CRITICAL-003 (2026-05-17 control audit): populate
            // the three Round-1 mandated fields — uptime / mode /
            // active rule count. Mode is "enforce" today (the
            // global default; per-feature log_only is handled
            // separately via /__waf_control/set_profile and
            // surfaces on the dashboard's mode-toggle UI).
            let uptime_seconds = {
                let started = aegis_control::api::about::boot_ts();
                let now = chrono::Utc::now();
                (now - started).num_seconds().max(0) as u64
            };
            let rule_count = services.rules.list().len() as u64;
            let resp = resp.with_runtime_info(uptime_seconds, "enforce", rule_count);
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

        // 2026-05-19 — Configuration backup (Phase 1 of the
        // dashboard's "clone this config to a new node" workflow).
        //
        // Serves the source-of-truth `waf.yaml` file the proxy
        // booted from, byte-for-byte. Includes whatever the
        // operator currently has on disk — comments preserved,
        // `${secret:*}` references preserved. Returns 404 when
        // the proxy booted from a non-file source (etcd / test
        // bundle); the dashboard renders an explanatory empty
        // state in that case.
        //
        // Does NOT include in-memory dashboard mutations (rule
        // CRUD, hot-flipped detector mask, risk-threshold edits,
        // mode toggle). Those live in dedicated persistence
        // sinks (`cfg.detectors.persistence.path` for the mask;
        // the rule store + risk thresholds are runtime-only).
        // The dashboard card surfaces this caveat next to the
        // download button.
        "/api/config/backup.yaml" => {
            let Some(path) = services.config_yaml_path.as_ref() else {
                return json_response(
                    404,
                    &serde_json::json!({
                        "ok": false,
                        "reason": "no_file_source",
                        "message": "proxy booted from a non-file config source \
                                    (etcd / test bundle); no waf.yaml to back up",
                    }),
                );
            };
            let on_disk = match std::fs::read_to_string(path) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "/api/config/backup.yaml: failed to read source-of-truth file",
                    );
                    return json_response(
                        500,
                        &serde_json::json!({
                            "ok": false,
                            "reason": "read_failed",
                            "message": format!("could not read config file: {e}"),
                        }),
                    );
                }
            };

            // Build a RuntimeOverlay from the live ArcSwap stores so
            // the downloaded YAML reflects dashboard mutations on
            // top of whatever's on disk. Operators who hot-flip
            // AI off / disable a detector class / tighten DDoS get
            // a backup that matches what's actually running.
            use aegis_control::api::config::{
                apply_runtime_overlay, DdosOverlay, RuntimeOverlay,
            };
            use aegis_security::detectors::mask::{
                tier_str, DetectorClass, ALL_TIERS,
            };
            let mask_state = services.detector_mask.load_state();
            let mut detector_base = std::collections::BTreeMap::new();
            for class in DetectorClass::ALL {
                detector_base.insert(
                    class.as_str().to_string(),
                    mask_state.base.is_enabled(class),
                );
            }
            let mut detector_per_tier = std::collections::BTreeMap::new();
            for tier in ALL_TIERS {
                if let Some(m) = mask_state.override_for(tier) {
                    let mut tier_map = std::collections::BTreeMap::new();
                    for class in DetectorClass::ALL {
                        tier_map.insert(
                            class.as_str().to_string(),
                            m.is_enabled(class),
                        );
                    }
                    detector_per_tier.insert(tier_str(tier).to_string(), tier_map);
                }
            }
            let ai_enabled =
                Some(mask_state.base.is_enabled(DetectorClass::Ai));
            let ddos = services.ddos.as_ref().map(|rt| {
                let snap = rt.config_snapshot();
                DdosOverlay {
                    enabled: snap.enabled,
                    observe_only: snap.observe_only,
                    per_ip_limit: snap.per_ip_limit,
                    per_ip_window_s: snap.per_ip_window_s,
                    block_ttl_s: snap.block_ttl_s,
                    spike_multiplier: snap.spike_multiplier,
                    tightened_per_ip_rps: snap.tightened_per_ip_rps,
                    spike_engage_ticks: snap.spike_engage_ticks,
                    spike_release_ticks: snap.spike_release_ticks,
                }
            });
            let overlay = RuntimeOverlay {
                ai_enabled,
                detector_base: Some(detector_base),
                detector_per_tier: if detector_per_tier.is_empty() {
                    None
                } else {
                    Some(detector_per_tier)
                },
                ddos,
            };
            match apply_runtime_overlay(&on_disk, &overlay) {
                Ok(merged) => Response::builder()
                    .status(200)
                    .header("content-type", "application/yaml; charset=utf-8")
                    .header(
                        "content-disposition",
                        format!(
                            "attachment; filename=\"{}\"",
                            path.file_name()
                                .and_then(|s| s.to_str())
                                .unwrap_or("waf.yaml"),
                        ),
                    )
                    .header("cache-control", "private, no-store")
                    .body(Full::new(Bytes::from(merged)))
                    .unwrap(),
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "/api/config/backup.yaml: overlay failed; falling back to on-disk file",
                    );
                    // Fail-soft: serve the unmodified on-disk file
                    // so the operator still gets something usable.
                    Response::builder()
                        .status(200)
                        .header("content-type", "application/yaml; charset=utf-8")
                        .header(
                            "content-disposition",
                            format!(
                                "attachment; filename=\"{}\"",
                                path.file_name()
                                    .and_then(|s| s.to_str())
                                    .unwrap_or("waf.yaml"),
                            ),
                        )
                        .header("x-aegis-backup-warning", "overlay_failed_serving_on_disk")
                        .header("cache-control", "private, no-store")
                        .body(Full::new(Bytes::from(on_disk)))
                        .unwrap()
                }
            }
        }

        // DD-T7 — mutation-progress signal for the hot-reload UI.
        // Returns this node's audit-chain length, which increments on
        // every successful audit-mutation (rule CRUD, detector toggle,
        // loadmode pin, etc.) routed through `services.mutate.apply()`,
        // so the dashboard can poll after a mutation and surface
        // "Applied in X.Xs".
        //
        // F2 (2026-06-11 cluster QC): the field is now `audit_chain_len`,
        // NOT `version` — it was confusingly named the same as
        // `/api/config`'s cluster config-doc version (a DIFFERENT
        // counter: the shared-doc version vs. this node's local
        // audit-chain length). They diverge by design (e.g. doc v43 vs.
        // chain_len 0 on a node that applied via propagation), which the
        // QC flagged. Renamed to say what it is.
        "/api/config/version" => {
            // Synchronous no-backend fallback. The async dispatch path
            // (`handle_config_version_get`) shadows this when a state
            // backend is wired and adds `applied_version`; here it is
            // omitted (no backend reachable from this sync context).
            let node = services
                .roster_view
                .as_ref()
                .map(|lv| lv.our_node.clone())
                .unwrap_or_default();
            let body = crate::admin_dispatch::config_version_body(
                services.mutate.chain_len() as u64,
                None,
                &node,
                chrono::Utc::now().timestamp_millis(),
            );
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
            // Cluster Phase 3 (§2a): serve the merged fleet view when
            // the snapshot cache is populated, else this node's local.
            let body = match fleet_view_scoped(services, query) {
                Some(m) => services.stats.render_from_fleet(&m),
                None => services.stats.render(),
            };
            json_body_response(200, body, "private, max-age=1")
        }
        "/api/stats/timeseries" => {
            let window = parse_query_u32(query, "window", 900);
            let step = parse_query_u32(query, "step", 5);
            // Fleet-merged only within the bounded window the snapshot
            // carries; wider windows fall back to this node's series.
            let resp = match fleet_view_scoped(services, query) {
                Some(m)
                    if window
                        <= aegis_control::metrics::fleet_snapshot::FLEET_TIMESERIES_MAX_WINDOW_SECS =>
                {
                    aegis_control::api::stats::timeseries_from_fleet(
                        &m.timeseries_seconds,
                        window,
                        step,
                    )
                }
                _ => services.stats_agg.timeseries(window, step),
            };
            let body = serde_json::to_string(&resp).unwrap_or_else(|_| "{}".into());
            json_body_response(200, body, "private, max-age=1")
        }
        "/api/upstreams/summary" => {
            json_body_response(200, services.upstreams.render(), "private, max-age=2")
        }
        // SC-1 — per-upstream smart-cache stats. The provider closure is
        // injected at boot by aegis-proxy (capturing the data-plane
        // ResponseCache); absent ⇒ no cache wired, report an empty set.
        "/api/cache/stats" => {
            let body = services
                .cache_stats
                .as_ref()
                .map(|f| f())
                .unwrap_or_else(|| "{\"pools\":[]}".to_string());
            json_body_response(200, body, "private, max-age=2")
        }
        "/api/attacks/distribution" => {
            let window = parse_query_u32(query, "window", 900);
            let body = match fleet_view_scoped(services, query) {
                Some(m) => services.attacks.render_distribution_from_fleet(&m, window),
                None => services.attacks.render(window),
            };
            json_body_response(200, body, "private, max-age=10")
        }
        "/api/attacks/top" => {
            let window = parse_query_u32(query, "window", 900);
            let limit = parse_query_u32(query, "limit", 5);
            let body = match fleet_view_scoped(services, query) {
                Some(m) => services.attacks.render_top_from_fleet(&m, window, limit),
                None => services.attacks.render_top(window, limit),
            };
            json_body_response(200, body, "private, max-age=10")
        }
        "/api/audit/since" => {
            // PR-UX-A2 (2026-05-12) — parse the optional pivot
            // filter so Investigation can ask the server for
            // just the rows it needs instead of grabbing 200 and
            // client-filtering.
            let cursor = parse_query_u64(query, "cursor", 0);
            let limit = parse_query_u32(query, "limit", 200);
            // F-CRITICAL-004 (2026-05-17 control audit): parse the
            // new `ts_from` / `ts_to` RFC 3339 timestamps so the
            // dashboard's Round-1 mandated "audit search by time"
            // dimension works. Malformed timestamps silently
            // fall back to `None` (no filter applied) rather than
            // 400 — operators see no events instead of an opaque
            // error, which matches existing behaviour for the
            // other filter fields.
            let parse_ts = |q: &str, key: &str| -> Option<chrono::DateTime<chrono::Utc>> {
                parse_query_str(q, key)
                    .map(percent_decode)
                    .and_then(|s| {
                        chrono::DateTime::parse_from_rfc3339(&s)
                            .ok()
                            .map(|t| t.with_timezone(&chrono::Utc))
                    })
            };
            let filter = aegis_control::api::audit::AuditFilter {
                ip: parse_query_str(query, "ip").map(percent_decode),
                request_id: parse_query_str(query, "request_id").map(percent_decode),
                rule_id: parse_query_str(query, "rule_id").map(percent_decode),
                // PR-B P1 (2026-07-02) — composite risk-bucket pivot
                // (Investigation page): matches fields.risk_key.key_hash.
                risk_key: parse_query_str(query, "risk_key").map(percent_decode),
                ts_from: parse_ts(query, "ts_from"),
                ts_to: parse_ts(query, "ts_to"),
            };
            // 2026-05-23 — `?tail=1` returns the NEWEST `limit` events
            // (back of the ring) for the dashboard's "newest-first"
            // backfill. Without it, `cursor=0` returns the OLDEST
            // retained events, which made the live views appear frozen
            // on stale traffic after a flood.
            let tail = parse_query_str(query, "tail")
                .map(|v| v == "1" || v == "true")
                .unwrap_or(false);
            // F6 (2026-06-11) — `?scope=fleet` serves the merged fleet
            // audit tail (this node's ring + every live peer's) so a
            // reload backfill keeps the cross-node rows the SSE live
            // feed already shows. Reads the pre-merged cache
            // synchronously; falls back to the local ring when the
            // cache isn't populated (single-node / before the first
            // merge), so the contract degrades cleanly.
            let want_fleet = parse_query_str(query, "scope")
                .map(|v| v == "fleet")
                .unwrap_or(false);
            let fleet_tail = if want_fleet {
                services.fleet_audit_cache.as_ref().and_then(|c| c.load())
            } else {
                None
            };
            // PB / F6 — make the silent degrade visible: a `scope=fleet`
            // request that finds no merged cache falls back to LOCAL rows
            // (exactly the disjoint-set symptom the cluster QC saw). Log it
            // so a future sweep can't mistake the fallback for a working
            // merge. Populated cache → no log (the common path).
            if want_fleet && fleet_tail.is_none() {
                tracing::warn!(
                    "/api/audit/since?scope=fleet has no merged cache — serving \
                     LOCAL rows only (fleet_view disabled, pre-first-merge, or \
                     the merge is failing); cross-node backfill will look disjoint"
                );
            }
            // F14 (2026-06-11) — time the render so the ~260 ms latency
            // floor the cluster QC saw is attributed in production logs.
            // The in-process render is sub-millisecond (in-memory ring +
            // cache), so a slow sample points OUTSIDE this code (TLS
            // handshake / connection churn / lock contention) — exactly
            // what the QC's remote-Chrome measurement couldn't isolate.
            let render_started = std::time::Instant::now();
            let body = if let Some(events) = fleet_tail {
                aegis_control::metrics::fleet_audit::render_fleet_since(&events, limit, &filter)
            } else if tail {
                services.audit.render_latest_filtered(limit, &filter)
            } else {
                services.audit.render_since_filtered(cursor, limit, &filter)
            };
            let render_ms = render_started.elapsed().as_millis();
            if render_ms > AUDIT_RENDER_SLOW_MS {
                tracing::warn!(
                    render_ms,
                    limit,
                    scope = if want_fleet { "fleet" } else { "local" },
                    tail,
                    filtered = !filter.is_empty(),
                    "/api/audit/since render exceeded the slow threshold — \
                     in-process render is normally sub-ms; investigate lock \
                     contention or move profiling to the transport layer",
                );
            }
            json_body_response(200, body, "private, no-store")
        }
        // Phase-3 reports: CSV export of the in-process audit ring.
        // Same data as `/api/audit/since` (capped at 200 events) but
        // emitted as CSV for direct spreadsheet import. Phase 4
        // adds time-range parameters + a streaming-from-disk path
        // for longer histories.
        "/api/reports/audit.csv" => {
            let limit = parse_query_u32(query, "limit", 200);
            let json_str = services.audit.render_since(0, limit);
            let parsed: serde_json::Value =
                serde_json::from_str(&json_str).unwrap_or(serde_json::Value::Null);
            let mut csv = String::from("seq,ts,class,action,client_ip,method,path,rule_id,reason,request_id\n");
            if let Some(events) = parsed.get("events").and_then(|v| v.as_array()) {
                for entry in events {
                    let seq = entry.get("seq").and_then(|v| v.as_u64()).unwrap_or(0);
                    let e = entry.get("event").unwrap_or(entry);
                    let getter = |k: &str| e.get(k).and_then(|v| v.as_str()).unwrap_or("");
                    // LOW-ADM-04 (2026-05-12) — detection rows carry
                    // method/path under `event.fields.*`, not at the
                    // top level (top-level is null for those rows).
                    // Same fallback pattern the Investigation timeline
                    // and Audit Trail RULE column adopted in
                    // MED-SO-06 / LOW-OBS-04.
                    let fields_get = |k: &str| {
                        e.get("fields")
                            .and_then(|f| f.get(k))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                    };
                    let with_fields = |k: &str| {
                        let top = getter(k);
                        if top.is_empty() { fields_get(k) } else { top }
                    };
                    csv.push_str(&format!(
                        "{},{},{},{},{},{},{},{},{},{}\n",
                        seq,
                        csv_escape(getter("ts")),
                        csv_escape(getter("class")),
                        csv_escape(getter("action")),
                        csv_escape(getter("client_ip")),
                        csv_escape(with_fields("method")),
                        csv_escape(with_fields("path")),
                        csv_escape(getter("rule_id")),
                        csv_escape(getter("reason")),
                        csv_escape(getter("request_id")),
                    ));
                }
            }
            Response::builder()
                .status(200)
                .header("content-type", "text/csv; charset=utf-8")
                .header("content-disposition", "attachment; filename=\"audit.csv\"")
                .header("cache-control", "no-store")
                .body(Full::new(Bytes::from(csv)))
                .unwrap()
        }
        "/api/attacks/by-detector" => {
            let window = parse_query_u32(query, "window", 900);
            let body = match fleet_view_scoped(services, query) {
                Some(m) => services.attacks.render_by_detector_from_fleet(&m, window),
                None => services.attacks.render_by_detector(window),
            };
            json_body_response(
                200,
                body,
                "private, max-age=10",
            )
        }
        // Phase-3: enriched alert view with operator overlay
        // (ack/snooze/resolve from `services.incidents`).
        // MED-SO-04 (2026-05-12) — previously the overlay was
        // composed against `Vec::new()`, so `incidents` was
        // permanently `[]` and the lifecycle UI never reflected
        // ack/snooze/resolve. Pull the live `SloAlert`s from the
        // tracking handler's engine accessor so the overlay
        // joins against today's firing list.
        "/api/incidents" => {
            let raw_json = services.tracking.render_alerts();
            // IF-P1b — fleet roll-up of firing incidents (deduped by uid,
            // with firing_on breadth) when fleet view is active; honors the
            // ?node= scope. Overlay is still read locally (convergence =
            // IF-P1c). Falls back to this node's active alerts otherwise.
            let overlay = match fleet_view_scoped(services, query) {
                Some(m) => services.incidents.enrich_fleet(m.firing_incidents),
                None => services.incidents.enrich(services.tracking.active_alerts()),
            };
            let body = serde_json::json!({
                "raw_alerts": serde_json::from_str::<serde_json::Value>(&raw_json)
                    .unwrap_or(serde_json::Value::Null),
                "incidents": overlay,
            });
            json_body_response(200, body.to_string(), "private, max-age=2")
        }
        // Phase-3: configured threat-intel feeds + their status.
        // Read from `cfg.threat_intel.feeds` if present; else
        // returns an empty list with a clear "no feeds configured"
        // body shape so the dashboard renders an actionable
        // empty state.
        "/api/threat-intel/feeds" => {
            let body = serde_json::json!({
                "feeds": [],
                "configured_in_yaml": false,
                "note": "Feed-management UI ships in Phase 4. Today: configure under `threat_intel:` in your YAML and restart.",
            });
            json_body_response(200, body.to_string(), "private, max-age=30")
        }
        // Phase-3: GeoIP database status. The geoip feature is
        // gated at compile time; this endpoint lights up the
        // "DB loaded?" pill on the Threat Intel + Overview pages.
        // Reads `feature_built` from cfg + `db_loaded` from the
        // live AttacksHandler (which got the lookup wired at
        // boot via `set_geo_lookup`).
        "/api/geoip/status" => {
            let db_loaded = services.attacks.geoip_loaded();
            let country_path = cfg
                .geoip
                .country_db
                .as_ref()
                .map(|p| p.display().to_string());
            let asn_path = cfg
                .geoip
                .asn_db
                .as_ref()
                .map(|p| p.display().to_string());
            let body = serde_json::json!({
                "feature_built": cfg!(feature = "geoip"),
                "db_loaded": db_loaded,
                "db_path": country_path,
                "asn_db_path": asn_path,
                "indicator_count": 0,
                "note": if db_loaded {
                    "GeoIP reader live. /api/attacks/top rows carry country + asn."
                } else if cfg!(feature = "geoip") {
                    "GeoIP feature built but no reader wired — set `geoip.country_db` (and optionally `asn_db`) in config and restart."
                } else {
                    "Build with FEATURES=\"redis geoip\" and set geoip.country_db in config."
                },
            });
            json_body_response(200, body.to_string(), "private, max-age=60")
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
            let body = match fleet_view_scoped(services, query) {
                Some(m) => services.attacks.render_bot_mix_from_fleet(&m, window),
                None => services.attacks.render_bot_mix(window),
            };
            json_body_response(200, body, "private, max-age=10")
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
        // Per-route error rate, computed on demand from the
        // in-process audit ring. Cardinality is bounded by
        // `route_id` distinct values; pages without an explicit
        // route fall back to the first path segment so requests
        // still attribute somewhere. ?limit=N caps the row count
        // (default 20).
        "/api/analytics/routes" => {
            let limit = parse_query_u32(query, "limit", 20);
            let rows = services.audit_ring.route_stats(limit);
            json_body_response(
                200,
                serde_json::json!({"routes": rows}).to_string(),
                "private, max-age=10",
            )
        }
        // Per-detector p50/p95/p99 from the dedicated
        // `DetectorLatencyHistogram`. Populated by the data plane
        // around each `Detector::inspect` call. Returns
        // `{detectors: [{class, p50_ms, p95_ms, p99_ms, samples}]}`
        // sorted by samples descending.
        "/api/analytics/latency/detectors" => {
            let body = match services.detector_latency_hist.as_ref() {
                None => serde_json::json!({"detectors": []}).to_string(),
                Some(h) => {
                    let mut rows: Vec<serde_json::Value> = h
                        .known_classes()
                        .into_iter()
                        .filter_map(|c| {
                            let p = h.percentiles_ms(&c)?;
                            Some(serde_json::json!({
                                "class": c,
                                "p50_ms": p.p50_ms,
                                "p95_ms": p.p95_ms,
                                "p99_ms": p.p99_ms,
                                "samples": p.samples,
                            }))
                        })
                        .collect();
                    rows.sort_by(|a, b| {
                        b.get("samples").and_then(|v| v.as_u64()).unwrap_or(0)
                            .cmp(&a.get("samples").and_then(|v| v.as_u64()).unwrap_or(0))
                    });
                    serde_json::json!({"detectors": rows}).to_string()
                }
            };
            json_body_response(200, body, "private, max-age=2")
        }
        // Phase-3: per-route p50/p95/p99 from the dedicated
        // `RouteLatencyHistogram`. Returns
        // `{routes: [{route, p50_ms, p95_ms, p99_ms, samples}]}`
        // sorted by samples descending. Capped at ?limit=N
        // (default 20). Routes with no samples are omitted.
        // P5 (2026-05-11) — sliding-window per-route activity. The
        // dashboard reads this every ~10s and renders a pulse pill
        // in the route table so dead routes are visible without
        // synthetic traffic. Returns
        // `{routes: [{route, last_60s_count, last_seen_age_s}]}`
        // sorted by `last_60s_count` descending. Routes with zero
        // recorded requests since boot are omitted.
        "/api/analytics/route-activity" => {
            let body = match services.route_activity.as_ref() {
                None => serde_json::json!({"routes": []}).to_string(),
                Some(w) => {
                    let rows: Vec<serde_json::Value> = match services
                        .route_activity_cache
                        .as_ref()
                    {
                        // Cluster-wide aggregate (Phase C): the count is
                        // summed across nodes; `last_seen_age_s` stays
                        // node-local ("when THIS node last saw the route").
                        Some(cache) => {
                            let now = now_unix_secs();
                            let mut rows: Vec<(String, u64, Option<u64>)> = cache
                                .window_totals(60, now)
                                .into_iter()
                                .map(|(route, count)| {
                                    let age =
                                        w.snapshot(&route).and_then(|a| a.last_seen_age_s);
                                    (route, count, age)
                                })
                                .collect();
                            rows.sort_by(|a, b| b.1.cmp(&a.1));
                            rows.into_iter()
                                .map(|(route, count, age)| {
                                    serde_json::json!({
                                        "route": route,
                                        "last_60s_count": count,
                                        "last_seen_age_s": age,
                                    })
                                })
                                .collect()
                        }
                        None => w
                            .snapshot_all()
                            .into_iter()
                            .map(|(route, a)| {
                                serde_json::json!({
                                    "route": route,
                                    "last_60s_count": a.count_60s,
                                    "last_seen_age_s": a.last_seen_age_s,
                                })
                            })
                            .collect(),
                    };
                    serde_json::json!({ "routes": rows }).to_string()
                }
            };
            json_body_response(200, body, "private, max-age=2")
        }
        "/api/analytics/latency/routes" => {
            let limit = parse_query_u32(query, "limit", 20);
            let body = match services.route_latency_hist.as_ref() {
                None => serde_json::json!({"routes": []}).to_string(),
                Some(h) => {
                    let mut rows: Vec<serde_json::Value> = h
                        .known_routes()
                        .into_iter()
                        .filter_map(|r| {
                            let p = h.percentiles_ms(&r)?;
                            Some(serde_json::json!({
                                "route": r,
                                "p50_ms": p.p50_ms,
                                "p95_ms": p.p95_ms,
                                "p99_ms": p.p99_ms,
                                "samples": p.samples,
                            }))
                        })
                        .collect();
                    rows.sort_by(|a, b| {
                        b.get("samples").and_then(|v| v.as_u64()).unwrap_or(0)
                            .cmp(&a.get("samples").and_then(|v| v.as_u64()).unwrap_or(0))
                    });
                    rows.truncate(limit as usize);
                    serde_json::json!({"routes": rows}).to_string()
                }
            };
            json_body_response(200, body, "private, max-age=2")
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
                    let stages = [
                        stage::TOTAL,
                        stage::QUEUE_WAIT,
                        stage::WAF_OVERHEAD,
                        stage::DETECT,
                        stage::RATE_LIMIT,
                        stage::RESPOND,
                    ];
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
            // Read-only view of the routing trie. Render **live** from
            // the route writer's current routes when wired: the watcher
            // rebuilds that trie from the activated config doc on every
            // node, so reading it here keeps `GET /api/routes` fleet-
            // consistent. The boot-seeded `services.routes` cache is the
            // fallback for bundles without a wired writer (tests).
            // BUG-fix 2026-06-14 — before this, the summary cache was only
            // refreshed on the mutating node, so peers showed stale routes
            // after a console mutation converged in the data plane.
            // See BUG-console-route-mutation-not-fleet-convergent.md.
            // Cached 30 s — config is hot-reloadable but doesn't change on
            // every request.
            let body = match services.route_writer.as_ref() {
                Some(writer) => {
                    let live = writer.current_routes();
                    if live.is_empty() {
                        services.routes.render()
                    } else {
                        let summaries = crate::route::route_summaries(&live);
                        serde_json::json!({ "routes": summaries }).to_string()
                    }
                }
                None => services.routes.render(),
            };
            json_body_response(200, body, "private, max-age=30")
        }
        "/api/blacklist" => {
            let body = serde_json::json!({"entries": services.blacklist.list()});
            json_body_response(200, body.to_string(), "private, max-age=2")
        }
        "/api/whitelist" => {
            let body = serde_json::json!({"entries": services.whitelist.list()});
            json_body_response(200, body.to_string(), "private, max-age=2")
        }
        // P4 (2026-05-11) — per-entry hit counts. Window defaults
        // to 3600 (1h); the dashboard's "consider removing"
        // affordance for stale entries reads `?window=86400`. The
        // ring is 1-hour-bucketed so any window smaller than 3600
        // rounds up to one bucket.
        "/api/blacklist/hits" => {
            let window = parse_query_u64(query, "window", 3600);
            // Cluster-wide aggregate when wired (Phase C); else node-local.
            let hits = match services.blacklist_hits_cache.as_ref() {
                Some(cache) => cache.window_totals(window, now_unix_secs()),
                None => services.blacklist.hit_counts(window),
            };
            let body = serde_json::json!({ "window_secs": window, "hits": hits });
            json_body_response(200, body.to_string(), "private, max-age=5")
        }
        "/api/whitelist/hits" => {
            let window = parse_query_u64(query, "window", 3600);
            let hits = match services.whitelist_hits_cache.as_ref() {
                Some(cache) => cache.window_totals(window, now_unix_secs()),
                None => services.whitelist.hit_counts(window),
            };
            let body = serde_json::json!({ "window_secs": window, "hits": hits });
            json_body_response(200, body.to_string(), "private, max-age=5")
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
            let body = match fleet_view_scoped(services, query) {
                Some(m) => aegis_control::api::risk::render_list_from_fleet(&m, limit),
                None => aegis_control::api::risk::render_list(&services.risk, limit),
            };
            json_body_response(200, body, "private, max-age=2")
        }

        // CI-T12 — current risk thresholds. Mirrors the PUT body
        // shape so a roundtrip {GET → modify → PUT} works.
        "/api/risk/thresholds" => {
            let t = services.risk.thresholds();
            let body = serde_json::json!({
                "enabled":      t.enabled,
                "challenge_at": t.challenge_at,
                "block_at":     t.block_at,
                "max":          t.max,
                // Live linear decay rate (points/hour), applied on read +
                // as trust-recovery. Lets the dashboard show the real decay
                // model instead of a misleading exponential "half-life".
                "trust_per_hour": services.risk.trust_per_hour(),
            })
            .to_string();
            json_body_response(200, body, "private, max-age=2")
        }

        // 2026-05-20 — current canary honeypot path set. Mirrors the
        // PUT body shape so a roundtrip {GET → edit → PUT} works.
        // `wired` reflects whether the proxy boot path installed the
        // live handle (false for test bundles → editor renders the
        // empty default).
        "/api/risk/canary-paths" => {
            let paths = services.canary_paths.raw();
            let count = paths.len();
            let body = serde_json::json!({
                "paths": paths,
                "count": count,
                "enabled": services.detector_mask.load().is_enabled_id("canary"),
            })
            .to_string();
            json_body_response(200, body, "private, max-age=2")
        }

        // P2: detector class mask — read returns the live mask
        // plus compliance lock-list. PUT is handled in
        // `handle_admin_request` (async — needs to read body).
        "/api/detectors" => {
            // F7 (2026-06-11): the cluster path intercepts this GET on
            // the ASYNC dispatch (`admin_dispatch::handle_detectors_get`)
            // to stamp `config_version` from the store. This sync arm is
            // the fallback for non-cluster / test builds (no async store
            // read available here) and renders without a version — the
            // client then uses the legacy unconditional PUT.
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

        // 2026-05-09 — DDoS request-flow gate read surface for the
        // Traffic Gates page. Returns config + EWMA telemetry
        // (current_rps, baseline_rps, spike_active). Returns the
        // empty-state shape (`enabled: false`) when the runtime
        // isn't installed, so the page renders an explicit
        // "DDoS gate disabled" card instead of erroring.
        "/api/gates/ddos" => {
            // 2026-05-22 — resolve the live interop mode for the `ddos`
            // feature so the gate view reflects a `set_profile log_only`,
            // not just the config-level `observe_only` flag. Same resolver
            // the data plane uses to decide enforce vs forward.
            let ddos_mode = services
                .interop
                .as_ref()
                .map(|rt| {
                    aegis_control::interop::rule_map::mode_for_rule(&rt.modes, Some("ddos"))
                        .as_str()
                })
                .unwrap_or("enforce");
            let body = aegis_control::api::gates::render_get(
                services.ddos.as_ref(),
                ddos_mode,
            );
            json_body_response(200, body, "private, max-age=2")
        }

        // 2026-05-09 — Rate-limit (F-T2 token bucket) read surface
        // for the Traffic Gates page. Distinct from DDoS — see
        // `docs/operator/traffic-gates.md` for the difference
        // (rate-limit is steady-state per-IP returning 429;
        // DDoS is sustained-burst → TTL'd auto-block returning 403).
        "/api/rate-limit" => {
            let body = aegis_control::api::gates::render_get_rate_limit(
                &services.ip_rate_limiter,
            );
            json_body_response(200, body, "private, max-age=2")
        }

        // 2026-05-10 — Strike-Block read surface for the Traffic
        // Gates page. Returns the current `enabled` flag, the
        // `block_at` threshold, and live telemetry (tracked IPs,
        // count at-or-over threshold). Strike-Block defaults to
        // disabled in production; flip via PUT /api/gates/strikes.
        "/api/gates/strikes" => {
            let body = aegis_control::api::gates::render_get_strikes(
                &services.risk,
            );
            json_body_response(200, body, "private, max-age=2")
        }

        // 2026-05-21 — bot-classifier gate on/off. Mirrors the PUT
        // body shape so a {GET → flip → PUT} roundtrip works.
        "/api/gates/bots" => {
            let enabled = services
                .bots_enabled
                .load(std::sync::atomic::Ordering::Relaxed);
            let body = serde_json::json!({ "enabled": enabled }).to_string();
            json_body_response(200, body, "private, max-age=2")
        }

        // D-M5: tracking
        "/api/slo" => json_body_response(200, services.tracking.render_slo(), "private, max-age=2"),
        "/api/cluster" => json_body_response(200, services.tracking.render_cluster(), "private, max-age=2"),
        // Fleet-scope status for per-panel badges + the degraded banner.
        // `configured` = the publish task is up (cluster deployment);
        // `active` = a merged snapshot is currently available.
        "/api/fleet/status" => {
            let configured = services.fleet_cache.is_some();
            let merged = fleet_view(services);
            json_body_response(
                200,
                aegis_control::metrics::fleet_snapshot::render_fleet_status(
                    configured,
                    merged.as_ref(),
                ),
                "private, max-age=2",
            )
        }
        // Node ids in the current merge, for the dashboard node-selector.
        "/api/fleet/nodes" => {
            let merged = fleet_view(services);
            json_body_response(
                200,
                aegis_control::metrics::fleet_snapshot::render_fleet_nodes(merged.as_ref()),
                "private, max-age=2",
            )
        }
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
        // MTLS-T10 — capability flag read so the dashboard knows
        // whether to render the CA bundle upload card. Mirrors
        // `cfg.admin.dashboard_auth.allow_ca_upload`. Distinct
        // from the actual upload (PUT) so the GET is cheap +
        // doesn't require auth.
        "/api/zero-trust/downstream/ca-bundle/capability" => {
            let allowed = services.allow_ca_upload;
            let body = serde_json::json!({"allow_ca_upload": allowed});
            json_body_response(200, body.to_string(), "private, max-age=30")
        }
        // MTLS-T8 — runtime mode override read. Reports the
        // configured mode (from cfg.tls.client_auth.mode at boot),
        // the current override (or null), the effective mode, and
        // a `requires_restart` flag set when the override differs
        // from the configured value (the TLS acceptor rebuilds
        // only on cfg.tls swaps today; mode flips alone need a
        // process restart to land at the handshake layer).
        "/api/zero-trust/downstream/mode" => {
            let store = &services.mtls_mode_store;
            let body = aegis_control::api::zero_trust::mode::render_mode_response(
                store.configured(),
                store.current(),
            );
            json_body_response(200, body.to_string(), "private, max-age=2")
        }
        "/api/zero-trust/downstream" => json_body_response(
            200,
            aegis_control::api::zero_trust::downstream::MtlsConfigView::from_config(cfg).render(),
            "private, max-age=2",
        ),
        // Zero Trust (P3) — upstream (WAF-as-client) read views.
        // Identity returns PUBLIC cert metadata only — never the key.
        "/api/zero-trust/upstream/identity" => {
            // If the rotation task or the console PUT has recorded a live cert
            // PEM, build the view directly from it. This is the correct path
            // for state-sourced identities uploaded via the console:
            //
            //   * The old overlay approach set `id.cert_pem` on the boot cfg
            //     but `from_config` only reads `cert_pem` when `source == State`.
            //     When the boot cfg has `source: file` (or no zero_trust block
            //     at all — first-ever upload), the overlay was silently ignored
            //     and the download still returned the old cert/file.
            //
            //   * `from_pem` constructs the view directly, always reflecting
            //     whatever the console last wrote — regardless of boot config.
            let rot = crate::upstream::rotation::status();
            if let Some(pem) = rot.identity_cert_pem {
                return json_body_response(
                    200,
                    aegis_control::api::zero_trust::UpstreamIdentityView::from_pem(pem).render(),
                    "no-cache",
                );
            }
            // No live rotation yet (server just started, or identity was never
            // uploaded via the console). Fall back to the boot config — this
            // handles file-source identities and state-sourced ones that were
            // materialized at boot (rotation task picked them up within 5 s).
            json_body_response(
                200,
                aegis_control::api::zero_trust::UpstreamIdentityView::from_config(cfg).render(),
                "no-cache",
            )
        }
        // P5 — hot-rotation status (generation + applied timestamp) so
        // the console can show "applied live, no restart".
        "/api/zero-trust/upstream/rotation" => json_body_response(
            200,
            crate::upstream::rotation::render(),
            "private, max-age=2",
        ),
        "/api/zero-trust/upstream/config" => {
            // Overlay the live raw pool configs (registry shadow) onto
            // the boot cfg so runtime `upstream_mtls` edits made via the
            // Zero Trust drawer (PUT /api/upstreams/pool/{id}) are
            // reflected immediately — mirrors `/api/upstreams/config`.
            let mut effective_cfg = cfg.clone();
            if let Some(writer) = services.upstream_writer.as_ref() {
                for (name, pool_cfg) in writer.current_pools() {
                    effective_cfg.upstreams.insert(name, pool_cfg);
                }
            }
            json_body_response(
                200,
                aegis_control::api::zero_trust::UpstreamConfigView::from_config(&effective_cfg)
                    .render(),
                "private, max-age=2",
            )
        }
        // P4 — upstream (WAF-as-client) mTLS handshake-failure
        // histogram, grouped by pool + reason. Process-global tracker
        // recorded by the data plane on `ForwardError::Handshake`.
        "/api/zero-trust/upstream/failures" => json_body_response(
            200,
            crate::upstream::mtls_failures::render(),
            "private, max-age=2",
        ),
        "/api/zero-trust/downstream/connections" => json_body_response(
            200,
            aegis_control::api::zero_trust::downstream::render_connections(
                services.identity_tracker.as_ref(),
            ),
            "private, max-age=2",
        ),
        "/api/zero-trust/downstream/failures" => json_body_response(
            200,
            aegis_control::api::zero_trust::downstream::render_failures(
                services.identity_tracker.as_ref(),
            ),
            "private, max-age=2",
        ),
        "/api/zero-trust/downstream/ca-summary" => json_body_response(
            200,
            aegis_control::api::zero_trust::downstream::render_ca_summary(
                services.identity_tracker.as_ref(),
            ),
            "private, max-age=2",
        ),
        // MTLS-T7 — live allowed-SAN list. Empty array when
        // no allowlist is wired (test bundles or operators
        // who haven't opted in).
        "/api/zero-trust/downstream/sans" => {
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
            // FIX 2026-05-04 (round 2) — read the live raw pool
            // configs from the writer's shadow map so runtime-
            // added pools render with their full member detail.
            // Round 1 inserted EMPTY placeholders for live-only
            // pools, which made the dashboard show "0 members"
            // for any pool created via the inline-add flow.
            //
            // Also pull the live routes so `referenced_by_routes`
            // reflects runtime-added route → pool relationships
            // (was always empty for pools wired up via the inline
            // route + pool flow).
            let mut effective_cfg = cfg.clone();
            if let Some(writer) = services.upstream_writer.as_ref() {
                for (name, pool_cfg) in writer.current_pools() {
                    effective_cfg.upstreams.insert(name, pool_cfg);
                }
            }
            if let Some(writer) = services.route_writer.as_ref() {
                let live_routes = writer.current_routes();
                if !live_routes.is_empty() {
                    effective_cfg.routes = live_routes;
                }
            }
            let view = aegis_control::api::upstreams_config::UpstreamsConfigView::from_config(&effective_cfg);
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

/// PR-UX-A2 (2026-05-12) — minimal percent-decode for query
/// params we want to compare byte-for-byte against stored
/// values (audit ring filter). Handles `%XX` sequences; leaves
/// everything else untouched. Not a full URL spec decoder —
/// `+` is *not* mapped to space (that's a form-encoding rule,
/// not a query-string rule).
///
/// MED-ADM-01 (2026-05-12) — also used by the admin dispatcher
/// to decode path segments before handing them to mutation
/// handlers. Without this, ids like `<sli>-<Nh>:<ts>` arrive
/// at the overlay store with literal `%3A`, masking
/// `enrich()`'s `:`-encoded lookup. Apply exactly once at the
/// dispatch layer (`req.uri().path()` returns the encoded form).
pub(crate) fn percent_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let h = (bytes[i + 1] as char).to_digit(16);
            let l = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (h, l) {
                out.push(((h << 4) | l) as u8 as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
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

/// Quote a CSV field per RFC 4180 — wrap in double-quotes if the
/// value contains comma / quote / newline; double up embedded
/// quotes. Returns the field as-is when no quoting is needed.
fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        let escaped = s.replace('"', "\"\"");
        format!("\"{escaped}\"")
    } else {
        s.to_string()
    }
}

// ---------------------------------------------------------------------------
// AI Operator Copilot — GET /api/copilot/summary (P1)
// ---------------------------------------------------------------------------

/// Assemble the copilot's [`TelemetrySnapshot`] from the live services:
/// top risk buckets, per-detector hit counts (→ blocked total + top
/// detectors), and the currently-firing SLO alerts. Read-only.
pub(crate) fn build_copilot_snapshot(
    services: &aegis_control::dashboard_services::DashboardServices,
    window_minutes: u32,
) -> aegis_control::copilot::summary::TelemetrySnapshot {
    use aegis_control::copilot::summary::{AttackerRow, TelemetrySnapshot};
    let window_seconds = window_minutes.saturating_mul(60);
    let top_attackers = services
        .risk
        .top(8)
        .into_iter()
        .map(|r| AttackerRow {
            ip: r.ip,
            score: r.score,
            level: r.level.to_string(),
        })
        .collect();
    let by_det = services.attacks_agg.by_detector(window_seconds);
    let blocked: u64 = by_det.detectors.iter().map(|d| d.count).sum();
    let top_detectors = by_det
        .detectors
        .into_iter()
        .take(8)
        .map(|d| (d.name, d.count))
        .collect();
    TelemetrySnapshot {
        window_minutes,
        // No windowed request-volume counter available — leave None so
        // the model doesn't read a placeholder 0 as a total outage.
        total_requests: None,
        blocked,
        top_attackers,
        top_detectors,
        active_slo_alerts: services.tracking.active_slo_alert_labels(),
        // Per-event clusters from the audit ring (detector → connected
        // IPs + paths) — the cross-correlation the aggregate rows lose.
        clusters: aegis_control::copilot::cluster::cluster_events(
            &services.audit_ring.recent(500),
        ),
    }
}

/// `GET /api/copilot/summary?minutes=15` — an LLM situational brief over
/// the WAF's own telemetry. Async (the LLM call) so it's dispatched on
/// the async admin path, not the sync [`admin_router`]. Admin-auth gated
/// upstream. Returns 503 when the copilot is disabled (no provider
/// configured / built without `--features llm`) and 502 on a provider
/// error — the WAF itself never fails because the copilot does.
pub(crate) async fn handle_copilot_summary(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let copilot = aegis_control::copilot::service::global();
    if !copilot.enabled() {
        let body = serde_json::json!({
            "error": "copilot disabled",
            "hint": "set LLM_ENABLED=true + LLM_BASE_URL/LLM_API_KEY/LLM_MODEL and build with --features llm",
        })
        .to_string();
        return json_body_response(503, body, "no-store");
    }
    let query = req.uri().query().unwrap_or("").to_string();
    let window_minutes = parse_query_u32(&query, "minutes", 15).clamp(1, 1440);
    let snapshot = build_copilot_snapshot(services, window_minutes);
    match copilot.summary(snapshot).await {
        Ok(brief) => {
            let body = serde_json::to_string(&brief).unwrap_or_else(|_| "{}".into());
            json_body_response(200, body, "no-store")
        }
        Err(e) => {
            let body = serde_json::json!({ "error": e.to_string() }).to_string();
            json_body_response(502, body, "no-store")
        }
    }
}

/// `GET /api/copilot/ask?q=<question>&minutes=15` — answer a free-form
/// operator question grounded in the current telemetry snapshot. GET (no
/// CSRF, mirrors the summary endpoint); the question is operator input so
/// it's redacted before egress like everything else. 400 on empty `q`.
/// The dashboard's Ask box uses this GET form.
pub(crate) async fn handle_copilot_ask(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let query = req.uri().query().unwrap_or("").to_string();
    let question = parse_query_str(&query, "q")
        .map(percent_decode)
        .unwrap_or_default();
    let window_minutes = parse_query_u32(&query, "minutes", 60);
    copilot_ask_respond(services, &question, window_minutes).await
}

/// `POST /api/copilot/ask` with JSON body `{ "question": "...",
/// "minutes": 15 }` — same answer as the GET form, for API/contract
/// callers (the test plan + any programmatic client POST a body rather
/// than a query string). `q` is accepted as an alias for `question`.
/// MED-3 (2026-06-14): the surface previously only wired GET, so a
/// `POST /api/copilot/ask` fell through to the router and 404'd.
pub(crate) async fn handle_copilot_ask_post(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    #[derive(serde::Deserialize, Default)]
    struct AskBody {
        #[serde(default)]
        question: Option<String>,
        /// Alias accepted for symmetry with the GET `?q=` form.
        #[serde(default)]
        q: Option<String>,
        #[serde(default)]
        minutes: Option<u32>,
    }

    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            let body = serde_json::json!({ "error": "body read failed" }).to_string();
            return json_body_response(400, body, "no-store");
        }
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");
    // Tolerate an empty body — fall through to the empty-question 400 in
    // the shared core so the caller gets a clear "missing question".
    let parsed: AskBody = if body_str.trim().is_empty() {
        AskBody::default()
    } else {
        match serde_json::from_str(body_str) {
            Ok(b) => b,
            Err(e) => {
                let body =
                    serde_json::json!({ "error": format!("invalid JSON body: {e}") }).to_string();
                return json_body_response(400, body, "no-store");
            }
        }
    };
    let question = parsed.question.or(parsed.q).unwrap_or_default();
    let window_minutes = parsed.minutes.unwrap_or(60);
    copilot_ask_respond(services, &question, window_minutes).await
}

/// Shared core for the GET and POST `ask` handlers: enforce the
/// enabled/empty/length guards, build the snapshot, and call the LLM.
/// `503` when copilot is disabled, `400` on an empty question, `200`
/// with the brief, `502` on a provider error.
async fn copilot_ask_respond(
    services: &aegis_control::dashboard_services::DashboardServices,
    question: &str,
    window_minutes: u32,
) -> Response<Full<Bytes>> {
    let copilot = aegis_control::copilot::service::global();
    if !copilot.enabled() {
        let body = serde_json::json!({
            "error": "copilot disabled",
            "hint": "set LLM_ENABLED=true + LLM_BASE_URL/LLM_API_KEY/LLM_MODEL and build with --features llm",
        })
        .to_string();
        return json_body_response(503, body, "no-store");
    }
    let question = question.trim();
    if question.is_empty() {
        let body = serde_json::json!({
            "error": "missing question; pass ?q=<question> (GET) or {\"question\":\"…\"} (POST)"
        })
        .to_string();
        return json_body_response(400, body, "no-store");
    }
    // Bound the question so a pasted wall of text can't blow up the prompt
    // / token cost.
    let question: String = question.chars().take(500).collect();
    let window_minutes = window_minutes.clamp(1, 1440);
    let snapshot = build_copilot_snapshot(services, window_minutes);
    match copilot.ask(snapshot, &question).await {
        Ok(brief) => {
            let body = serde_json::to_string(&brief).unwrap_or_else(|_| "{}".into());
            json_body_response(200, body, "no-store")
        }
        Err(e) => {
            let body = serde_json::json!({ "error": e.to_string() }).to_string();
            json_body_response(502, body, "no-store")
        }
    }
}

/// `POST /api/copilot/rule` with JSON `{ "intent": "...", "id": "..." }` —
/// generate a rule DSL body from a natural-language intent for the New-rule
/// editor. **Advisory** — the body is returned + server-validated, never
/// auto-applied (the operator reviews + saves through the normal POST
/// /api/rules path). 503 when copilot disabled, 400 on empty intent, 502 on a
/// provider error.
pub(crate) async fn handle_copilot_generate_rule(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;
    let _ = services; // generation needs no telemetry snapshot

    #[derive(serde::Deserialize, Default)]
    struct GenBody {
        #[serde(default)]
        intent: Option<String>,
        #[serde(default)]
        id: Option<String>,
    }

    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            let body = serde_json::json!({ "error": "body read failed" }).to_string();
            return json_body_response(400, body, "no-store");
        }
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");
    let parsed: GenBody = if body_str.trim().is_empty() {
        GenBody::default()
    } else {
        match serde_json::from_str(body_str) {
            Ok(b) => b,
            Err(e) => {
                let body =
                    serde_json::json!({ "error": format!("invalid JSON body: {e}") }).to_string();
                return json_body_response(400, body, "no-store");
            }
        }
    };
    let intent = parsed.intent.unwrap_or_default();
    let intent = intent.trim();
    if intent.is_empty() {
        let body =
            serde_json::json!({ "error": "missing intent; pass {\"intent\":\"…\"}" }).to_string();
        return json_body_response(400, body, "no-store");
    }
    // Bound the intent so a pasted wall of text can't blow up the prompt/cost.
    let intent: String = intent.chars().take(500).collect();
    let id = parsed.id.unwrap_or_default();
    let id: String = id.trim().chars().take(64).collect();

    let copilot = aegis_control::copilot::service::global();
    if !copilot.enabled() {
        let body = serde_json::json!({
            "error": "copilot disabled",
            "hint": "set LLM_ENABLED=true + LLM_BASE_URL/LLM_API_KEY/LLM_MODEL and build with --features llm",
        })
        .to_string();
        return json_body_response(503, body, "no-store");
    }
    match copilot.generate_rule(&intent, &id).await {
        Ok(rule_body) => {
            // Server-validate the generated DSL so the UI can flag a bad
            // generation before the operator tries to save it.
            let validation = aegis_control::api::rules::validate_rule_body(&rule_body);
            let body = serde_json::json!({
                "ok": true,
                "body": rule_body,
                "validation": validation,
            })
            .to_string();
            json_body_response(200, body, "no-store")
        }
        Err(e) => {
            let body = serde_json::json!({ "error": e.to_string() }).to_string();
            json_body_response(502, body, "no-store")
        }
    }
}

/// `GET /api/copilot/suggestions?minutes=60` — smart-catch triage:
/// cluster the snapshot into campaigns + candidate rules. **Advisory** —
/// the response is a review queue; nothing is applied. 503 disabled /
/// 502 provider-error.
pub(crate) async fn handle_copilot_suggestions(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let copilot = aegis_control::copilot::service::global();
    if !copilot.enabled() {
        let body = serde_json::json!({
            "error": "copilot disabled",
            "hint": "set LLM_ENABLED=true + LLM_BASE_URL/LLM_API_KEY/LLM_MODEL and build with --features llm",
        })
        .to_string();
        return json_body_response(503, body, "no-store");
    }
    let query = req.uri().query().unwrap_or("").to_string();
    let window_minutes = parse_query_u32(&query, "minutes", 60).clamp(1, 1440);
    let snapshot = build_copilot_snapshot(services, window_minutes);
    match copilot.triage(snapshot).await {
        Ok(result) => {
            let body = serde_json::to_string(&result).unwrap_or_else(|_| "{}".into());
            json_body_response(200, body, "no-store")
        }
        Err(e) => {
            let body = serde_json::json!({ "error": e.to_string() }).to_string();
            json_body_response(502, body, "no-store")
        }
    }
}

/// `GET /api/upstreams/probe?addr=host:port&scheme=https&host_header=…&health_path=/healthz`
/// — routing-upstream #2. One-shot DNS/TCP/TLS/(optional)HTTP probe of an
/// upstream member. Read-only (no audit, no config change); admin-auth
/// gated by the upstream middleware. GET so it needs no CSRF, mirroring the
/// copilot endpoints (which also do network I/O off the sync router).
pub(crate) async fn handle_upstream_probe(
    req: hyper::Request<hyper::body::Incoming>,
    _services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let query = req.uri().query().unwrap_or("").to_string();
    let addr_owned = parse_query_str(&query, "addr").map(percent_decode).unwrap_or_default();
    let addr = addr_owned.trim();
    if addr.is_empty() || !addr.contains(':') {
        let body = serde_json::json!({
            "error": "missing or malformed addr; pass ?addr=host:port",
        })
        .to_string();
        return json_body_response(400, body, "no-store");
    }
    let scheme = parse_query_str(&query, "scheme")
        .map(percent_decode)
        .unwrap_or_else(|| "http".into());
    let host_header = parse_query_str(&query, "host_header")
        .map(percent_decode)
        .filter(|s| !s.trim().is_empty());
    let health_path = parse_query_str(&query, "health_path")
        .map(percent_decode)
        .filter(|s| !s.trim().is_empty());

    let result = crate::upstream::probe::probe_member(
        addr,
        &scheme,
        host_header.as_deref(),
        health_path.as_deref(),
    )
    .await;
    let body = serde_json::to_string(&result).unwrap_or_else(|_| "{}".into());
    json_body_response(200, body, "no-store")
}

#[cfg(test)]
mod percent_decode_tests {
    use super::percent_decode;

    #[test]
    fn passthrough_for_unencoded_input() {
        assert_eq!(percent_decode("abc-123"), "abc-123");
        assert_eq!(percent_decode("DataPlaneAvailability-1h:1778574385"), "DataPlaneAvailability-1h:1778574385");
    }

    #[test]
    fn decodes_colon_in_incident_id() {
        // MED-ADM-01 — the dashboard URL-encodes the `:` in the
        // ack id; the dispatcher decodes before handing to the
        // overlay-store key.
        let encoded = "DataPlaneAvailability-1h%3A1778574385";
        assert_eq!(
            percent_decode(encoded),
            "DataPlaneAvailability-1h:1778574385",
            "%3A must decode to ':' so overlay key matches enrich() lookup",
        );
    }

    #[test]
    fn decodes_mixed_case_hex() {
        // Browsers may emit upper or lowercase hex.
        assert_eq!(percent_decode("a%3ab"), "a:b");
        assert_eq!(percent_decode("a%3Ab"), "a:b");
    }

    #[test]
    fn leaves_malformed_escapes_alone() {
        // `%` not followed by two hex digits must NOT crash.
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
        assert_eq!(percent_decode("%2"), "%2");
    }

    #[test]
    fn handles_empty_and_only_escapes() {
        assert_eq!(percent_decode(""), "");
        assert_eq!(percent_decode("%20%2F%3A"), " /:");
    }
}
