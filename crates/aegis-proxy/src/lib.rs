// aegis-proxy: data-plane proxy core (M1)
//
// Owns: listeners, TLS, routing, upstream pools, transforms,
//       state backend impls, service discovery, caching, load shedding.

use std::convert::Infallible;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::Response;
use hyper_util::rt::TokioIo;

use aegis_core::config::WafConfig;
use aegis_core::pipeline::SecurityPipeline;
use aegis_core::state::StateBackend;
use aegis_core::{AuditBus, ReadinessSignal};

pub mod acme;
pub mod acme_instant;
pub mod cache;
pub mod cluster;
pub mod dr;
pub mod hotbin;
pub mod listener;
pub mod ocsp;
pub mod proto;
pub mod proxy;
pub mod quota;
pub mod route;
pub mod sd;
pub mod secrets;
pub mod session;
pub mod shed;
pub mod state;
pub mod supervisor;
pub mod traffic;
pub mod transform;
pub mod upstream;

/// Boot the data-plane proxy + admin (control-plane) listener.
///
/// Binds each listener in `cfg.listeners.data`, spawns accept loops, and
/// starts the admin listener on `cfg.listeners.admin.bind`.
/// Serves until the process receives SIGTERM / Ctrl-C.
pub async fn run(
    cfg: Arc<WafConfig>,
    _pipeline: Arc<dyn SecurityPipeline>,
    _state: Arc<dyn StateBackend>,
    bus: AuditBus,
    readiness: ReadinessSignal,
) -> aegis_core::Result<()> {
    let mut handles = Vec::new();

    // Build the detector set once, shared across all data-plane listeners.
    let detectors: Arc<Vec<Box<dyn aegis_security::detectors::Detector>>> =
        Arc::new(aegis_security::detectors::default_detectors());

    // Hot-reloadable detector class mask. Initial state mirrors
    // `cfg.detectors`; the control plane swaps it via PUT
    // `/api/detectors` (P2 of the security-toggle plan).
    let mask = aegis_security::detectors::SharedDetectorMask::from_config(&cfg.detectors);

    // P6 risk tracker. Per-IP score + lifetime strikes shared
    // between data plane (records signals + classifies for
    // adaptive mitigation) and control plane (renders /api/risk
    // + handles operator reset).
    let risk = aegis_security::risk::RiskTracker::new(&cfg.risk);

    // P7 load gauge. Hot path bumps the request counter; the
    // background sampler reads it and updates the live LoadMode.
    // Hot path + control plane share the same handle.
    let load_gauge = aegis_core::LoadGauge::new(cfg.load_mode.clone());
    let _sampler = load_gauge.clone().spawn_sampler();

    // P8 verbosity. Operator-controlled audit-emission filter.
    // Hot path skips event emission below this level; control
    // plane reads/writes via /api/logging.
    let verbosity = aegis_core::SharedVerbosity::from_config(&cfg.logging);

    // Data-plane listeners.
    for listener_cfg in &cfg.listeners.data {
        let addr = listener_cfg.bind;
        let tcp = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!("data-plane listening on {addr}");

        let detectors = detectors.clone();
        let mask = mask.clone();
        let risk = risk.clone();
        let load_gauge = load_gauge.clone();
        let verbosity = verbosity.clone();
        let bus = bus.clone();
        handles.push(tokio::spawn(accept_loop(
            tcp, detectors, mask, risk, load_gauge, verbosity, bus,
        )));
    }

    // P5 ACME challenge store. Shared between the AcmeManager
    // (which publishes new tokens) and the force-https listener
    // (which serves them on `/.well-known/acme-challenge/`).
    let challenges = crate::acme::ChallengeStore::new();

    // P4 force-HTTPS redirect listener (optional). Spawns only if
    // `listeners.force_https` is set. Also responds to HTTP-01
    // challenges from the ACME directory when it has a token to
    // serve (P5).
    if let Some(redirect_cfg) = cfg.listeners.force_https.as_ref() {
        let addr = redirect_cfg.bind;
        let status = redirect_cfg.status;
        let tcp = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!("force-https redirect listening on {addr}");
        let challenges = challenges.clone();
        handles.push(tokio::spawn(force_https_loop(tcp, status, challenges)));
    }

    // Admin (control-plane) listener.
    let admin_addr = cfg.listeners.admin.bind;
    let admin_tcp = tokio::net::TcpListener::bind(admin_addr).await?;
    tracing::info!("admin-plane listening on {admin_addr}");

    let admin_cfg = cfg.clone();
    let admin_readiness = readiness.clone();
    let admin_bus = bus;
    let admin_mask = mask.clone();
    let admin_risk = risk.clone();
    let admin_load_gauge = load_gauge.clone();
    let admin_verbosity = verbosity.clone();
    handles.push(tokio::spawn(admin_accept_loop(
        admin_tcp,
        admin_cfg,
        admin_readiness,
        admin_bus,
        admin_mask,
        admin_risk,
        admin_load_gauge,
        admin_verbosity,
    )));

    readiness.config_loaded.store(true, Ordering::Relaxed);
    readiness.state_backend_up.store(true, Ordering::Relaxed);
    readiness.certs_loaded.store(true, Ordering::Relaxed);
    readiness.pool_has_healthy.store(true, Ordering::Relaxed);

    // Hold alive until shutdown signal.
    tokio::signal::ctrl_c().await.ok();
    tracing::info!("shutting down");

    for h in handles {
        h.abort();
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn admin_accept_loop(
    tcp: tokio::net::TcpListener,
    cfg: Arc<WafConfig>,
    readiness: ReadinessSignal,
    bus: AuditBus,
    mask: aegis_security::detectors::SharedDetectorMask,
    risk: aegis_security::risk::RiskTracker,
    load_gauge: aegis_core::LoadGauge,
    verbosity: aegis_core::SharedVerbosity,
) {
    let startup = aegis_control::health::StartupProbe::default();
    startup.mark_started();
    let metrics = aegis_control::metrics::MetricsRegistry::init();

    // Build the dashboard service bundle once at boot. The drain
    // task runs for the lifetime of the admin listener — see
    // `aegis-control::dashboard_services` (D-M2-T2.7).
    let pool_provider =
        aegis_control::dashboard_services::pool_snapshot_provider(&cfg);
    let (services, _drain) = aegis_control::dashboard_services::DashboardServices::spawn_with_mask(
        bus,
        pool_provider,
        cfg.admin.environment.clone(),
        mask,
        risk,
        load_gauge,
        verbosity,
    );
    let services = Arc::new(services);

    loop {
        let (stream, peer) = match tcp.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::error!("admin accept error: {e}");
                continue;
            }
        };

        let cfg = cfg.clone();
        let readiness = readiness.clone();
        let startup = startup.clone();
        let metrics = metrics.clone();
        let services = services.clone();

        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                let cfg = cfg.clone();
                let readiness = readiness.clone();
                let startup = startup.clone();
                let metrics = metrics.clone();
                let services = services.clone();
                async move {
                    Ok::<_, Infallible>(
                        handle_admin_request(
                            req, &cfg, &readiness, &startup, &metrics, &services,
                        )
                        .await,
                    )
                }
            });

            if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                tracing::debug!("admin connection from {peer} closed: {e}");
            }
        });
    }
}

/// Async wrapper around the sync [`admin_router`]. Endpoints that
/// need to consume a request body (PUT/POST mutations) branch here
/// first — the rest fall through to the existing sync path.
async fn handle_admin_request(
    req: hyper::Request<hyper::body::Incoming>,
    cfg: &WafConfig,
    readiness: &ReadinessSignal,
    startup: &aegis_control::health::StartupProbe,
    metrics: &aegis_control::metrics::MetricsRegistry,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();

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

    admin_router(req, cfg, readiness, startup, metrics, services)
}

async fn handle_logging_put(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let csrf_cookie = req
        .headers()
        .get_all(hyper::header::COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .find_map(|raw| extract_named_cookie(raw, "aegis_csrf"))
        .map(|s| s.to_string());
    let csrf_header = req
        .headers()
        .get("x-csrf-token")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    let actor = req
        .headers()
        .get("x-actor")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("admin")
        .to_string();
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            blake3::hash(
                format!(
                    "logging-put:{}",
                    chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
                )
                .as_bytes(),
            )
            .to_hex()
            .to_string()
        });

    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Internal(
                    "failed to read request body".into(),
                ),
            );
        }
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");
    let parsed: aegis_control::api::logging::LoggingPutBody =
        match serde_json::from_str(body_str) {
            Ok(b) => b,
            Err(e) => {
                return mutation_error_response(
                    aegis_control::api::mutation::MutationError::Validation(e.to_string()),
                );
            }
        };

    let before = serde_json::to_value(services.verbosity.snapshot())
        .unwrap_or(serde_json::Value::Null);
    let after = serde_json::json!({"level": parsed.level});
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: csrf_cookie.as_deref(),
        csrf_header: csrf_header.as_deref(),
        actor: &actor,
        request_id: &request_id,
        resource: "/api/logging",
        action: "verbosity_set",
        reason: "operator changes verbosity",
    };
    let verbosity = services.verbosity.clone();
    let outcome = services.mutate.apply(&req_ctx, before, after, || {
        aegis_control::api::logging::apply_logging_put(&verbosity, parsed)
    });

    match outcome {
        Ok(_) => json_body_response(
            200,
            aegis_control::api::logging::render_logging_get(&services.verbosity),
            "private, no-store",
        ),
        Err(e) => mutation_error_response(e),
    }
}

async fn handle_loadmode_put(
    req: hyper::Request<hyper::body::Incoming>,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    let csrf_cookie = req
        .headers()
        .get_all(hyper::header::COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .find_map(|raw| extract_named_cookie(raw, "aegis_csrf"))
        .map(|s| s.to_string());
    let csrf_header = req
        .headers()
        .get("x-csrf-token")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    let actor = req
        .headers()
        .get("x-actor")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("admin")
        .to_string();
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            blake3::hash(
                format!(
                    "loadmode-put:{}",
                    chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
                )
                .as_bytes(),
            )
            .to_hex()
            .to_string()
        });

    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Internal(
                    "failed to read request body".into(),
                ),
            );
        }
    };
    let body_str = std::str::from_utf8(body_bytes.as_ref()).unwrap_or("");
    let parsed: aegis_control::api::load_mode::LoadModePutBody =
        match serde_json::from_str(if body_str.is_empty() { "{}" } else { body_str }) {
            Ok(b) => b,
            Err(e) => {
                return mutation_error_response(
                    aegis_control::api::mutation::MutationError::Validation(e.to_string()),
                );
            }
        };

    let before = serde_json::to_value(services.load_gauge.snapshot())
        .unwrap_or(serde_json::Value::Null);
    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: csrf_cookie.as_deref(),
        csrf_header: csrf_header.as_deref(),
        actor: &actor,
        request_id: &request_id,
        resource: "/api/loadmode",
        action: "loadmode_set",
        reason: "operator pins load mode",
    };
    let gauge = services.load_gauge.clone();
    let outcome = services.mutate.apply(
        &req_ctx,
        before,
        serde_json::Value::Null,
        || aegis_control::api::load_mode::apply_put_body(&gauge, parsed),
    );

    match outcome {
        Ok(_) => json_body_response(
            200,
            aegis_control::api::load_mode::render_get(&services.load_gauge),
            "private, no-store",
        ),
        Err(e) => mutation_error_response(e),
    }
}

async fn handle_risk_reset(
    req: hyper::Request<hyper::body::Incoming>,
    ip_segment: &str,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    let Some(ip) = aegis_control::api::risk::parse_ip_segment(ip_segment) else {
        return json_response(
            400,
            &serde_json::json!({"error": "invalid_ip", "segment": ip_segment}),
        );
    };

    let csrf_cookie = req
        .headers()
        .get_all(hyper::header::COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .find_map(|raw| extract_named_cookie(raw, "aegis_csrf"))
        .map(|s| s.to_string());
    let csrf_header = req
        .headers()
        .get("x-csrf-token")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    let actor = req
        .headers()
        .get("x-actor")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("admin")
        .to_string();
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            blake3::hash(
                format!(
                    "risk-reset:{}:{}",
                    ip,
                    chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
                )
                .as_bytes(),
            )
            .to_hex()
            .to_string()
        });

    let resource = format!("/api/risk/{ip}/reset");
    let before = services
        .risk
        .snapshot_wire(ip)
        .map(|s| serde_json::to_value(s).unwrap_or(serde_json::Value::Null))
        .unwrap_or(serde_json::Value::Null);

    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: csrf_cookie.as_deref(),
        csrf_header: csrf_header.as_deref(),
        actor: &actor,
        request_id: &request_id,
        resource: &resource,
        action: "risk_reset",
        reason: "operator clears risk state",
    };
    let risk = services.risk.clone();
    let outcome = services.mutate.apply(
        &req_ctx,
        before,
        serde_json::json!({"score": 0, "strikes": 0}),
        || {
            let removed = risk.reset(ip);
            Ok::<bool, String>(removed)
        },
    );
    match outcome {
        Ok(o) => json_body_response(
            200,
            serde_json::json!({
                "ok": true,
                "ip": ip.to_string(),
                "had_state": o.value,
            })
            .to_string(),
            "private, no-store",
        ),
        Err(err) => mutation_error_response(err),
    }
}

async fn handle_detectors_put(
    req: hyper::Request<hyper::body::Incoming>,
    cfg: &WafConfig,
    services: &aegis_control::dashboard_services::DashboardServices,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

    // Pull CSRF cookie + header before consuming the body.
    let csrf_cookie = req
        .headers()
        .get_all(hyper::header::COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .find_map(|raw| extract_named_cookie(raw, "aegis_csrf"))
        .map(|s| s.to_string());
    let csrf_header = req
        .headers()
        .get("x-csrf-token")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    let actor = req
        .headers()
        .get("x-actor")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("admin")
        .to_string();
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            blake3::hash(
                format!(
                    "detectors-put:{}",
                    chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
                )
                .as_bytes(),
            )
            .to_hex()
            .to_string()
        });

    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            let err = aegis_control::api::mutation::MutationError::Internal(
                "failed to read request body".into(),
            );
            return mutation_error_response(err);
        }
    };
    let body_str = match std::str::from_utf8(body_bytes.as_ref()) {
        Ok(s) => s,
        Err(_) => {
            let err = aegis_control::api::mutation::MutationError::Validation(
                "request body is not valid UTF-8".into(),
            );
            return mutation_error_response(err);
        }
    };

    let put_body = match aegis_control::api::detectors::parse_full_put_body(body_str) {
        Ok(b) => b,
        Err(e) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(e),
            );
        }
    };

    let modes: Vec<aegis_core::config::ComplianceMode> = cfg
        .compliance
        .as_ref()
        .map(|c| c.modes.clone())
        .unwrap_or_default();

    // Snapshot before/after states for the audit-chain diff. The
    // dashboard reads `diff.before` / `diff.after` to render a
    // "what changed" tooltip on the audit log row.
    let before_state = services.detector_mask.load_state();
    let proposed_state = match aegis_control::api::detectors::apply_put_body(
        before_state.clone(),
        put_body,
        &modes,
    ) {
        Ok(s) => s,
        Err(violations) => {
            return mutation_error_response(
                aegis_control::api::mutation::MutationError::Validation(violations.join("; ")),
            );
        }
    };

    let before = mask_state_to_json(&before_state);
    let after = mask_state_to_json(&proposed_state);

    let req_ctx = aegis_control::api::mutation::MutationRequest {
        method: "PUT",
        csrf_cookie: csrf_cookie.as_deref(),
        csrf_header: csrf_header.as_deref(),
        actor: &actor,
        request_id: &request_id,
        resource: "/api/detectors",
        action: "update",
        reason: "detector class toggle",
    };
    let mask_handle = services.detector_mask.clone();
    let outcome = services.mutate.apply(&req_ctx, before, after, || {
        mask_handle.store_state(proposed_state.clone());
        Ok::<(), String>(())
    });

    match outcome {
        Ok(_) => {
            let body = aegis_control::api::detectors::render_get(
                &services.detector_mask,
                &modes,
            );
            json_body_response(200, body, "private, no-store")
        }
        Err(e) => mutation_error_response(e),
    }
}

fn mutation_error_response(
    err: aegis_control::api::mutation::MutationError,
) -> Response<Full<Bytes>> {
    json_body_response(err.http_status(), err.to_body(), "private, no-store")
}

/// Render a [`MaskState`] as a JSON object with `base` and
/// `overrides` keys. Used as the `before`/`after` payload of the
/// audit-chain diff so reviewers can see exactly which tier (and
/// which class within that tier) changed.
fn mask_state_to_json(
    state: &aegis_security::detectors::MaskState,
) -> serde_json::Value {
    use aegis_security::detectors::{tier_str, DetectorMaskBody, ALL_TIERS};
    let mut overrides = serde_json::Map::new();
    for tier in ALL_TIERS {
        if let Some(m) = state.override_for(tier) {
            let body: DetectorMaskBody = m.into();
            overrides.insert(
                tier_str(tier).to_string(),
                serde_json::to_value(body).unwrap_or(serde_json::Value::Null),
            );
        }
    }
    let base: DetectorMaskBody = state.base.into();
    serde_json::json!({
        "base": base,
        "overrides": serde_json::Value::Object(overrides),
    })
}

/// Pull a single named cookie value out of a `Cookie:` header
/// payload. Returns `None` if the cookie isn't present.
fn extract_named_cookie<'a>(raw: &'a str, name: &str) -> Option<&'a str> {
    for pair in raw.split(';') {
        let trimmed = pair.trim();
        if let Some(rest) = trimmed.strip_prefix(name) {
            if let Some(value) = rest.strip_prefix('=') {
                return Some(value);
            }
        }
    }
    None
}

fn admin_router(
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
        // SSE stub — returns a connected status message.
        // Full SSE streaming requires a streaming body (future work).
        "/dashboard/sse" => {
            Response::builder()
                .status(200)
                .header("content-type", "text/event-stream")
                .header("cache-control", "no-cache")
                .header("connection", "keep-alive")
                .body(Full::new(Bytes::from(
                    "data: {\"class\":\"system\",\"action\":\"connected\",\"reason\":\"dashboard SSE connected\",\"ts\":\"\"}\n\n"
                )))
                .unwrap()
        }

        // Health probes.
        "/healthz/live" => {
            let (code, msg) = aegis_control::health::check_live(readiness);
            json_response(code, &serde_json::json!({"status": msg}))
        }
        "/healthz/ready" => {
            let (code, resp) = aegis_control::health::check_ready(readiness);
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

        // P6 risk inventory. Top-N high-risk clients ordered by
        // strike count then score. The dashboard polls this to
        // render the Tracking page risk widget.
        "/api/risk" => {
            let limit = parse_query_u32(query, "limit", 50);
            let body = aegis_control::api::risk::render_list(&services.risk, limit);
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
        "/api/certs" => json_body_response(200, services.tracking.render_certs(), "private, max-age=10"),
        "/api/gitops/status" => json_body_response(200, services.tracking.render_gitops(), "private, max-age=5"),
        "/api/alerts" => json_body_response(200, services.tracking.render_alerts(), "private, max-age=2"),
        "/api/upstreams" => json_body_response(200, services.upstreams.render(), "private, max-age=2"),
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

fn json_response(status: u16, value: &serde_json::Value) -> Response<Full<Bytes>> {
    let body = serde_json::to_string(value).unwrap_or_else(|_| "{}".into());
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

/// JSON response from a pre-rendered body. Adds `Cache-Control` per
/// the per-endpoint TTLs documented in
/// `docs/dashboard-enterprise/api.md` §"Caching".
fn json_body_response(status: u16, body: String, cache_control: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json; charset=utf-8")
        .header("cache-control", cache_control)
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

/// Apply the documented dashboard security headers to a response
/// builder. Single application point for the
/// `aegis_control::dashboard::security::SECURITY_HEADERS` table — see
/// `docs/dashboard-enterprise/security.md` §"Headers (full set …)".
fn apply_dashboard_security_headers(
    mut builder: hyper::http::response::Builder,
) -> hyper::http::response::Builder {
    for (name, value) in aegis_control::dashboard::security::SECURITY_HEADERS {
        builder = builder.header(*name, *value);
    }
    builder
}

/// Convert an [`aegis_control::dashboard::dispatch::DashboardResponse`]
/// into a hyper response. Centralises the dashboard transport rules
/// so security headers, ETags, and cache-control all sit in one place.
///
/// `use_legacy` selects between the v1 single-file shell and the
/// enterprise SPA for the [`DashboardResponse::Shell`] variant only;
/// asset routes are independent of the toggle.
fn dashboard_response(
    r: aegis_control::dashboard::dispatch::DashboardResponse,
    use_legacy: bool,
) -> Response<Full<Bytes>> {
    use aegis_control::dashboard::dispatch::DashboardResponse;
    match r {
        DashboardResponse::Shell => dashboard_shell_response(use_legacy),
        DashboardResponse::Asset(asset) => apply_dashboard_security_headers(
            Response::builder()
                .status(200)
                .header("content-type", asset.content_type)
                .header("etag", format!("\"{}\"", asset.etag))
                .header("cache-control", "public, max-age=3600, must-revalidate"),
        )
        .body(Full::new(Bytes::from_static(asset.bytes)))
        .unwrap(),
        DashboardResponse::AssetNotFound => apply_dashboard_security_headers(
            Response::builder()
                .status(404)
                .header("content-type", "application/json"),
        )
        .body(Full::new(Bytes::from_static(
            br#"{"error":"asset not found"}"#,
        )))
        .unwrap(),
    }
}

/// Serve the SPA shell (`index.html`) by default, or the legacy v1
/// shell when `use_legacy` is `true` (admin opt-in via
/// `cfg.admin.dashboard.legacy_shell`).
fn dashboard_shell_response(use_legacy: bool) -> Response<Full<Bytes>> {
    let shell = aegis_control::dashboard::dispatch::shell_for(use_legacy);
    apply_dashboard_security_headers(
        Response::builder()
            .status(200)
            .header("content-type", shell.content_type)
            .header("cache-control", "no-store"),
    )
    .body(Full::new(Bytes::from_static(shell.bytes)))
    .unwrap()
}

/// Plain-HTTP listener that responds to:
/// - `/.well-known/acme-challenge/{token}` → key authorisation
///   string (HTTP-01 challenge response, P5).
/// - everything else → 301 / 308 redirect to HTTPS (P4).
async fn force_https_loop(
    tcp: tokio::net::TcpListener,
    status: u16,
    challenges: crate::acme::ChallengeStore,
) {
    loop {
        let (stream, peer) = match tcp.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::error!("force-https accept error: {e}");
                continue;
            }
        };
        let challenges = challenges.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let challenges = challenges.clone();
            let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                let challenges = challenges.clone();
                async move {
                    Ok::<_, Infallible>(handle_force_https_request(req, status, &challenges))
                }
            });
            if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                tracing::debug!("force-https connection from {peer} closed: {e}");
            }
        });
    }
}

const ACME_CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";

fn handle_force_https_request(
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

async fn accept_loop(
    tcp: tokio::net::TcpListener,
    detectors: Arc<Vec<Box<dyn aegis_security::detectors::Detector>>>,
    mask: aegis_security::detectors::SharedDetectorMask,
    risk: aegis_security::risk::RiskTracker,
    load_gauge: aegis_core::LoadGauge,
    verbosity: aegis_core::SharedVerbosity,
    bus: AuditBus,
) {
    loop {
        let (stream, peer) = match tcp.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::error!("accept error: {e}");
                continue;
            }
        };

        let detectors = detectors.clone();
        let mask = mask.clone();
        let risk = risk.clone();
        let load_gauge = load_gauge.clone();
        let verbosity = verbosity.clone();
        let bus = bus.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                let detectors = detectors.clone();
                let mask = mask.clone();
                let risk = risk.clone();
                let load_gauge = load_gauge.clone();
                let verbosity = verbosity.clone();
                let bus = bus.clone();
                async move {
                    Ok::<_, Infallible>(handle_data_request(
                        req,
                        peer,
                        &detectors,
                        &mask,
                        &risk,
                        &load_gauge,
                        &verbosity,
                        &bus,
                    ))
                }
            });

            if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                tracing::debug!("connection from {peer} closed: {e}");
            }
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_data_request(
    req: hyper::Request<hyper::body::Incoming>,
    peer: std::net::SocketAddr,
    detectors: &[Box<dyn aegis_security::detectors::Detector>],
    mask: &aegis_security::detectors::SharedDetectorMask,
    risk: &aegis_security::risk::RiskTracker,
    load_gauge: &aegis_core::LoadGauge,
    verbosity: &aegis_core::SharedVerbosity,
    bus: &AuditBus,
) -> Response<Full<Bytes>> {
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

    // P6 short-circuit: if the client's lifetime strike counter
    // has crossed the configured threshold, refuse before running
    // any detectors. Saves CPU under DDoS from known-bad sources.
    let peer_ip = peer.ip();
    if risk.is_strike_blocked(peer_ip) {
        return blocked_response(
            peer,
            "blocked by repeat-offender strikes",
            None,
            risk.snapshot(peer_ip).map(|s| s.score),
            req.uri(),
            req.method(),
            bus,
        );
    }

    // Run security detectors filtered by the effective mask for
    // this tier. A class turned off via PUT /api/detectors (base
    // or per-tier override) short-circuits before the detector body
    // runs.
    let effective = mask.resolve(Some(tier));
    let signals = aegis_security::detectors::run_all_filtered(detectors, effective, &view);

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

        return Response::builder()
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
    }

    // Clean request — let the trust-recovery clock claw back any
    // accumulated score (capped at `trust_recovery.per_hour` so
    // one benign request can't reset a flagged client). Then the
    // adaptive-mitigation classifier decides between Allow,
    // Challenge, and Block based on the post-state vs the
    // configured `RiskThresholds`.
    risk.record_clean(peer_ip);
    match risk.level(peer_ip) {
        aegis_security::risk::RiskLevel::Block => blocked_response(
            peer,
            "blocked by risk score",
            None,
            risk.snapshot(peer_ip).map(|s| s.score),
            req.uri(),
            req.method(),
            bus,
        ),
        aegis_security::risk::RiskLevel::Challenge => Response::builder()
            .status(429)
            .header("content-type", "application/json")
            .header("retry-after", "5")
            .body(Full::new(Bytes::from(
                serde_json::json!({
                    "error": "challenge_required",
                    "reason": "risk score over challenge threshold",
                })
                .to_string(),
            )))
            .unwrap(),
        aegis_security::risk::RiskLevel::Allow => {
            // No detections + low score — proxy to upstream (stub).
            Response::new(Full::new(Bytes::from("OK\n")))
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

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::config::WafConfig;
    use aegis_core::ReadinessSignal;
    use std::sync::Arc;

    #[tokio::test]
    async fn run_binds_and_serves_200() {
        // Build a minimal config pointing at a random free port.
        let yaml = r#"
listeners:
  data:
    - bind: "127.0.0.1:0"
  admin:
    bind: "127.0.0.1:0"
routes:
  - id: catch-all
    path: "/"
    upstream: default
upstreams:
  default:
    members:
      - addr: "127.0.0.1:9999"
state:
  backend: in_memory
"#;
        let cfg: WafConfig = serde_yaml::from_str(yaml).unwrap();

        // We can't use port 0 with the current `run()` because it spawns
        // tasks internally. Instead, bind manually and test the accept loop.
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();

        let detectors: Arc<Vec<Box<dyn aegis_security::detectors::Detector>>> =
            Arc::new(aegis_security::detectors::default_detectors());
        let mask = aegis_security::detectors::SharedDetectorMask::default();
        let risk = aegis_security::risk::RiskTracker::new(
            &aegis_core::config::RiskConfig::default(),
        );
        let load_gauge = aegis_core::LoadGauge::new(aegis_core::LoadModeConfig::default());
        let verbosity = aegis_core::SharedVerbosity::default();
        let bus = aegis_core::AuditBus::new(64);
        let _handle = tokio::spawn(accept_loop(
            tcp, detectors, mask, risk, load_gauge, verbosity, bus,
        ));

        // Give the accept loop a moment to start.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect and send a minimal HTTP/1.1 request.
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);

        let req = hyper::Request::builder()
            .uri("/")
            .body(Full::<Bytes>::default())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), 200);

        // Verify readiness defaults (run() was not called here, just accept_loop)
        let readiness = ReadinessSignal::default();
        assert!(!readiness.is_ready());

        // Verify that a WafConfig with port 0 parses (for the skeleton)
        let _ = cfg;
    }

    // ---------- P4 force-HTTPS redirect loop ------------------------------

    #[tokio::test]
    async fn force_https_loop_returns_301_with_https_location() {
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let challenges = crate::acme::ChallengeStore::new();
        let _handle = tokio::spawn(force_https_loop(tcp, 301, challenges));

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);

        let req = hyper::Request::builder()
            .uri("/api/secret?x=1")
            .header("host", "shop.example.com")
            .body(Full::<Bytes>::default())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status().as_u16(), 301);
        let loc = resp.headers().get("location").unwrap().to_str().unwrap();
        assert_eq!(loc, "https://shop.example.com/api/secret?x=1");
    }

    #[tokio::test]
    async fn force_https_loop_honours_308_status() {
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let challenges = crate::acme::ChallengeStore::new();
        let _handle = tokio::spawn(force_https_loop(tcp, 308, challenges));

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);

        let req = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri("/")
            .header("host", "api.example.com")
            .body(Full::<Bytes>::default())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status().as_u16(), 308);
    }

    // ---------- P5 ACME HTTP-01 challenge responder -----------------------

    #[tokio::test]
    async fn force_https_loop_serves_http01_challenge_when_token_published() {
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let challenges = crate::acme::ChallengeStore::new();
        challenges.insert("acme-tok-1".into(), "acme-tok-1.thumb".into());
        let _handle = tokio::spawn(force_https_loop(tcp, 301, challenges));

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);

        let req = hyper::Request::builder()
            .uri("/.well-known/acme-challenge/acme-tok-1")
            .header("host", "shop.example.com")
            .body(Full::<Bytes>::default())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        use http_body_util::BodyExt;
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&bytes[..], b"acme-tok-1.thumb");
    }

    #[tokio::test]
    async fn force_https_loop_returns_404_for_unknown_acme_token() {
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let challenges = crate::acme::ChallengeStore::new();
        let _handle = tokio::spawn(force_https_loop(tcp, 301, challenges));

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);

        let req = hyper::Request::builder()
            .uri("/.well-known/acme-challenge/missing")
            .header("host", "shop.example.com")
            .body(Full::<Bytes>::default())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        // ACME directory expects a definitive 404, not a redirect.
        assert_eq!(resp.status().as_u16(), 404);
    }

    // ---------- D-M1-T1.5 dashboard security headers ---------------------

    use aegis_control::dashboard::dispatch::{dispatch, DashboardResponse};
    use aegis_control::dashboard::security::SECURITY_HEADERS;

    /// Every header in SECURITY_HEADERS must appear on the response,
    /// with the canonical value.
    fn assert_security_headers(headers: &hyper::HeaderMap) {
        for (name, value) in SECURITY_HEADERS {
            let got = headers.get(*name).unwrap_or_else(|| {
                panic!("missing security header {name}");
            });
            assert_eq!(
                got.to_str().unwrap_or(""),
                *value,
                "wrong value for {name}"
            );
        }
    }

    #[test]
    fn dashboard_shell_response_carries_security_headers() {
        let resp = dashboard_shell_response(false);
        assert_eq!(resp.status(), 200);
        assert_security_headers(resp.headers());
    }

    #[test]
    fn dashboard_asset_response_carries_security_headers() {
        let r = dispatch("/dashboard/assets/app.js")
            .expect("known asset must resolve");
        let resp = match r {
            DashboardResponse::Asset(_) => dashboard_response(r, false),
            _ => panic!("expected Asset"),
        };
        assert_eq!(resp.status(), 200);
        assert_security_headers(resp.headers());
    }

    #[test]
    fn dashboard_asset_not_found_carries_security_headers() {
        // 404s also need the headers — a missing asset must not become
        // a CSP-bypass vector.
        let r = dispatch("/dashboard/assets/missing.js")
            .expect("must dispatch");
        let resp = dashboard_response(r, false);
        assert_eq!(resp.status(), 404);
        assert_security_headers(resp.headers());
    }

    // ---------- D-M1-T1.6 legacy shell flag ------------------------------

    async fn body_string(resp: Response<Full<Bytes>>) -> String {
        use http_body_util::BodyExt;
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn dashboard_shell_response_default_serves_spa_shell() {
        // legacy flag off (default) -> new SPA shell, identified by
        // the #aegis-app sentinel.
        let resp = dashboard_shell_response(false);
        assert_eq!(resp.status(), 200);
        let body = body_string(resp).await;
        assert!(
            body.contains(r#"id="aegis-app""#),
            "default shell must be the new SPA"
        );
    }

    #[tokio::test]
    async fn dashboard_shell_response_legacy_now_returns_spa() {
        // D-M6-T6.9 removed the legacy shell. The legacy flag is a
        // no-op for back-compat — every shell response is now the SPA.
        let resp = dashboard_shell_response(true);
        assert_eq!(resp.status(), 200);
        let body = body_string(resp).await;
        assert!(
            body.contains(r#"id="aegis-app""#),
            "legacy flag must now return the SPA shell"
        );
    }

    #[test]
    fn dashboard_shell_response_legacy_keeps_security_headers() {
        // The legacy shell still goes through the security-header
        // middleware — the toggle must not become a header bypass.
        let resp = dashboard_shell_response(true);
        assert_security_headers(resp.headers());
    }
}
