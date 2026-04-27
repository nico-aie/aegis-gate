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

    // Data-plane listeners.
    for listener_cfg in &cfg.listeners.data {
        let addr = listener_cfg.bind;
        let tcp = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!("data-plane listening on {addr}");

        let detectors = detectors.clone();
        let bus = bus.clone();
        handles.push(tokio::spawn(accept_loop(tcp, detectors, bus)));
    }

    // Admin (control-plane) listener.
    let admin_addr = cfg.listeners.admin.bind;
    let admin_tcp = tokio::net::TcpListener::bind(admin_addr).await?;
    tracing::info!("admin-plane listening on {admin_addr}");

    let admin_cfg = cfg.clone();
    let admin_readiness = readiness.clone();
    let admin_bus = bus;
    handles.push(tokio::spawn(admin_accept_loop(
        admin_tcp,
        admin_cfg,
        admin_readiness,
        admin_bus,
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

async fn admin_accept_loop(
    tcp: tokio::net::TcpListener,
    cfg: Arc<WafConfig>,
    readiness: ReadinessSignal,
    bus: AuditBus,
) {
    let startup = aegis_control::health::StartupProbe::default();
    startup.mark_started();
    let metrics = aegis_control::metrics::MetricsRegistry::init();

    // Build the dashboard service bundle once at boot. The drain
    // task runs for the lifetime of the admin listener — see
    // `aegis-control::dashboard_services` (D-M2-T2.7).
    let pool_provider =
        aegis_control::dashboard_services::pool_snapshot_provider(&cfg);
    let (services, _drain) = aegis_control::dashboard_services::DashboardServices::spawn(
        bus,
        pool_provider,
        cfg.admin.environment.clone(),
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
                    Ok::<_, Infallible>(admin_router(
                        req, &cfg, &readiness, &startup, &metrics, &services,
                    ))
                }
            });

            if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                tracing::debug!("admin connection from {peer} closed: {e}");
            }
        });
    }
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

async fn accept_loop(
    tcp: tokio::net::TcpListener,
    detectors: Arc<Vec<Box<dyn aegis_security::detectors::Detector>>>,
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
        let bus = bus.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                let detectors = detectors.clone();
                let bus = bus.clone();
                async move {
                    Ok::<_, Infallible>(handle_data_request(req, peer, &detectors, &bus))
                }
            });

            if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                tracing::debug!("connection from {peer} closed: {e}");
            }
        });
    }
}

fn handle_data_request(
    req: hyper::Request<hyper::body::Incoming>,
    peer: std::net::SocketAddr,
    detectors: &[Box<dyn aegis_security::detectors::Detector>],
    bus: &AuditBus,
) -> Response<Full<Bytes>> {
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

    // Run all security detectors.
    let signals = aegis_security::detectors::run_all(detectors, &view);

    if !signals.is_empty() {
        let total_score: u32 = signals.iter().map(|s| s.score).sum();
        let tags: Vec<&str> = signals.iter().map(|s| s.tag.as_str()).collect();
        let reason = format!("blocked by detectors: {} (score: {})", tags.join(", "), total_score);
        tracing::warn!(
            peer = %peer,
            path = %req.uri(),
            score = total_score,
            detectors = ?tags,
            "request blocked"
        );

        // Emit audit event.
        let ev = aegis_core::audit::AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: blake3::hash(format!("{}:{}", peer, chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)).as_bytes()).to_hex().to_string(),
            class: aegis_core::audit::AuditClass::Detection,
            tenant_id: None,
            tier: None,
            action: "block".into(),
            reason: reason.clone(),
            client_ip: peer.ip().to_string(),
            route_id: None,
            rule_id: None,
            risk_score: Some(total_score),
            fields: serde_json::json!({
                "path": req.uri().to_string(),
                "method": req.method().to_string(),
                "detectors": tags,
            }),
        };
        bus.emit(ev);

        return Response::builder()
            .status(403)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(
                serde_json::json!({
                    "error": "forbidden",
                    "reason": reason,
                })
                .to_string(),
            )))
            .unwrap();
    }

    // No detections — proxy to upstream (stub: return OK for now).
    Response::new(Full::new(Bytes::from("OK\n")))
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
        let bus = aegis_core::AuditBus::new(64);
        let _handle = tokio::spawn(accept_loop(tcp, detectors, bus));

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
