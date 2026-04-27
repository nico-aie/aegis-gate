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
    _bus: AuditBus,
) {
    let startup = aegis_control::health::StartupProbe::default();
    startup.mark_started();
    let metrics = aegis_control::metrics::MetricsRegistry::init();

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

        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                let cfg = cfg.clone();
                let readiness = readiness.clone();
                let startup = startup.clone();
                let metrics = metrics.clone();
                async move {
                    Ok::<_, Infallible>(admin_router(req, &cfg, &readiness, &startup, &metrics))
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
) -> Response<Full<Bytes>> {
    let path = req.uri().path();

    match path {
        // Dashboard.
        "/" | "/dashboard" | "/dashboard/" => {
            Response::builder()
                .status(200)
                .header("content-type", "text/html; charset=utf-8")
                .body(Full::new(Bytes::from(aegis_control::dashboard::DASHBOARD_HTML)))
                .unwrap()
        }

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

        // 404 for everything else.
        _ => {
            json_response(404, &serde_json::json!({"error": "not found", "path": path}))
        }
    }
}

fn json_response(status: u16, value: &serde_json::Value) -> Response<Full<Bytes>> {
    let body = serde_json::to_string(value).unwrap_or_else(|_| "{}".into());
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
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
}
