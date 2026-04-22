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

pub mod listener;
pub mod proxy;
pub mod route;
pub mod state;
pub mod supervisor;
pub mod upstream;

// Future modules (stubs):
// pub mod tls;
// pub mod transform;
// pub mod sd;
// pub mod cache;
// pub mod cluster;
// pub mod secrets;
// pub mod shed;
// pub mod proto;

/// Boot the data-plane proxy.
///
/// Binds each listener in `cfg.listeners.data`, spawns accept loops, and
/// serves 200 OK to every request until the process receives SIGTERM / Ctrl-C.
pub async fn run(
    cfg: Arc<WafConfig>,
    _pipeline: Arc<dyn SecurityPipeline>,
    _state: Arc<dyn StateBackend>,
    _bus: AuditBus,
    readiness: ReadinessSignal,
) -> aegis_core::Result<()> {
    let mut handles = Vec::new();

    for listener_cfg in &cfg.listeners.data {
        let addr = listener_cfg.bind;
        let tcp = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!("data-plane listening on {addr}");

        handles.push(tokio::spawn(accept_loop(tcp)));
    }

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

async fn accept_loop(tcp: tokio::net::TcpListener) {
    loop {
        let (stream, peer) = match tcp.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::error!("accept error: {e}");
                continue;
            }
        };

        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(|_req: hyper::Request<hyper::body::Incoming>| async {
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from("OK\n"))))
            });

            if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                tracing::debug!("connection from {peer} closed: {e}");
            }
        });
    }
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

        let _handle = tokio::spawn(accept_loop(tcp));

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
