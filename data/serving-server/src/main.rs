//! Aegis WAF — gRPC AI Batch Inference Server
//!
//! ## Quick start
//!
//! ```bash
//! # Mock mode (no ONNX model needed) — good for first-run test:
//! cargo run -- --mock
//!
//! # With real ONNX model, 4 parallel sessions, UDS socket:
//! cargo run --release -- \
//!   --model-path /data/ai_model/model.onnx \
//!   --workers 4 \
//!   --bind-uds /tmp/aegis-infer.sock
//! ```

mod args;
mod batch;
mod features;
mod model;
mod server;
mod stats;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tonic::transport::Server;
use tracing::info;

use args::Args;
use model::Model;
use server::{AegisInferServer, InferService};
use stats::Stats;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // ── Logging ───────────────────────────────────────────────────────────────
    init_logging(&args);
    info!(
        bind_tcp   = %args.bind_tcp,
        bind_uds   = ?args.bind_uds,
        mock       = args.mock,
        model_path = %args.model_path,
        workers    = args.workers,
        max_batch  = args.max_batch,
        delay_ms   = args.delay_ms,
        threshold  = args.threshold,
        "Aegis inference server starting"
    );

    // ── Build model pool (one ORT session per worker) ─────────────────────────
    let models: Vec<Arc<Model>> = if args.mock {
        info!("mock mode — no ONNX model loaded");
        (0..args.workers)
            .map(|_| Arc::new(Model::mock(args.normal_class_idx, args.threshold)))
            .collect()
    } else {
        let path = Path::new(&args.model_path);
        info!(path = %path.display(), workers = args.workers, "loading ONNX model");
        let mut pool = Vec::with_capacity(args.workers);
        for i in 0..args.workers {
            let m = Model::load(path, args.normal_class_idx, args.threshold)
                .map_err(|e| anyhow::anyhow!("worker {i} model load failed: {e}"))?;
            info!(worker = i, "ORT session ready");
            pool.push(Arc::new(m));
        }
        pool
    };

    let mode: &'static str = if args.mock { "mock" } else { "onnx" };

    // ── Shared stats ──────────────────────────────────────────────────────────
    let stats = Arc::new(Stats::default());

    // ── Batch accumulator (one collector + N worker tasks) ────────────────────
    let delay     = Duration::from_millis(args.delay_ms);
    let batch_svc = batch::spawn(
        models,
        args.max_batch,
        delay,
        args.queue_cap,
        Arc::clone(&stats),
    );

    // ── gRPC service (Clone-cheap: all fields are Arc/cheap clones) ───────────
    let infer_svc = InferService::new(
        batch_svc,
        Arc::clone(&stats),
        mode,
        args.workers as u32,
        args.max_batch as u32,
        args.delay_ms as f32,
    );

    // ── TCP server task ───────────────────────────────────────────────────────
    let tcp_addr: std::net::SocketAddr = args.bind_tcp.parse()
        .map_err(|e| anyhow::anyhow!("invalid --bind-tcp '{0}': {e}", args.bind_tcp))?;

    info!(addr = %tcp_addr, "gRPC TCP listener starting");

    let tcp_svc = AegisInferServer::new(infer_svc.clone());
    let tcp_task: tokio::task::JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
        Server::builder()
            .add_service(tcp_svc)
            .serve(tcp_addr)
            .await
            .map_err(|e| anyhow::anyhow!("TCP server error: {e}"))
    });

    // ── UDS server task (optional) ────────────────────────────────────────────
    let uds_task: tokio::task::JoinHandle<anyhow::Result<()>> =
        if let Some(ref uds_path) = args.bind_uds {
            // Remove stale socket file.
            let _ = std::fs::remove_file(uds_path);
            let uds_path = uds_path.clone();
            info!(path = %uds_path, "gRPC UDS listener starting");

            let uds_svc = AegisInferServer::new(infer_svc.clone());
            tokio::spawn(async move {
                use tokio::net::UnixListener;
                use tokio_stream::wrappers::UnixListenerStream;

                let listener = UnixListener::bind(&uds_path)
                    .map_err(|e| anyhow::anyhow!("UDS bind failed ({uds_path}): {e}"))?;
                let incoming = UnixListenerStream::new(listener);

                Server::builder()
                    .add_service(uds_svc)
                    .serve_with_incoming(incoming)
                    .await
                    .map_err(|e| anyhow::anyhow!("UDS server error: {e}"))
            })
        } else {
            // No UDS configured — use a future that never resolves so the
            // select! below doesn't spuriously exit.
            tokio::spawn(std::future::pending::<anyhow::Result<()>>())
        };

    // ── Periodic stats log (every 30s) ────────────────────────────────────────
    {
        let s = Arc::clone(&stats);
        tokio::spawn(async move {
            use std::sync::atomic::Ordering::Relaxed;
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                info!(
                    total_req    = s.total_requests.load(Relaxed),
                    total_batch  = s.total_batches.load(Relaxed),
                    avg_batch    = format!("{:.1}", s.avg_batch_size()),
                    avg_infer_us = format!("{:.0}", s.avg_infer_us()),
                    attacks      = s.total_attacks.load(Relaxed),
                    uptime_s     = s.uptime_secs(),
                    "stats"
                );
            }
        });
    }

    info!("server ready — waiting for requests (Ctrl+C to stop)");

    // ── Block until shutdown ──────────────────────────────────────────────────
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("SIGINT received — shutting down gracefully");
        }
        res = tcp_task => {
            match res {
                Ok(Err(e)) => tracing::error!(error = %e, "TCP server crashed"),
                Err(e)     => tracing::error!(error = %e, "TCP task panicked"),
                Ok(Ok(())) => info!("TCP server exited cleanly"),
            }
        }
        res = uds_task => {
            match res {
                Ok(Err(e)) => tracing::error!(error = %e, "UDS server crashed"),
                Err(e)     => tracing::error!(error = %e, "UDS task panicked"),
                Ok(Ok(())) => info!("UDS server exited cleanly"),
            }
        }
    }

    info!("server stopped");
    Ok(())
}

// ── Logging initialisation ────────────────────────────────────────────────────

fn init_logging(args: &Args) {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&args.log_level));

    if args.json_logs {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .compact()
            .init();
    }
}
