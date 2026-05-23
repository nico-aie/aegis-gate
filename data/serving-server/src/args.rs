//! CLI arguments — all server tuning knobs exposed via `--flag`.

use clap::Parser;

/// Aegis WAF — gRPC AI batch inference server.
///
/// Receives individual Classify RPCs, accumulates them into batches
/// (up to `--delay-ms` or `--max-batch`), runs ONNX inference once
/// per batch, and fans results back to callers via oneshot channels.
///
/// ## Quick start (mock, no model needed)
///   aegis-infer --mock
///
/// ## Production
///   aegis-infer --model-path /data/ai_model/model.onnx --workers 4 --bind-uds /run/aegis/infer.sock
#[derive(Parser, Debug, Clone)]
#[command(name = "aegis-infer", version, about)]
pub struct Args {
    // ── Network ──────────────────────────────────────────────────────────

    /// TCP listen address (host:port).
    #[arg(long, default_value = "127.0.0.1:50051", env = "INFER_BIND_TCP")]
    pub bind_tcp: String,

    /// Unix domain socket path.  When set, the server also listens on a
    /// UDS socket in addition to TCP.  Production recommended.
    ///
    /// Example: /run/aegis/infer.sock
    #[arg(long, env = "INFER_BIND_UDS")]
    pub bind_uds: Option<String>,

    // ── Model ────────────────────────────────────────────────────────────

    /// Path to the ONNX model file.
    /// Expected inputs:  "X"  shape [batch, 27]  dtype float32
    /// Expected outputs: "label" shape [batch]    dtype int64
    ///                   "probabilities" shape [batch, K] dtype float32
    #[arg(long, default_value = "model.onnx", env = "INFER_MODEL_PATH")]
    pub model_path: String,

    /// Run without a real ONNX model.
    /// Predictions are computed from a simple heuristic over the extracted
    /// features — good for load testing the batching + transport stack.
    #[arg(long, env = "INFER_MOCK")]
    pub mock: bool,

    /// Index of the "Normal" class in the model output.
    /// P(Attack) = 1 − probabilities[normal_class_idx].
    #[arg(long, default_value = "0", env = "INFER_NORMAL_CLASS_IDX")]
    pub normal_class_idx: i64,

    /// Minimum P(Attack) to emit `is_attack = true`.
    /// 0.5 = argmax behaviour.  Raise to 0.7–0.95 to reduce FP.
    #[arg(long, default_value = "0.5", env = "INFER_THRESHOLD")]
    pub threshold: f32,

    // ── Batching ─────────────────────────────────────────────────────────

    /// Maximum requests accumulated per batch before forcing inference.
    /// Larger values = better GPU/CPU utilisation; higher worst-case latency.
    #[arg(long, default_value = "256", env = "INFER_MAX_BATCH")]
    pub max_batch: usize,

    /// Maximum time (ms) to wait for a batch to fill before flushing.
    /// Lower = lower latency; higher = better throughput at low RPS.
    #[arg(long, default_value = "2", env = "INFER_DELAY_MS")]
    pub delay_ms: u64,

    // ── Workers ──────────────────────────────────────────────────────────

    /// Number of parallel ONNX inference workers.
    /// Each worker owns one ONNX Session (one set of ORT threads).
    /// Increase to saturate multi-core CPUs; memory cost = workers × model_size.
    #[arg(long, default_value_t = default_workers(), env = "INFER_WORKERS")]
    pub workers: usize,

    // ── Channel ──────────────────────────────────────────────────────────

    /// Internal request-queue capacity (requests buffered before backpressure).
    #[arg(long, default_value = "16384", env = "INFER_QUEUE_CAP")]
    pub queue_cap: usize,

    // ── Logging ──────────────────────────────────────────────────────────

    /// Log level: trace | debug | info | warn | error
    #[arg(long, default_value = "info", env = "RUST_LOG")]
    pub log_level: String,

    /// Emit JSON log lines (for log aggregators).
    #[arg(long, env = "INFER_JSON_LOGS")]
    pub json_logs: bool,
}

fn default_workers() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(8)
}
