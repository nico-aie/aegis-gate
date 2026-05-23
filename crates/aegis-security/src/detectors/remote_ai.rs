//! gRPC client to the standalone `aegis-infer` batch inference server
//! (`data/serving-server/`). Drop-in `Detector` — emits the same `"ai"`
//! signal/score as the in-process [`super::ai::AiDetector`] but offloads
//! ONNX inference to the serving server, which batches across requests.
//!
//! Gated by the `ai-remote` feature (independent of `ai`). See
//! `data/serving-server/INTEGRATION.md`.
//!
//! ## What gets sent
//! We send the **raw request string** (`raw_request`) and let the server
//! extract the 27-feature vector with its own `features.rs`. That keeps
//! feature extraction in ONE place (the server) — no WAF/server feature
//! drift to keep in sync — and the request string is small.
//!
//! ## Failure mode
//! Always **fail-open**: any gRPC error (timeout / reset / server down)
//! → no signal, identical to the in-process detector's behaviour when
//! inference errors. The WAF keeps serving on the regex detectors alone.
//!
//! ## Concurrency / load safety
//! `Detector::inspect` is sync, so each call bridges to async gRPC via
//! `block_in_place` (parking the worker for the round-trip). To stop a
//! traffic burst from parking unbounded worker threads and wedging the
//! runtime, in-flight inferences are capped by a [`Semaphore`]: when the
//! cap is reached `inspect` **sheds** (fails open immediately) instead of
//! queueing. Combined with a hard per-call timeout, this bounds both the
//! number of parked threads and how long each is held. The tonic client
//! is cloned per call (cheap — the HTTP/2 channel multiplexes), so calls
//! run concurrently and the server can actually batch across them.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use tonic::transport::Channel;

use super::{Detector, Signal};
use aegis_core::pipeline::RequestView;

mod proto {
    tonic::include_proto!("aegis.infer.v1");
}
use proto::{aegis_infer_client::AegisInferClient, ClassifyRequest};

/// Remote AI detector — a thin gRPC client over a multiplexed HTTP/2
/// channel. One per WAF process; the client is cloned per call (cheap)
/// rather than shared behind a lock, so calls run concurrently.
pub struct RemoteAiDetector {
    /// Cloneable tonic client. The underlying [`Channel`] multiplexes
    /// concurrent RPCs over one HTTP/2 connection, so `clone()` is cheap
    /// and there is no need (and good reason NOT) to serialise behind a
    /// `Mutex` — serialising would also force the server to batch=1.
    client: AegisInferClient<Channel>,
    threshold: f32,
    score: u32,
    /// Bounds concurrent in-flight inferences. Acquired with
    /// `try_acquire` (never blocks); when exhausted, `inspect` sheds
    /// (fails open). Caps how many worker threads `block_in_place` can
    /// park at once, so a burst can't starve the runtime.
    inflight: Arc<Semaphore>,
    /// Runtime on/off, flipped by `PUT /api/ai/enabled`. Mirrors the
    /// in-process [`super::ai::AiDetector`] so the dashboard's AI card
    /// controls remote inference identically. Seeded at boot from
    /// `cfg.ai.enabled`; defaults to `true`.
    runtime_enabled: Arc<AtomicBool>,
}

/// Hard per-call deadline. Keeps a slow/hung server inside the WAF's
/// latency budget and guarantees a parked worker (and its semaphore
/// permit) is released promptly so the in-flight cap actually drains.
const CALL_TIMEOUT: Duration = Duration::from_millis(50);

/// Max concurrent in-flight inferences. Scales with CPU count (calls are
/// I/O-bound on the server) but stays well under tokio's blocking-thread
/// budget so `block_in_place` always has headroom to spawn replacement
/// workers that keep driving I/O.
fn default_max_inflight() -> usize {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    (cpus * 8).clamp(16, 128)
}

impl RemoteAiDetector {
    /// Connect over TCP (`host:port`). A 50 ms per-call timeout keeps a
    /// slow/overloaded server inside the WAF's latency budget — on
    /// timeout we fail-open.
    pub async fn connect_tcp(addr: &str, threshold: f32) -> Result<Self, tonic::transport::Error> {
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))?
            .connect_timeout(Duration::from_secs(5))
            .timeout(CALL_TIMEOUT)
            .connect()
            .await?;
        Ok(Self::from_channel(channel, threshold))
    }

    /// Connect over a Unix Domain Socket (same-host: lower latency than
    /// TCP, no TLS). Recommended for the co-located topology.
    pub async fn connect_uds(path: &str, threshold: f32) -> Result<Self, tonic::transport::Error> {
        use hyper_util::rt::TokioIo;
        use tokio::net::UnixStream;
        use tower::service_fn;

        let path = path.to_string();
        // The URI authority is ignored for a UDS connector; the
        // service_fn dials the socket path directly. The per-call
        // `timeout` is essential: without it a hung server would park a
        // worker (and hold its semaphore permit) indefinitely.
        let channel = tonic::transport::Endpoint::try_from("http://[::]:0")?
            .timeout(CALL_TIMEOUT)
            .connect_with_connector(service_fn(move |_| {
                let p = path.clone();
                async move { Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(p).await?)) }
            }))
            .await?;
        Ok(Self::from_channel(channel, threshold))
    }

    fn from_channel(channel: Channel, threshold: f32) -> Self {
        Self {
            client: AegisInferClient::new(channel),
            threshold,
            // Reuse the same calibrated weight as the in-process detector.
            score: crate::detectors::scores::ai::AI,
            inflight: Arc::new(Semaphore::new(default_max_inflight())),
            runtime_enabled: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Hand the data plane / control plane the same `AtomicBool` so the
    /// audit-mutated `PUT /api/ai/enabled` handler can flip remote AI on
    /// and off hot. Mirrors [`super::ai::AiDetector::runtime_toggle`].
    pub fn runtime_toggle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.runtime_enabled)
    }
}

impl Detector for RemoteAiDetector {
    fn id(&self) -> &'static str {
        "ai"
    }

    fn inspect(&self, req: &RequestView<'_>) -> Vec<Signal> {
        // Runtime toggle (PUT /api/ai/enabled) — when off, skip the gRPC
        // round-trip entirely. Same gate the in-process detector applies.
        if !self.runtime_enabled.load(Ordering::Relaxed) {
            return vec![];
        }

        // Concurrency cap. `try_acquire_owned` never blocks: if every
        // permit is in use we SHED (fail open) rather than queue, so a
        // burst can't park unbounded worker threads. The permit is held
        // for the whole call and released on drop. AI is best-effort —
        // the regex chain still ran on this request.
        let permit = match Arc::clone(&self.inflight).try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::trace!("remote ai shed — in-flight cap reached, failing open");
                return vec![];
            }
        };

        // Build the request string locally (cheap, no model) and let the
        // server extract features + classify the batch. Clone the client
        // (cheap, multiplexed channel) so this call runs concurrently
        // with others instead of serialising behind a lock.
        let raw = build_request_string(req);
        let mut client = self.client.clone();
        let threshold = self.threshold;
        let score = self.score;

        // The `Detector` trait is sync; the WAF runs on a multi-threaded
        // tokio runtime, so `block_in_place` parks THIS worker thread for
        // the gRPC round-trip while the scheduler spins up a replacement
        // worker to keep other tasks (and the I/O driver) running. The
        // semaphore above bounds how many workers this can park at once.
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                let _permit = permit; // released when the call completes
                let request = ClassifyRequest {
                    request_id: String::new(),
                    features: Vec::new(), // server extracts from raw_request
                    raw_request: raw,
                };
                match client.classify(request).await {
                    Ok(resp) => {
                        let r = resp.into_inner();
                        if r.prob_attack >= threshold {
                            vec![Signal {
                                score,
                                tag: "ai".into(),
                                field: "request".into(),
                            }]
                        } else {
                            vec![]
                        }
                    }
                    Err(e) => {
                        // Fail-open — same as the in-process detector on
                        // an inference error.
                        tracing::trace!(error = %e, "remote ai inference error — fail-open");
                        vec![]
                    }
                }
            })
        })
    }
}

/// Build the request string the model was trained on. MUST match
/// `AiDetector::build_request_string` (in-process) and the server's
/// `features.rs` input format:
///   `"METHOD /path?query body\nUser-Agent: …\nCookie: …\nReferer: …"`
fn build_request_string(req: &RequestView<'_>) -> String {
    let pq = req
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let body = req.body.peek(4096);

    let mut out = String::with_capacity(64 + body.len());
    out.push_str(req.method.as_str());
    out.push(' ');
    out.push_str(pq);
    if !body.is_empty() {
        out.push(' ');
        out.push_str(&String::from_utf8_lossy(body));
    }
    for hdr in ["user-agent", "cookie", "referer"] {
        if let Some(v) = req.headers.get(hdr).and_then(|v| v.to_str().ok()) {
            out.push('\n');
            let canonical = match hdr {
                "user-agent" => "User-Agent",
                "cookie" => "Cookie",
                _ => "Referer",
            };
            out.push_str(canonical);
            out.push_str(": ");
            out.push_str(v);
        }
    }
    out
}
