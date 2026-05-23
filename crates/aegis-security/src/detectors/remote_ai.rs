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

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tonic::transport::Channel;

use super::{Detector, Signal};
use aegis_core::pipeline::RequestView;

mod proto {
    tonic::include_proto!("aegis.infer.v1");
}
use proto::{aegis_infer_client::AegisInferClient, ClassifyRequest};

/// Remote AI detector — a thin gRPC client over a multiplexed HTTP/2
/// channel (cheap to clone). One per WAF process.
pub struct RemoteAiDetector {
    client: Arc<tokio::sync::Mutex<AegisInferClient<Channel>>>,
    threshold: f32,
    score: u32,
    /// Runtime on/off, flipped by `PUT /api/ai/enabled`. Mirrors the
    /// in-process [`super::ai::AiDetector`] so the dashboard's AI card
    /// controls remote inference identically. Seeded at boot from
    /// `cfg.ai.enabled`; defaults to `true`.
    runtime_enabled: Arc<AtomicBool>,
}

impl RemoteAiDetector {
    /// Connect over TCP (`host:port`). A 50 ms per-call timeout keeps a
    /// slow/overloaded server inside the WAF's latency budget — on
    /// timeout we fail-open.
    pub async fn connect_tcp(addr: &str, threshold: f32) -> Result<Self, tonic::transport::Error> {
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))?
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_millis(50))
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
        // service_fn dials the socket path directly.
        let channel = tonic::transport::Endpoint::try_from("http://[::]:0")?
            .connect_with_connector(service_fn(move |_| {
                let p = path.clone();
                async move { Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(p).await?)) }
            }))
            .await?;
        Ok(Self::from_channel(channel, threshold))
    }

    fn from_channel(channel: Channel, threshold: f32) -> Self {
        Self {
            client: Arc::new(tokio::sync::Mutex::new(AegisInferClient::new(channel))),
            threshold,
            // Reuse the same calibrated weight as the in-process detector.
            score: crate::detectors::scores::ai::AI,
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
        // Build the request string locally (cheap, no model) and let the
        // server extract features + classify the batch.
        let raw = build_request_string(req);
        let client = Arc::clone(&self.client);
        let threshold = self.threshold;
        let score = self.score;

        // The `Detector` trait is sync; the WAF runs on a multi-threaded
        // tokio runtime, so `block_in_place` parks THIS worker thread for
        // the gRPC round-trip while the scheduler keeps other tasks
        // running on the remaining workers.
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                let request = ClassifyRequest {
                    request_id: String::new(),
                    features: Vec::new(), // server extracts from raw_request
                    raw_request: raw,
                };
                let mut c = client.lock().await;
                match c.classify(request).await {
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
