//! AI-T4 — ML-based detector.
//!
//! ## Purpose
//!
//! Run the trained ONNX classifier against every request that
//! reaches the detector chain.  When the model predicts a
//! non-`Normal` class (and the result clears the configured
//! confidence threshold), emit a single signal tagged `"ai"`.
//! The downstream chain treats this exactly like sqli/xss/etc.
//! — same audit shape, same dashboard rendering, same
//! score-driven mitigation.
//!
//! ## Binary verdict semantics
//!
//! Operators don't need to know which of the model's 11 classes
//! fired — the WAF only needs `attack | not-attack`.  The
//! detector emits one tag (`"ai"`), not 11 (`"ai_sqli"`,
//! `"ai_xss"`, …).  When the model is later retrained as a
//! pure binary classifier, this code path doesn't change at
//! all — `Model::predict` already collapses the verdict to a
//! `is_attack: bool` field.
//!
//! ## Failure mode
//!
//! Inference errors (load issue, runtime error, missing
//! tensor) collapse to "no signal" — the request flows through
//! the rest of the detector chain.  We never **block** on an
//! AI failure.  The fallback is observable via the metric the
//! caller increments around the `inspect()` call.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use aegis_core::pipeline::RequestView;

use super::{Detector, Signal};

pub mod features;
pub mod model;

pub use model::{Model, ModelError, Prediction};

/// Metric-recording surface the AI detector calls per
/// inference.  Lives in this crate so `aegis-security` doesn't
/// have to depend on `aegis-control`; the real impl
/// (`aegis_control::metrics::ai::AiMetrics`) lives there and
/// implements this trait.
///
/// Methods are infallible / cheap — single-digit ns at
/// production rates.  Fall-back implementations are no-ops.
pub trait AiMetricsSink: Send + Sync {
    /// Successful inference — the detector ran the model and
    /// got back a verdict.  `is_attack` is the binary verdict;
    /// `latency_seconds` the wall-clock time the inference
    /// took (for histogram bucketing).
    fn record_prediction(&self, is_attack: bool, latency_seconds: f64);

    /// Inference / tensor-build error or below-threshold
    /// confidence.  The detector chain treats it as "no
    /// signal" and the request flows to the next detector;
    /// the operator sees the bucket counter rise.
    fn record_fallback(&self, reason: &'static str);
}

/// No-op sink used when the binary boots without the metrics
/// registry wired (e.g. tests, fuzz harnesses).
pub struct NoopAiMetricsSink;
impl AiMetricsSink for NoopAiMetricsSink {
    fn record_prediction(&self, _is_attack: bool, _latency_seconds: f64) {}
    fn record_fallback(&self, _reason: &'static str) {}
}

/// Stable label values for [`AiMetricsSink::record_fallback`].
pub mod fallback_reason {
    pub const INFERENCE_ERROR: &str = "inference_error";
    pub const LOW_CONFIDENCE: &str = "low_confidence";
    pub const TENSOR_BUILD: &str = "tensor_build";
}

/// Default index of the `Normal` class in the shipped 11-class
/// model.  See `data/ai_model/label_map.json`.  When a future
/// model swaps the layout, override at construction.
pub const DEFAULT_NORMAL_CLASS_IDX: i64 = 6;

/// Model wrapped in `Arc` so cheap clones share the underlying
/// `ort::Session`.
pub type SharedModel = Arc<Model>;

/// AI-backed attack detector.  Stateless aside from the model
/// handle.  Cheap to clone.
pub struct AiDetector {
    model: SharedModel,
    /// Top-1 softmax probability the model must reach before
    /// the verdict counts.  When the model output doesn't
    /// expose probabilities (sklearn's Sequence<Map<i64,f32>>
    /// is awkward to extract today), `Prediction::confidence`
    /// reports `1.0` so this gate is effectively a no-op.
    threshold: f32,
    /// Per-signal score added to the risk total when AI flags
    /// a request.  Mirrors the score the regex detectors
    /// contribute (50–60 each); set high enough that AI alone
    /// can drive a block when other detectors are silent.
    score: u32,
    /// Metrics recorder.  Defaults to [`NoopAiMetricsSink`];
    /// the boot path replaces it with the live AiMetrics
    /// implementation when /metrics is wired.
    metrics: Arc<dyn AiMetricsSink>,
    /// Runtime on/off — flipped by the audit-mutated
    /// `PUT /api/ai/enabled` handler. When `false`,
    /// [`Detector::inspect`] short-circuits and returns no
    /// signals (and skips inference entirely so AI cost is
    /// genuinely zero). Initialised to `cfg.ai.enabled` at boot.
    /// Wrapped in `Arc<AtomicBool>` so the dashboard's writer
    /// can flip the same handle the data plane reads.
    runtime_enabled: Arc<AtomicBool>,
}

impl AiDetector {
    /// Load the model from disk and build the detector.
    pub fn load(
        model_path: &Path,
        normal_class_idx: i64,
        threshold: f32,
    ) -> Result<Self, ModelError> {
        let model = Model::load(model_path, normal_class_idx)?;
        Ok(Self {
            model: Arc::new(model),
            threshold,
            score: 60,
            metrics: Arc::new(NoopAiMetricsSink),
            runtime_enabled: Arc::new(AtomicBool::new(true)),
        })
    }

    /// Build a detector around an already-loaded model.
    /// Useful for tests + sharing one session across multiple
    /// detector instances.
    pub fn from_model(model: SharedModel, threshold: f32) -> Self {
        Self {
            model,
            threshold,
            score: 60,
            metrics: Arc::new(NoopAiMetricsSink),
            runtime_enabled: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Get a clone of the runtime-toggle handle. The control
    /// plane stashes this on `DashboardServices` so the
    /// audit-mutated `PUT /api/ai/enabled` handler can flip it
    /// hot. The data plane reads the same `AtomicBool` per
    /// inference — no lock, single relaxed load.
    pub fn runtime_toggle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.runtime_enabled)
    }

    /// Override the initial runtime-toggle value (defaults to
    /// `true` — same as the boot config). Useful for tests that
    /// want to verify the short-circuit path without a writer.
    pub fn with_runtime_enabled(self, enabled: bool) -> Self {
        self.runtime_enabled.store(enabled, Ordering::Relaxed);
        self
    }

    /// Override the per-hit score (default 60).  A request
    /// whose total score crosses the strike threshold gets
    /// blocked; tuning the AI score lets operators dial up /
    /// down its standalone weight.
    pub fn with_score(mut self, score: u32) -> Self {
        self.score = score;
        self
    }

    /// Wire a metrics sink so per-prediction observations
    /// land on `/metrics`.  Boot path uses this; tests leave
    /// the no-op default.
    pub fn with_metrics(mut self, sink: Arc<dyn AiMetricsSink>) -> Self {
        self.metrics = sink;
        self
    }

    /// Render the request into the `"METHOD /path?query body"`
    /// shape the feature extractor + the trained model expect.
    fn build_request_string(req: &RequestView<'_>) -> String {
        let method = req.method.as_str();
        // Path-and-query, falling back to "/" for empty URIs.
        let pq = req
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        // Bound the body peek at a sensible chunk — feature
        // extraction iterates the full string, so a multi-MB
        // upload would blow the latency budget.  4 KiB matches
        // the corpus the model was trained on.
        let body_bytes = req.body.peek(4096);
        if body_bytes.is_empty() {
            format!("{method} {pq}")
        } else {
            // Lossy UTF-8 — non-text payloads still produce a
            // string suitable for regex feature counts, which
            // is what the training pipeline did.
            let body = String::from_utf8_lossy(body_bytes);
            format!("{method} {pq} {body}")
        }
    }
}

impl Detector for AiDetector {
    fn id(&self) -> &'static str {
        "ai"
    }

    fn inspect(&self, req: &RequestView<'_>) -> Vec<Signal> {
        // Runtime gate — same shape as the existing class mask
        // for sqli/xss/etc. but a separate AtomicBool because
        // AI isn't in the `DetectorClass` enum (the bitmask
        // lives in aegis-security; AI is feature-gated and
        // bolted on). Flipped by `PUT /api/ai/enabled`. When
        // off we skip inference entirely so the cost is
        // genuinely zero, not just "no signal emitted".
        if !self.runtime_enabled.load(Ordering::Relaxed) {
            return Vec::new();
        }
        let request_str = Self::build_request_string(req);
        let feats = features::extract_features(&request_str);
        match self.model.predict(&feats) {
            Ok(p) => {
                let lat_seconds = (p.latency_us as f64) / 1_000_000.0;
                self.metrics.record_prediction(p.is_attack, lat_seconds);
                if p.is_attack && p.confidence >= self.threshold {
                    vec![Signal {
                        score: self.score,
                        tag: "ai".into(),
                        field: "request".into(),
                    }]
                } else {
                    if p.is_attack {
                        // Verdict said attack but confidence
                        // was under threshold — count the
                        // safety fall-through so operators
                        // can tune the threshold from data.
                        self.metrics
                            .record_fallback(fallback_reason::LOW_CONFIDENCE);
                    }
                    Vec::new()
                }
            }
            Err(e) => {
                self.metrics
                    .record_fallback(fallback_reason::INFERENCE_ERROR);
                tracing::trace!(
                    error = %e,
                    "ai detector inference error — fail-open",
                );
                Vec::new()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::pipeline::BodyPeek;

    /// `BodyPeek::new_helper` — small adapter around the
    /// crate's `BodyPeek::new(data, len, chunked)` so the
    /// tests below read cleanly.
    fn make_body(bytes: &[u8]) -> BodyPeek {
        BodyPeek::new(bytes.to_vec(), Some(bytes.len() as u64), false)
    }

    fn view_for<'a>(
        m: &'a http::Method,
        u: &'a http::Uri,
        h: &'a http::HeaderMap,
        b: &'a BodyPeek,
    ) -> RequestView<'a> {
        RequestView {
            method: m,
            uri: u,
            version: http::Version::HTTP_11,
            headers: h,
            peer: "127.0.0.1:1234".parse().unwrap(),
            tls: None,
            body: b,
        }
    }

    #[test]
    fn build_request_string_handles_empty_body() {
        let m = http::Method::GET;
        let u: http::Uri = "/api/users?id=1".parse().unwrap();
        let h = http::HeaderMap::new();
        let b = BodyPeek::empty();
        let req = view_for(&m, &u, &h, &b);
        let s = AiDetector::build_request_string(&req);
        assert_eq!(s, "GET /api/users?id=1");
    }

    #[test]
    fn build_request_string_includes_body_when_present() {
        let m = http::Method::POST;
        let u: http::Uri = "/login".parse().unwrap();
        let h = http::HeaderMap::new();
        let b = make_body(b"user=admin&pass=secret");
        let req = view_for(&m, &u, &h, &b);
        let s = AiDetector::build_request_string(&req);
        assert!(s.starts_with("POST /login "), "got {s:?}");
        assert!(s.contains("user=admin"), "got {s:?}");
    }

    #[test]
    fn build_request_string_caps_body_at_4kb() {
        // 6 KiB of body — extractor only sees the first 4 KiB.
        let big = vec![b'a'; 6 * 1024];
        let m = http::Method::POST;
        let u: http::Uri = "/upload".parse().unwrap();
        let h = http::HeaderMap::new();
        let b = make_body(&big);
        let req = view_for(&m, &u, &h, &b);
        let s = AiDetector::build_request_string(&req);
        // "POST /upload " + 4096 chars = 13 + 4096 = 4109 chars.
        assert!(
            s.len() <= "POST /upload ".len() + 4096,
            "expected ≤ 4 KiB body cap, got {}",
            s.len()
        );
    }

    // The model load + predict path needs a real .onnx file so
    // its tests live in `tests/ai_e2e.rs` (gated by AEGIS_AI_MODEL).
    // What we cover here is the shape transforms.
}
