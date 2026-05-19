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
//! The bundled model is a pure binary classifier
//! (`0` = Normal, `1` = Attack — see `data/ai_model/label_map.json`).
//! The detector emits one tag (`"ai"`) regardless of which class
//! fired.  The code path stays binary; swapping in a multi-class
//! model later only requires updating the `normal_class_idx`
//! passed to `Model::load`.
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

/// Default index of the `Normal` class in the shipped binary
/// model.  See `data/ai_model/label_map.json` — `{"0":"Normal",
/// "1":"Attack"}`.  Override at construction when a future model
/// swaps the layout.
pub const DEFAULT_NORMAL_CLASS_IDX: i64 = 0;

/// Model wrapped in `Arc` so cheap clones share the underlying
/// `ort::Session`.
pub type SharedModel = Arc<Model>;

/// AI-backed attack detector.  Stateless aside from the model
/// handle.  Cheap to clone.
pub struct AiDetector {
    model: SharedModel,
    /// 2026-05-19 — `P(Attack)` threshold the model must clear
    /// before the verdict counts as malicious. Operators tune
    /// this knob to trade FP rate vs detection rate without
    /// retraining:
    ///   - 0.50 (default)  — argmax behaviour: trust the model's
    ///                       binary verdict
    ///   - 0.70 / 0.85 / 0.95 — escalating "high-confidence only"
    ///                       gates that match the calibration
    ///                       advice in `config/dev.yaml`
    /// Falls back to argmax behaviour when the model exporter
    /// doesn't ship a dense probability tensor (legacy sklearn
    /// shape — `prob_attack` is 1.0 when is_attack, 0.0 else).
    threshold: f32,
    /// Per-signal score added to the risk total when AI flags
    /// a request.  Mirrors the score the regex detectors
    /// contribute (50–60 each); set high enough that AI alone
    /// can drive a block when other detectors are silent.
    score: u32,
    /// 2026-05-19 — When true, multiply `score` by `prob_attack`
    /// so high-confidence attacks contribute the full AI score
    /// to the risk aggregator and borderline cases (e.g.
    /// `prob_attack = 0.55`) contribute only a fraction.
    /// Default `false` (preserves backward compatibility — every
    /// hit emits the full `score`).
    scale_score_by_prob: bool,
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
            score: super::scores::ai::AI,
            scale_score_by_prob: false,
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
            score: super::scores::ai::AI,
            scale_score_by_prob: false,
            metrics: Arc::new(NoopAiMetricsSink),
            runtime_enabled: Arc::new(AtomicBool::new(true)),
        }
    }

    /// 2026-05-19 — Enable proportional signal-score scaling.
    /// When on, `Signal.score = round(score * prob_attack)` so a
    /// borderline `prob_attack = 0.55` contributes ~33 (when base
    /// score = 60) instead of the full 60. Default off.
    pub fn with_prob_scaled_score(mut self, on: bool) -> Self {
        self.scale_score_by_prob = on;
        self
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

    /// Render the request into the multi-line shape the
    /// feature extractor + the trained model expect:
    ///
    /// ```text
    /// METHOD /path?query body
    /// User-Agent: …
    /// Cookie: …
    /// Referer: …
    /// ```
    ///
    /// Only the three headers the training pipeline saw are
    /// folded in — scanner UA detection lives in `User-Agent`,
    /// session-shape signals in `Cookie`, and origin-rewrite /
    /// SSRF hints in `Referer`.  Other headers are ignored to
    /// keep the feature distribution close to what the model
    /// was trained on.  The legacy single-line shape still
    /// parses cleanly (extractor handles both).
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

        let mut out = String::with_capacity(64 + body_bytes.len());
        out.push_str(method);
        out.push(' ');
        out.push_str(pq);
        if !body_bytes.is_empty() {
            out.push(' ');
            // Lossy UTF-8 — non-text payloads still produce a
            // string suitable for regex feature counts, which
            // is what the training pipeline did.
            let body = String::from_utf8_lossy(body_bytes);
            out.push_str(&body);
        }

        // Headers the training pipeline included.  Skip silently
        // when a header is missing or its value isn't valid
        // UTF-8 (regexes only run on the textual portion).
        for hdr in ["user-agent", "cookie", "referer"] {
            if let Some(value) = req.headers.get(hdr).and_then(|v| v.to_str().ok()) {
                out.push('\n');
                // RFC 9110 header names are case-insensitive;
                // emit the canonical spelling the training set
                // used so the textual line shape matches.
                let canonical = match hdr {
                    "user-agent" => "User-Agent",
                    "cookie"     => "Cookie",
                    "referer"    => "Referer",
                    _ => hdr,
                };
                out.push_str(canonical);
                out.push_str(": ");
                out.push_str(value);
            }
        }

        out
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

                // 2026-05-19 — Gate on `prob_attack` (probability that
                // the request is malicious, regardless of which class
                // won argmax) instead of the previous
                // `is_attack && confidence >= threshold` shape. Two
                // benefits:
                //   1. `threshold` is interpretable: it's the minimum
                //      P(Attack) the operator accepts as evidence of an
                //      attack. 0.5 == argmax behaviour, 0.85/0.95 ==
                //      "high-confidence only" gating.
                //   2. Multi-class model upgrades are transparent:
                //      P(Attack) = 1 - P(Normal) regardless of K, so
                //      future `[Normal, SQLi, XSS, RCE, ...]` models
                //      plug in without changing the gate.
                tracing::trace!(
                    prob_attack = p.prob_attack,
                    class_idx = p.class_idx,
                    threshold = self.threshold,
                    latency_us = p.latency_us,
                    "ai prediction",
                );

                if p.prob_attack >= self.threshold {
                    // Score contribution: full base score, or scaled by
                    // P(Attack) when the operator opted into smooth
                    // risk-aggregator semantics via
                    // `with_prob_scaled_score(true)`.
                    let signal_score = if self.scale_score_by_prob {
                        ((self.score as f32) * p.prob_attack).round() as u32
                    } else {
                        self.score
                    };
                    vec![Signal {
                        score: signal_score,
                        tag: "ai".into(),
                        field: "request".into(),
                    }]
                } else {
                    if p.is_attack {
                        // Model's argmax committed to "attack" but
                        // P(Attack) was below the operator's gate —
                        // count the fall-through so operators can tune
                        // the threshold from data.
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

    #[test]
    fn build_request_string_folds_in_user_agent() {
        let m = http::Method::GET;
        let u: http::Uri = "/admin".parse().unwrap();
        let mut h = http::HeaderMap::new();
        h.insert(
            "user-agent",
            http::HeaderValue::from_static("sqlmap/1.7"),
        );
        let b = BodyPeek::empty();
        let req = view_for(&m, &u, &h, &b);
        let s = AiDetector::build_request_string(&req);
        assert_eq!(s, "GET /admin\nUser-Agent: sqlmap/1.7");
    }

    #[test]
    fn build_request_string_folds_in_cookie_and_referer() {
        let m = http::Method::GET;
        let u: http::Uri = "/dashboard".parse().unwrap();
        let mut h = http::HeaderMap::new();
        h.insert(
            "user-agent",
            http::HeaderValue::from_static("Mozilla/5.0"),
        );
        h.insert("cookie", http::HeaderValue::from_static("sid=abc"));
        h.insert(
            "referer",
            http::HeaderValue::from_static("https://example.com/"),
        );
        let b = BodyPeek::empty();
        let req = view_for(&m, &u, &h, &b);
        let s = AiDetector::build_request_string(&req);
        // Order is User-Agent → Cookie → Referer (the order
        // build_request_string iterates).
        assert!(s.contains("\nUser-Agent: Mozilla/5.0"));
        assert!(s.contains("\nCookie: sid=abc"));
        assert!(s.contains("\nReferer: https://example.com/"));
    }

    // The model load + predict path needs a real .onnx file so
    // its tests live in `tests/ai_e2e.rs` (gated by AEGIS_AI_MODEL).
    // What we cover here is the shape transforms.
}
