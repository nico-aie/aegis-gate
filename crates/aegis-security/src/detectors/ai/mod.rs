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
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;

use aegis_core::pipeline::RequestView;

use super::{Detector, Signal};

pub mod batch;
pub mod batch_detector;
pub mod features;
pub mod model;

pub use batch::{batch_spawn, BatchError, BatchService};
pub use batch_detector::BatchAiDetector;
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

/// Shared verdict logic for both the synchronous [`AiDetector`] and the
/// batch-backed [`batch_detector::BatchAiDetector`]: gate on
/// `P(Attack) ≥ threshold`, optionally scale the emitted score by
/// `P(Attack)`, and record the low-confidence fall-through.
///
/// One source of truth so the two detectors can't drift — the gate and
/// the score-scaling rule live here, not copy-pasted into each
/// `inspect()`. Caller is responsible for `record_prediction` (it owns
/// the latency) before calling this.
pub(crate) fn signals_from_prediction(
    p: &Prediction,
    threshold: f32,
    score: u32,
    scale_score_by_prob: bool,
    metrics: &dyn AiMetricsSink,
) -> Vec<Signal> {
    // 2026-05-19 — Gate on `prob_attack` (probability the request is
    // malicious regardless of which class won argmax), not
    // `is_attack && confidence`. `threshold` is then interpretable as the
    // minimum P(Attack) the operator accepts as evidence, and multi-class
    // model upgrades plug in unchanged (P(Attack) = 1 - P(Normal) for any K).
    if p.prob_attack >= threshold {
        // Full base score, or score scaled by P(Attack) when the operator
        // opted into smooth risk-aggregator semantics.
        let signal_score = if scale_score_by_prob {
            ((score as f32) * p.prob_attack).round() as u32
        } else {
            score
        };
        vec![Signal {
            score: signal_score,
            tag: "ai".into(),
            field: "request".into(),
        }]
    } else {
        if p.is_attack {
            // argmax committed to "attack" but P(Attack) was below the
            // operator's gate — count it so the threshold can be tuned
            // from data.
            metrics.record_fallback(fallback_reason::LOW_CONFIDENCE);
        }
        Vec::new()
    }
}

/// Model wrapped in `Arc` so cheap clones share the underlying
/// `ort::Session`.
pub type SharedModel = Arc<Model>;

/// Hot-swappable model handle. The data plane reads the *current* model with
/// one lock-free `.load()` per inference; a reloader atomically `.store()`s a
/// freshly-loaded model. In-flight requests holding the old `Arc` finish on it
/// (RCU), so a swap never stalls or drops a request. See
/// [`AiDetector::model_handle`].
pub type ModelHandle = Arc<ArcSwap<Model>>;

/// AI-backed attack detector.  Stateless aside from the model
/// handle.  Cheap to clone.
pub struct AiDetector {
    /// Swappable so the model can be hot-reloaded without a restart. The read
    /// side (`.load()`) is wait-free; the cost is nanoseconds against a
    /// ~0.5 ms inference, so the indirection is free in practice.
    model: ModelHandle,
    /// 2026-05-29 — runtime-mutable `P(Attack)` threshold. Stored as
    /// `f32::to_bits` in an `AtomicU32` so the dashboard can adjust it
    /// hot via `PUT /api/ai/confidence` without rebuilding the detector
    /// (the model + session pool stay live). Seeded at construction from
    /// the f32 the boot path passes (`cfg.ai.confidence_threshold`).
    /// Read per-inference with a single relaxed load — same hot-path
    /// shape as `runtime_enabled`.
    ///
    /// Operators tune this knob to trade FP rate vs detection rate
    /// without retraining:
    ///   - 0.50  — argmax behaviour: trust the model's binary verdict
    ///   - 0.70 / 0.85 (default) / 0.95 — escalating "high-confidence
    ///     only" gates that match the calibration advice in
    ///     `config/dev.yaml`
    ///
    /// Falls back to argmax behaviour when the model exporter doesn't
    /// ship a dense probability tensor (legacy sklearn shape —
    /// `prob_attack` is 1.0 when is_attack, 0.0 else).
    runtime_threshold: Arc<AtomicU32>,
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
            model: Arc::new(ArcSwap::from_pointee(model)),
            runtime_threshold: Arc::new(AtomicU32::new(threshold.to_bits())),
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
            model: Arc::new(ArcSwap::new(model)),
            runtime_threshold: Arc::new(AtomicU32::new(threshold.to_bits())),
            score: super::scores::ai::AI,
            scale_score_by_prob: false,
            metrics: Arc::new(NoopAiMetricsSink),
            runtime_enabled: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Current `P(Attack)` gate. Reads the runtime-mutable atomic with
    /// a single relaxed load — same shape as `runtime_enabled.load`.
    /// Exposed so callers (the data plane, the dashboard's GET surface)
    /// don't reach into `runtime_threshold` directly.
    pub fn threshold(&self) -> f32 {
        f32::from_bits(self.runtime_threshold.load(Ordering::Relaxed))
    }

    /// Clone of the runtime-threshold handle. Production wiring stashes
    /// this on `DashboardServices` so the audit-mutated
    /// `PUT /api/ai/confidence` handler can update the same atomic the
    /// data plane reads each inference. Mirrors `runtime_toggle`.
    pub fn runtime_threshold(&self) -> Arc<AtomicU32> {
        Arc::clone(&self.runtime_threshold)
    }

    /// Override the initial runtime-threshold value (defaults to the
    /// `threshold` passed to the constructor). Useful for tests that
    /// want to verify the hot-swap path without going through a writer.
    pub fn with_runtime_threshold(self, threshold: f32) -> Self {
        self.runtime_threshold
            .store(threshold.to_bits(), Ordering::Relaxed);
        self
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

    /// Clone of the hot-swappable model handle. The proxy boot path stashes
    /// this so the audit-mutated `POST /api/ai/reload` handler can load a new
    /// model and `.store()` it atomically — the data plane reads the same
    /// [`ArcSwap`] per inference. Mirrors [`Self::runtime_toggle`].
    pub fn model_handle(&self) -> ModelHandle {
        Arc::clone(&self.model)
    }

    /// Atomically replace the live model with `next` (already loaded +
    /// validated by the caller). In-flight inferences finish on the old model;
    /// new ones pick up `next`. Returns the previous model so the caller can
    /// observe/drop it. Used by the reload handler after a successful load.
    pub fn swap_model(&self, next: SharedModel) -> SharedModel {
        self.model.swap(next)
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

    /// Render the request into the multi-line shape the feature
    /// extractor + the trained model expect — a verbatim match of how
    /// `data/ml_waf/build_clean_dataset.py` (`save_csv`) renders each
    /// training row:
    ///
    /// ```text
    /// METHOD /path?query body
    /// User-Agent: …
    /// Cookie: …
    /// …
    /// ```
    ///
    /// - **Body** is capped at 8 KiB (`_MAX_BODY_LEN`) and its CR/LF are
    ///   collapsed to spaces (`make_row` did `\r\n→\n`, `\r→\n`; `save_csv`
    ///   did `\n→space`) so the body stays on the request line. Without
    ///   this, a multi-line body (XML/XXE, multipart, pretty JSON) makes
    ///   the extractor mis-split at the first body newline and lump the
    ///   rest into header text.
    /// - **Headers** folded = `_INCLUDE_HEADERS` exactly (set + canonical
    ///   casing). The 29 features are order-invariant w.r.t. header order
    ///   (`header_count` = `\n` count; `header_entropy` and the pattern
    ///   scans are char-frequency / match counts), so a fixed canonical
    ///   order reproduces the training feature values.
    ///
    /// `pub(crate)` so [`super::batch_detector::BatchAiDetector`] renders
    /// requests identically — one source of truth, no feature drift.
    pub(crate) fn build_request_string(req: &RequestView<'_>) -> String {
        let method = req.method.as_str();
        // Path-and-query, falling back to "/" for empty URIs (already the
        // relative target — matches `_normalize_url` output at training).
        let pq = req
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        // Body: up to 8 KiB (matches `_MAX_BODY_LEN`; features.rs then
        // truncates to MAX_BODY_BYTES). Trim + collapse CR/LF to spaces
        // exactly as the training renderer does. A gzip/deflate body is first
        // inflated (bounded) so the model inspects the real content instead of
        // a high-entropy compressed blob — see `decode_body`.
        let decoded = decode_body(req);
        let body_bytes: &[u8] = decoded.as_deref().unwrap_or_else(|| req.body.peek(8192));
        let body_raw = String::from_utf8_lossy(body_bytes);
        let body = body_raw
            .trim()
            .replace("\r\n", "\n")
            .replace('\r', "\n")
            .replace('\n', " ");

        let mut out = String::with_capacity(96 + body.len());
        out.push_str(method);
        out.push(' ');
        out.push_str(pq);
        if !body.is_empty() {
            out.push(' ');
            out.push_str(&body);
        }

        // Fold the SAME header set the training pipeline kept
        // (`_INCLUDE_HEADERS`), one per line as "Canonical-Key: value".
        // Skip a header that's absent, non-UTF-8, or empty after trim
        // (matches `_filter_headers`' truthiness check).
        for (lower, canonical) in HEADER_FOLD {
            if let Some(value) = req.headers.get(*lower).and_then(|v| v.to_str().ok()) {
                let value = value.trim();
                if value.is_empty() {
                    continue;
                }
                out.push('\n');
                out.push_str(canonical);
                out.push_str(": ");
                out.push_str(value);
            }
        }

        out
    }
}

/// Inflate a gzip/deflate request body so feature extraction sees the real
/// content rather than a high-entropy compressed blob. A compressed body both
/// masks attacks (the pattern scans can't read it) and triggers benign false
/// positives (legitimate gzipped analytics looked like obfuscated payload).
///
/// Bounded against decompression bombs: at most `DECODE_OUT_CAP` bytes are
/// produced regardless of input size or compression ratio, and only the first
/// `COMPRESSED_PEEK` bytes of the body are read. Returns `None` when there is no
/// supported `Content-Encoding` or decoding yields nothing — the caller then
/// falls back to the raw bytes (current behavior), so this can never make a
/// request fail to be inspected.
fn decode_body(req: &RequestView<'_>) -> Option<Vec<u8>> {
    use std::io::Read;
    // Read at most 32 KiB of compressed input and emit at most 8 KiB inflated
    // (= `_MAX_BODY_LEN`; the body is truncated to 8 KiB downstream anyway).
    const COMPRESSED_PEEK: usize = 32 * 1024;
    const DECODE_OUT_CAP: u64 = 8192;

    let enc = req.headers.get("content-encoding")?.to_str().ok()?;
    let enc = enc.trim().to_ascii_lowercase();
    let compressed = req.body.peek(COMPRESSED_PEEK);
    if compressed.is_empty() {
        return None;
    }

    let mut out = Vec::new();
    if enc.contains("gzip") {
        let mut d = flate2::read::GzDecoder::new(compressed).take(DECODE_OUT_CAP);
        let _ = d.read_to_end(&mut out); // partial inflate still useful; bounded by take()
    } else if enc.contains("deflate") {
        let mut d = flate2::read::ZlibDecoder::new(compressed).take(DECODE_OUT_CAP);
        let _ = d.read_to_end(&mut out);
    } else {
        return None;
    }

    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Headers folded into the model's request string — must match
/// `_INCLUDE_HEADERS` in `data/ml_waf/build_clean_dataset.py` exactly
/// (set + canonical casing), or the 29-feature vector (header_count,
/// header_entropy, and the pattern scans over header text) drifts from
/// what the model was trained on. `(lowercase-lookup, canonical-render)`.
const HEADER_FOLD: &[(&str, &str)] = &[
    ("user-agent", "User-Agent"),
    ("cookie", "Cookie"),
    ("referer", "Referer"),
    ("authorization", "Authorization"),
    ("content-type", "Content-Type"),
    ("x-forwarded-for", "X-Forwarded-For"),
    ("x-real-ip", "X-Real-IP"),
    // Classic log4shell / shellshock injection points — fold so the pattern
    // scans (#15-26) can see payloads delivered via these headers. Order is
    // irrelevant to the 29 features (header_count, header_entropy, and the
    // pattern counts are all order-independent); only the set + casing matter.
    ("accept", "Accept"),
    ("accept-language", "Accept-Language"),
    ("accept-encoding", "Accept-Encoding"),
    ("x-api-version", "X-Api-Version"),
    ("x-originating-ip", "X-Originating-IP"),
    ("x-remote-addr", "X-Remote-Addr"),
    ("x-client-ip", "X-Client-IP"),
    ("x-wap-profile", "X-Wap-Profile"),
    ("x-remote-ip", "X-Remote-IP"),
];

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
        // Lock-free read of the current model — wait-free, nanoseconds. A
        // concurrent hot-reload swaps the pointer; this request keeps the
        // model it loaded here for the duration of the call (RCU).
        let model = self.model.load();
        match model.predict(&feats) {
            Ok(p) => {
                let lat_seconds = (p.latency_us as f64) / 1_000_000.0;
                self.metrics.record_prediction(p.is_attack, lat_seconds);
                let threshold = self.threshold();
                tracing::trace!(
                    prob_attack = p.prob_attack,
                    class_idx = p.class_idx,
                    threshold,
                    latency_us = p.latency_us,
                    "ai prediction",
                );
                // Shared gate (prob_attack ≥ threshold + score scaling) —
                // see `signals_from_prediction`.
                signals_from_prediction(
                    &p,
                    threshold,
                    self.score,
                    self.scale_score_by_prob,
                    self.metrics.as_ref(),
                )
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

    fn gzip(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn headers_with(name: &'static str, val: &str) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        h.insert(name, val.parse().unwrap());
        h
    }

    #[test]
    fn build_request_string_inflates_gzip_body() {
        let plain = br#"{"events":[{"e":"page_view","ts":1742}]}"#;
        let m = http::Method::POST;
        let u: http::Uri = "/api/analytics/events".parse().unwrap();
        let h = headers_with("content-encoding", "gzip");
        let b = make_body(&gzip(plain));
        let req = view_for(&m, &u, &h, &b);
        let s = AiDetector::build_request_string(&req);
        assert!(s.contains("page_view"), "gzip body was not inflated: {s:?}");
    }

    #[test]
    fn decode_body_is_bounded_against_zip_bombs() {
        // 1 MiB of zeros compresses to ~1 KiB but must inflate to ≤ 8 KiB.
        let bomb = gzip(&vec![0u8; 1024 * 1024]);
        let m = http::Method::POST;
        let u: http::Uri = "/x".parse().unwrap();
        let h = headers_with("content-encoding", "gzip");
        let b = make_body(&bomb);
        let req = view_for(&m, &u, &h, &b);
        let out = decode_body(&req).expect("some output");
        assert!(out.len() <= 8192, "decompression not capped: {}", out.len());
    }

    #[test]
    fn decode_body_none_without_content_encoding() {
        let m = http::Method::POST;
        let u: http::Uri = "/x".parse().unwrap();
        let h = http::HeaderMap::new();
        let b = make_body(&gzip(b"hello"));
        let req = view_for(&m, &u, &h, &b);
        assert!(decode_body(&req).is_none());
    }

    #[test]
    fn decode_body_falls_back_on_invalid_gzip() {
        // Content-Encoding says gzip but the bytes are not — must not panic, and
        // build_request_string still renders (using the raw bytes).
        let m = http::Method::POST;
        let u: http::Uri = "/x".parse().unwrap();
        let h = headers_with("content-encoding", "gzip");
        let b = make_body(b"not actually gzip data");
        let req = view_for(&m, &u, &h, &b);
        assert!(decode_body(&req).is_none());
        let _ = AiDetector::build_request_string(&req); // must not panic
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
    fn build_request_string_caps_body_at_8kb() {
        // 10 KiB of body — renderer peeks only the first 8 KiB
        // (matches _MAX_BODY_LEN in build_clean_dataset.py).
        let big = vec![b'a'; 10 * 1024];
        let m = http::Method::POST;
        let u: http::Uri = "/upload".parse().unwrap();
        let h = http::HeaderMap::new();
        let b = make_body(&big);
        let req = view_for(&m, &u, &h, &b);
        let s = AiDetector::build_request_string(&req);
        assert!(
            s.len() <= "POST /upload ".len() + 8192,
            "expected ≤ 8 KiB body cap, got {}",
            s.len()
        );
    }

    #[test]
    fn build_request_string_collapses_body_newlines() {
        // Multi-line body (e.g. XML) must stay on the request line so the
        // first '\n' marks where headers begin — CR/LF collapse to spaces.
        let m = http::Method::POST;
        let u: http::Uri = "/api/feedback".parse().unwrap();
        let h = http::HeaderMap::new();
        let b = make_body(b"<?xml version=\"1.0\"?>\r\n<!DOCTYPE x [\n<!ENTITY e SYSTEM \"file:///etc/passwd\">\n]>");
        let req = view_for(&m, &u, &h, &b);
        let s = AiDetector::build_request_string(&req);
        assert!(!s.contains('\n'), "body newlines must be collapsed, got {s:?}");
        assert!(s.starts_with("POST /api/feedback "), "got {s:?}");
        assert!(s.contains("<!ENTITY"), "payload preserved, got {s:?}");
    }

    #[test]
    fn build_request_string_folds_all_include_headers() {
        // Every header in _INCLUDE_HEADERS / HEADER_FOLD must be folded.
        let m = http::Method::GET;
        let u: http::Uri = "/".parse().unwrap();
        let mut h = http::HeaderMap::new();
        h.insert("user-agent", http::HeaderValue::from_static("UA"));
        h.insert("cookie", http::HeaderValue::from_static("sid=1"));
        h.insert("referer", http::HeaderValue::from_static("https://x/"));
        h.insert("authorization", http::HeaderValue::from_static("Bearer t"));
        h.insert("content-type", http::HeaderValue::from_static("application/json"));
        h.insert("x-forwarded-for", http::HeaderValue::from_static("1.2.3.4"));
        h.insert("x-real-ip", http::HeaderValue::from_static("1.2.3.4"));
        // log4shell / shellshock injection-point headers
        h.insert("accept", http::HeaderValue::from_static("*/*"));
        h.insert("accept-language", http::HeaderValue::from_static("en-US"));
        h.insert("accept-encoding", http::HeaderValue::from_static("gzip"));
        h.insert("x-api-version", http::HeaderValue::from_static("v1"));
        h.insert("x-originating-ip", http::HeaderValue::from_static("1.2.3.4"));
        h.insert("x-remote-addr", http::HeaderValue::from_static("1.2.3.4"));
        h.insert("x-client-ip", http::HeaderValue::from_static("1.2.3.4"));
        h.insert("x-wap-profile", http::HeaderValue::from_static("http://x/p.xml"));
        h.insert("x-remote-ip", http::HeaderValue::from_static("1.2.3.4"));
        let b = BodyPeek::empty();
        let req = view_for(&m, &u, &h, &b);
        let s = AiDetector::build_request_string(&req);
        for canon in [
            "User-Agent: UA", "Cookie: sid=1", "Referer: https://x/",
            "Authorization: Bearer t", "Content-Type: application/json",
            "X-Forwarded-For: 1.2.3.4", "X-Real-IP: 1.2.3.4",
            "Accept: */*", "Accept-Language: en-US", "Accept-Encoding: gzip",
            "X-Api-Version: v1", "X-Originating-IP: 1.2.3.4", "X-Remote-Addr: 1.2.3.4",
            "X-Client-IP: 1.2.3.4", "X-Wap-Profile: http://x/p.xml", "X-Remote-IP: 1.2.3.4",
        ] {
            assert!(s.contains(canon), "missing folded header {canon:?} in {s:?}");
        }
        // header_count feature == number of folded lines == 16.
        assert_eq!(features::extract_features(&s)[27], 16.0);
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

    // -------- runtime_threshold hot-swap (no model required) --------
    //
    // signals_from_prediction is the pure verdict gate both detectors
    // route through. We exercise the hot-swap mechanism end-to-end by
    // pulling the live threshold out of an AtomicU32 via the same
    // `threshold()` getter the data plane calls each inference, and
    // checking that updating the shared handle flips the verdict —
    // proving the dashboard PUT path will affect the live gate without
    // a detector rebuild.

    #[test]
    fn runtime_threshold_round_trips_f32_through_atomic_u32() {
        let bits = Arc::new(AtomicU32::new(0.85_f32.to_bits()));
        assert!((f32::from_bits(bits.load(Ordering::Relaxed)) - 0.85).abs() < 1e-6);
        bits.store(0.50_f32.to_bits(), Ordering::Relaxed);
        assert!((f32::from_bits(bits.load(Ordering::Relaxed)) - 0.50).abs() < 1e-6);
    }

    #[test]
    fn hot_swap_changes_verdict_via_shared_handle() {
        // Borderline prediction: prob_attack = 0.60.
        let p = Prediction {
            is_attack: true,
            class_idx: 1,
            confidence: 0.60,
            prob_attack: 0.60,
            latency_us: 1,
        };
        // Shared handle the "detector" and the "writer" both reference.
        let handle = Arc::new(AtomicU32::new(0.85_f32.to_bits()));
        let metrics = NoopAiMetricsSink;

        // At 0.85 the verdict is below the gate — no signal.
        let gate = f32::from_bits(handle.load(Ordering::Relaxed));
        let sigs = signals_from_prediction(&p, gate, 60, false, &metrics);
        assert!(sigs.is_empty(), "0.60 < 0.85 should yield no signal");

        // Writer flips the gate to 0.50 (mimicking PUT /api/ai/confidence).
        handle.store(0.50_f32.to_bits(), Ordering::Relaxed);

        // Same prediction now crosses the gate — emits one "ai" signal.
        let gate = f32::from_bits(handle.load(Ordering::Relaxed));
        let sigs = signals_from_prediction(&p, gate, 60, false, &metrics);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].tag, "ai");
        assert_eq!(sigs[0].score, 60);
    }
}
