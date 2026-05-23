//! Batch-backed AI detector.
//!
//! Same verdict semantics, tag (`"ai"`), score, threshold gate, runtime
//! toggle, and fail-open contract as [`super::AiDetector`] — the only
//! difference is *where* inference runs: instead of a per-request
//! `Mutex<Session>::run([1, 27])`, this routes the feature vector through
//! the in-process batch accumulator ([`super::batch`]) so concurrent
//! requests share a single `[N, 27]` forward pass.
//!
//! The sync `Detector::inspect` bridges to the async accumulator with
//! `block_in_place`; [`BatchService::classify`] sheds + times out under
//! overload so a burst can't park unbounded worker threads (see
//! `super::batch` for the load-safety rationale).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use aegis_core::pipeline::RequestView;

use crate::detectors::{Detector, Signal};

use super::{
    fallback_reason, features, AiDetector, AiMetricsSink, BatchService, NoopAiMetricsSink,
};

/// AI detector backed by the in-process batch accumulator. Cheap to
/// clone — holds a [`BatchService`] handle (an `mpsc::Sender`).
pub struct BatchAiDetector {
    batch: BatchService,
    /// Minimum `P(Attack)` for the verdict to count — same meaning as
    /// [`super::AiDetector`]'s threshold.
    threshold: f32,
    /// Per-hit score added to the request's risk total.
    score: u32,
    /// When true, scale the emitted score by `prob_attack`.
    scale_score_by_prob: bool,
    metrics: Arc<dyn AiMetricsSink>,
    /// Runtime on/off, flipped by `PUT /api/ai/enabled`. Mirrors
    /// [`super::AiDetector`] so the dashboard AI card controls batch mode
    /// identically. Seeded from `cfg.ai.enabled` at boot.
    runtime_enabled: Arc<AtomicBool>,
}

impl BatchAiDetector {
    /// Build a detector around a running batch service.
    pub fn new(batch: BatchService, threshold: f32, score: u32) -> Self {
        Self {
            batch,
            threshold,
            score,
            scale_score_by_prob: false,
            metrics: Arc::new(NoopAiMetricsSink),
            runtime_enabled: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Enable proportional signal-score scaling (`score * prob_attack`).
    pub fn with_prob_scaled_score(mut self, on: bool) -> Self {
        self.scale_score_by_prob = on;
        self
    }

    /// Wire a metrics sink (boot path; tests leave the no-op default).
    pub fn with_metrics(mut self, sink: Arc<dyn AiMetricsSink>) -> Self {
        self.metrics = sink;
        self
    }

    /// Clone the runtime-toggle handle for the control plane (the
    /// dashboard AI enable/disable flips this).
    pub fn runtime_toggle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.runtime_enabled)
    }

    /// Seed the initial runtime-toggle value (defaults to `true`).
    pub fn with_runtime_enabled(self, enabled: bool) -> Self {
        self.runtime_enabled.store(enabled, Ordering::Relaxed);
        self
    }
}

impl Detector for BatchAiDetector {
    fn id(&self) -> &'static str {
        "ai"
    }

    fn inspect(&self, req: &RequestView<'_>) -> Vec<Signal> {
        // Runtime gate — when off, skip feature extraction + inference.
        if !self.runtime_enabled.load(Ordering::Relaxed) {
            return Vec::new();
        }

        // Render + extract features locally (cheap, no model). Reuse
        // AiDetector's renderer so single and batch modes feed the model
        // the exact same string — no drift.
        let request_str = AiDetector::build_request_string(req);
        let feats = features::extract_features(&request_str);

        // Bridge sync → async. `block_in_place` parks this worker for the
        // batched round-trip while the runtime spawns a replacement to
        // keep serving; `classify` sheds/timeouts to bound the wait.
        let batch = self.batch.clone();
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async move { batch.classify(feats).await })
        });

        match result {
            Ok(p) => {
                let lat_seconds = (p.latency_us as f64) / 1_000_000.0;
                self.metrics.record_prediction(p.is_attack, lat_seconds);

                if p.prob_attack >= self.threshold {
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
                        self.metrics
                            .record_fallback(fallback_reason::LOW_CONFIDENCE);
                    }
                    Vec::new()
                }
            }
            Err(e) => {
                // Overload-shed and inference/timeout errors both collapse
                // to fail-open — the request flows on through the chain.
                self.metrics
                    .record_fallback(fallback_reason::INFERENCE_ERROR);
                tracing::trace!(error = ?e, "ai batch detector — fail-open");
                Vec::new()
            }
        }
    }
}
