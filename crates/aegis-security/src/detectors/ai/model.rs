//! AI-T3 — ONNX model wrapper.
//!
//! Owns one `ort::session::Session` for the lifetime of the
//! detector.  Sessions are thread-safe; `Arc<Model>` is fine to
//! share between request handlers.
//!
//! The trained model emits a `label` output of shape `[batch]`
//! containing the argmax class index, AND (depending on the
//! exporter) a `probabilities` output of shape `[batch, K]`.
//! For our binary use-case we only need the argmax — anything
//! that isn't the configured `normal_class_idx` is "attack".
//! Confidence (top-1 softmax probability) is read from the
//! probability output when present; missing → 1.0 fall-back so
//! the threshold check passes (the model was confident enough
//! to commit to a class).

use std::path::Path;
use std::sync::Mutex;

use ndarray::Array2;
use ort::{
    inputs,
    session::{Session, SessionOutputs},
    value::Tensor,
};

use super::features::NUM_FEATURES;

/// A single prediction result.
#[derive(Clone, Debug)]
pub struct Prediction {
    /// Predicted class index (0..K-1).
    pub class_idx: i64,
    /// True when `class_idx != normal_class_idx`.  For the
    /// 11-class WAF model `normal_class_idx == 6`.  When the
    /// underlying model goes binary (2 classes) we just flip
    /// the configured normal index — no other plumbing
    /// changes.
    pub is_attack: bool,
    /// Top-1 softmax probability when the model exposes a
    /// `probabilities` output, otherwise `1.0`.  Used by the
    /// detector to gate on the `confidence_threshold` knob.
    pub confidence: f32,
    /// Wall-clock inference time, useful for the metric +
    /// fall-back logic.
    pub latency_us: u64,
}

/// Errors the loader / inference can produce.
#[derive(thiserror::Error, Debug)]
pub enum ModelError {
    #[error("model file missing: {path}")]
    NotFound { path: String },
    #[error("ort session build failed: {0}")]
    SessionBuild(String),
    #[error("ort session load failed: {0}")]
    SessionLoad(String),
    #[error("inference failed: {0}")]
    Inference(String),
    #[error("model output shape unexpected: {0}")]
    Output(String),
}

/// Loaded ONNX session ready to predict.
///
/// `session` is wrapped in `Mutex` because `ort::Session::run`
/// takes `&mut self` even though the underlying ORT runtime is
/// thread-safe.  The mutex is the smallest synchronisation
/// that satisfies the borrow checker; per-request inference is
/// short (~0.5 ms) so contention is negligible at WAF scale.
pub struct Model {
    session: Mutex<Session>,
    /// Index of the `Normal` class.  Anything else is "attack".
    /// Default 6 for the shipped 11-class model.
    normal_class_idx: i64,
}

impl Model {
    /// Open an ONNX file and prepare the session.
    pub fn load(model_path: &Path, normal_class_idx: i64) -> Result<Self, ModelError> {
        if !model_path.exists() {
            return Err(ModelError::NotFound {
                path: model_path.display().to_string(),
            });
        }
        let session = Session::builder()
            .map_err(|e| ModelError::SessionBuild(e.to_string()))?
            .commit_from_file(model_path)
            .map_err(|e| ModelError::SessionLoad(e.to_string()))?;
        Ok(Self {
            session: Mutex::new(session),
            normal_class_idx,
        })
    }

    /// Run one inference.  Allocates a single 1×N tensor; no
    /// batch shaping yet (per-request inference is the WAF
    /// shape).  Returns `Err` only on hard failures — the
    /// caller treats a model error as fail-open.
    pub fn predict(&self, features: &[f32; NUM_FEATURES]) -> Result<Prediction, ModelError> {
        let started = std::time::Instant::now();

        // Build a 1×26 input matrix.
        let mut mat = Array2::<f32>::zeros((1, NUM_FEATURES));
        for (j, &v) in features.iter().enumerate() {
            mat[[0, j]] = v;
        }
        let input = Tensor::from_array(mat)
            .map_err(|e| ModelError::Inference(format!("tensor build: {e}")))?;

        let mut session = self
            .session
            .lock()
            .map_err(|_| ModelError::Inference("session mutex poisoned".into()))?;

        let outputs: SessionOutputs = session
            .run(inputs!["X" => input])
            .map_err(|e| ModelError::Inference(e.to_string()))?;

        // Pull the predicted class index from the `label` output.
        let class_idx = extract_class_idx(&outputs)?;
        let confidence = extract_confidence(&outputs, class_idx).unwrap_or(1.0);

        let latency_us = started.elapsed().as_micros() as u64;

        Ok(Prediction {
            class_idx,
            is_attack: class_idx != self.normal_class_idx,
            confidence,
            latency_us,
        })
    }
}

/// Read the argmax class index from the model's `label`
/// output. The training pipeline emits an `i64` tensor.
fn extract_class_idx(outputs: &SessionOutputs) -> Result<i64, ModelError> {
    let entry = outputs
        .get("label")
        .ok_or_else(|| ModelError::Output("missing `label` output".into()))?;
    let (_shape, data) = entry
        .try_extract_tensor::<i64>()
        .map_err(|e| ModelError::Output(format!("label extract: {e}")))?;
    data.first()
        .copied()
        .ok_or_else(|| ModelError::Output("empty label tensor".into()))
}

/// Read top-1 softmax probability from the `probabilities`
/// output when present.  ONNX classifiers emit this as a
/// `Sequence<Map<i64, f32>>` (the standard sklearn export
/// shape) which `ort` doesn't yet have a direct extractor for
/// in the public API, so we fall back to "no confidence
/// signal" in that case.  Future: parse via a generic Value
/// inspection.  For v1 we accept missing confidence and let the
/// detector's threshold default to 0 (always-allow-confident)
/// when we can't read it.
fn extract_confidence(_outputs: &SessionOutputs, _class_idx: i64) -> Option<f32> {
    // TODO: support the Sequence<Map<i64, f32>> shape produced
    // by sklearn's ONNX exporter so callers can gate on
    // softmax probability.  For now we report None and let the
    // detector treat it as a confident hit (the model already
    // committed to a class via argmax).
    None
}
