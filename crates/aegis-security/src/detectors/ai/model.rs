//! AI-T3 — ONNX model wrapper.
//!
//! Owns one `ort::session::Session` for the lifetime of the
//! detector.  Sessions are thread-safe; `Arc<Model>` is fine to
//! share between request handlers.
//!
//! The trained model emits two outputs:
//!
//! - `label` of shape `[batch]` — `i64` class index per row
//!   (`0` = Normal, `1` = Attack for the bundled binary model).
//! - `probabilities` of shape `[batch, K]` — `f32` softmax row,
//!   one column per class (`[P(Normal), P(Attack)]` for the
//!   binary model).
//!
//! Verdict is binary: `class_idx != normal_class_idx` ⇒ attack.
//! `confidence` is the top-1 softmax probability when the
//! `probabilities` output is exposed as a dense tensor; falls
//! back to `1.0` (i.e. always passes the threshold gate) when
//! the model exporter emitted the legacy
//! `Sequence<Map<i64, f32>>` shape.

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
    /// bundled binary model `normal_class_idx == 0`.  When the
    /// underlying model swaps to a different layout we just flip
    /// the configured normal index — no other plumbing changes.
    pub is_attack: bool,
    /// Top-1 softmax probability when the model exposes a dense
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
    /// Default 0 for the shipped binary model.
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

        // Build a 1×NUM_FEATURES input matrix.
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
/// output.
///
/// The bundled binary model exports `probabilities` as a dense
/// `[batch, K]` `f32` tensor — we extract row 0 and index by
/// `class_idx`.  Older sklearn exporters emit it as
/// `Sequence<Map<i64, f32>>`, which the public `ort` API can't
/// decode today; in that case we return `None` and the detector
/// treats the threshold gate as a no-op (the model committed to
/// a class via argmax, so we trust it).
fn extract_confidence(outputs: &SessionOutputs, class_idx: i64) -> Option<f32> {
    if class_idx < 0 {
        return None;
    }
    let entry = outputs.get("probabilities")?;
    // Batch is always 1 (the WAF runs inference per request), so
    // `data` is the K-element row for the single sample, in
    // class-index order.  We don't need to read the shape — just
    // index by `class_idx` and let `get` bound-check.
    let (_shape, data) = entry.try_extract_tensor::<f32>().ok()?;
    data.get(class_idx as usize)
        .filter(|p| p.is_finite())
        .copied()
}
