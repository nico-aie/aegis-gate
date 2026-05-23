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
    /// Predicted class index (0..K-1) — the model's argmax over
    /// the probability row.
    pub class_idx: i64,
    /// True when `class_idx != normal_class_idx`.  For the
    /// bundled binary model `normal_class_idx == 0`.  When the
    /// underlying model swaps to a different layout we just flip
    /// the configured normal index — no other plumbing changes.
    pub is_attack: bool,
    /// Top-1 softmax probability — `probabilities[class_idx]`.
    /// Equals `prob_attack` when `is_attack == true`, otherwise
    /// equals `prob_normal`. Falls back to `1.0` when the model
    /// doesn't expose a dense `probabilities` tensor.
    pub confidence: f32,
    /// 2026-05-19 — P(Attack) ∈ [0, 1]. Sum of probabilities of
    /// all non-normal classes (== `probabilities[1]` for the
    /// binary model). Use this for threshold-gating in the
    /// detector — independent of which class won argmax. Falls
    /// back to `1.0` if `is_attack` and `0.0` otherwise when
    /// probabilities aren't available.
    pub prob_attack: f32,
    /// Wall-clock inference time, useful for the metric +
    /// fall-back logic.
    pub latency_us: u64,
}

impl Prediction {
    /// Convenience: P(Normal) = 1 - P(Attack).
    #[inline]
    pub fn prob_normal(&self) -> f32 {
        1.0 - self.prob_attack
    }
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
        let is_attack = class_idx != self.normal_class_idx;

        // 2026-05-19 — Extract the full probability row once, then
        // derive both `confidence` (probability of the predicted
        // class) and `prob_attack` (sum of non-normal classes) from
        // it. For the bundled binary model, `prob_attack` reduces
        // to `probabilities[1]`.
        let probs = extract_probabilities(&outputs).unwrap_or_default();
        let confidence = probs
            .get(class_idx as usize)
            .filter(|p| p.is_finite())
            .copied()
            .unwrap_or(1.0);
        let prob_attack = compute_prob_attack(&probs, self.normal_class_idx)
            // Fallback: if probabilities aren't dense, use the
            // argmax label as the only signal. is_attack ⇒ 1.0,
            // else 0.0 — keeps the threshold gate sensible.
            .unwrap_or(if is_attack { 1.0 } else { 0.0 });

        let latency_us = started.elapsed().as_micros() as u64;

        Ok(Prediction {
            class_idx,
            is_attack,
            confidence,
            prob_attack,
            latency_us,
        })
    }

    /// Run batch inference: `n` feature rows in a single
    /// `[n, NUM_FEATURES]` forward pass, returning one `Prediction` per
    /// row in order. This is what the in-process batch accumulator
    /// ([`super::batch`]) calls — amortising the per-call ORT overhead
    /// across the whole batch, which is the whole point of batching.
    /// Same fail-open contract as [`Model::predict`]: a hard error
    /// returns `Err` and the caller treats it as "no signal".
    pub fn predict_batch(
        &self,
        features: &[[f32; NUM_FEATURES]],
    ) -> Result<Vec<Prediction>, ModelError> {
        let n = features.len();
        if n == 0 {
            return Ok(Vec::new());
        }
        let started = std::time::Instant::now();

        // Build the [n, NUM_FEATURES] input matrix.
        let mut mat = Array2::<f32>::zeros((n, NUM_FEATURES));
        for (i, row) in features.iter().enumerate() {
            for (j, &v) in row.iter().enumerate() {
                mat[[i, j]] = v;
            }
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

        // Labels [n].
        let labels: Vec<i64> = {
            let entry = outputs
                .get("label")
                .ok_or_else(|| ModelError::Output("missing `label` output".into()))?;
            let (_shape, data) = entry
                .try_extract_tensor::<i64>()
                .map_err(|e| ModelError::Output(format!("label extract: {e}")))?;
            data.to_vec()
        };
        if labels.len() != n {
            return Err(ModelError::Output(format!(
                "label tensor length {} != batch size {n}",
                labels.len()
            )));
        }

        // Probabilities [n, K] — optional (legacy exporters omit a dense
        // tensor; we fall back to the argmax label per row).
        let (probs, k): (Vec<f32>, usize) = outputs
            .get("probabilities")
            .and_then(|e| e.try_extract_tensor::<f32>().ok())
            .and_then(|(shape, data)| {
                let k = *shape.get(1)? as usize;
                (k > 0 && data.len() == n * k).then(|| (data.to_vec(), k))
            })
            .unwrap_or_default();

        let latency_us = started.elapsed().as_micros() as u64;
        let per_us = latency_us / n as u64;

        let results = labels
            .into_iter()
            .enumerate()
            .map(|(i, class_idx)| {
                let is_attack = class_idx != self.normal_class_idx;
                let (confidence, prob_attack) = if k > 0 {
                    let row = &probs[i * k..(i + 1) * k];
                    let confidence = row
                        .get(class_idx as usize)
                        .filter(|p| p.is_finite())
                        .copied()
                        .unwrap_or(1.0);
                    let prob_attack = compute_prob_attack(row, self.normal_class_idx)
                        .unwrap_or(if is_attack { 1.0 } else { 0.0 });
                    (confidence, prob_attack)
                } else {
                    (1.0, if is_attack { 1.0 } else { 0.0 })
                };
                Prediction {
                    class_idx,
                    is_attack,
                    confidence,
                    prob_attack,
                    latency_us: per_us,
                }
            })
            .collect();

        Ok(results)
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

/// 2026-05-19 — Extract the full probability row from the
/// `probabilities` output. Batch is always 1 (per-request
/// inference) so the returned slice is the K-element row for the
/// single sample, in class-index order. Returns an empty Vec when
/// the model doesn't expose a dense tensor (legacy
/// `Sequence<Map<i64, f32>>` exporters); the caller falls back to
/// the argmax label.
fn extract_probabilities(outputs: &SessionOutputs) -> Option<Vec<f32>> {
    let entry = outputs.get("probabilities")?;
    let (_shape, data) = entry.try_extract_tensor::<f32>().ok()?;
    Some(data.to_vec())
}

/// Compute P(Attack) = 1 - P(Normal) = sum of probabilities
/// across all non-normal classes.
///
/// For the bundled binary model (`normal_class_idx == 0`, classes
/// `[Normal, Attack]`), this reduces to `probs[1]`. For future
/// multi-class layouts (e.g. `[Normal, SQLi, XSS, RCE, …]`), it
/// aggregates every malicious class — operator threshold becomes
/// "model is at least X% sure the request is malicious of any
/// kind", which is what the WAF cares about.
///
/// Returns `None` when probs is empty (rare; only the legacy
/// sklearn `ZipMap` shape that ORT can't decode today).
fn compute_prob_attack(probs: &[f32], normal_class_idx: i64) -> Option<f32> {
    if probs.is_empty() {
        return None;
    }
    let p_normal = if normal_class_idx >= 0 {
        probs
            .get(normal_class_idx as usize)
            .filter(|p| p.is_finite())
            .copied()
            .unwrap_or(0.0)
    } else {
        0.0
    };
    // Clamp to [0, 1] — softmax should already be normalised but
    // sklearn's LogisticRegression isotonic-calibrated output
    // occasionally drifts by 1e-7.
    Some((1.0 - p_normal).clamp(0.0, 1.0))
}
