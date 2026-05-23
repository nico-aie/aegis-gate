//! ONNX model wrapper with batch inference support.
//!
//! ## Modes
//!
//! - **ONNX mode**: loads a real `.onnx` model via `ort`.
//!   Input: `"X"` shape `[batch, 27]` float32.
//!   Outputs: `"label"` shape `[batch]` int64,
//!            `"probabilities"` shape `[batch, K]` float32.
//!
//! - **Mock mode**: no file needed.  Predictions computed from a
//!   lightweight heuristic over the feature vector — good for load
//!   testing the batching and transport stack without a trained model.
//!
//! ## Thread safety
//!
//! `Model` is `Send + Sync`.  The ORT session is wrapped in a `Mutex`
//! because `ort::Session::run` requires `&mut self`; ORT's C++ runtime
//! is thread-safe, the mutex is just to satisfy the borrow checker.
//! For true parallel inference, instantiate multiple `Model`s (one per
//! worker); the server does this automatically with `--workers N`.

use std::path::Path;
use std::sync::Mutex;
use std::time::Instant;

use ndarray::Array2;
use thiserror::Error;

use crate::features::NUM_FEATURES;

// ── Error type ───────────────────────────────────────────────────────────────

#[derive(Error, Debug)]
pub enum ModelError {
    #[error("model file not found: {0}")]
    NotFound(String),
    #[error("failed to build ORT session: {0}")]
    Build(String),
    #[error("failed to load ORT session: {0}")]
    Load(String),
    #[error("inference error: {0}")]
    Inference(String),
    #[error("unexpected output shape: {0}")]
    Output(String),
}

// ── Prediction ───────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct Prediction {
    /// Argmax class index (0 = Normal for the bundled binary model).
    #[allow(dead_code)]
    pub class_idx: i64,
    /// True when `class_idx != normal_class_idx`.
    pub is_attack: bool,
    /// P(Attack) = 1 − P(Normal).  Use this for threshold gating.
    pub prob_attack: f32,
    /// Per-sample wall-clock (µs) — total batch time / batch size.
    #[allow(dead_code)]
    pub latency_us: u64,
}

// ── Internal enum for ONNX vs. mock ─────────────────────────────────────────

pub struct Model {
    inner: ModelInner,
    normal_class_idx: i64,
    pub threshold: f32,
}

enum ModelInner {
    Onnx(Mutex<ort::session::Session>),
    Mock,
}

// Implement Send + Sync manually because raw pointers inside Mutex<Session>
// are !Send by default in some ort versions — the ORT runtime IS thread-safe.
// Safety: ORT sessions are documented to be safe across threads.
unsafe impl Send for ModelInner {}
unsafe impl Sync for ModelInner {}

impl Model {
    /// Load an ONNX model from disk.
    pub fn load(path: &Path, normal_class_idx: i64, threshold: f32) -> Result<Self, ModelError> {
        if !path.exists() {
            return Err(ModelError::NotFound(path.display().to_string()));
        }
        let session = ort::session::Session::builder()
            .map_err(|e| ModelError::Build(e.to_string()))?
            .commit_from_file(path)
            .map_err(|e| ModelError::Load(e.to_string()))?;

        Ok(Self {
            inner: ModelInner::Onnx(Mutex::new(session)),
            normal_class_idx,
            threshold,
        })
    }

    /// Create a mock model (no file required).
    pub fn mock(normal_class_idx: i64, threshold: f32) -> Self {
        Self {
            inner: ModelInner::Mock,
            normal_class_idx,
            threshold,
        }
    }

    /// Returns `"onnx"` or `"mock"`.
    pub fn mode(&self) -> &'static str {
        match &self.inner {
            ModelInner::Onnx(_) => "onnx",
            ModelInner::Mock    => "mock",
        }
    }

    /// Run batch inference.
    ///
    /// # Arguments
    /// * `features` — slice of 27-element feature vectors, one per request.
    ///
    /// Returns one `Prediction` per input row in the same order.
    pub fn predict_batch(
        &self,
        features: &[[f32; NUM_FEATURES]],
    ) -> Result<Vec<Prediction>, ModelError> {
        let n = features.len();
        if n == 0 {
            return Ok(vec![]);
        }

        match &self.inner {
            ModelInner::Mock => Ok(self.predict_batch_mock(features)),
            ModelInner::Onnx(mutex) => self.predict_batch_onnx(mutex, features),
        }
    }

    // ── Mock heuristic ───────────────────────────────────────────────────────

    /// Lightweight heuristic: attack signal = weighted sum of relevant features.
    /// No model file needed.  Good for testing the batching / transport stack.
    fn predict_batch_mock(&self, features: &[[f32; NUM_FEATURES]]) -> Vec<Prediction> {
        features.iter().map(|f| {
            // Feature indices for attack signals (see features.rs layout):
            //  15 sql_keyword   16 xss   17 path_traversal  18 cmd_injection
            //  19 scanner       20 ssrf  21 php              22 null_byte
            //  23 hex_literal   24 crlf  25 double_encode    26 ssti
            let signal: f32 = f[15] * 0.15 + f[16] * 0.15 + f[17] * 0.1
                + f[18] * 0.15 + f[19] * 0.2  + f[20] * 0.1
                + f[21] * 0.05 + f[22] * 0.05 + f[24] * 0.05;
            let prob_attack = signal.clamp(0.0, 1.0);
            let is_attack   = prob_attack >= self.threshold;
            Prediction {
                class_idx:  if is_attack { 1 } else { 0 },
                is_attack,
                prob_attack,
                latency_us: 0,
            }
        }).collect()
    }

    // ── ONNX batch inference ─────────────────────────────────────────────────

    fn predict_batch_onnx(
        &self,
        mutex: &Mutex<ort::session::Session>,
        features: &[[f32; NUM_FEATURES]],
    ) -> Result<Vec<Prediction>, ModelError> {
        use ort::{inputs, value::Tensor};

        let n = features.len();
        let started = Instant::now();

        // Build [n, NUM_FEATURES] input matrix.
        let mut mat = Array2::<f32>::zeros((n, NUM_FEATURES));
        for (i, row) in features.iter().enumerate() {
            for (j, &v) in row.iter().enumerate() {
                mat[[i, j]] = v;
            }
        }
        let input = Tensor::from_array(mat)
            .map_err(|e| ModelError::Inference(format!("tensor build: {e}")))?;

        let mut session = mutex
            .lock()
            .map_err(|_| ModelError::Inference("session mutex poisoned".into()))?;

        let outputs = session
            .run(inputs!["X" => input])
            .map_err(|e| ModelError::Inference(e.to_string()))?;

        let latency_us = started.elapsed().as_micros() as u64;
        let per_us     = latency_us / n as u64;

        // ── Extract labels [n] ───────────────────────────────────────────────
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

        // ── Extract probabilities [n, K] — optional ──────────────────────────
        let (probs, k): (Vec<f32>, usize) = outputs
            .get("probabilities")
            .and_then(|e| e.try_extract_tensor::<f32>().ok())
            .and_then(|(shape, data)| {
                let k = *shape.get(1)? as usize;
                (data.len() == n * k).then(|| (data.to_vec(), k))
            })
            .unwrap_or_else(|| (vec![], 0));

        // ── Build Prediction per sample ──────────────────────────────────────
        let normal = self.normal_class_idx as usize;
        let results = labels
            .into_iter()
            .enumerate()
            .map(|(i, class_idx)| {
                let is_attack = class_idx != self.normal_class_idx;
                let prob_attack = if k > 0 {
                    let row = &probs[i * k..(i + 1) * k];
                    let p_normal = row.get(normal).copied().unwrap_or(0.0);
                    (1.0_f32 - p_normal).clamp(0.0, 1.0)
                } else {
                    if is_attack { 1.0 } else { 0.0 }
                };
                Prediction { class_idx, is_attack, prob_attack, latency_us: per_us }
            })
            .collect();

        Ok(results)
    }
}
