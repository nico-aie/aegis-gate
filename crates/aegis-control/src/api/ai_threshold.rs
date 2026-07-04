//! `/api/ai/confidence` — runtime `confidence_threshold` for the AI
//! detector.
//!
//! Sibling of [`ai_toggle`](crate::api::ai_toggle): the same indirection
//! pattern (control plane defines the trait, proxy boot stashes an
//! `Arc<AtomicU32>` storing `f32::to_bits`, audit-mutated
//! `PUT /api/ai/confidence` flips it hot) for the `P(Attack)` gate the
//! data plane reads each inference. Letting operators tune this knob
//! from the dashboard trades FP rate vs detection rate without rebuilding
//! the detector or restarting the proxy.
//!
//! Why a separate writer instead of folding into `AiToggleWriter`:
//! the toggle is `AtomicBool`, the threshold is `f32` encoded in
//! `AtomicU32`. The two atomics travel together at the wiring sites but
//! have different storage shapes; one trait per shape keeps the data
//! plane's hot-path read symmetrical and the test fakes trivial.


use std::sync::atomic::{AtomicU32, Ordering};

use serde::{Deserialize, Serialize};

/// `PUT /api/ai/confidence` body — the new gate the operator wants live.
/// Validated in [0.0, 1.0] at the handler before any write hits the
/// runtime atomic or the persisted config doc.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AiConfidencePatch {
    pub confidence_threshold: f32,
}

/// Read-only snapshot — `GET /api/ai/confidence`.
///
/// `confidence_threshold` is the **live** value the data plane is reading
/// right now (from the shared `AtomicU32`); `default` is the value loaded
/// from `cfg.ai.confidence_threshold` at boot, so the dashboard can show
/// both "current" and "what config says" without re-parsing YAML on the
/// frontend.
#[derive(Clone, Debug, Serialize)]
pub struct AiThresholdView {
    pub confidence_threshold: f32,
    pub default: f32,
    /// `false` when the binary was built without `--features ai`. The
    /// PUT still writes to the config doc + the atomic so a later
    /// feature-rebuild picks the operator's choice up, but the live
    /// detector isn't in the chain to honour it.
    pub feature_present: bool,
}

/// Bridge to the live `AtomicU32` the AI detector reads (storing the
/// `f32` gate as `to_bits`/`from_bits`).
///
/// Production impl: `Arc<AtomicU32>` returned by
/// `AiDetector::runtime_threshold()`. Tests can supply their own fake to
/// exercise the handler without an ONNX model. Mirrors
/// [`AiToggleWriter`](crate::api::ai_toggle::AiToggleWriter).
pub trait AiThresholdWriter: Send + Sync {
    fn set(&self, threshold: f32);
    fn get(&self) -> f32;
}

// Impl on the bare `AtomicU32` (not `Arc<AtomicU32>`) so
// `Arc<AtomicU32>` coerces to `Arc<dyn AiThresholdWriter>` via Rust's
// standard unsized-pointer coercion. With the impl on `Arc<AtomicU32>`
// the cast doesn't work — the trait would need to be on the pointee.
// Same trick `AiToggleWriter` uses against `AtomicBool`.
impl AiThresholdWriter for AtomicU32 {
    fn set(&self, threshold: f32) {
        self.store(threshold.to_bits(), Ordering::Relaxed);
    }
    fn get(&self) -> f32 {
        f32::from_bits(self.load(Ordering::Relaxed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn arc_atomicu32_writes_and_reads_as_threshold_writer() {
        let cell: Arc<AtomicU32> = Arc::new(AtomicU32::new(0.85_f32.to_bits()));
        // Same coercion the proxy uses to stash this on
        // `services.ai_threshold`.
        let writer: Arc<dyn AiThresholdWriter> = cell.clone();
        assert!((writer.get() - 0.85).abs() < 1e-6);
        writer.set(0.50);
        assert!((writer.get() - 0.50).abs() < 1e-6);
        // Same Arc → same backing store, even through the trait object.
        assert!((f32::from_bits(cell.load(Ordering::Relaxed)) - 0.50).abs() < 1e-6);
    }

    #[test]
    fn patch_round_trips_json() {
        let p = AiConfidencePatch { confidence_threshold: 0.7 };
        let s = serde_json::to_string(&p).unwrap();
        assert_eq!(s, r#"{"confidence_threshold":0.7}"#);
        let back: AiConfidencePatch = serde_json::from_str(&s).unwrap();
        assert!((back.confidence_threshold - 0.7).abs() < 1e-6);
    }

    #[test]
    fn view_serializes_current_default_feature_present() {
        let v = AiThresholdView {
            confidence_threshold: 0.7,
            default: 0.85,
            feature_present: true,
        };
        let s = serde_json::to_string(&v).unwrap();
        assert!(s.contains("\"confidence_threshold\":0.7"));
        assert!(s.contains("\"default\":0.85"));
        assert!(s.contains("\"feature_present\":true"));
    }
}
