//! `/api/ai/enabled` — runtime on/off for the AI detector.
//!
//! AI doesn't live in the `DetectorClass` bitmask the rest of
//! the detectors use (it's feature-gated and bolted on after the
//! 8 fixed regex/heuristic classes). This module owns the
//! parallel knob: a `Send + Sync + 'static` toggle that the
//! audit-mutated `PUT /api/ai/enabled` handler in `aegis-proxy`
//! flips hot, and that the AI detector reads on every request.
//!
//! Same indirection as
//! [`UpstreamWriter`](crate::api::upstreams_config::UpstreamWriter)
//! and [`RouteWriter`](crate::api::routes_config::RouteWriter):
//! `aegis-control` defines the trait, the proxy boot path stashes
//! an `Arc<AtomicBool>` (the live handle the AiDetector reads),
//! and the handler flips it through this trait so test bundles
//! that don't wire the proxy can fake it without pulling the
//! real detector.

#![allow(dead_code)]

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use serde::{Deserialize, Serialize};

/// `PUT /api/ai/enabled` body.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AiEnabledPatch {
    pub enabled: bool,
}

/// Read-only snapshot — `GET /api/ai/enabled`.
#[derive(Clone, Debug, Serialize)]
pub struct AiEnabledView {
    pub enabled: bool,
    /// `false` when the binary was built without `--features ai`
    /// or `cfg.ai.enabled = false` at boot. The toggle stays
    /// inert in that case — flipping it has no effect because
    /// the detector isn't in the chain.
    pub feature_present: bool,
}

/// Bridge to the live `AtomicBool` the AiDetector reads.
///
/// Production impl is `Arc<AtomicBool>` (the handle returned by
/// `AiDetector::runtime_toggle()`); tests can substitute their
/// own type to verify the handler shape without an ONNX model.
pub trait AiToggleWriter: Send + Sync {
    fn set(&self, enabled: bool);
    fn get(&self) -> bool;
}

// Impl on the bare `AtomicBool` (not `Arc<AtomicBool>`) so
// `Arc<AtomicBool>` can be coerced to `Arc<dyn AiToggleWriter>`
// via Rust's standard unsized-pointer coercion. With the impl on
// `Arc<AtomicBool>` the cast doesn't work because the trait
// would need to be implemented on the *pointee*.
impl AiToggleWriter for AtomicBool {
    fn set(&self, enabled: bool) {
        self.store(enabled, Ordering::Relaxed);
    }
    fn get(&self) -> bool {
        self.load(Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------
// 2026-05-25 — `/api/ai/threshold` — runtime P(Attack) gate.
// ---------------------------------------------------------------------------

/// `PUT /api/ai/threshold` body. `threshold` is the minimum P(Attack) the
/// AI verdict must clear to count as malicious (0.0–1.0). Higher = fewer
/// false positives / fewer catches.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AiThresholdPatch {
    pub threshold: f32,
}

/// Read-only snapshot — `GET /api/ai/threshold`.
#[derive(Clone, Debug, Serialize)]
pub struct AiThresholdView {
    pub threshold: f32,
    /// `false` when the binary lacks `--features ai` / no model at boot —
    /// the knob is inert (the detector isn't in the chain).
    pub feature_present: bool,
}

/// Lowest threshold the API accepts. A floor guards against a fat-finger
/// `0.0` that would make the model flag (near-)everything → FP flood.
pub const AI_THRESHOLD_FLOOR: f32 = 0.5;

/// Bridge to the live `AtomicU32` (f32 bits) the AiDetector reads. Production
/// impl is `Arc<AtomicU32>` (from `AiDetector::runtime_threshold()`); the
/// `set`/`get` convert f32 ↔ bits. Same coercion trick as [`AiToggleWriter`]
/// (impl on the bare atomic so `Arc<AtomicU32>` coerces to the trait object).
pub trait AiThresholdWriter: Send + Sync {
    fn set(&self, threshold: f32);
    fn get(&self) -> f32;
}

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
    fn arc_atomicbool_writes_and_reads() {
        let toggle: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
        // Coerce through `Arc<dyn AiToggleWriter>` — same shape
        // the proxy uses to stash this on `services.ai_toggle`.
        let writer: Arc<dyn AiToggleWriter> = toggle.clone();
        assert!(!writer.get());
        writer.set(true);
        assert!(writer.get());
        // Same Arc → same backing store, even when accessed via the trait.
        assert!(toggle.load(Ordering::Relaxed));
    }

    #[test]
    fn arc_atomicu32_threshold_writes_and_reads_as_f32() {
        let atom: Arc<AtomicU32> = Arc::new(AtomicU32::new(0.5f32.to_bits()));
        let writer: Arc<dyn AiThresholdWriter> = atom.clone();
        assert!((writer.get() - 0.5).abs() < 1e-6);
        writer.set(0.95);
        assert!((writer.get() - 0.95).abs() < 1e-6);
        // Same backing atom — the detector reading f32::from_bits sees it.
        assert!((f32::from_bits(atom.load(Ordering::Relaxed)) - 0.95).abs() < 1e-6);
    }

    #[test]
    fn enabled_patch_round_trips_json() {
        let p = AiEnabledPatch { enabled: true };
        let s = serde_json::to_string(&p).unwrap();
        assert_eq!(s, r#"{"enabled":true}"#);
        let back: AiEnabledPatch = serde_json::from_str(&s).unwrap();
        assert!(back.enabled);
    }

    #[test]
    fn view_serializes_with_feature_present() {
        let v = AiEnabledView { enabled: true, feature_present: true };
        let s = serde_json::to_string(&v).unwrap();
        assert!(s.contains("\"enabled\":true"));
        assert!(s.contains("\"feature_present\":true"));
    }
}
