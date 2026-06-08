//! `/api/ai/reload` — hot-reload the AI model from its on-disk path.
//!
//! A **per-node, local** action: each node re-reads its *own*
//! `cfg.ai.model_path` and atomically swaps the new model into the live
//! detector. It is deliberately NOT routed through the cluster config plane
//! (unlike `PUT /api/ai/enabled`) — the model file is node-local state, so on a
//! multi-node fleet the operator (or their deploy automation) drops the new
//! file and calls this endpoint on each node.
//!
//! Same indirection as [`AiToggleWriter`](crate::api::ai_toggle::AiToggleWriter):
//! `aegis-control` defines the trait + wire shapes; the proxy boot path stashes
//! a concrete implementation that owns the hot-swappable model handle, so test
//! bundles can fake it without an ONNX runtime.

#![allow(dead_code)]

use serde::Serialize;

/// Result of a reload attempt — also the `POST /api/ai/reload` response body.
///
/// On failure the previously-loaded model is left untouched and still serving;
/// the operator sees `ok: false` + `error` and nothing in the data plane
/// changed.
#[derive(Clone, Debug, Serialize)]
pub struct AiReloadReport {
    pub ok: bool,
    /// The path the model was (re)loaded from.
    pub model_path: String,
    /// Sessions in the freshly-loaded pool. Present on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sessions: Option<usize>,
    /// Wall-clock load time in milliseconds. Present on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load_ms: Option<u64>,
    /// Failure reason. Present on failure — the running model is kept.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Read-only snapshot — `GET /api/ai/reload`.
#[derive(Clone, Debug, Serialize)]
pub struct AiReloadView {
    /// `false` when the binary lacks `--features ai` or no model loaded at boot
    /// (nothing to reload).
    pub feature_present: bool,
    /// Configured model path, when a model is loaded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_path: Option<String>,
}

/// Bridge to the live, hot-swappable model handle.
///
/// The production impl (in `aegis-proxy`) owns the `ArcSwap<Model>` the data
/// plane reads and re-loads from the configured path. The load is blocking
/// (ORT reads the file), so the handler runs [`Self::reload`] on a blocking
/// thread — never on the request path.
pub trait AiReloadWriter: Send + Sync {
    /// The configured model path (for the GET surface / observability).
    fn model_path(&self) -> String;
    /// Load a fresh model from the configured path and atomically swap it in.
    /// On failure the running model is retained. **Blocking** — call from a
    /// blocking context.
    fn reload(&self) -> AiReloadReport;
}
