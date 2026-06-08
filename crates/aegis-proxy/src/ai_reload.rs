//! Concrete AI model hot-reloader (the `ai`-feature side of
//! [`aegis_control::api::ai_reload`]).
//!
//! Owns the live [`ModelHandle`] (`Arc<ArcSwap<Model>>`) the data plane reads
//! per inference, plus the parameters needed to re-load: the on-disk path, the
//! normal-class index, and the session-pool size. On reload it loads a *fresh*
//! model and only swaps it in **on success** — a corrupt or half-written file
//! leaves the running model untouched.
//!
//! Built in `run.rs` at the point the AI detector is constructed (where the
//! `aegis-security` model handle is in scope) and stashed on
//! `DashboardServices::ai_reload` via `admin_accept_loop`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use aegis_control::api::ai_reload::{AiReloadReport, AiReloadWriter};
use aegis_security::detectors::ai::{Model, ModelHandle};

/// Re-reads `model_path` and atomically swaps the new model into the live
/// detector. Cheap to construct; holds only `Arc` handles + small config.
pub struct AiModelReloader {
    handle: ModelHandle,
    model_path: PathBuf,
    normal_class_idx: i64,
    sessions: usize,
}

impl AiModelReloader {
    pub fn new(
        handle: ModelHandle,
        model_path: PathBuf,
        normal_class_idx: i64,
        sessions: usize,
    ) -> Self {
        Self {
            handle,
            model_path,
            normal_class_idx,
            sessions,
        }
    }
}

impl AiReloadWriter for AiModelReloader {
    fn model_path(&self) -> String {
        self.model_path.display().to_string()
    }

    fn reload(&self) -> AiReloadReport {
        let t0 = Instant::now();
        // Rebuild a fresh session pool with the same shape as boot. Blocking —
        // the handler runs this on a blocking thread.
        match Model::load_pool(&self.model_path, self.normal_class_idx, self.sessions) {
            Ok(model) => {
                let sessions = model.session_count();
                // Atomic swap. In-flight inferences finish on the old model
                // (RCU); the old `Arc<Model>` drops when the last one releases.
                self.handle.store(Arc::new(model));
                AiReloadReport {
                    ok: true,
                    model_path: self.model_path.display().to_string(),
                    sessions: Some(sessions),
                    load_ms: Some(t0.elapsed().as_millis() as u64),
                    error: None,
                }
            }
            // Load failed (missing / corrupt / mid-write file): keep the
            // running model, report the reason. Nothing in the data plane moved.
            Err(e) => AiReloadReport {
                ok: false,
                model_path: self.model_path.display().to_string(),
                sessions: None,
                load_ms: None,
                error: Some(e.to_string()),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_security::detectors::ai::DEFAULT_NORMAL_CLASS_IDX;
    use arc_swap::ArcSwap;

    // Real-model tests — set AEGIS_AI_MODEL=/abs/path/to/waf_model.onnx to run;
    // they self-skip otherwise (mirrors crates/aegis-security/tests/ai_e2e.rs).
    fn model_path() -> Option<PathBuf> {
        std::env::var_os("AEGIS_AI_MODEL").map(PathBuf::from)
    }

    #[test]
    fn reload_from_valid_path_swaps_and_reports_ok() {
        let Some(path) = model_path() else {
            eprintln!("ai_reload: AEGIS_AI_MODEL unset — skipping.");
            return;
        };
        if !path.exists() {
            return;
        }
        let model = Model::load_pool(&path, DEFAULT_NORMAL_CLASS_IDX, 1).expect("model loads");
        let handle: ModelHandle = Arc::new(ArcSwap::from_pointee(model));
        let reloader = AiModelReloader::new(handle, path.clone(), DEFAULT_NORMAL_CLASS_IDX, 1);

        let report = reloader.reload();
        assert!(
            report.ok,
            "reload from a valid path should succeed: {report:?}"
        );
        assert_eq!(report.sessions, Some(1));
        assert!(report.error.is_none());
    }

    #[test]
    fn reload_from_bad_path_keeps_running_model_and_reports_error() {
        let Some(path) = model_path() else {
            return;
        };
        if !path.exists() {
            return;
        }
        let model = Model::load_pool(&path, DEFAULT_NORMAL_CLASS_IDX, 1).expect("model loads");
        let handle: ModelHandle = Arc::new(ArcSwap::from_pointee(model));
        // Snapshot the live model so we can prove a failed reload doesn't swap it.
        let before = handle.load_full();
        let reloader = AiModelReloader::new(
            handle.clone(),
            PathBuf::from("/no/such/model-file.onnx"),
            DEFAULT_NORMAL_CLASS_IDX,
            1,
        );

        let report = reloader.reload();
        assert!(!report.ok, "reload from a missing path must fail");
        assert!(report.error.is_some());
        assert!(
            Arc::ptr_eq(&before, &handle.load_full()),
            "a failed reload must leave the running model untouched",
        );
    }
}
