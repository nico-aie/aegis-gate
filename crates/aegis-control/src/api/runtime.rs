//! `/api/runtime` — Layer-1 (in-node) scaling visibility.
//!
//! Read-only view of the tokio runtime sizing currently in effect.
//! Operators use this to confirm the binary actually picked up
//! their `runtime:` config block (a common boot-time mistake is
//! pasting YAML into the wrong file or running an older image).
//!
//! Restart-only by design — tokio runtime sizing is fixed at
//! build time. The handler does **not** accept PUT / PATCH; the
//! admin surface reflects the boot config, no hot reload.

use serde::Serialize;

/// Snapshot of the tokio runtime configuration in effect.
#[derive(Clone, Debug, Serialize)]
pub struct RuntimeView {
    /// Effective worker thread count after `Auto` resolution.
    pub workers: usize,
    /// `auto` if the config value was `"auto"`, otherwise `"fixed"`.
    pub workers_mode: &'static str,
    /// Configured blocking-thread pool ceiling.
    pub blocking_threads: usize,
    /// Per-thread stack size in KiB.
    pub stack_size_kb: usize,
    /// Whether `cpu_affinity: true` was set in config.
    pub cpu_affinity_requested: bool,
    /// Whether the binary actually has the `affinity` Cargo feature
    /// compiled in (and therefore can honour the request).
    pub cpu_affinity_active: bool,
    /// `num_cpus::get()` at boot. Useful for sanity-checking the
    /// effective worker count against the host.
    pub host_logical_cpus: usize,
}

impl RuntimeView {
    /// Build the view from a parsed [`aegis_core::config::RuntimeConfig`].
    /// Pass `cpu_affinity_active` as `true` only if the binary's
    /// `affinity` Cargo feature is on.
    pub fn render(
        cfg: &aegis_core::config::RuntimeConfig,
        cpu_affinity_active: bool,
    ) -> Self {
        let workers_mode = match cfg.workers {
            aegis_core::config::Workers::Auto => "auto",
            aegis_core::config::Workers::Fixed(_) => "fixed",
        };
        Self {
            workers: cfg.workers.resolve(),
            workers_mode,
            blocking_threads: cfg.blocking_threads,
            stack_size_kb: cfg.stack_size_kb,
            cpu_affinity_requested: cfg.cpu_affinity,
            cpu_affinity_active,
            host_logical_cpus: num_cpus::get(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::config::{RuntimeConfig, Workers};

    #[test]
    fn auto_view_serialises_with_workers_mode_auto() {
        let cfg = RuntimeConfig::default();
        let view = RuntimeView::render(&cfg, false);
        assert_eq!(view.workers_mode, "auto");
        assert!(view.workers >= 2);
        assert_eq!(view.blocking_threads, 512);
        assert!(!view.cpu_affinity_requested);
        assert!(!view.cpu_affinity_active);
    }

    #[test]
    fn fixed_view_serialises_with_workers_mode_fixed() {
        let cfg = RuntimeConfig {
            workers: Workers::Fixed(8),
            ..Default::default()
        };
        let view = RuntimeView::render(&cfg, false);
        assert_eq!(view.workers_mode, "fixed");
        assert_eq!(view.workers, 8);
    }

    #[test]
    fn affinity_active_propagates() {
        let cfg = RuntimeConfig {
            cpu_affinity: true,
            ..Default::default()
        };
        let view = RuntimeView::render(&cfg, true);
        assert!(view.cpu_affinity_requested);
        assert!(view.cpu_affinity_active);
    }

    #[test]
    fn affinity_requested_but_inactive_when_feature_off() {
        let cfg = RuntimeConfig {
            cpu_affinity: true,
            ..Default::default()
        };
        let view = RuntimeView::render(&cfg, false);
        assert!(view.cpu_affinity_requested);
        assert!(
            !view.cpu_affinity_active,
            "binary without `affinity` feature must report inactive",
        );
    }

    #[test]
    fn view_serialises_to_json() {
        let cfg = RuntimeConfig::default();
        let view = RuntimeView::render(&cfg, false);
        let json = serde_json::to_string(&view).unwrap();
        assert!(json.contains("\"workers\""));
        assert!(json.contains("\"workers_mode\":\"auto\""));
        assert!(json.contains("\"blocking_threads\":512"));
    }
}
