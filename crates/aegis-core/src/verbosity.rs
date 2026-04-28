//! Operator-controlled audit-emission verbosity (P8 of the
//! security-toggle plan).
//!
//! [`VerbosityLevel`] is process-global per the user-confirmed
//! default (per-tenant verbosity is deferred under the RBAC track).
//! The proxy hot path consults it to decide whether to emit each
//! audit event; the dashboard pill surfaces the current level.
//!
//! # Why this is separate from [`LoadMode`]
//!
//! `LoadMode` is **automatic** — it follows observed RPS. Verbosity
//! is **manual** — the operator dials it. Combining them in one
//! enum tangled the UI affordance ("auto"-vs-"pinned" pill +
//! threshold tuning) with a knob that's never auto-adjusted.
//!
//! [`LoadMode`]: crate::LoadMode

use std::sync::Arc;

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};

/// Verbosity ladder. `Silent` is the most extreme degradation —
/// only blocks reach the audit chain. `Trace` is the noisiest and
/// is intended for short-lived debugging only.
///
/// Ordering matters: [`is_at_least`] uses it. Editing the variant
/// list means migrating any persisted `last_admin_change` column.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerbosityLevel {
    Silent,
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

impl VerbosityLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            VerbosityLevel::Silent => "silent",
            VerbosityLevel::Error => "error",
            VerbosityLevel::Warn => "warn",
            VerbosityLevel::Info => "info",
            VerbosityLevel::Debug => "debug",
            VerbosityLevel::Trace => "trace",
        }
    }

    /// Parse a wire string. `None` for unrecognised levels.
    pub fn parse_str(s: &str) -> Option<VerbosityLevel> {
        match s {
            "silent" => Some(VerbosityLevel::Silent),
            "error" => Some(VerbosityLevel::Error),
            "warn" => Some(VerbosityLevel::Warn),
            "info" => Some(VerbosityLevel::Info),
            "debug" => Some(VerbosityLevel::Debug),
            "trace" => Some(VerbosityLevel::Trace),
            _ => None,
        }
    }

    /// `true` when `self` is at least as verbose as `required`.
    /// Hot-path predicate: an event tagged `Info` reaches the bus
    /// only when the live verbosity ≥ Info.
    pub const fn is_at_least(self, required: VerbosityLevel) -> bool {
        (self as u8) >= (required as u8)
    }
}

/// Logging configuration block. Single field today (the
/// verbosity); kept as a struct so future per-channel knobs
/// (file vs SIEM vs Prometheus) can land without a YAML break.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LoggingConfig {
    #[serde(default)]
    pub verbosity: VerbosityLevel,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            verbosity: VerbosityLevel::Info,
        }
    }
}

/// Snapshot returned by the dashboard `/api/logging` handler.
#[derive(Clone, Debug, Serialize)]
pub struct VerbositySnapshot {
    pub level: VerbosityLevel,
    /// Levels in display order, lowest → highest. Pinned here so
    /// the UI can render a slider without re-deriving the order.
    pub levels: &'static [&'static str],
}

/// Process-global verbosity handle. Cheap to clone (Arc-shared);
/// the hot path reads via [`Self::current`] which is one
/// `ArcSwap::load` + Copy.
#[derive(Clone)]
pub struct SharedVerbosity {
    inner: Arc<ArcSwap<VerbosityLevel>>,
}

impl SharedVerbosity {
    pub fn new(initial: VerbosityLevel) -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(initial)),
        }
    }

    pub fn from_config(cfg: &LoggingConfig) -> Self {
        Self::new(cfg.verbosity)
    }

    /// Hot-path read.
    pub fn current(&self) -> VerbosityLevel {
        **self.inner.load()
    }

    /// Operator-driven change. Atomic — readers never observe a
    /// torn value.
    pub fn set(&self, level: VerbosityLevel) {
        self.inner.store(Arc::new(level));
    }

    /// `true` when the live verbosity ≥ `required`. Convenience
    /// for the hot path so it doesn't have to copy the level.
    pub fn allows(&self, required: VerbosityLevel) -> bool {
        self.current().is_at_least(required)
    }

    pub fn snapshot(&self) -> VerbositySnapshot {
        VerbositySnapshot {
            level: self.current(),
            levels: &["silent", "error", "warn", "info", "debug", "trace"],
        }
    }
}

impl Default for SharedVerbosity {
    fn default() -> Self {
        Self::new(VerbosityLevel::Info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_string_codes_round_trip() {
        for lv in [
            VerbosityLevel::Silent,
            VerbosityLevel::Error,
            VerbosityLevel::Warn,
            VerbosityLevel::Info,
            VerbosityLevel::Debug,
            VerbosityLevel::Trace,
        ] {
            assert_eq!(VerbosityLevel::parse_str(lv.as_str()), Some(lv));
        }
        assert_eq!(VerbosityLevel::parse_str("nope"), None);
    }

    #[test]
    fn is_at_least_orders_levels_low_to_high() {
        assert!(VerbosityLevel::Trace.is_at_least(VerbosityLevel::Info));
        assert!(VerbosityLevel::Info.is_at_least(VerbosityLevel::Info));
        assert!(!VerbosityLevel::Warn.is_at_least(VerbosityLevel::Info));
        assert!(!VerbosityLevel::Silent.is_at_least(VerbosityLevel::Error));
    }

    #[test]
    fn silent_blocks_everything_above() {
        let v = SharedVerbosity::new(VerbosityLevel::Silent);
        assert!(!v.allows(VerbosityLevel::Error));
        assert!(!v.allows(VerbosityLevel::Info));
        assert!(!v.allows(VerbosityLevel::Trace));
        // Silent allows Silent (vacuously — emitter passes Silent
        // tag for "this is a hard-floor block-action event").
        assert!(v.allows(VerbosityLevel::Silent));
    }

    #[test]
    fn shared_verbosity_set_is_atomic() {
        let v = SharedVerbosity::new(VerbosityLevel::Info);
        v.set(VerbosityLevel::Debug);
        assert_eq!(v.current(), VerbosityLevel::Debug);
        assert!(v.allows(VerbosityLevel::Info));
        assert!(v.allows(VerbosityLevel::Debug));
        assert!(!v.allows(VerbosityLevel::Trace));
    }

    #[test]
    fn from_config_initialises_from_yaml_struct() {
        let cfg = LoggingConfig {
            verbosity: VerbosityLevel::Warn,
        };
        let v = SharedVerbosity::from_config(&cfg);
        assert_eq!(v.current(), VerbosityLevel::Warn);
    }

    #[test]
    fn snapshot_lists_all_levels_in_ladder_order() {
        let v = SharedVerbosity::new(VerbosityLevel::Debug);
        let snap = v.snapshot();
        assert_eq!(snap.level, VerbosityLevel::Debug);
        assert_eq!(
            snap.levels,
            &["silent", "error", "warn", "info", "debug", "trace"],
        );
    }

    #[test]
    fn default_logging_config_is_info() {
        let cfg = LoggingConfig::default();
        assert_eq!(cfg.verbosity, VerbosityLevel::Info);
    }
}
