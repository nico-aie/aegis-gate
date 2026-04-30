//! HK-T4 — per-feature/policy `enforce` / `log_only` map.
//!
//! Drives the WAF's enforcement decision when the OC's
//! benchmarker calls `POST /__waf_control/set_profile` (§2.5 of
//! the contract). Each feature has zero or more policies; the
//! caller can override at any granularity:
//!
//! - `scope: "all"`        — change `default_mode` for every feature.
//! - `scope: "features"`   — override a list of features.
//! - `scope: "policies"`   — override a list of policies under one feature.
//!
//! Resolution order (most specific wins):
//!
//! 1. `policy_overrides[(feature, policy)]`
//! 2. `feature_overrides[feature]`
//! 3. `default_mode`
//!
//! Fully concurrent — the data plane reads via `ArcSwap` so the
//! hot path never takes a lock. The control plane writes through
//! a `parking_lot::Mutex` to serialise concurrent `set_profile`
//! calls.

use std::collections::HashMap;
use std::sync::Mutex;

use arc_swap::ArcSwap;

use super::headers::Mode;

/// Snapshot of every override active at one instant. Cheap to
/// clone — only `Arc` bumps, no map clone.
#[derive(Clone, Debug)]
pub struct ModeSnapshot {
    pub default: Mode,
    pub feature_overrides: HashMap<String, Mode>,
    pub policy_overrides: HashMap<(String, String), Mode>,
}

impl ModeSnapshot {
    pub fn empty(default: Mode) -> Self {
        Self {
            default,
            feature_overrides: HashMap::new(),
            policy_overrides: HashMap::new(),
        }
    }

    /// Effective mode for `(feature, policy)`. `None` for the
    /// `policy` argument means "look only at feature + default."
    pub fn resolve(&self, feature: &str, policy: Option<&str>) -> Mode {
        if let Some(policy) = policy {
            let key = (feature.to_string(), policy.to_string());
            if let Some(m) = self.policy_overrides.get(&key) {
                return *m;
            }
        }
        if let Some(m) = self.feature_overrides.get(feature) {
            return *m;
        }
        self.default
    }
}

/// Live, atomically-swapped mode store. Hot-path readers call
/// [`ModeStore::current`] (lock-free); the control plane calls
/// [`ModeStore::set_all`] / [`set_feature`] / [`set_policy`].
pub struct ModeStore {
    snapshot: ArcSwap<ModeSnapshot>,
    write_lock: Mutex<()>,
}

impl ModeStore {
    pub fn new(default: Mode) -> Self {
        Self {
            snapshot: ArcSwap::from_pointee(ModeSnapshot::empty(default)),
            write_lock: Mutex::new(()),
        }
    }

    /// Lock-free snapshot read. Returns a cheap `Arc` bump.
    pub fn current(&self) -> std::sync::Arc<ModeSnapshot> {
        self.snapshot.load_full()
    }

    /// Resolve mode for a `(feature, policy?)` pair without
    /// allocating a snapshot clone. Hot-path use.
    pub fn resolve(&self, feature: &str, policy: Option<&str>) -> Mode {
        self.snapshot.load().resolve(feature, policy)
    }

    /// Replace the default mode and clear all overrides.
    /// Mirrors `scope: "all"` in the contract — it's the
    /// "factory reset" of the mode plane.
    pub fn set_all(&self, mode: Mode) {
        let _g = self.write_lock.lock().expect("mode write lock poisoned");
        self.snapshot.store(std::sync::Arc::new(ModeSnapshot::empty(mode)));
    }

    /// Override one feature; `policy_overrides` for that feature
    /// stay in place. Other features unchanged.
    pub fn set_feature(&self, feature: impl Into<String>, mode: Mode) {
        let _g = self.write_lock.lock().expect("mode write lock poisoned");
        let cur = self.snapshot.load_full();
        let mut next = (*cur).clone();
        next.feature_overrides.insert(feature.into(), mode);
        self.snapshot.store(std::sync::Arc::new(next));
    }

    /// Override one policy. Feature-level + default unchanged.
    pub fn set_policy(
        &self,
        feature: impl Into<String>,
        policy: impl Into<String>,
        mode: Mode,
    ) {
        let _g = self.write_lock.lock().expect("mode write lock poisoned");
        let cur = self.snapshot.load_full();
        let mut next = (*cur).clone();
        next.policy_overrides.insert(
            (feature.into(), policy.into()),
            mode,
        );
        self.snapshot.store(std::sync::Arc::new(next));
    }
}

impl Default for ModeStore {
    fn default() -> Self {
        // Contract default: `enforce` for every feature.
        Self::new(Mode::Enforce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_resolves_to_default_for_anything() {
        let s = ModeStore::new(Mode::Enforce);
        assert_eq!(s.resolve("access_control", None), Mode::Enforce);
        assert_eq!(s.resolve("rules", Some("sqli")), Mode::Enforce);
    }

    #[test]
    fn feature_override_takes_precedence_over_default() {
        let s = ModeStore::new(Mode::Enforce);
        s.set_feature("access_control", Mode::LogOnly);
        assert_eq!(s.resolve("access_control", None), Mode::LogOnly);
        assert_eq!(s.resolve("rules", None), Mode::Enforce);
    }

    #[test]
    fn policy_override_takes_precedence_over_feature() {
        let s = ModeStore::new(Mode::Enforce);
        s.set_feature("access_control", Mode::LogOnly);
        s.set_policy("access_control", "blacklist", Mode::Enforce);
        // policy beats feature
        assert_eq!(
            s.resolve("access_control", Some("blacklist")),
            Mode::Enforce,
        );
        // feature still applies to other policies
        assert_eq!(
            s.resolve("access_control", Some("whitelist")),
            Mode::LogOnly,
        );
    }

    #[test]
    fn set_all_clears_overrides_and_changes_default() {
        let s = ModeStore::new(Mode::Enforce);
        s.set_feature("a", Mode::LogOnly);
        s.set_policy("a", "p1", Mode::Enforce);
        s.set_all(Mode::LogOnly);
        let snap = s.current();
        assert_eq!(snap.default, Mode::LogOnly);
        assert!(snap.feature_overrides.is_empty(), "feature overrides leaked");
        assert!(snap.policy_overrides.is_empty(), "policy overrides leaked");
    }

    #[test]
    fn snapshot_clone_is_independent_of_subsequent_writes() {
        let s = ModeStore::new(Mode::Enforce);
        let before = s.current();
        s.set_feature("a", Mode::LogOnly);
        // The pre-write snapshot must not see the new override.
        assert!(before.feature_overrides.is_empty());
        // The current snapshot must.
        assert_eq!(
            s.current().feature_overrides.get("a"),
            Some(&Mode::LogOnly),
        );
    }

    #[test]
    fn default_constructor_uses_enforce() {
        let s = ModeStore::default();
        assert_eq!(s.resolve("anything", None), Mode::Enforce);
    }
}
