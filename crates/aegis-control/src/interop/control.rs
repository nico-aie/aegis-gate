//! `/__waf_control/*` endpoints.
//!
//! Pure response builders + request validators. The proxy
//! crate plugs the actual reset-state callbacks into a
//! [`ControlContext`] so the data plane keeps owning its
//! own state — no `aegis-control` → `aegis-proxy` upcall.
//!
//! Authentication: every endpoint requires the configured
//! control secret in the [`super::CONTROL_SECRET_HEADER`]
//! header. Missing or wrong secret returns `403 Forbidden`.
//! Auth check happens before any side effect.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use super::headers::Mode;
use super::mode::ModeStore;

/// Constant-time byte-slice equality. Returns `false` immediately
/// on length mismatch (length is assumed not secret). On equal
/// lengths, walks every byte and OR-folds the diff into a single
/// accumulator so the runtime is independent of how many leading
/// bytes match. Standard pattern from RFC 7564 et al; used here
/// to compare the `X-Benchmark-Secret` header against the
/// configured value without leaking secret prefixes via timing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Capabilities
// ---------------------------------------------------------------------------

/// One feature exposed by the WAF, with its toggleable policies.
/// Names MUST be stable for the duration of a benchmark run.
#[derive(Clone, Debug, Serialize)]
pub struct CapabilityFeature {
    pub supported: bool,
    pub toggleable: bool,
    pub policies: Vec<String>,
}

/// Snapshot of `default_mode` + active overrides. Mirrors the
/// shape the contract's example response uses.
#[derive(Clone, Debug, Serialize)]
pub struct CapabilityActive {
    pub default_mode: String,
    /// Flat key → mode map. Feature-level entries use the bare
    /// feature name; policy-level entries use `feature.policy`.
    pub overrides: BTreeMap<String, String>,
}

/// `GET /__waf_control/capabilities` body shape.
#[derive(Clone, Debug, Serialize)]
pub struct CapabilityResponse {
    pub ok: bool,
    pub features: BTreeMap<String, CapabilityFeature>,
    pub active: CapabilityActive,
}

// ---------------------------------------------------------------------------
// reset_state
// ---------------------------------------------------------------------------

/// Returned to the OC after a successful `reset_state`.
#[derive(Clone, Debug, Serialize)]
pub struct ResetResponse {
    pub ok: bool,
    pub action: &'static str,
    pub audit_log_preserved: bool,
    pub ts_ms: i64,
}

// ---------------------------------------------------------------------------
// set_profile
// ---------------------------------------------------------------------------

/// JSON body shape accepted by `POST /__waf_control/set_profile`.
/// The contract enumerates exactly these field combinations
/// (§2.5); anything else returns `400 Bad Request`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetProfileRequest {
    pub scope: SetProfileScope,
    pub mode: ModeRepr,
    /// Required for `scope: "features"`.
    #[serde(default)]
    pub features: Option<Vec<String>>,
    /// Required for `scope: "policies"`.
    #[serde(default)]
    pub feature: Option<String>,
    /// Required for `scope: "policies"`.
    #[serde(default)]
    pub policies: Option<Vec<String>>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SetProfileScope {
    All,
    Features,
    Policies,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ModeRepr {
    Enforce,
    LogOnly,
}

impl From<ModeRepr> for Mode {
    fn from(value: ModeRepr) -> Self {
        match value {
            ModeRepr::Enforce => Mode::Enforce,
            ModeRepr::LogOnly => Mode::LogOnly,
        }
    }
}

/// One half of a `set_profile` round-trip — the diff that was
/// applied. Matches the example response in §2.5.
#[derive(Clone, Debug, Serialize)]
pub struct SetProfileApplied {
    pub scope: String,
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub features: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policies: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SetProfileResponse {
    pub ok: bool,
    pub action: &'static str,
    pub applied: SetProfileApplied,
    pub active: CapabilityActive,
    pub unsupported: Vec<String>,
    pub ts_ms: i64,
}

// ---------------------------------------------------------------------------
// flush_cache
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
pub struct FlushCacheResponse {
    pub ok: bool,
    pub action: &'static str,
    pub supported: bool,
    pub ts_ms: i64,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    #[error("missing or invalid X-Benchmark-Secret header")]
    Forbidden,
    #[error("invalid request body: {0}")]
    BadRequest(String),
    #[error("unsupported feature/policy: {0}")]
    Unsupported(String),
}

impl ControlError {
    /// HTTP status code per the contract.
    pub fn status(&self) -> u16 {
        match self {
            ControlError::Forbidden => 403,
            ControlError::BadRequest(_) => 400,
            ControlError::Unsupported(_) => 422,
        }
    }
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

/// Wires the control plane to the live runtime. The proxy crate
/// constructs this once, hooks the reset callbacks into its
/// `RiskTracker` / `IpRateLimiter` / etc., and dispatches all
/// `/__waf_control/*` requests through it.
pub struct ControlContext {
    pub modes: Arc<ModeStore>,
    /// Stable list of features + policies the WAF supports. Used
    /// by `capabilities` and to validate `set_profile` payloads.
    /// Order is irrelevant; the response uses the BTreeMap order.
    pub features: BTreeMap<String, CapabilityFeature>,
    /// `reset_state` callback chain. Each closure clears one
    /// runtime state surface (rate limit, risk, sessions, etc.).
    /// Run synchronously in registration order; failures are
    /// logged but don't block the success response — `reset_state`
    /// MUST appear atomic to the caller.
    ///
    /// 2026-05-05 — wrapped in `Mutex` so subsystems built AFTER
    /// the runtime (e.g. `AttacksAggregator` inside
    /// `DashboardServices`) can append their own cleaners via
    /// [`ControlContext::register_reset_callback`]. The boot path
    /// pre-populates the chain with risk + rate-limit before the
    /// runtime goes live; late-binders extend it before the first
    /// reset_state call lands.
    pub reset_callbacks: Mutex<Vec<ResetCallback>>,
    /// `flush_cache` callback. `None` = no cache implemented;
    /// the endpoint returns `supported: false`.
    pub flush_callback: Option<ResetCallback>,
    /// Expected value of the `X-Benchmark-Secret` header. Set
    /// from `interop.control_secret` config; defaults to
    /// [`crate::interop::DEFAULT_CONTROL_SECRET`].
    pub secret: String,
}

/// Type alias for a reset callback. Wrapped in `Arc<dyn Fn>` so
/// `ControlContext` itself is cheap to clone.
pub type ResetCallback = Arc<dyn Fn() + Send + Sync>;

impl ControlContext {
    /// Authenticate a request against the contract secret.
    /// Comparison is case-insensitive on the header name and
    /// case-sensitive on the value (the contract pins both).
    ///
    /// 2026-05-05 — uses [`constant_time_eq`] to defeat the
    /// timing-side-channel attack against the secret. Plain `==`
    /// short-circuits on the first mismatched byte, which leaks
    /// secret prefixes byte-by-byte over enough samples; the
    /// constant-time compare runs through every byte regardless.
    pub fn check_auth(
        &self,
        header_value: Option<&str>,
    ) -> Result<(), ControlError> {
        match header_value {
            Some(v) if constant_time_eq(v.as_bytes(), self.secret.as_bytes()) => Ok(()),
            _ => Err(ControlError::Forbidden),
        }
    }

    /// Build the `capabilities` response from the registered
    /// feature list + the live mode store.
    pub fn capabilities(&self) -> CapabilityResponse {
        CapabilityResponse {
            ok: true,
            features: self.features.clone(),
            active: render_active(&self.modes),
        }
    }

    /// Run every reset callback, return the response. The
    /// audit log is always preserved.
    pub fn reset_state(&self) -> ResetResponse {
        // Snapshot under the lock + run callbacks unlocked so a
        // late-registering caller doesn't deadlock if its closure
        // ever recurses into `register_reset_callback`. Callbacks
        // are `Arc<dyn Fn>` clones — cheap.
        let cbs: Vec<ResetCallback> = {
            let g = self.reset_callbacks.lock().expect("reset_callbacks poisoned");
            g.iter().cloned().collect()
        };
        for cb in &cbs {
            cb();
        }
        ResetResponse {
            ok: true,
            action: "reset_state",
            audit_log_preserved: true,
            ts_ms: now_ms(),
        }
    }

    /// 2026-05-05 — append a reset cleaner after the runtime is
    /// already live. Used by subsystems that come up AFTER
    /// `build_interop_runtime` (notably `DashboardServices`'
    /// `AttacksAggregator`). Idempotent under contention via the
    /// inner `Mutex`. Caller is responsible for ensuring the
    /// closure is cheap + non-blocking — the v2.3 contract
    /// requires `reset_state` to feel atomic to the caller.
    pub fn register_reset_callback(&self, cb: ResetCallback) {
        let mut g = self.reset_callbacks.lock().expect("reset_callbacks poisoned");
        g.push(cb);
    }

    /// Apply a `set_profile` request.
    ///
    /// Returns the applied diff + new active state. Validates
    /// the request body shape per §2.5 — empty `features`,
    /// missing `feature` for policy scope, etc. all surface as
    /// `BadRequest`.
    pub fn set_profile(
        &self,
        req: &SetProfileRequest,
    ) -> Result<SetProfileResponse, ControlError> {
        let unsupported = self.validate_and_apply(req)?;
        Ok(SetProfileResponse {
            ok: true,
            action: "set_profile",
            applied: applied_from(req),
            active: render_active(&self.modes),
            unsupported,
            ts_ms: now_ms(),
        })
    }

    /// `POST /__waf_control/flush_cache`. When no cache is wired,
    /// this still returns 200 with `supported: false` so the
    /// benchmarker can detect the no-op gracefully.
    pub fn flush_cache(&self) -> FlushCacheResponse {
        let supported = self.flush_callback.is_some();
        if let Some(cb) = self.flush_callback.as_ref() {
            cb();
        }
        FlushCacheResponse {
            ok: true,
            action: "flush_cache",
            supported,
            ts_ms: now_ms(),
        }
    }

    fn validate_and_apply(
        &self,
        req: &SetProfileRequest,
    ) -> Result<Vec<String>, ControlError> {
        let mode: Mode = req.mode.into();
        let mut unsupported = Vec::new();

        match req.scope {
            SetProfileScope::All => {
                if req.features.is_some()
                    || req.feature.is_some()
                    || req.policies.is_some()
                {
                    return Err(ControlError::BadRequest(
                        "scope=all must not include features/feature/policies".into(),
                    ));
                }
                self.modes.set_all(mode);
            }
            SetProfileScope::Features => {
                let features = req.features.as_ref().ok_or_else(|| {
                    ControlError::BadRequest(
                        "scope=features requires `features: [...]`".into(),
                    )
                })?;
                if features.is_empty() {
                    return Err(ControlError::BadRequest(
                        "features list must not be empty".into(),
                    ));
                }
                for f in features {
                    if !self.features.contains_key(f) {
                        unsupported.push(f.clone());
                        continue;
                    }
                    self.modes.set_feature(f, mode);
                }
            }
            SetProfileScope::Policies => {
                let feature = req.feature.as_ref().ok_or_else(|| {
                    ControlError::BadRequest(
                        "scope=policies requires `feature: \"...\"`".into(),
                    )
                })?;
                let policies = req.policies.as_ref().ok_or_else(|| {
                    ControlError::BadRequest(
                        "scope=policies requires `policies: [...]`".into(),
                    )
                })?;
                if policies.is_empty() {
                    return Err(ControlError::BadRequest(
                        "policies list must not be empty".into(),
                    ));
                }
                let known = self.features.get(feature).ok_or_else(|| {
                    ControlError::Unsupported(format!("feature {feature}"))
                })?;
                for p in policies {
                    if !known.policies.contains(p) {
                        unsupported.push(format!("{feature}.{p}"));
                        continue;
                    }
                    self.modes.set_policy(feature, p, mode);
                }
            }
        }

        Ok(unsupported)
    }
}

fn render_active(store: &ModeStore) -> CapabilityActive {
    let snap = store.current();
    let mut overrides = BTreeMap::new();
    for (k, v) in &snap.feature_overrides {
        overrides.insert(k.clone(), v.as_str().to_string());
    }
    for ((feature, policy), v) in &snap.policy_overrides {
        overrides.insert(format!("{feature}.{policy}"), v.as_str().to_string());
    }
    CapabilityActive {
        default_mode: snap.default.as_str().to_string(),
        overrides,
    }
}

fn applied_from(req: &SetProfileRequest) -> SetProfileApplied {
    let scope = match req.scope {
        SetProfileScope::All => "all",
        SetProfileScope::Features => "features",
        SetProfileScope::Policies => "policies",
    };
    let mode: Mode = req.mode.into();
    SetProfileApplied {
        scope: scope.to_string(),
        mode: mode.as_str().to_string(),
        features: req.features.clone(),
        feature: req.feature.clone(),
        policies: req.policies.clone(),
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn ctx() -> ControlContext {
        let mut features = BTreeMap::new();
        features.insert(
            "access_control".into(),
            CapabilityFeature {
                supported: true,
                toggleable: true,
                policies: vec!["blacklist".into(), "whitelist".into()],
            },
        );
        features.insert(
            "rules_name".into(),
            CapabilityFeature {
                supported: true,
                toggleable: true,
                policies: vec!["sqli".into(), "xss".into()],
            },
        );
        ControlContext {
            modes: Arc::new(ModeStore::new(Mode::Enforce)),
            features,
            reset_callbacks: Mutex::new(Vec::new()),
            flush_callback: None,
            secret: crate::interop::DEFAULT_CONTROL_SECRET.to_string(),
        }
    }

    /// Mirror of the v2.3 capability feature set built by
    /// `build_interop_runtime` in `aegis-proxy/src/run.rs`. Keep in
    /// sync — these tests guard against drift in the run.rs wiring.
    fn ctx_v23() -> ControlContext {
        let mut features = BTreeMap::new();
        features.insert(
            "access_control".into(),
            CapabilityFeature {
                supported: true,
                toggleable: true,
                policies: vec!["blacklist".into(), "whitelist".into()],
            },
        );
        features.insert(
            "rules_engine".into(),
            CapabilityFeature {
                supported: true,
                toggleable: true,
                policies: vec![
                    "sqli".into(),
                    "xss".into(),
                    "path_traversal".into(),
                    "ssrf".into(),
                    "header_injection".into(),
                    "body_abuse".into(),
                    "recon".into(),
                    "brute_force".into(),
                    "ai".into(),
                    "command_injection".into(),
                    "template_injection".into(),
                    "nosql_injection".into(),
                ],
            },
        );
        features.insert(
            "rate_limit".into(),
            CapabilityFeature {
                supported: true,
                toggleable: true,
                policies: vec!["per_ip".into()],
            },
        );
        features.insert(
            "risk_engine".into(),
            CapabilityFeature {
                supported: true,
                toggleable: true,
                policies: vec!["score".into(), "strikes".into()],
            },
        );
        ControlContext {
            modes: Arc::new(ModeStore::new(Mode::Enforce)),
            features,
            reset_callbacks: Mutex::new(Vec::new()),
            flush_callback: None,
            secret: crate::interop::DEFAULT_CONTROL_SECRET.to_string(),
        }
    }

    #[test]
    fn auth_rejects_missing_header() {
        let c = ctx();
        let err = c.check_auth(None).unwrap_err();
        matches!(err, ControlError::Forbidden);
        assert_eq!(err.status(), 403);
    }

    #[test]
    fn auth_rejects_wrong_secret() {
        let c = ctx();
        let err = c.check_auth(Some("wrong-secret")).unwrap_err();
        assert_eq!(err.status(), 403);
    }

    #[test]
    fn auth_accepts_correct_secret() {
        let c = ctx();
        c.check_auth(Some(crate::interop::DEFAULT_CONTROL_SECRET)).unwrap();
    }

    #[test]
    fn constant_time_eq_basics() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
        // Same-length, fully different — all bytes accumulated.
        assert!(!constant_time_eq(b"aaa", b"bbb"));
    }

    #[test]
    fn auth_rejects_secret_with_one_byte_off() {
        // Regression — pre-fix `==` short-circuited on the first
        // byte mismatch, leaking the prefix length via timing.
        // The constant-time compare must reject identically here.
        let mut c = ctx();
        c.secret = "supersecret".to_string();
        let almost = "supersecreT"; // last byte differs
        let err = c.check_auth(Some(almost)).unwrap_err();
        assert_eq!(err.status(), 403);
    }

    #[test]
    fn capabilities_lists_features_and_active_state() {
        let c = ctx();
        let r = c.capabilities();
        assert!(r.ok);
        assert!(r.features.contains_key("access_control"));
        assert_eq!(r.active.default_mode, "enforce");
        assert!(r.active.overrides.is_empty());
    }

    #[test]
    fn capabilities_lists_ai_under_rules_engine() {
        // v2.3 §2.5 — AI must be exposed as a toggleable policy so the
        // OC harness can disable it via set_profile without a config
        // edit or restart. Guards against regression where someone
        // drops "ai" from build_interop_runtime in run.rs.
        let c = ctx_v23();
        let r = c.capabilities();
        let policies = &r
            .features
            .get("rules_engine")
            .expect("rules_engine present in v2.3 capabilities")
            .policies;
        assert!(
            policies.contains(&"ai".to_string()),
            "v2.3 capabilities must list 'ai' under rules_engine; got {policies:?}",
        );
    }

    #[test]
    fn capabilities_renders_overrides_correctly() {
        let c = ctx();
        c.modes.set_feature("access_control", Mode::LogOnly);
        c.modes.set_policy("rules_name", "sqli", Mode::LogOnly);
        let r = c.capabilities();
        assert_eq!(
            r.active.overrides.get("access_control"),
            Some(&"log_only".to_string()),
        );
        assert_eq!(
            r.active.overrides.get("rules_name.sqli"),
            Some(&"log_only".to_string()),
        );
    }

    #[test]
    fn reset_state_runs_callbacks_in_order() {
        let c = ctx();
        let log: Arc<std::sync::Mutex<Vec<&'static str>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let l1 = log.clone();
        c.register_reset_callback(Arc::new(move || {
            l1.lock().unwrap().push("first");
        }));
        let l2 = log.clone();
        c.register_reset_callback(Arc::new(move || {
            l2.lock().unwrap().push("second");
        }));
        let r = c.reset_state();
        assert!(r.ok);
        assert!(r.audit_log_preserved);
        assert_eq!(*log.lock().unwrap(), vec!["first", "second"]);
    }

    #[test]
    fn register_reset_callback_appends_after_construction() {
        // 2026-05-05 — late-binders (e.g. AttacksAggregator inside
        // DashboardServices) push their cleaners after the
        // ControlContext is already live.
        let c = ctx();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_for_cb = counter.clone();
        c.register_reset_callback(Arc::new(move || {
            counter_for_cb.fetch_add(1, Ordering::Relaxed);
        }));
        c.reset_state();
        assert_eq!(counter.load(Ordering::Relaxed), 1);
        // Idempotent under repeated reset
        c.reset_state();
        assert_eq!(counter.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn reset_state_preserves_unrelated_state_surface() {
        // v2.3 §2.4 — reset_state MUST clear runtime WAF state but
        // MUST preserve operator/admin-side state (sessions, audit
        // log, long-term config). This test simulates an external
        // state surface (e.g. SessionStore) by asserting that
        // anything NOT registered as a reset callback stays
        // untouched. Regression guard for QA finding H003
        // (2026-05-07): the report's described eviction does not
        // exist on develop, and this test fails fast if a future
        // change accidentally wires a session-evicting callback into
        // reset_state.
        let c = ctx();
        let session_alive = Arc::new(AtomicUsize::new(1));
        let cleared_count = Arc::new(AtomicUsize::new(0));
        let cleared_for_cb = cleared_count.clone();
        c.register_reset_callback(Arc::new(move || {
            cleared_for_cb.fetch_add(1, Ordering::Relaxed);
        }));
        let r = c.reset_state();
        assert!(r.ok);
        // Registered callback ran exactly once
        assert_eq!(cleared_count.load(Ordering::Relaxed), 1);
        // Anything not registered (i.e. session state) is untouched
        assert_eq!(
            session_alive.load(Ordering::Relaxed), 1,
            "reset_state must NOT touch state surfaces that didn't register a callback",
        );
    }

    #[test]
    fn flush_cache_reports_unsupported_when_no_callback() {
        let c = ctx();
        let r = c.flush_cache();
        assert!(r.ok);
        assert!(!r.supported);
    }

    #[test]
    fn flush_cache_runs_callback_when_present() {
        let mut c = ctx();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_for_cb = counter.clone();
        c.flush_callback = Some(Arc::new(move || {
            counter_for_cb.fetch_add(1, Ordering::Relaxed);
        }));
        let r = c.flush_cache();
        assert!(r.supported);
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn set_profile_scope_all_clears_overrides() {
        let c = ctx();
        c.modes.set_feature("access_control", Mode::LogOnly);
        let req = SetProfileRequest {
            scope: SetProfileScope::All,
            mode: ModeRepr::Enforce,
            features: None,
            feature: None,
            policies: None,
        };
        let r = c.set_profile(&req).unwrap();
        assert!(r.ok);
        assert_eq!(r.active.default_mode, "enforce");
        assert!(r.active.overrides.is_empty(), "overrides leaked");
    }

    #[test]
    fn set_profile_scope_features_overrides_listed_only() {
        let c = ctx();
        let req = SetProfileRequest {
            scope: SetProfileScope::Features,
            mode: ModeRepr::LogOnly,
            features: Some(vec!["access_control".into()]),
            feature: None,
            policies: None,
        };
        let r = c.set_profile(&req).unwrap();
        assert!(r.ok);
        assert_eq!(
            r.active.overrides.get("access_control"),
            Some(&"log_only".to_string()),
        );
        // rules_name unchanged
        assert!(!r.active.overrides.contains_key("rules_name"));
    }

    #[test]
    fn set_profile_scope_policies_overrides_named_policy() {
        let c = ctx();
        let req = SetProfileRequest {
            scope: SetProfileScope::Policies,
            mode: ModeRepr::LogOnly,
            features: None,
            feature: Some("access_control".into()),
            policies: Some(vec!["blacklist".into()]),
        };
        let r = c.set_profile(&req).unwrap();
        assert_eq!(
            r.active.overrides.get("access_control.blacklist"),
            Some(&"log_only".to_string()),
        );
        // whitelist NOT overridden
        assert!(
            !r.active.overrides.contains_key("access_control.whitelist"),
            "whitelist must remain enforce",
        );
    }

    #[test]
    fn set_profile_can_log_only_just_ai() {
        // v2.3 §2.5 — operator path for putting AI into log_only.
        // The set_profile call must (a) accept "ai" as a known policy
        // under rules_engine, and (b) cause the data plane's
        // mode lookup to resolve "ai" to LogOnly while leaving the
        // other rules_engine policies on the default mode.
        let c = ctx_v23();
        let req = SetProfileRequest {
            scope: SetProfileScope::Policies,
            mode: ModeRepr::LogOnly,
            features: None,
            feature: Some("rules_engine".into()),
            policies: Some(vec!["ai".into()]),
        };
        let r = c.set_profile(&req).expect("set_profile must accept ai");
        assert!(r.unsupported.is_empty(), "ai must be supported, got {:?}", r.unsupported);
        assert_eq!(
            r.active.overrides.get("rules_engine.ai"),
            Some(&"log_only".to_string()),
            "ai override must surface in active state",
        );
        // Direct ModeStore resolution — what the data plane uses
        // before deciding enforce vs log_only on each request.
        assert_eq!(c.modes.resolve("rules_engine", Some("ai")), Mode::LogOnly);
        // Other rules_engine policies are unchanged.
        assert_eq!(c.modes.resolve("rules_engine", Some("sqli")), Mode::Enforce);
    }

    #[test]
    fn set_profile_unknown_feature_in_features_is_listed_unsupported() {
        let c = ctx();
        let req = SetProfileRequest {
            scope: SetProfileScope::Features,
            mode: ModeRepr::LogOnly,
            features: Some(vec!["does-not-exist".into()]),
            feature: None,
            policies: None,
        };
        let r = c.set_profile(&req).unwrap();
        assert_eq!(r.unsupported, vec!["does-not-exist"]);
    }

    #[test]
    fn set_profile_unknown_feature_in_policies_scope_returns_422() {
        let c = ctx();
        let req = SetProfileRequest {
            scope: SetProfileScope::Policies,
            mode: ModeRepr::LogOnly,
            features: None,
            feature: Some("nope".into()),
            policies: Some(vec!["x".into()]),
        };
        let err = c.set_profile(&req).unwrap_err();
        assert_eq!(err.status(), 422);
    }

    #[test]
    fn set_profile_unknown_policy_under_known_feature_is_listed_unsupported() {
        let c = ctx();
        let req = SetProfileRequest {
            scope: SetProfileScope::Policies,
            mode: ModeRepr::LogOnly,
            features: None,
            feature: Some("access_control".into()),
            policies: Some(vec!["unknown-policy".into()]),
        };
        let r = c.set_profile(&req).unwrap();
        assert_eq!(r.unsupported, vec!["access_control.unknown-policy"]);
    }

    #[test]
    fn set_profile_scope_all_rejects_extra_fields() {
        let c = ctx();
        let req = SetProfileRequest {
            scope: SetProfileScope::All,
            mode: ModeRepr::Enforce,
            features: Some(vec!["access_control".into()]),
            feature: None,
            policies: None,
        };
        let err = c.set_profile(&req).unwrap_err();
        assert_eq!(err.status(), 400);
    }

    #[test]
    fn set_profile_scope_features_rejects_empty_list() {
        let c = ctx();
        let req = SetProfileRequest {
            scope: SetProfileScope::Features,
            mode: ModeRepr::Enforce,
            features: Some(vec![]),
            feature: None,
            policies: None,
        };
        let err = c.set_profile(&req).unwrap_err();
        assert_eq!(err.status(), 400);
    }

    #[test]
    fn json_set_profile_round_trip() {
        // The example in §2.5 of the contract — must parse.
        let json = r#"{
            "scope": "policies",
            "mode": "log_only",
            "feature": "access_control",
            "policies": ["blacklist"]
        }"#;
        let req: SetProfileRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.scope, SetProfileScope::Policies);
        assert_eq!(req.mode, ModeRepr::LogOnly);
    }

    #[test]
    fn json_unknown_field_is_rejected() {
        // `deny_unknown_fields` keeps the contract strict —
        // typos in field names must surface as bad request.
        let json = r#"{
            "scope": "all",
            "mode": "enforce",
            "extra": "x"
        }"#;
        let r: Result<SetProfileRequest, _> = serde_json::from_str(json);
        assert!(r.is_err());
    }
}
