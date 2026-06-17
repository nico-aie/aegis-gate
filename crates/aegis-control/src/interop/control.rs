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

use aegis_core::state::StateBackend;

use super::headers::Mode;
use super::mode::{ModeSnapshot, ModeStore};

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
/// The contract enumerates these field combinations (§2.5).
///
/// 2026-06-17 (v2.6 audit MED-02): we are a *tolerant reader* of
/// unknown JSON fields — `deny_unknown_fields` is intentionally NOT
/// set. The contract authorizes 400/422 only for malformed
/// scope/mode combinations; a stray diagnostic or versioning field
/// from the benchmarker (or operator tooling) must not 400, since a
/// 400 here can trip the §2.5 punitive run-abort path. Field
/// *values* are still validated explicitly in `validate_and_apply`.
#[derive(Clone, Debug, Deserialize)]
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
    /// C-1 — propagation scope. `true` (default) publishes the change
    /// to the shared config plane so every node converges; `false`
    /// confines it to the node that received the request (the legacy
    /// loopback-only behaviour). Independent of the `scope`
    /// (all/features/policies) field above. No-op on single-node /
    /// in-memory deployments, which don't wire cluster sync.
    #[serde(default = "default_cluster_scope")]
    pub cluster: bool,
}

fn default_cluster_scope() -> bool {
    true
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
    /// 2026-05-20 — async `reset_state` cleaners. Sync callbacks
    /// (above) cover in-process trackers; these cover async work
    /// such as the `StateBackend` ephemeral wipe (rate-limit
    /// windows, challenge nonces, auto-block, backend risk keys).
    /// Awaited in [`ControlContext::reset_state_async`] AFTER the
    /// sync chain, so the whole reset stays atomic from the
    /// caller's POV.
    pub async_reset_callbacks: Mutex<Vec<AsyncResetCallback>>,
    /// `flush_cache` callback. `None` = no cache implemented; the endpoint
    /// returns `supported: false`. Behind a `Mutex` so it can be registered
    /// late at boot (`register_flush_callback`) once the data-plane cache —
    /// not in scope when the runtime is first built — exists.
    pub flush_callback: Mutex<Option<ResetCallback>>,
    /// Expected value of the `X-Benchmark-Secret` header. Set
    /// from `interop.control_secret` config; defaults to
    /// [`crate::interop::DEFAULT_CONTROL_SECRET`].
    pub secret: String,
    /// C-1 — shared state backend for cluster-native control-plane
    /// propagation. Installed via [`Self::set_cluster_state`] AFTER
    /// construction (the runtime is built before the backend is wired,
    /// same as `reset_in_progress`), and only when the deployment runs
    /// on a shared backend (Redis). Empty for single-node / in-memory
    /// builds, in which case `set_profile` / `reset_state` stay
    /// node-local (the legacy behaviour). Used to publish the mode map
    /// + reset epoch; a sibling poller (`aegis-proxy::accept`) reads
    /// them back.
    pub cluster_state: std::sync::OnceLock<Arc<dyn StateBackend>>,
    /// Phase 5 (§3) — optional pub/sub bus for the state *nudge*.
    /// Installed via [`Self::set_cluster_nudge`] at boot only when
    /// `cluster.pubsub_nudge` is on (and Redis is present). When set,
    /// `publish_modes` / `publish_reset_epoch` fire a 1-byte bump on
    /// [`super::cluster_sync::CONTROL_BUMP_CHANNEL`] so peer pollers
    /// re-poll immediately. Best-effort + non-load-bearing — a missed
    /// bump just falls back to the next poll interval.
    pub cluster_nudge: std::sync::OnceLock<Arc<dyn aegis_core::fleet::FleetBus>>,
}

/// Type alias for a reset callback. Wrapped in `Arc<dyn Fn>` so
/// `ControlContext` itself is cheap to clone.
pub type ResetCallback = Arc<dyn Fn() + Send + Sync>;

/// Async reset callback — returns a boxed future run by
/// [`ControlContext::reset_state_async`]. Used for cleaners that
/// must `.await` (e.g. the `StateBackend` ephemeral wipe).
pub type AsyncResetCallback = Arc<
    dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

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

    /// Run every SYNC reset callback, return the response. The
    /// audit log is always preserved.
    ///
    /// Prefer [`Self::reset_state_async`] on the live request path
    /// — it additionally awaits the async cleaners (the
    /// `StateBackend` ephemeral wipe). This sync-only variant
    /// stays for tests + callers without a runtime handle.
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

    /// 2026-05-20 — full reset: run the sync chain, then await
    /// every async cleaner. Used by the live
    /// `/__waf_control/reset_state` handler so the StateBackend
    /// wipe (rate-limit windows, nonces, auto-block, backend risk
    /// keys) completes BEFORE the 200 response — keeping the
    /// reset atomic from the benchmarker's POV (§2.4). Async
    /// cleaner failures are swallowed-with-log, same as the sync
    /// chain: a backend hiccup must not turn a reset into a 500.
    pub async fn reset_state_async(&self) -> ResetResponse {
        // Sync chain first (in-process trackers).
        let _ = self.reset_state();
        // Then async cleaners (backend wipe).
        let acbs: Vec<AsyncResetCallback> = {
            let g = self
                .async_reset_callbacks
                .lock()
                .expect("async_reset_callbacks poisoned");
            g.iter().cloned().collect()
        };
        for cb in &acbs {
            cb().await;
        }
        ResetResponse {
            ok: true,
            action: "reset_state",
            audit_log_preserved: true,
            ts_ms: now_ms(),
        }
    }

    /// Register an async reset cleaner (e.g. the StateBackend
    /// ephemeral wipe). Appended after construction, same pattern
    /// as [`Self::register_reset_callback`].
    pub fn register_async_reset_callback(&self, cb: AsyncResetCallback) {
        let mut g = self
            .async_reset_callbacks
            .lock()
            .expect("async_reset_callbacks poisoned");
        g.push(cb);
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

    /// C-1 — publish the current mode snapshot to the shared config
    /// plane so peers converge. Best-effort: no-op when cluster sync
    /// isn't wired (single-node), errors are logged and swallowed so a
    /// `set_profile` never fails on a backend hiccup. Called from the
    /// async dispatch AFTER the local apply, when `req.cluster` is set.
    pub async fn publish_modes(&self) {
        if let Some(state) = self.cluster_state.get() {
            let snap = self.modes.current();
            super::cluster_sync::publish_modes(state, &snap).await;
            self.fire_nudge().await;
        }
    }

    /// HIGH-2 — publish an operator access-list upsert to the shared
    /// config plane so peers converge. Best-effort + no-op when cluster
    /// sync isn't wired (single-node). Called from the access-list POST
    /// handler AFTER the local apply succeeds. `label` is `blacklist` or
    /// `whitelist`.
    pub async fn publish_access_list_upsert(
        &self,
        label: &str,
        entry: &crate::api::blacklist::AccessListEntry,
    ) {
        if let Some(state) = self.cluster_state.get() {
            super::cluster_sync::publish_access_list_upsert(state, label, entry).await;
            self.fire_nudge().await;
        }
    }

    /// HIGH-2 — publish an operator access-list removal to the shared
    /// config plane so peers converge. Best-effort + no-op without
    /// cluster sync. Called from the access-list DELETE handler AFTER the
    /// local delete succeeds.
    pub async fn publish_access_list_remove(&self, label: &str, id: &str) {
        if let Some(state) = self.cluster_state.get() {
            super::cluster_sync::publish_access_list_remove(state, label, id).await;
            self.fire_nudge().await;
        }
    }

    /// C-1 — install the shared backend used for cluster propagation.
    /// Called once at boot for Redis deployments. Idempotent (later
    /// calls are ignored).
    pub fn set_cluster_state(&self, state: Arc<dyn StateBackend>) {
        let _ = self.cluster_state.set(state);
    }

    /// Phase 5 (§3) — install the pub/sub nudge bus. Called once at
    /// boot only when `cluster.pubsub_nudge` is on. Idempotent.
    pub fn set_cluster_nudge(&self, bus: Arc<dyn aegis_core::fleet::FleetBus>) {
        let _ = self.cluster_nudge.set(bus);
    }

    /// Phase 5 (§3) — the installed nudge bus, if any. Read by the
    /// poller to decide whether to subscribe for immediate re-polls.
    pub fn cluster_nudge(&self) -> Option<Arc<dyn aegis_core::fleet::FleetBus>> {
        self.cluster_nudge.get().cloned()
    }

    /// Phase 5 (§3) — publish a 1-byte `control:waf:bump` so peer
    /// pollers re-poll immediately. Best-effort + no-op when the nudge
    /// bus isn't wired. The bump carries no payload meaning — it's a
    /// pure "re-poll now" signal; correctness lives in the polled keys.
    async fn fire_nudge(&self) {
        if let Some(bus) = self.cluster_nudge.get() {
            bus.publish(super::cluster_sync::CONTROL_BUMP_CHANNEL, vec![1]).await;
        }
    }

    /// C-1 — true when cluster propagation is wired (Redis backend).
    pub fn cluster_enabled(&self) -> bool {
        self.cluster_state.get().is_some()
    }

    /// C-1 — bump the cluster reset epoch so peers flush their *local*
    /// trackers (the shared-backend wipe already fanned out fleet-wide
    /// in `reset_state_async`). Best-effort / no-op without cluster
    /// sync.
    pub async fn publish_reset_epoch(&self) {
        if let Some(state) = self.cluster_state.get() {
            super::cluster_sync::publish_reset_epoch(state).await;
            self.fire_nudge().await;
        }
    }

    /// C-1 — apply a mode snapshot published by another node. Called by
    /// the cluster poller; replaces the whole local snapshot atomically.
    pub fn apply_remote_snapshot(&self, snapshot: ModeSnapshot) {
        self.modes.set_snapshot(snapshot);
    }

    /// C-1 — run only the *local* (in-process) reset chain, without the
    /// async shared-backend wipe. Used by the cluster poller when a
    /// peer bumps the reset epoch: that peer already wiped the shared
    /// backend fleet-wide, so this node only needs to flush its own
    /// trackers. Idempotent (clearing already-clear state is safe).
    pub fn reset_local(&self) {
        let _ = self.reset_state();
    }

    /// `POST /__waf_control/flush_cache`. When no cache is wired,
    /// this still returns 200 with `supported: false` so the
    /// benchmarker can detect the no-op gracefully.
    pub fn flush_cache(&self) -> FlushCacheResponse {
        let cb = self
            .flush_callback
            .lock()
            .expect("flush_callback poisoned")
            .clone();
        let supported = cb.is_some();
        if let Some(cb) = cb {
            cb();
        }
        FlushCacheResponse {
            ok: true,
            action: "flush_cache",
            supported,
            ts_ms: now_ms(),
        }
    }

    /// SC-1 — register the data-plane cache-flush callback. Called late at
    /// boot (after the `ResponseCache` exists) so `POST /__waf_control/
    /// flush_cache` actually evicts instead of reporting `supported: false`.
    pub fn register_flush_callback(&self, cb: ResetCallback) {
        *self.flush_callback.lock().expect("flush_callback poisoned") = Some(cb);
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
                // v2.6 §2.5 — an unknown feature name must be reported
                // as an unsupported item with `200 OK`, NOT a punitive
                // 422 (which aborts the benchmark run). Mirror the
                // `scope=features` branch: list every requested policy
                // under the unknown feature as unsupported and return
                // Ok. Only known features get their policies applied.
                let Some(known) = self.features.get(feature) else {
                    for p in policies {
                        unsupported.push(format!("{feature}.{p}"));
                    }
                    return Ok(unsupported);
                };
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
            async_reset_callbacks: Mutex::new(Vec::new()),
            flush_callback: std::sync::Mutex::new(None),
            secret: crate::interop::DEFAULT_CONTROL_SECRET.to_string(),
            cluster_state: std::sync::OnceLock::new(),
            cluster_nudge: std::sync::OnceLock::new(),
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
                    "open_redirect".into(),
                    "jwt_inspection".into(),
                    "cookie_injection".into(),
                    // 2026-05-20 committee interop fix — Phase-F
                    // detectors. Keep in sync with build_interop_runtime.
                    "canary".into(),
                    "velocity".into(),
                    "behavior_signals".into(),
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
        features.insert(
            "ddos".into(),
            CapabilityFeature {
                supported: true,
                toggleable: true,
                policies: vec!["per_ip".into()],
            },
        );
        ControlContext {
            modes: Arc::new(ModeStore::new(Mode::Enforce)),
            features,
            reset_callbacks: Mutex::new(Vec::new()),
            async_reset_callbacks: Mutex::new(Vec::new()),
            flush_callback: std::sync::Mutex::new(None),
            secret: crate::interop::DEFAULT_CONTROL_SECRET.to_string(),
            cluster_state: std::sync::OnceLock::new(),
            cluster_nudge: std::sync::OnceLock::new(),
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

    #[tokio::test]
    async fn reset_state_async_runs_sync_then_async() {
        // 2026-05-20 — reset_state_async must run the sync chain
        // (in-process trackers) AND await the async cleaners
        // (StateBackend wipe) before returning, so the reset is
        // atomic from the benchmarker's POV.
        let c = ctx();
        let log: Arc<std::sync::Mutex<Vec<&'static str>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let ls = log.clone();
        c.register_reset_callback(Arc::new(move || {
            ls.lock().unwrap().push("sync");
        }));
        let la = log.clone();
        c.register_async_reset_callback(Arc::new(move || {
            let la = la.clone();
            Box::pin(async move {
                la.lock().unwrap().push("async");
            })
        }));
        let r = c.reset_state_async().await;
        assert!(r.ok);
        assert!(r.audit_log_preserved);
        assert_eq!(*log.lock().unwrap(), vec!["sync", "async"]);
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
        let c = ctx();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_for_cb = counter.clone();
        c.register_flush_callback(Arc::new(move || {
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
            cluster: true,
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
            cluster: true,
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
            cluster: true,
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
            cluster: true,
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
            cluster: true,
        };
        let r = c.set_profile(&req).unwrap();
        assert_eq!(r.unsupported, vec!["does-not-exist"]);
    }

    #[test]
    fn set_profile_unknown_feature_in_policies_scope_is_listed_unsupported() {
        // v2.6 §2.5 — an unknown feature under scope=policies must be
        // reported as an unsupported item with 200 OK (benchmark-safe),
        // not a punitive 422 that aborts the run. Every requested
        // policy is namespaced under the unknown feature.
        let c = ctx();
        let req = SetProfileRequest {
            scope: SetProfileScope::Policies,
            mode: ModeRepr::LogOnly,
            features: None,
            feature: Some("nope".into()),
            policies: Some(vec!["x".into(), "y".into()]),
            cluster: true,
        };
        let r = c.set_profile(&req).unwrap();
        assert_eq!(r.unsupported, vec!["nope.x", "nope.y"]);
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
            cluster: true,
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
            cluster: true,
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
            cluster: true,
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
    fn json_unknown_field_is_tolerated() {
        // v2.6 MED-02 — tolerant reader: an extra field must be
        // ignored, not rejected, so a 400 can't trip the §2.5
        // punitive run-abort path. The known fields still parse.
        let json = r#"{
            "scope": "all",
            "mode": "enforce",
            "comment": "baseline",
            "extra": "x"
        }"#;
        let req: SetProfileRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.scope, SetProfileScope::All);
        assert_eq!(req.mode, ModeRepr::Enforce);
    }

    // ---- Phase 5 — pub/sub state nudge --------------------------------

    /// Recording FleetBus: captures every publish so the test can
    /// assert a bump was fired. `subscribe` is unused here.
    #[derive(Default)]
    struct RecordingFleetBus {
        published: std::sync::Mutex<Vec<(String, Vec<u8>)>>,
    }

    #[async_trait::async_trait]
    impl aegis_core::fleet::FleetBus for RecordingFleetBus {
        async fn publish(&self, channel: &str, payload: Vec<u8>) {
            self.published.lock().unwrap().push((channel.to_string(), payload));
        }
        fn subscribe(&self, _: &str, bound: usize) -> tokio::sync::mpsc::Receiver<Vec<u8>> {
            let (_tx, rx) = tokio::sync::mpsc::channel(bound.max(1));
            rx
        }
    }

    /// Trivial StateBackend so `publish_modes` has a `cluster_state`
    /// (the bump only fires when cluster propagation is wired). Only
    /// `get`/`cas_set` are exercised; the rest are inert stubs.
    struct NoopState;

    #[async_trait::async_trait]
    impl StateBackend for NoopState {
        async fn get(&self, _: &str) -> aegis_core::Result<Option<Vec<u8>>> { Ok(None) }
        async fn set(&self, _: &str, _: &[u8], _: std::time::Duration) -> aegis_core::Result<()> { Ok(()) }
        async fn del(&self, _: &str) -> aegis_core::Result<()> { Ok(()) }
        async fn cas_set(
            &self, _: &str, _: Option<&[u8]>, _: &[u8], _: Option<std::time::Duration>,
        ) -> aegis_core::Result<bool> { Ok(true) }
        async fn incr_window(
            &self, _: &str, _: std::time::Duration, _: u64,
        ) -> aegis_core::Result<aegis_core::state::SlidingWindowResult> {
            Ok(aegis_core::state::SlidingWindowResult { count: 0, allowed: true, retry_after: None })
        }
        async fn token_bucket(&self, _: &str, _: u32, _: u32) -> aegis_core::Result<bool> { Ok(true) }
        async fn get_risk(&self, _: &aegis_core::risk::RiskKey) -> aegis_core::Result<u32> { Ok(0) }
        async fn add_risk(&self, _: &aegis_core::risk::RiskKey, _: i32, _: u32) -> aegis_core::Result<u32> { Ok(0) }
        async fn auto_block(&self, _: std::net::IpAddr, _: std::time::Duration) -> aegis_core::Result<()> { Ok(()) }
        async fn is_auto_blocked(&self, _: std::net::IpAddr) -> aegis_core::Result<bool> { Ok(false) }
        async fn put_nonce(&self, _: &str, _: std::time::Duration) -> aegis_core::Result<bool> { Ok(true) }
        async fn consume_nonce(&self, _: &str) -> aegis_core::Result<bool> { Ok(true) }
    }

    #[tokio::test]
    async fn publish_modes_fires_a_nudge_when_bus_wired() {
        let ctx = ctx();
        ctx.set_cluster_state(Arc::new(NoopState));
        let bus = Arc::new(RecordingFleetBus::default());
        ctx.set_cluster_nudge(bus.clone());

        ctx.publish_modes().await;

        let pubs = bus.published.lock().unwrap();
        assert_eq!(pubs.len(), 1, "exactly one bump fired");
        assert_eq!(pubs[0].0, super::super::cluster_sync::CONTROL_BUMP_CHANNEL);
    }

    #[tokio::test]
    async fn publish_modes_no_nudge_without_bus() {
        // cluster_state set but no nudge bus → no bump, no panic.
        let ctx = ctx();
        ctx.set_cluster_state(Arc::new(NoopState));
        ctx.publish_modes().await; // must not panic
        assert!(ctx.cluster_nudge().is_none());
    }
}
