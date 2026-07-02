//! `/api/gates/*` — operator-facing read surface for the four
//! request-flow gates (access list, strike-block, rate-limit, DDoS)
//! that fire BEFORE the detector chain.
//!
//! 2026-05-09 — built alongside the new "Traffic Gates" dashboard
//! page so operators have one place to see (a) which gates are
//! protecting them and (b) live telemetry from each.
//!
//! Today this module ships the **DDoS** read surface only. The
//! other three gates already have dedicated endpoints
//! (`/api/blacklist`, `/api/whitelist`, `/api/risk`,
//! `/api/rate-limit/*`); the SPA aggregates them on the Traffic
//! Gates page client-side. A future `/api/gates/summary`
//! endpoint can collapse those into one server-side response if
//! the page-load cost ever matters.
//!
//! ## Why a dedicated module
//!
//! DDoS is **not a `Detector` trait impl** — it doesn't fit on
//! the Detectors page or under `/api/detectors`. It's a request-
//! flow gate (sliding-window per-IP burst counter + EWMA spike-
//! mode ticker, both reading from the shared `StateBackend`).
//! See [`docs/security/ddos-protection.md`](../../../../docs/security/ddos-protection.md).

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use aegis_security::ddos::{DdosConfig, DdosRuntime};
use aegis_security::rate_limit::{IpRateLimitConfig, IpRateLimiter};
use aegis_security::risk::RiskTracker;
use aegis_core::config::StrikeConfig;

/// Read shape returned by `GET /api/gates/ddos`.
///
/// `runtime` is `None` when the gate is disabled at boot
/// (`cfg.ddos.enabled = false`) — the SPA renders an empty-state
/// card with a "DDoS gate disabled" message in that case.
#[derive(Debug, Serialize)]
pub struct DdosView {
    /// `true` if a `DdosRuntime` is installed in `DashboardServices`.
    pub enabled: bool,
    /// 2026-05-09 — full live config snapshot so the dashboard can
    /// render the active threshold values + the operator can edit
    /// them via PUT /api/gates/ddos. ArcSwap inside DdosDetector
    /// makes the snapshot consistent across field reads even
    /// when a concurrent PUT lands.
    pub config: DdosConfigView,
    /// EWMA spike-detection telemetry. `current_rps` and
    /// `baseline_rps` are updated by the once-per-second
    /// `tick_rps()` ticker spawned in `aegis-proxy::run`.
    pub current_rps: u64,
    pub baseline_rps: u64,
    /// Fleet RPS aggregation P3 — the fleet-wide RPS the spike signal acted on
    /// when `config.spike_scope == fleet` (0 in per-node scope). Lets the panel
    /// show "fleet N rps vs node M rps".
    #[serde(default)]
    pub fleet_rps: u64,
    pub spike_active: bool,
    /// 2026-05-22 — interop mode resolved for the `ddos` feature
    /// (`set_profile`). `"enforce"` or `"log_only"`. This is
    /// INDEPENDENT of `config.observe_only`: either one suppresses
    /// the 503 (the data plane honors both — see
    /// `aegis-proxy::data_plane`). The dashboard shows the gate as
    /// observe/log_only when `config.observe_only` is true OR this is
    /// `"log_only"`, so a global `set_profile log_only` is no longer
    /// mislabeled as "enforcing".
    pub effective_mode: String,
}

/// Wire-shape mirror of `aegis_security::ddos::DdosConfig`.
/// Same field names as the YAML schema so operator can map
/// dashboard ↔ YAML 1:1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdosConfigView {
    pub enabled: bool,
    pub observe_only: bool,
    pub per_ip_limit: u64,
    pub per_ip_window_s: u32,
    pub block_ttl_s: u64,
    pub spike_multiplier: f64,
    pub tightened_per_ip_rps: u64,
    /// P2 spike hysteresis — consecutive over-threshold ticks to engage
    /// `spike_active`, and consecutive under-threshold ticks to release it.
    pub spike_engage_ticks: u32,
    pub spike_release_ticks: u32,
    /// Fleet RPS aggregation — `per_node` (default) or `fleet`. Surfaced so the
    /// dashboard can show + edit the spike scope alongside the dwell knobs.
    #[serde(default)]
    pub spike_scope: aegis_core::config::SpikeScope,
}

impl From<DdosConfig> for DdosConfigView {
    fn from(c: DdosConfig) -> Self {
        Self {
            enabled: c.enabled,
            observe_only: c.observe_only,
            per_ip_limit: c.per_ip_limit,
            per_ip_window_s: c.per_ip_window_s,
            block_ttl_s: c.block_ttl_s,
            spike_multiplier: c.spike_multiplier,
            tightened_per_ip_rps: c.tightened_per_ip_rps,
            spike_engage_ticks: c.spike_engage_ticks,
            spike_release_ticks: c.spike_release_ticks,
            spike_scope: c.spike_scope,
        }
    }
}

impl DdosView {
    pub fn from_runtime(runtime: Option<&Arc<DdosRuntime>>) -> Self {
        match runtime {
            Some(r) => Self {
                enabled: true,
                config: DdosConfigView::from(r.config_snapshot()),
                current_rps: r.current_rps(),
                baseline_rps: r.baseline_rps(),
                fleet_rps: r.fleet_rps(),
                spike_active: r.is_spike_active(),
                // Default; `render_get` overlays the live interop mode.
                effective_mode: "enforce".into(),
            },
            None => Self {
                enabled: false,
                config: DdosConfigView {
                    enabled: false,
                    observe_only: false,
                    per_ip_limit: 0,
                    per_ip_window_s: 0,
                    block_ttl_s: 0,
                    spike_multiplier: 0.0,
                    tightened_per_ip_rps: 0,
                    spike_engage_ticks: 0,
                    spike_release_ticks: 0,
                    spike_scope: aegis_core::config::SpikeScope::PerNode,
                },
                current_rps: 0,
                baseline_rps: 0,
                fleet_rps: 0,
                spike_active: false,
                effective_mode: "enforce".into(),
            },
        }
    }
}

/// PUT /api/gates/ddos request body. Validation enforces sane
/// bounds (no zero thresholds, spike_multiplier finite + > 1.0).
/// Audit-mutated through the existing `AuditedMutate` pipeline.
#[derive(Debug, Clone, Deserialize)]
pub struct DdosPutBody {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub observe_only: bool,
    pub per_ip_limit: u64,
    pub per_ip_window_s: u32,
    pub block_ttl_s: u64,
    pub spike_multiplier: f64,
    pub tightened_per_ip_rps: u64,
    /// P2 spike hysteresis. Optional in the PUT body (serde defaults 2/8)
    /// so older clients that omit them keep working; the dashboard panel
    /// always sends them so an operator edit round-trips.
    #[serde(default = "default_spike_engage_ticks")]
    pub spike_engage_ticks: u32,
    #[serde(default = "default_spike_release_ticks")]
    pub spike_release_ticks: u32,
    /// Fleet RPS aggregation — `per_node` (default) or `fleet`. Round-tripped
    /// so a dashboard PUT preserves the scope instead of clobbering a YAML
    /// `fleet` back to `per_node`.
    #[serde(default)]
    pub spike_scope: aegis_core::config::SpikeScope,
}

fn default_true() -> bool { true }
fn default_spike_engage_ticks() -> u32 { 2 }
fn default_spike_release_ticks() -> u32 { 8 }

impl DdosPutBody {
    pub fn validate(self) -> Result<DdosConfig, Vec<String>> {
        let mut errors = Vec::new();
        if self.per_ip_limit == 0 {
            errors.push("per_ip_limit must be > 0".into());
        }
        if self.per_ip_window_s == 0 {
            errors.push("per_ip_window_s must be > 0".into());
        }
        if self.block_ttl_s == 0 {
            errors.push("block_ttl_s must be > 0".into());
        }
        if !self.spike_multiplier.is_finite() || self.spike_multiplier <= 1.0 {
            errors.push("spike_multiplier must be finite and > 1.0".into());
        }
        if self.tightened_per_ip_rps == 0 {
            errors.push("tightened_per_ip_rps must be > 0".into());
        }
        if self.spike_engage_ticks == 0 {
            errors.push("spike_engage_ticks must be > 0".into());
        }
        if self.spike_release_ticks == 0 {
            errors.push("spike_release_ticks must be > 0".into());
        }
        if !errors.is_empty() {
            return Err(errors);
        }
        Ok(DdosConfig {
            enabled: self.enabled,
            observe_only: self.observe_only,
            per_ip_limit: self.per_ip_limit,
            per_ip_window_s: self.per_ip_window_s,
            block_ttl_s: self.block_ttl_s,
            spike_multiplier: self.spike_multiplier,
            tightened_per_ip_rps: self.tightened_per_ip_rps,
            // 2026-06-20 (P2) — spike hysteresis is now dashboard-editable
            // (surfaced in the DDoS panel); the PUT carries it.
            spike_engage_ticks: self.spike_engage_ticks,
            spike_release_ticks: self.spike_release_ticks,
            spike_scope: self.spike_scope,
            // 2026-05-18 (QC Sprint 1.2 — F-CRITICAL-005): the PUT
            // body doesn't carry per-tier overrides today —
            // operators tune those via YAML. The hot-swap surface
            // preserves the existing in-memory overrides by NOT
            // clearing them here. (Dashboard knob for per-tier
            // limits is tracked in plans/issue-fix/2026-05-18-qc-followup
            // § DD-06.) For now: PUT replaces the global knobs
            // but leaves tier_overrides + failure_mode untouched.
            tier_overrides: std::collections::HashMap::new(),
            failure_mode: std::collections::HashMap::new(),
        })
    }
}

/// Render the GET payload. Stable across calls; cheap (one
/// atomic load per telemetry field). Caller plumbs the response
/// into the standard `json_body_response(200, ..., "private,
/// max-age=2")` shape.
/// `effective_mode` is the interop mode resolved for the `ddos`
/// feature (`"enforce"` / `"log_only"`); the caller resolves it from
/// the live `ModeStore` so a `set_profile log_only` is reflected in
/// the gate view, not just the config-level `observe_only` flag.
pub fn render_get(runtime: Option<&Arc<DdosRuntime>>, effective_mode: &str) -> String {
    let mut view = DdosView::from_runtime(runtime);
    view.effective_mode = effective_mode.to_string();
    serde_json::to_string(&view).unwrap_or_else(|_| String::from("{}"))
}

// =====================================================================
// Rate-limit gate read + write surface
// =====================================================================

/// Read shape returned by `GET /api/rate-limit`.
///
/// Mirrors the F-T2 token-bucket rate limiter (lives in
/// `aegis-security/src/rate_limit/ip_limiter.rs`). The DDoS gate
/// is a separate sliding-window auto-block — see the operator
/// guide at `docs/operator/traffic-gates.md` for the full
/// distinction:
///
/// - **Rate Limit (this surface):** steady-state per-IP token
///   bucket. Returns 429 + `X-WAF-Action: rate_limit`. Allows the
///   request to retry after the window. Configured via
///   `cfg.rate_limit.buckets` in YAML.
/// - **DDoS Gate** (`/api/gates/ddos`): sliding-window burst
///   counter that triggers a TTL'd auto-block. Returns 403 +
///   `X-WAF-Action: block`. The IP is rejected entirely for
///   `block_ttl_s` seconds.
#[derive(Debug, Serialize)]
pub struct RateLimitView {
    /// Operator enable toggle — `false` skips the per-IP gate entirely.
    pub enabled: bool,
    /// Configured limit (max requests within the window).
    pub limit: u32,
    /// Configured window in seconds.
    pub window_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitPutBody {
    /// 2026-06-22 — DDoS-style enable toggle. `#[serde(default = "default_true")]`
    /// so older dashboard clients that PUT only `{ limit, window_seconds }`
    /// keep the gate enabled instead of tripping a missing-field 400 / silently
    /// disabling it.
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub limit: u32,
    pub window_seconds: u64,
}

impl RateLimitPutBody {
    pub fn validate(self) -> Result<IpRateLimitConfig, Vec<String>> {
        let mut errors = Vec::new();
        if self.limit == 0 {
            errors.push("limit must be > 0".into());
        }
        if self.window_seconds == 0 {
            errors.push("window_seconds must be > 0".into());
        }
        if !errors.is_empty() {
            return Err(errors);
        }
        Ok(IpRateLimitConfig {
            limit: self.limit,
            window: std::time::Duration::from_secs(self.window_seconds),
            enabled: self.enabled,
        })
    }
}

pub fn render_get_rate_limit(limiter: &Arc<IpRateLimiter>) -> String {
    let cfg = limiter.config_snapshot();
    let view = RateLimitView {
        enabled: cfg.enabled,
        limit: cfg.limit,
        window_seconds: cfg.window.as_secs(),
    };
    serde_json::to_string(&view).unwrap_or_else(|_| String::from("{}"))
}

// =====================================================================
// Strike-Block gate read + write surface (2026-05-10)
// =====================================================================

/// Read shape returned by `GET /api/gates/strikes`.
///
/// Mirrors `aegis_core::config::StrikeConfig` so dashboard ↔ YAML
/// fields map 1:1. `tracked_ips` and `blocked_ips` are live
/// telemetry counts derived from the per-IP map (cheap — O(N)
/// over the typically-tiny tracked set).
///
/// Strike-Block is opt-in (`enabled` defaults to `false`); when
/// disabled, the lifetime counter still climbs for forensics
/// but the data plane does not 403 on threshold cross. See
/// `docs/operator/traffic-gates.md` for the operator guide.
#[derive(Debug, Serialize)]
pub struct StrikesView {
    pub enabled: bool,
    pub block_at: u32,
    /// Number of IPs currently in the per-IP map (any non-zero
    /// score or strike count).
    pub tracked_ips: usize,
    /// Number of tracked IPs whose lifetime strike count is
    /// already at-or-over `block_at` — i.e. how many would 403
    /// right now if the gate is enabled.
    pub at_or_over_threshold: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StrikesPutBody {
    pub enabled: bool,
    #[serde(default = "default_strikes_block_at")]
    pub block_at: u32,
}

fn default_strikes_block_at() -> u32 {
    50
}

impl StrikesPutBody {
    pub fn validate(self) -> Result<StrikeConfig, Vec<String>> {
        let mut errors = Vec::new();
        if self.block_at == 0 {
            errors.push("block_at must be > 0".into());
        }
        if !errors.is_empty() {
            return Err(errors);
        }
        Ok(StrikeConfig {
            enabled: self.enabled,
            block_at: self.block_at,
        })
    }
}

/// Render the `/api/gates/strikes` GET payload from the live
/// `RiskTracker`. The `top(usize::MAX)` snapshot is N entries
/// where N is bounded by the per-IP map size — typically tiny
/// in production (only IPs that have triggered a detector are
/// tracked).
pub fn render_get_strikes(risk: &RiskTracker) -> String {
    let cfg = risk.strike_config_snapshot();
    let n = risk.len();
    // Count IPs whose strike count is at-or-over `block_at`.
    // Iterating top(n) is the public read path; the snapshot
    // already carries `strikes` so no extra cost vs. a custom
    // map walk.
    let at_or_over = if cfg.block_at == 0 {
        0
    } else {
        risk.top(n)
            .into_iter()
            .filter(|s| s.strikes >= cfg.block_at)
            .count()
    };
    let view = StrikesView {
        enabled: cfg.enabled,
        block_at: cfg.block_at,
        tracked_ips: n,
        at_or_over_threshold: at_or_over,
    };
    serde_json::to_string(&view).unwrap_or_else(|_| String::from("{}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interop::headers::Mode;
    use crate::interop::mode::ModeStore;
    use crate::interop::rule_map::mode_for_rule;

    // ---- PR (2026-07-02) — per-feature gate mode toggle from the UI -----
    //
    // `set_feature_mode` lets the admin surface (PUT /api/gates/ddos/mode)
    // flip a feature's interop mode override, so a `set_profile log_only`
    // on the DDoS gate can be re-enforced without the loopback control API.

    #[test]
    fn set_feature_mode_enforce_makes_the_feature_enforce() {
        // Start with the whole store in log_only (a global dry-run).
        let modes = ModeStore::new(Mode::LogOnly);
        assert_eq!(mode_for_rule(&modes, Some("ddos")), Mode::LogOnly);
        let applied = set_feature_mode(&modes, "ddos", "enforce").unwrap();
        assert_eq!(applied, Mode::Enforce);
        // Explicit override wins over the global default.
        assert_eq!(mode_for_rule(&modes, Some("ddos")), Mode::Enforce);
    }

    #[test]
    fn set_feature_mode_log_only_makes_the_feature_log_only() {
        let modes = ModeStore::new(Mode::Enforce);
        let applied = set_feature_mode(&modes, "ddos", "log_only").unwrap();
        assert_eq!(applied, Mode::LogOnly);
        assert_eq!(mode_for_rule(&modes, Some("ddos")), Mode::LogOnly);
    }

    #[test]
    fn set_feature_mode_rejects_unknown_mode_and_leaves_store_unchanged() {
        let modes = ModeStore::new(Mode::Enforce);
        let r = set_feature_mode(&modes, "ddos", "shadow_banana");
        assert!(r.is_err());
        // The store must not have been mutated by the rejected call.
        assert_eq!(mode_for_rule(&modes, Some("ddos")), Mode::Enforce);
    }

    #[test]
    fn set_feature_mode_only_affects_the_named_feature() {
        let modes = ModeStore::new(Mode::Enforce);
        set_feature_mode(&modes, "ddos", "log_only").unwrap();
        // A different feature still follows the (enforce) default.
        assert_eq!(mode_for_rule(&modes, Some("sqli")), Mode::Enforce);
    }

    #[test]
    fn rate_limit_put_body_defaults_enabled_true_when_omitted() {
        // Older dashboard clients PUT only `{ limit, window_seconds }`. The
        // serde default keeps the gate enabled rather than disabling it.
        let body: RateLimitPutBody =
            serde_json::from_str(r#"{ "limit": 500, "window_seconds": 10 }"#).unwrap();
        assert!(body.enabled);
        let cfg = body.validate().unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.limit, 500);
    }

    #[test]
    fn rate_limit_put_body_carries_explicit_disable() {
        let body: RateLimitPutBody =
            serde_json::from_str(r#"{ "enabled": false, "limit": 500, "window_seconds": 10 }"#)
                .unwrap();
        assert!(!body.enabled);
        assert!(!body.validate().unwrap().enabled);
    }

    #[test]
    fn rate_limit_put_body_still_validates_limit_and_window() {
        let errs = serde_json::from_str::<RateLimitPutBody>(
            r#"{ "enabled": true, "limit": 0, "window_seconds": 0 }"#,
        )
        .unwrap()
        .validate()
        .unwrap_err();
        assert_eq!(errs.len(), 2);
    }

    #[test]
    fn render_returns_disabled_shape_when_runtime_absent() {
        let body = render_get(None, "enforce");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["enabled"], false);
        // 2026-05-09 — config is now nested so the dashboard can
        // render the full configured-state grid alongside live
        // telemetry.
        assert_eq!(v["config"]["enabled"], false);
        assert_eq!(v["config"]["observe_only"], false);
        assert_eq!(v["current_rps"], 0);
        assert_eq!(v["baseline_rps"], 0);
        assert_eq!(v["spike_active"], false);
        assert_eq!(v["effective_mode"], "enforce");
    }

    #[test]
    fn render_reflects_log_only_interop_mode() {
        // 2026-05-22 — a `set_profile log_only` on the ddos feature must
        // surface in the gate view so the dashboard stops mislabeling it
        // as "enforcing". effective_mode is independent of the config
        // observe_only flag.
        let body = render_get(None, "log_only");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["effective_mode"], "log_only");
    }

    #[test]
    fn render_returns_runtime_shape_when_present() {
        // MockState lives in the ddos test module; we can't reach
        // it from here. Build a real DdosRuntime against a
        // `noop` state backend for the smoke test.
        use aegis_security::ddos::DdosConfig;
        use std::time::Duration;

        struct DummyState;

        #[async_trait::async_trait]
        impl aegis_core::state::StateBackend for DummyState {
            async fn get(&self, _: &str) -> aegis_core::Result<Option<Vec<u8>>> {
                Ok(None)
            }
            async fn set(&self, _: &str, _: &[u8], _: Duration) -> aegis_core::Result<()> {
                Ok(())
            }
            async fn del(&self, _: &str) -> aegis_core::Result<()> {
                Ok(())
            }
            async fn incr_window(
                &self,
                _: &str,
                _: Duration,
                _: u64,
            ) -> aegis_core::Result<aegis_core::SlidingWindowResult> {
                Ok(aegis_core::SlidingWindowResult {
                    count: 1,
                    allowed: true,
                    retry_after: None,
                })
            }
            async fn token_bucket(&self, _: &str, _: u32, _: u32) -> aegis_core::Result<bool> {
                Ok(true)
            }
            async fn get_risk(&self, _: &aegis_core::RiskKey) -> aegis_core::Result<u32> {
                Ok(0)
            }
            async fn add_risk(
                &self,
                _: &aegis_core::RiskKey,
                _: i32,
                _: u32,
            ) -> aegis_core::Result<u32> {
                Ok(0)
            }
            async fn auto_block(
                &self,
                _: std::net::IpAddr,
                _: Duration,
            ) -> aegis_core::Result<()> {
                Ok(())
            }
            async fn is_auto_blocked(
                &self,
                _: std::net::IpAddr,
            ) -> aegis_core::Result<bool> {
                Ok(false)
            }
            async fn put_nonce(&self, _: &str, _: Duration) -> aegis_core::Result<bool> {
                Ok(true)
            }
            async fn consume_nonce(&self, _: &str) -> aegis_core::Result<bool> {
                Ok(true)
            }
        }

        let runtime = Arc::new(DdosRuntime::new(
            DdosConfig {
                enabled: true,
                observe_only: false,
                per_ip_limit: 100,
                per_ip_window_s: 10,
                block_ttl_s: 60,
                spike_multiplier: 3.0,
                tightened_per_ip_rps: 20,
                tier_overrides: std::collections::HashMap::new(),
                failure_mode: std::collections::HashMap::new(),
                ..Default::default()
            },
            Arc::new(DummyState),
        ));
        let body = render_get(Some(&runtime), "enforce");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["enabled"], true);
        assert_eq!(v["config"]["enabled"], true);
        assert_eq!(v["config"]["observe_only"], false);
        assert_eq!(v["config"]["per_ip_limit"], 100);
        assert_eq!(v["config"]["per_ip_window_s"], 10);
        assert_eq!(v["config"]["block_ttl_s"], 60);
        assert_eq!(v["config"]["tightened_per_ip_rps"], 20);
        // P2 dwell knobs surfaced to the dashboard (defaults 2/8).
        assert_eq!(v["config"]["spike_engage_ticks"], 2);
        assert_eq!(v["config"]["spike_release_ticks"], 8);
        assert!(v.get("current_rps").is_some());
        assert!(v.get("baseline_rps").is_some());
        assert_eq!(v["spike_active"], false);
    }

    #[test]
    fn ddos_put_body_validates_thresholds() {
        let valid = DdosPutBody {
            enabled: true,
            observe_only: false,
            per_ip_limit: 100,
            per_ip_window_s: 10,
            block_ttl_s: 60,
            spike_multiplier: 3.0,
            tightened_per_ip_rps: 20,
            spike_engage_ticks: 3,
            spike_release_ticks: 9,
            spike_scope: aegis_core::config::SpikeScope::PerNode,
        };
        // Fleet RPS aggregation — spike_scope round-trips so a dashboard PUT
        // never clobbers a YAML `fleet` back to `per_node`.
        let fleet = DdosPutBody {
            spike_scope: aegis_core::config::SpikeScope::Fleet,
            ..valid.clone()
        };
        assert_eq!(
            fleet.validate().unwrap().spike_scope,
            aegis_core::config::SpikeScope::Fleet
        );

        // Dwell knobs round-trip from PUT into the runtime config.
        let cfg = valid.validate().unwrap();
        assert_eq!(cfg.spike_engage_ticks, 3);
        assert_eq!(cfg.spike_release_ticks, 9);

        let zero_limit = DdosPutBody {
            enabled: true,
            observe_only: false,
            per_ip_limit: 0,
            per_ip_window_s: 10,
            block_ttl_s: 60,
            spike_multiplier: 3.0,
            tightened_per_ip_rps: 20,
            spike_engage_ticks: 2,
            spike_release_ticks: 8,
            spike_scope: aegis_core::config::SpikeScope::PerNode,
        };
        let errs = zero_limit.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("per_ip_limit")));

        let bad_multiplier = DdosPutBody {
            enabled: true,
            observe_only: false,
            per_ip_limit: 100,
            per_ip_window_s: 10,
            block_ttl_s: 60,
            spike_multiplier: 0.5, // < 1.0
            tightened_per_ip_rps: 20,
            spike_engage_ticks: 2,
            spike_release_ticks: 8,
            spike_scope: aegis_core::config::SpikeScope::PerNode,
        };
        let errs = bad_multiplier.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("spike_multiplier")));

        let zero_engage = DdosPutBody {
            enabled: true,
            observe_only: false,
            per_ip_limit: 100,
            per_ip_window_s: 10,
            block_ttl_s: 60,
            spike_multiplier: 3.0,
            tightened_per_ip_rps: 20,
            spike_engage_ticks: 0,
            spike_release_ticks: 8,
            spike_scope: aegis_core::config::SpikeScope::PerNode,
        };
        let errs = zero_engage.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("spike_engage_ticks")));
    }

    #[test]
    fn rate_limit_put_body_validates_bounds() {
        let valid = RateLimitPutBody { enabled: true, limit: 100, window_seconds: 60 };
        assert!(valid.validate().is_ok());

        let zero = RateLimitPutBody { enabled: true, limit: 0, window_seconds: 60 };
        let errs = zero.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("limit")));

        let zero_w = RateLimitPutBody { enabled: true, limit: 100, window_seconds: 0 };
        let errs = zero_w.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("window_seconds")));
    }

    #[test]
    fn strikes_put_body_validates_bounds() {
        let valid = StrikesPutBody { enabled: true, block_at: 50 };
        let cfg = valid.validate().unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.block_at, 50);

        let disable = StrikesPutBody { enabled: false, block_at: 50 };
        assert!(disable.validate().is_ok());

        let zero = StrikesPutBody { enabled: true, block_at: 0 };
        let errs = zero.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("block_at")));
    }

    #[test]
    fn render_get_strikes_returns_disabled_default_shape() {
        use aegis_core::config::RiskConfig;
        let tracker = RiskTracker::new(&RiskConfig::default());
        let body = render_get_strikes(&tracker);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        // 2026-05-10 — production default is `enabled: false`.
        assert_eq!(v["enabled"], false);
        assert_eq!(v["block_at"], 50);
        assert_eq!(v["tracked_ips"], 0);
        assert_eq!(v["at_or_over_threshold"], 0);
    }
}
