//! Load-mode primitive (P7 of the security-toggle plan).
//!
//! Exposes `LoadMode` (Normal / Elevated / Critical), a
//! [`LoadGauge`] that the data plane increments once per request,
//! and the threshold + override surface read by the dashboard.
//! Lives in `aegis-core` because both the proxy (producer) and
//! the control plane (consumer) need it without introducing a new
//! cross-crate dep.
//!
//! # Why explicit modes instead of a single RPS number
//!
//! The hot path makes a small set of yes/no decisions based on
//! load — degrade audit detail, drop non-essential metrics writes,
//! force critical-only logging. Boiling everything to one of
//! three discrete states keeps every decision branch trivial
//! (`if mode == Critical { … }`) and lets the operator pin a mode
//! during incidents without arguing about a numeric threshold.
//!
//! Hysteresis: see `LoadGauge::sample`. Without it, a load right
//! at a threshold would oscillate the mode every second.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};

/// Discrete operational modes the WAF can be in.
///
/// - `Normal`: full audit detail, full metrics, all detectors run.
/// - `Elevated`: skip body/header echoes in audit events, drop
///   non-block detection events from the live feed, halve the SSE
///   broadcast capacity.
/// - `Critical`: only blocked requests produce audit events at
///   all; metrics aggregation runs at lower fidelity; the
///   dashboard pill turns red.
///
/// The set is closed: any future degradation step needs to extend
/// this enum and update [`tier_str`]-style serializers explicitly.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadMode {
    #[default]
    Normal,
    Elevated,
    Critical,
}

impl LoadMode {
    /// Stable string code for the wire / dashboard.
    pub const fn as_str(self) -> &'static str {
        match self {
            LoadMode::Normal => "normal",
            LoadMode::Elevated => "elevated",
            LoadMode::Critical => "critical",
        }
    }

    /// Parse a wire string into a `LoadMode`. Named `parse_str`
    /// rather than `from_str` to avoid colliding with the
    /// `FromStr` trait — we don't want to commit to its
    /// `Result<…, Error>` contract for what is effectively an
    /// optional lookup.
    pub fn parse_str(s: &str) -> Option<LoadMode> {
        match s {
            "normal" => Some(LoadMode::Normal),
            "elevated" => Some(LoadMode::Elevated),
            "critical" => Some(LoadMode::Critical),
            _ => None,
        }
    }

    /// `true` when running in Critical — used by the hot path to
    /// short-circuit non-essential work.
    pub const fn is_critical(self) -> bool {
        matches!(self, LoadMode::Critical)
    }

    /// `true` when running in Elevated or Critical — used by the
    /// hot path to apply mid-tier degradations.
    pub const fn is_degraded(self) -> bool {
        !matches!(self, LoadMode::Normal)
    }
}

/// Threshold configuration. RPS is the fast path metric — the
/// gauge increments a bare atomic per request and samples once
/// per `sample_interval`. `elevated_rps < critical_rps` is
/// validated at config load.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LoadModeConfig {
    #[serde(default = "default_elevated_rps")]
    pub elevated_rps: u32,
    #[serde(default = "default_critical_rps")]
    pub critical_rps: u32,
    /// How often the sampler reads the request counter. Default
    /// 1 s — short enough to react to bursts, long enough that
    /// the AtomicU64 read isn't on a tight loop.
    #[serde(default = "default_sample_interval", with = "humantime_serde")]
    pub sample_interval: Duration,
    /// Hysteresis margin — once the mode steps up, RPS must drop
    /// below `threshold * (1 - hysteresis)` before the mode steps
    /// back down. Stops a borderline workload from oscillating
    /// every second. Default 0.10 (10 %).
    #[serde(default = "default_hysteresis")]
    pub hysteresis: f64,
}

fn default_elevated_rps() -> u32 {
    2_000
}
fn default_critical_rps() -> u32 {
    8_000
}
fn default_sample_interval() -> Duration {
    Duration::from_secs(1)
}
fn default_hysteresis() -> f64 {
    0.10
}

impl Default for LoadModeConfig {
    fn default() -> Self {
        Self {
            elevated_rps: default_elevated_rps(),
            critical_rps: default_critical_rps(),
            sample_interval: default_sample_interval(),
            hysteresis: default_hysteresis(),
        }
    }
}

impl LoadModeConfig {
    /// Validate the configuration — invariant
    /// `elevated_rps < critical_rps` and `0 <= hysteresis < 1`.
    pub fn validate(&self) -> crate::Result<()> {
        if self.elevated_rps == 0 {
            return Err(crate::error::WafError::Config(
                "load_mode.elevated_rps must be > 0".into(),
            ));
        }
        if self.critical_rps <= self.elevated_rps {
            return Err(crate::error::WafError::Config(format!(
                "load_mode.critical_rps ({}) must exceed elevated_rps ({})",
                self.critical_rps, self.elevated_rps,
            )));
        }
        if !(0.0..1.0).contains(&self.hysteresis) {
            return Err(crate::error::WafError::Config(
                "load_mode.hysteresis must be in [0.0, 1.0)".into(),
            ));
        }
        if self.sample_interval < Duration::from_millis(100) {
            return Err(crate::error::WafError::Config(
                "load_mode.sample_interval must be >= 100ms".into(),
            ));
        }
        Ok(())
    }
}

/// Snapshot returned by the gauge for telemetry / API responses.
#[derive(Clone, Debug, Serialize)]
pub struct LoadModeSnapshot {
    pub mode: LoadMode,
    pub effective_mode: LoadMode,
    pub rps_last_sample: u32,
    pub override_active: bool,
    pub elevated_rps: u32,
    pub critical_rps: u32,
}

/// Per-listener gauge. Cheap to clone — internals are `Arc`-shared.
/// The data plane calls `tick()` once per accepted request; a
/// background task calls `sample(now)` once per `sample_interval`.
#[derive(Clone)]
pub struct LoadGauge {
    inner: Arc<LoadGaugeInner>,
}

struct LoadGaugeInner {
    counter: AtomicU64,
    /// Last automatic mode, set by `sample()`.
    auto_mode: ArcSwap<LoadMode>,
    /// Operator override. `Some(_)` wins over `auto_mode` until
    /// cleared. `None` means "follow the sampler".
    manual_override: ArcSwap<Option<LoadMode>>,
    cfg: ArcSwap<LoadModeConfig>,
    /// RPS observed during the last `sample()` window. Atomic so
    /// the API layer can read without taking a lock.
    last_rps: AtomicU64,
}

impl LoadGauge {
    pub fn new(cfg: LoadModeConfig) -> Self {
        Self {
            inner: Arc::new(LoadGaugeInner {
                counter: AtomicU64::new(0),
                auto_mode: ArcSwap::from_pointee(LoadMode::Normal),
                manual_override: ArcSwap::from_pointee(None),
                cfg: ArcSwap::from_pointee(cfg),
                last_rps: AtomicU64::new(0),
            }),
        }
    }

    /// Increment the request counter. Hot-path safe — one
    /// `Relaxed` add and that's it.
    pub fn tick(&self) {
        self.inner.counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Read the effective mode (manual override > auto). Hot path
    /// uses this to gate degraded-detail branches.
    pub fn current(&self) -> LoadMode {
        if let Some(m) = **self.inner.manual_override.load() {
            return m;
        }
        **self.inner.auto_mode.load()
    }

    /// Auto-detected mode (ignoring overrides) — surfaced in the
    /// snapshot so the dashboard can show "auto: critical, pinned:
    /// elevated".
    pub fn auto(&self) -> LoadMode {
        **self.inner.auto_mode.load()
    }

    /// Operator override. Pass `None` to clear.
    pub fn set_override(&self, mode: Option<LoadMode>) {
        self.inner.manual_override.store(Arc::new(mode));
    }

    pub fn override_value(&self) -> Option<LoadMode> {
        **self.inner.manual_override.load()
    }

    /// Sample the request counter and recompute `auto_mode`. Returns
    /// the post-sample mode. Driven by a background task in
    /// production; tests call directly with synthetic counter values.
    pub fn sample(&self, elapsed: Duration) -> LoadMode {
        let count = self.inner.counter.swap(0, Ordering::Relaxed);
        let secs = elapsed.as_secs_f64().max(0.001);
        let rps = (count as f64 / secs).round() as u64;
        self.inner.last_rps.store(rps, Ordering::Relaxed);

        let cfg = (**self.inner.cfg.load()).clone();
        let prev = **self.inner.auto_mode.load();
        let next = next_mode(prev, rps as u32, &cfg);
        if next != prev {
            self.inner.auto_mode.store(Arc::new(next));
        }
        next
    }

    /// Inject a config change at runtime. Useful for the
    /// `PUT /api/loadmode` thresholds-tuning surface.
    pub fn replace_config(&self, cfg: LoadModeConfig) {
        self.inner.cfg.store(Arc::new(cfg));
    }

    pub fn config(&self) -> LoadModeConfig {
        (**self.inner.cfg.load()).clone()
    }

    pub fn last_rps(&self) -> u32 {
        self.inner.last_rps.load(Ordering::Relaxed) as u32
    }

    /// Wire-friendly snapshot of every observable field.
    pub fn snapshot(&self) -> LoadModeSnapshot {
        let cfg = self.config();
        let auto = self.auto();
        let manual = self.override_value();
        LoadModeSnapshot {
            mode: auto,
            effective_mode: manual.unwrap_or(auto),
            rps_last_sample: self.last_rps(),
            override_active: manual.is_some(),
            elevated_rps: cfg.elevated_rps,
            critical_rps: cfg.critical_rps,
        }
    }

    /// Test helper — replaces the internal counter, used by unit
    /// tests that want to drive `sample()` without spinning a
    /// runtime.
    #[doc(hidden)]
    pub fn test_seed_counter(&self, count: u64) {
        self.inner.counter.store(count, Ordering::Relaxed);
    }

    /// Spawn the background sampler. Returns the join handle so
    /// the caller can detach (typical) or await for shutdown.
    pub fn spawn_sampler(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let interval = self.config().sample_interval;
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // First tick fires immediately; absorb it so we sample
            // a full window of requests rather than zero.
            ticker.tick().await;
            let mut last = Instant::now();
            loop {
                ticker.tick().await;
                let now = Instant::now();
                self.sample(now.saturating_duration_since(last));
                last = now;
            }
        })
    }
}

/// Compute the next mode given the previous one, the latest RPS
/// reading, and the threshold / hysteresis config. Pulled out so
/// the transition rules are unit-testable without a gauge.
pub fn next_mode(prev: LoadMode, rps: u32, cfg: &LoadModeConfig) -> LoadMode {
    let crit = cfg.critical_rps as f64;
    let elev = cfg.elevated_rps as f64;
    let hys = cfg.hysteresis;
    let crit_step_down = (crit * (1.0 - hys)) as u32;
    let elev_step_down = (elev * (1.0 - hys)) as u32;
    let r = rps;

    match prev {
        LoadMode::Normal => {
            if r >= cfg.critical_rps {
                LoadMode::Critical
            } else if r >= cfg.elevated_rps {
                LoadMode::Elevated
            } else {
                LoadMode::Normal
            }
        }
        LoadMode::Elevated => {
            if r >= cfg.critical_rps {
                LoadMode::Critical
            } else if r < elev_step_down {
                LoadMode::Normal
            } else {
                LoadMode::Elevated
            }
        }
        LoadMode::Critical => {
            if r < crit_step_down {
                if r >= cfg.elevated_rps {
                    LoadMode::Elevated
                } else {
                    LoadMode::Normal
                }
            } else {
                LoadMode::Critical
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> LoadModeConfig {
        LoadModeConfig {
            elevated_rps: 1_000,
            critical_rps: 5_000,
            sample_interval: Duration::from_secs(1),
            hysteresis: 0.10,
        }
    }

    // ---------- LoadMode primitive ---------------------------------

    #[test]
    fn load_mode_string_codes_round_trip() {
        for m in [LoadMode::Normal, LoadMode::Elevated, LoadMode::Critical] {
            assert_eq!(LoadMode::parse_str(m.as_str()), Some(m));
        }
        assert_eq!(LoadMode::parse_str("nope"), None);
    }

    #[test]
    fn is_degraded_only_for_elevated_and_critical() {
        assert!(!LoadMode::Normal.is_degraded());
        assert!(LoadMode::Elevated.is_degraded());
        assert!(LoadMode::Critical.is_degraded());
    }

    #[test]
    fn is_critical_is_strict() {
        assert!(!LoadMode::Normal.is_critical());
        assert!(!LoadMode::Elevated.is_critical());
        assert!(LoadMode::Critical.is_critical());
    }

    // ---------- Validation -----------------------------------------

    #[test]
    fn config_validate_passes_for_defaults() {
        LoadModeConfig::default().validate().unwrap();
    }

    #[test]
    fn config_rejects_zero_elevated() {
        let mut c = cfg();
        c.elevated_rps = 0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_rejects_critical_below_elevated() {
        let mut c = cfg();
        c.critical_rps = c.elevated_rps; // not strict <
        assert!(c.validate().is_err());
        c.critical_rps = c.elevated_rps - 1;
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_rejects_hysteresis_out_of_range() {
        let mut c = cfg();
        c.hysteresis = 1.0;
        assert!(c.validate().is_err());
        c.hysteresis = -0.1;
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_rejects_short_sample_interval() {
        let mut c = cfg();
        c.sample_interval = Duration::from_millis(50);
        assert!(c.validate().is_err());
    }

    // ---------- next_mode (state transitions) ----------------------

    #[test]
    fn next_mode_steps_up_normal_to_elevated() {
        assert_eq!(next_mode(LoadMode::Normal, 999, &cfg()), LoadMode::Normal);
        assert_eq!(
            next_mode(LoadMode::Normal, 1_000, &cfg()),
            LoadMode::Elevated
        );
    }

    #[test]
    fn next_mode_jumps_normal_to_critical_on_burst() {
        assert_eq!(
            next_mode(LoadMode::Normal, 5_000, &cfg()),
            LoadMode::Critical
        );
    }

    #[test]
    fn next_mode_elevated_steps_up_to_critical() {
        assert_eq!(
            next_mode(LoadMode::Elevated, 5_000, &cfg()),
            LoadMode::Critical
        );
    }

    #[test]
    fn next_mode_elevated_holds_within_hysteresis() {
        let c = cfg();
        // Elevated → step-down at 900 (1000 * 0.9). Anything in
        // [900, 4_999] should keep Elevated.
        assert_eq!(next_mode(LoadMode::Elevated, 950, &c), LoadMode::Elevated);
        assert_eq!(next_mode(LoadMode::Elevated, 900, &c), LoadMode::Elevated);
        assert_eq!(next_mode(LoadMode::Elevated, 899, &c), LoadMode::Normal);
    }

    #[test]
    fn next_mode_critical_holds_within_hysteresis() {
        let c = cfg();
        // Critical → step-down at 4500 (5000 * 0.9).
        assert_eq!(
            next_mode(LoadMode::Critical, 4_700, &c),
            LoadMode::Critical
        );
        assert_eq!(
            next_mode(LoadMode::Critical, 4_500, &c),
            LoadMode::Critical
        );
        // Below 4500 but still above elevated_rps → Elevated.
        assert_eq!(
            next_mode(LoadMode::Critical, 4_499, &c),
            LoadMode::Elevated
        );
        // Below elevated_rps → Normal.
        assert_eq!(
            next_mode(LoadMode::Critical, 500, &c),
            LoadMode::Normal
        );
    }

    // ---------- LoadGauge end-to-end -------------------------------

    #[test]
    fn gauge_tick_and_sample_compute_rps() {
        let g = LoadGauge::new(cfg());
        for _ in 0..1_500 {
            g.tick();
        }
        assert_eq!(g.sample(Duration::from_secs(1)), LoadMode::Elevated);
        assert_eq!(g.last_rps(), 1_500);
        assert_eq!(g.current(), LoadMode::Elevated);
    }

    #[test]
    fn gauge_resets_counter_each_sample() {
        let g = LoadGauge::new(cfg());
        for _ in 0..2_000 {
            g.tick();
        }
        g.sample(Duration::from_secs(1));
        // No new ticks → next sample sees zero RPS.
        assert_eq!(g.sample(Duration::from_secs(1)), LoadMode::Normal);
        assert_eq!(g.last_rps(), 0);
    }

    #[test]
    fn gauge_override_wins_over_auto() {
        let g = LoadGauge::new(cfg());
        for _ in 0..6_000 {
            g.tick();
        }
        g.sample(Duration::from_secs(1));
        // Auto would say Critical, but operator pinned Elevated.
        g.set_override(Some(LoadMode::Elevated));
        assert_eq!(g.current(), LoadMode::Elevated);
        assert_eq!(g.auto(), LoadMode::Critical);
        assert!(g.override_value().is_some());
    }

    #[test]
    fn gauge_clear_override_falls_back_to_auto() {
        let g = LoadGauge::new(cfg());
        g.set_override(Some(LoadMode::Critical));
        assert_eq!(g.current(), LoadMode::Critical);
        g.set_override(None);
        assert_eq!(g.current(), LoadMode::Normal);
        assert!(g.override_value().is_none());
    }

    #[test]
    fn gauge_snapshot_renders_documented_shape() {
        let g = LoadGauge::new(cfg());
        for _ in 0..1_500 {
            g.tick();
        }
        g.sample(Duration::from_secs(1));
        let snap = g.snapshot();
        assert_eq!(snap.mode, LoadMode::Elevated);
        assert_eq!(snap.effective_mode, LoadMode::Elevated);
        assert_eq!(snap.rps_last_sample, 1_500);
        assert!(!snap.override_active);
        assert_eq!(snap.elevated_rps, 1_000);
        assert_eq!(snap.critical_rps, 5_000);
    }

    #[test]
    fn gauge_snapshot_reflects_override() {
        let g = LoadGauge::new(cfg());
        g.set_override(Some(LoadMode::Critical));
        let snap = g.snapshot();
        assert_eq!(snap.mode, LoadMode::Normal); // auto
        assert_eq!(snap.effective_mode, LoadMode::Critical); // override
        assert!(snap.override_active);
    }

    #[test]
    fn gauge_replace_config_changes_thresholds_live() {
        let g = LoadGauge::new(cfg());
        let mut next = cfg();
        next.elevated_rps = 100;
        next.critical_rps = 200;
        g.replace_config(next.clone());
        assert_eq!(g.config().elevated_rps, 100);
        for _ in 0..150 {
            g.tick();
        }
        assert_eq!(g.sample(Duration::from_secs(1)), LoadMode::Elevated);
    }
}
