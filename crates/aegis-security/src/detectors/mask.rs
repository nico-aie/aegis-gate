//! Detector class mask — hot-path on/off bitfield for the toggles
//! exposed in `DetectorsConfig` (P2 of the security-toggle plan).
//!
//! The configuration schema has carried per-detector
//! `{ enabled: bool }` flags since W1, but the data plane never
//! consulted them — `default_detectors()` was hardwired at boot.
//! This module closes that gap with a compact bitfield + an
//! `ArcSwap` so a control-plane PUT can flip a class off in O(1)
//! without restarting the proxy.
//!
//! # Why a bitfield
//! The hot path runs the mask check once per detector per request
//! (currently 7 detectors × ~5 000 RPS = 35 k checks/sec). A bit
//! mask collapses the seven YAML toggles into a single 32-bit
//! word, which fits in one cache line and is read with a relaxed
//! load — cheaper than a `HashMap<&str, bool>` lookup or even a
//! pointer chase through `Arc<DetectorsConfig>`.
//!
//! # Hot-reload
//! [`SharedDetectorMask`] wraps the mask in
//! `arc_swap::ArcSwap<DetectorMask>`. The control-plane PUT
//! handler calls [`SharedDetectorMask::store`]; readers call
//! [`SharedDetectorMask::load`] — neither blocks the other.

use std::sync::Arc;

use aegis_core::config::DetectorsConfig;
use aegis_core::tier::Tier;
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};

/// Detector classes that map 1:1 onto `DetectorsConfig` fields and
/// `Detector::id()` strings. Adding a new detector means
/// 1. add a variant here,
/// 2. add a bit to [`DetectorMask::BITS`] table below,
/// 3. add a field to `DetectorsConfig`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectorClass {
    Sqli,
    Xss,
    PathTraversal,
    Ssrf,
    HeaderInjection,
    BodyAbuse,
    Recon,
    BruteForce,
    /// 2026-05-08 SEC-M002 — dedicated command-injection class.
    /// `$()`, backticks, `${}`, pipe/semi-shell-cmd patterns.
    CommandInjection,
    /// 2026-05-08 Run-5 GAP-006 — server-side template injection.
    /// Jinja2 / Twig / Mako / Freemarker / Velocity / SpEL / Handlebars.
    TemplateInjection,
    /// 2026-05-08 Run-5 GAP-007 — NoSQL (MongoDB) operator injection.
    /// Bracketed query operators + `$`-prefixed JSON keys.
    NoSqlInjection,
    /// 2026-05-09 Run-5 GAP-009 — open-redirect detector. Flags
    /// suspicious external-URL values in known redirect-style
    /// query parameters (`?next=`, `?redirect_uri=`, etc.). Score
    /// 30; `allowed_domains` allowlist suppresses operator-approved
    /// targets.
    OpenRedirect,
    /// 2026-05-19 — promoted from "always-on stealth detector" to a
    /// first-class togglable class. Stateful per-IP behaviour
    /// signals: burst (<50 ms), missing UA, missing Referer on
    /// mutations, zero-depth first-touch. Default OFF — high FP on
    /// single-IP smoke tests / NAT'd egress.
    BehaviorSignals,
    /// 2026-05-19 — cross-endpoint sequence engine. Detects
    /// login→deposit / login→withdrawal chains tighter than 5 s.
    /// Default ON — zero cost when the upstream has no matching
    /// routes.
    Velocity,
    /// 2026-05-19 — operator-supplied recon tripwire (`/wp-admin`,
    /// `/.env`, etc.). Inert unless `cfg.risk.canary_paths` is
    /// non-empty AND this toggle is on. Default OFF.
    Canary,
    /// 2026-05-19 — the ONNX classifier detector. Previously gated
    /// only by `cfg.ai.enabled` + a separate AtomicBool; now also
    /// reflected in the mask so the dashboard can list it and
    /// per-tier overrides apply (Phase 3 — wires the hot-path
    /// short-circuit).
    Ai,
}

impl DetectorClass {
    /// All classes in the order they appear in `DetectorsConfig`.
    pub const ALL: [DetectorClass; 16] = [
        DetectorClass::Sqli,
        DetectorClass::Xss,
        DetectorClass::PathTraversal,
        DetectorClass::Ssrf,
        DetectorClass::HeaderInjection,
        DetectorClass::BodyAbuse,
        DetectorClass::Recon,
        DetectorClass::BruteForce,
        DetectorClass::CommandInjection,
        DetectorClass::TemplateInjection,
        DetectorClass::NoSqlInjection,
        DetectorClass::OpenRedirect,
        DetectorClass::BehaviorSignals,
        DetectorClass::Velocity,
        DetectorClass::Canary,
        DetectorClass::Ai,
    ];

    /// Wire-compatible string used in `Detector::id()` and the JSON
    /// API. Stable: the dashboard pins these names.
    pub const fn as_str(self) -> &'static str {
        match self {
            DetectorClass::Sqli => "sqli",
            DetectorClass::Xss => "xss",
            DetectorClass::PathTraversal => "path_traversal",
            DetectorClass::Ssrf => "ssrf",
            DetectorClass::HeaderInjection => "header_injection",
            DetectorClass::BodyAbuse => "body_abuse",
            DetectorClass::Recon => "recon",
            DetectorClass::BruteForce => "brute_force",
            DetectorClass::CommandInjection => "command_injection",
            DetectorClass::TemplateInjection => "template_injection",
            DetectorClass::NoSqlInjection => "nosql_injection",
            DetectorClass::OpenRedirect => "open_redirect",
            DetectorClass::BehaviorSignals => "behavior_signals",
            DetectorClass::Velocity => "velocity",
            DetectorClass::Canary => "canary",
            DetectorClass::Ai => "ai",
        }
    }

    /// Bit position in [`DetectorMask`]. Stable across versions —
    /// never reorder.
    pub const fn bit(self) -> u32 {
        match self {
            DetectorClass::Sqli => 1 << 0,
            DetectorClass::Xss => 1 << 1,
            DetectorClass::PathTraversal => 1 << 2,
            DetectorClass::Ssrf => 1 << 3,
            DetectorClass::HeaderInjection => 1 << 4,
            DetectorClass::BodyAbuse => 1 << 5,
            DetectorClass::Recon => 1 << 6,
            DetectorClass::BruteForce => 1 << 7,
            DetectorClass::CommandInjection => 1 << 8,
            DetectorClass::TemplateInjection => 1 << 9,
            DetectorClass::NoSqlInjection => 1 << 10,
            DetectorClass::OpenRedirect => 1 << 11,
            DetectorClass::BehaviorSignals => 1 << 12,
            DetectorClass::Velocity => 1 << 13,
            DetectorClass::Canary => 1 << 14,
            DetectorClass::Ai => 1 << 15,
        }
    }

    /// Reverse lookup from `Detector::id()` → class. Returns `None`
    /// for unrecognised detectors so future plug-in detectors can
    /// run unconditionally until they're toggleable.
    pub fn from_id(id: &str) -> Option<DetectorClass> {
        Self::ALL.iter().copied().find(|c| c.as_str() == id)
    }
}

/// Compact bitfield of enabled detector classes. Cheap to copy
/// (`u32`); cheap to compare; cheap to AND with a per-request
/// override mask if/when D-M4 tier-level overrides land.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DetectorMask {
    bits: u32,
}

impl DetectorMask {
    /// Mask with every known class enabled.
    pub const fn all_enabled() -> Self {
        let mut bits = 0;
        let mut i = 0;
        // const-loop unrolled — keep in sync with `DetectorClass::ALL`.
        while i < DetectorClass::ALL.len() {
            bits |= DetectorClass::ALL[i].bit();
            i += 1;
        }
        Self { bits }
    }

    /// Empty mask — every class off. Useful for "disable everything"
    /// tests + the future maintenance-mode footgun.
    pub const fn none() -> Self {
        Self { bits: 0 }
    }

    /// Build the mask from a config snapshot.
    pub fn from_config(cfg: &DetectorsConfig) -> Self {
        let mut m = Self::none();
        if cfg.sqli.enabled {
            m.set(DetectorClass::Sqli, true);
        }
        if cfg.xss.enabled {
            m.set(DetectorClass::Xss, true);
        }
        if cfg.path_traversal.enabled {
            m.set(DetectorClass::PathTraversal, true);
        }
        if cfg.ssrf.enabled {
            m.set(DetectorClass::Ssrf, true);
        }
        if cfg.header_injection.enabled {
            m.set(DetectorClass::HeaderInjection, true);
        }
        if cfg.body_abuse.enabled {
            m.set(DetectorClass::BodyAbuse, true);
        }
        if cfg.recon.enabled {
            m.set(DetectorClass::Recon, true);
        }
        if cfg.brute_force.enabled {
            m.set(DetectorClass::BruteForce, true);
        }
        if cfg.command_injection.enabled {
            m.set(DetectorClass::CommandInjection, true);
        }
        if cfg.template_injection.enabled {
            m.set(DetectorClass::TemplateInjection, true);
        }
        if cfg.nosql_injection.enabled {
            m.set(DetectorClass::NoSqlInjection, true);
        }
        if cfg.open_redirect.enabled {
            m.set(DetectorClass::OpenRedirect, true);
        }
        // 2026-05-19 — Phase F detectors promoted to togglable mask
        // bits. Defaults applied via DetectorsConfig::default in
        // aegis-core (behavior_signals=false, velocity=true,
        // canary=false). `Ai` is seeded in aegis-proxy::run from
        // `cfg.ai.enabled` because the AI config lives in a sibling
        // struct (cfg.ai), not in DetectorsConfig.
        if cfg.behavior_signals.enabled {
            m.set(DetectorClass::BehaviorSignals, true);
        }
        if cfg.velocity.enabled {
            m.set(DetectorClass::Velocity, true);
        }
        if cfg.canary.enabled {
            m.set(DetectorClass::Canary, true);
        }
        m
    }

    /// Read one class.
    pub const fn is_enabled(self, class: DetectorClass) -> bool {
        (self.bits & class.bit()) != 0
    }

    /// Convenience: look up by detector id string.
    pub fn is_enabled_id(self, id: &str) -> bool {
        match DetectorClass::from_id(id) {
            Some(c) => self.is_enabled(c),
            // Unknown detectors run unconditionally.
            None => true,
        }
    }

    /// Set one class on or off, returning the new mask.
    pub fn with(self, class: DetectorClass, on: bool) -> Self {
        let mut m = self;
        m.set(class, on);
        m
    }

    pub fn set(&mut self, class: DetectorClass, on: bool) {
        if on {
            self.bits |= class.bit();
        } else {
            self.bits &= !class.bit();
        }
    }

    /// Iterate over `(class, enabled)` pairs in declaration order —
    /// stable for JSON serialization.
    pub fn entries(self) -> impl Iterator<Item = (DetectorClass, bool)> {
        DetectorClass::ALL
            .into_iter()
            .map(move |c| (c, self.is_enabled(c)))
    }

    /// Raw bits — exposed for tests + observability metrics.
    pub const fn bits(self) -> u32 {
        self.bits
    }
}

/// Serializable form of the mask used by `/api/detectors`.
/// Every field is `#[serde(default)]` so a partial PUT body (only
/// the toggles the caller wants to change) deserialises with the
/// rest defaulting to `false`. The dashboard always sends the full
/// shape; partial bodies are tolerated for scripted callers.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DetectorMaskBody {
    #[serde(default)]
    pub sqli: bool,
    #[serde(default)]
    pub xss: bool,
    #[serde(default)]
    pub path_traversal: bool,
    #[serde(default)]
    pub ssrf: bool,
    #[serde(default)]
    pub header_injection: bool,
    #[serde(default)]
    pub body_abuse: bool,
    #[serde(default)]
    pub recon: bool,
    #[serde(default)]
    pub brute_force: bool,
    /// 2026-05-08 SEC-M002 — command-injection class. Defaults
    /// to `false` on the wire (`#[serde(default)]`) so older
    /// snapshot files load without erroring; the round-trip
    /// helpers below populate it from the bitmask.
    #[serde(default)]
    pub command_injection: bool,
    /// 2026-05-08 Run-5 GAP-006 — template-injection class.
    /// Same `#[serde(default)]` back-compat for older snapshots.
    #[serde(default)]
    pub template_injection: bool,
    /// 2026-05-08 Run-5 GAP-007 — NoSQL operator injection class.
    /// Same `#[serde(default)]` back-compat.
    #[serde(default)]
    pub nosql_injection: bool,
    /// 2026-05-09 Run-5 GAP-009 — open-redirect class. Same
    /// `#[serde(default)]` back-compat.
    #[serde(default)]
    pub open_redirect: bool,
    /// 2026-05-19 — behaviour-signals detector (burst / no-UA /
    /// missing-Referer / zero-depth). Stateful per-IP; default OFF
    /// on the schema side, see `DetectorsConfig::default`.
    #[serde(default)]
    pub behavior_signals: bool,
    /// 2026-05-19 — cross-endpoint velocity-sequence engine. Default
    /// ON. Zero cost when the upstream has no matching routes.
    #[serde(default)]
    pub velocity: bool,
    /// 2026-05-19 — canary recon tripwire. Default OFF; also gated
    /// by `cfg.risk.canary_paths` being non-empty.
    #[serde(default)]
    pub canary: bool,
    /// 2026-05-19 — ONNX classifier detector. Mirrors
    /// `cfg.ai.enabled` at boot; runtime PUT /api/ai/enabled keeps
    /// flipping both this bit AND the existing AtomicBool so the
    /// hot path stays cheap.
    #[serde(default)]
    pub ai: bool,
}

impl From<DetectorMask> for DetectorMaskBody {
    fn from(m: DetectorMask) -> Self {
        Self {
            sqli: m.is_enabled(DetectorClass::Sqli),
            xss: m.is_enabled(DetectorClass::Xss),
            path_traversal: m.is_enabled(DetectorClass::PathTraversal),
            ssrf: m.is_enabled(DetectorClass::Ssrf),
            header_injection: m.is_enabled(DetectorClass::HeaderInjection),
            body_abuse: m.is_enabled(DetectorClass::BodyAbuse),
            recon: m.is_enabled(DetectorClass::Recon),
            brute_force: m.is_enabled(DetectorClass::BruteForce),
            command_injection: m.is_enabled(DetectorClass::CommandInjection),
            template_injection: m.is_enabled(DetectorClass::TemplateInjection),
            nosql_injection: m.is_enabled(DetectorClass::NoSqlInjection),
            open_redirect: m.is_enabled(DetectorClass::OpenRedirect),
            behavior_signals: m.is_enabled(DetectorClass::BehaviorSignals),
            velocity: m.is_enabled(DetectorClass::Velocity),
            canary: m.is_enabled(DetectorClass::Canary),
            ai: m.is_enabled(DetectorClass::Ai),
        }
    }
}

impl From<DetectorMaskBody> for DetectorMask {
    fn from(b: DetectorMaskBody) -> Self {
        DetectorMask::none()
            .with(DetectorClass::Sqli, b.sqli)
            .with(DetectorClass::Xss, b.xss)
            .with(DetectorClass::PathTraversal, b.path_traversal)
            .with(DetectorClass::Ssrf, b.ssrf)
            .with(DetectorClass::HeaderInjection, b.header_injection)
            .with(DetectorClass::BodyAbuse, b.body_abuse)
            .with(DetectorClass::Recon, b.recon)
            .with(DetectorClass::BruteForce, b.brute_force)
            .with(DetectorClass::CommandInjection, b.command_injection)
            .with(DetectorClass::TemplateInjection, b.template_injection)
            .with(DetectorClass::NoSqlInjection, b.nosql_injection)
            .with(DetectorClass::OpenRedirect, b.open_redirect)
            .with(DetectorClass::BehaviorSignals, b.behavior_signals)
            .with(DetectorClass::Velocity, b.velocity)
            .with(DetectorClass::Canary, b.canary)
            .with(DetectorClass::Ai, b.ai)
    }
}

/// Effective mask state held inside the [`SharedDetectorMask`]
/// `ArcSwap`. Carries both the global base mask and per-tier
/// overrides (P3 of the security-toggle plan). Indexed by
/// [`tier_index`] so reads stay branchless on the hot path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaskState {
    pub base: DetectorMask,
    pub overrides: [Option<DetectorMask>; 4],
}

impl MaskState {
    pub const fn new(base: DetectorMask) -> Self {
        Self {
            base,
            overrides: [None; 4],
        }
    }

    /// Resolve the effective mask for a request whose tier was
    /// classified to `tier`. `None` (e.g. an unrouted health
    /// check) falls back to the base mask.
    pub fn resolve(&self, tier: Option<Tier>) -> DetectorMask {
        match tier {
            Some(t) => self.overrides[tier_index(t)].unwrap_or(self.base),
            None => self.base,
        }
    }

    pub fn override_for(&self, tier: Tier) -> Option<DetectorMask> {
        self.overrides[tier_index(tier)]
    }

    pub fn with_override(mut self, tier: Tier, mask: Option<DetectorMask>) -> Self {
        self.overrides[tier_index(tier)] = mask;
        self
    }

    pub fn with_base(mut self, base: DetectorMask) -> Self {
        self.base = base;
        self
    }
}

impl Default for MaskState {
    fn default() -> Self {
        Self::new(DetectorMask::all_enabled())
    }
}

/// Stable index into [`MaskState::overrides`]. Pinned so a future
/// new tier variant doesn't silently shift existing entries.
pub const fn tier_index(tier: Tier) -> usize {
    match tier {
        Tier::Critical => 0,
        Tier::High => 1,
        Tier::Medium => 2,
        Tier::Low => 3,
    }
}

/// All tier variants in [`tier_index`] order — used for stable
/// iteration in JSON serialization.
pub const ALL_TIERS: [Tier; 4] = [Tier::Critical, Tier::High, Tier::Medium, Tier::Low];

/// Wire-compatible string codes for `Tier`. Mirrors
/// `#[serde(rename_all = "snake_case")]` so dashboards and YAML
/// agree.
pub const fn tier_str(tier: Tier) -> &'static str {
    match tier {
        Tier::Critical => "critical",
        Tier::High => "high",
        Tier::Medium => "medium",
        Tier::Low => "low",
    }
}

/// `Arc<ArcSwap<MaskState>>` newtype so the proxy and control
/// plane share a single hot-reloadable mask handle. Cheap to clone.
#[derive(Clone)]
pub struct SharedDetectorMask {
    inner: Arc<ArcSwap<MaskState>>,
}

impl SharedDetectorMask {
    pub fn new(initial: DetectorMask) -> Self {
        Self::from_state(MaskState::new(initial))
    }

    pub fn from_state(state: MaskState) -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(state)),
        }
    }

    pub fn from_config(cfg: &DetectorsConfig) -> Self {
        Self::new(DetectorMask::from_config(cfg))
    }

    /// Hot path read — returns the *base* mask. Preserved for
    /// callers that don't have a tier in scope (e.g. legacy
    /// readers); per-tier callers should use [`Self::resolve`].
    pub fn load(&self) -> DetectorMask {
        self.inner.load().base
    }

    /// Effective mask for a request. `None` falls back to the base.
    pub fn resolve(&self, tier: Option<Tier>) -> DetectorMask {
        self.inner.load().resolve(tier)
    }

    /// Snapshot the full state (base + overrides). Cheap clone of
    /// a `MaskState` — `Copy` for `Option<DetectorMask>` arrays.
    pub fn load_state(&self) -> MaskState {
        (**self.inner.load()).clone()
    }

    /// Replace the **base** mask, leaving per-tier overrides
    /// untouched. Hot-reload write — see [`Self::store_state`]
    /// for full replacement.
    pub fn store(&self, base: DetectorMask) {
        let new_state = self.load_state().with_base(base);
        self.inner.store(Arc::new(new_state));
    }

    /// Replace the entire mask state (base + overrides) atomically.
    pub fn store_state(&self, state: MaskState) {
        self.inner.store(Arc::new(state));
    }

    /// Set or clear one tier's override. Pass `None` to revert
    /// the tier back to the base mask.
    pub fn set_override(&self, tier: Tier, mask: Option<DetectorMask>) {
        let new_state = self.load_state().with_override(tier, mask);
        self.inner.store(Arc::new(new_state));
    }

    /// Expose the inner handle so other crates can wire their own
    /// hot-reload listeners.
    pub fn handle(&self) -> Arc<ArcSwap<MaskState>> {
        Arc::clone(&self.inner)
    }
}

impl Default for SharedDetectorMask {
    fn default() -> Self {
        Self::from_state(MaskState::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn class_str_round_trips() {
        for c in DetectorClass::ALL {
            assert_eq!(DetectorClass::from_id(c.as_str()), Some(c));
        }
        assert_eq!(DetectorClass::from_id("nope"), None);
    }

    #[test]
    fn bits_are_unique_and_dense() {
        let mut seen = 0u32;
        for c in DetectorClass::ALL {
            let b = c.bit();
            assert_eq!(b & seen, 0, "duplicate bit for {c:?}");
            seen |= b;
        }
        // One bit per class — must match `DetectorClass::ALL`.
        assert_eq!(seen.count_ones(), DetectorClass::ALL.len() as u32);
    }

    #[test]
    fn default_config_mask_matches_documented_defaults() {
        // 2026-05-19 — adjusted from "default == all_enabled" because
        // the Phase F detectors landed with non-uniform defaults:
        //  - behavior_signals: OFF (high FP on single-IP smoke tests)
        //  - velocity: ON (zero cost when upstream lacks matching routes)
        //  - canary: OFF (inert without cfg.risk.canary_paths anyway)
        // AI is also OFF in from_config — its bit is seeded later in
        // aegis-proxy::run from cfg.ai.enabled (sibling config block).
        let cfg = DetectorsConfig::default();
        let mask = DetectorMask::from_config(&cfg);
        // 12 OWASP classes still on by default
        for c in [
            DetectorClass::Sqli,
            DetectorClass::Xss,
            DetectorClass::PathTraversal,
            DetectorClass::Ssrf,
            DetectorClass::HeaderInjection,
            DetectorClass::BodyAbuse,
            DetectorClass::Recon,
            DetectorClass::BruteForce,
            DetectorClass::CommandInjection,
            DetectorClass::TemplateInjection,
            DetectorClass::NoSqlInjection,
            DetectorClass::OpenRedirect,
        ] {
            assert!(mask.is_enabled(c), "OWASP class {c:?} should be on by default");
        }
        assert!(mask.is_enabled(DetectorClass::Velocity), "velocity is ON by default");
        assert!(!mask.is_enabled(DetectorClass::BehaviorSignals), "behavior_signals is OFF by default");
        assert!(!mask.is_enabled(DetectorClass::Canary), "canary is OFF by default");
        assert!(!mask.is_enabled(DetectorClass::Ai), "AI bit seeded by aegis-proxy::run, not from_config");
    }

    #[test]
    fn from_config_respects_disabled_field() {
        let mut cfg = DetectorsConfig::default();
        cfg.xss.enabled = false;
        cfg.recon.enabled = false;
        let mask = DetectorMask::from_config(&cfg);
        assert!(mask.is_enabled(DetectorClass::Sqli));
        assert!(!mask.is_enabled(DetectorClass::Xss));
        assert!(!mask.is_enabled(DetectorClass::Recon));
        assert!(mask.is_enabled(DetectorClass::PathTraversal));
    }

    #[test]
    fn with_toggles_one_class_only() {
        let m = DetectorMask::all_enabled();
        let m2 = m.with(DetectorClass::Sqli, false);
        assert!(!m2.is_enabled(DetectorClass::Sqli));
        // Every other class still on.
        for c in DetectorClass::ALL.iter().filter(|c| **c != DetectorClass::Sqli) {
            assert!(m2.is_enabled(*c), "{c:?} flipped unexpectedly");
        }
    }

    #[test]
    fn phase_f_and_ai_ids_resolve_and_gate() {
        // 2026-05-19 — the dispatcher (run_all_filtered_timed) gates
        // detectors by `mask.is_enabled_id(d.id())`. For Phase F +
        // AI to be per-tier overridable, each id must round-trip
        // through DetectorClass::from_id and respect the mask bit.
        for (id, class) in [
            ("behavior_signals", DetectorClass::BehaviorSignals),
            ("velocity", DetectorClass::Velocity),
            ("canary", DetectorClass::Canary),
            ("ai", DetectorClass::Ai),
        ] {
            assert_eq!(DetectorClass::from_id(id), Some(class), "{id} did not round-trip");
            let off = DetectorMask::all_enabled().with(class, false);
            assert!(!off.is_enabled_id(id), "{id} should be skipped when bit off");
            assert!(off.is_enabled_id("sqli"), "OWASP detectors must stay on when only {id} is off");
        }
    }

    #[test]
    fn is_enabled_id_unknown_runs_unconditionally() {
        let m = DetectorMask::none();
        assert!(m.is_enabled_id("future_detector_not_yet_classed"));
        // Known disabled class still respects the bit.
        assert!(!m.is_enabled_id("sqli"));
    }

    #[test]
    fn body_round_trip_preserves_mask() {
        let mut mask = DetectorMask::all_enabled();
        mask.set(DetectorClass::Sqli, false);
        mask.set(DetectorClass::BruteForce, false);
        let body: DetectorMaskBody = mask.into();
        let back: DetectorMask = body.into();
        assert_eq!(mask, back);
    }

    #[test]
    fn shared_mask_load_returns_initial() {
        let s = SharedDetectorMask::new(DetectorMask::all_enabled());
        assert_eq!(s.load(), DetectorMask::all_enabled());
    }

    #[test]
    fn shared_mask_store_swaps_atomically() {
        let s = SharedDetectorMask::new(DetectorMask::all_enabled());
        let new_mask = DetectorMask::all_enabled().with(DetectorClass::Xss, false);
        s.store(new_mask);
        assert_eq!(s.load(), new_mask);
    }

    #[test]
    fn shared_mask_concurrent_reads_see_consistent_value() {
        // Property: while the writer flips between two known masks,
        // every reader observes one of the two — never a torn value.
        let s = SharedDetectorMask::new(DetectorMask::all_enabled());
        let a = DetectorMask::all_enabled();
        let b = DetectorMask::none();

        let writer = {
            let s = s.clone();
            thread::spawn(move || {
                for i in 0..1_000 {
                    s.store(if i % 2 == 0 { a } else { b });
                }
            })
        };
        let mut readers = Vec::new();
        for _ in 0..4 {
            let s = s.clone();
            readers.push(thread::spawn(move || {
                for _ in 0..1_000 {
                    let observed = s.load();
                    assert!(observed == a || observed == b);
                }
            }));
        }
        writer.join().unwrap();
        for r in readers {
            r.join().unwrap();
        }
    }

    #[test]
    fn entries_iterates_in_declaration_order() {
        let mask = DetectorMask::all_enabled().with(DetectorClass::Xss, false);
        let entries: Vec<_> = mask.entries().collect();
        assert_eq!(entries.len(), DetectorClass::ALL.len());
        assert_eq!(entries[0], (DetectorClass::Sqli, true));
        assert_eq!(entries[1], (DetectorClass::Xss, false));
        // 2026-05-19 — last entry is now Ai (bit 15) after the
        // Phase F + AI promotion to first-class togglable classes.
        // Order: …, OpenRedirect, BehaviorSignals, Velocity, Canary, Ai.
        assert_eq!(
            entries[entries.len() - 1].0,
            DetectorClass::Ai,
        );
        assert_eq!(
            entries[11].0,
            DetectorClass::OpenRedirect,
            "OpenRedirect stays at index 11 — never reorder",
        );
    }

    // ---------- P3 per-tier overrides --------------------------------

    #[test]
    fn tier_index_pinned_to_declaration_order() {
        // Critical=0 / High=1 / Medium=2 / CatchAll=3 — never reorder.
        assert_eq!(tier_index(Tier::Critical), 0);
        assert_eq!(tier_index(Tier::High), 1);
        assert_eq!(tier_index(Tier::Medium), 2);
        assert_eq!(tier_index(Tier::Low), 3);
    }

    #[test]
    fn tier_str_matches_serde_snake_case() {
        assert_eq!(tier_str(Tier::Critical), "critical");
        assert_eq!(tier_str(Tier::Low), "low");
    }

    #[test]
    fn resolve_returns_base_when_no_override_set() {
        let state = MaskState::new(DetectorMask::all_enabled());
        for t in ALL_TIERS {
            assert_eq!(state.resolve(Some(t)), DetectorMask::all_enabled());
        }
        assert_eq!(state.resolve(None), DetectorMask::all_enabled());
    }

    #[test]
    fn resolve_returns_override_when_set() {
        let override_mask =
            DetectorMask::all_enabled().with(DetectorClass::Recon, false);
        let state = MaskState::new(DetectorMask::all_enabled())
            .with_override(Tier::Medium, Some(override_mask));

        // Medium gets the override; everyone else falls back to base.
        assert_eq!(state.resolve(Some(Tier::Medium)), override_mask);
        assert_eq!(state.resolve(Some(Tier::High)), DetectorMask::all_enabled());
        assert_eq!(state.resolve(Some(Tier::Critical)), DetectorMask::all_enabled());
    }

    #[test]
    fn shared_mask_set_override_is_visible_via_resolve() {
        let s = SharedDetectorMask::default();
        let override_mask = DetectorMask::none();
        s.set_override(Tier::Low, Some(override_mask));

        // CatchAll requests now run no detectors; other tiers untouched.
        assert_eq!(s.resolve(Some(Tier::Low)), DetectorMask::none());
        assert_eq!(s.resolve(Some(Tier::High)), DetectorMask::all_enabled());

        // Clearing the override reverts to base.
        s.set_override(Tier::Low, None);
        assert_eq!(s.resolve(Some(Tier::Low)), DetectorMask::all_enabled());
    }

    #[test]
    fn shared_mask_store_preserves_overrides() {
        let s = SharedDetectorMask::default();
        let override_mask =
            DetectorMask::all_enabled().with(DetectorClass::BruteForce, false);
        s.set_override(Tier::High, Some(override_mask));

        // Now flip the BASE mask. The High override must survive.
        s.store(DetectorMask::all_enabled().with(DetectorClass::Sqli, false));
        let state = s.load_state();
        assert!(!state.base.is_enabled(DetectorClass::Sqli));
        assert_eq!(state.override_for(Tier::High), Some(override_mask));
        assert_eq!(state.override_for(Tier::Medium), None);
    }

    #[test]
    fn shared_mask_load_returns_base_unchanged_by_overrides() {
        // Backward-compat: existing callers of `load()` see the
        // base mask only; per-tier overrides don't leak through.
        let s = SharedDetectorMask::default();
        s.set_override(Tier::Critical, Some(DetectorMask::none()));
        assert_eq!(s.load(), DetectorMask::all_enabled());
    }

    #[test]
    fn store_state_replaces_overrides_too() {
        let s = SharedDetectorMask::default();
        s.set_override(Tier::Medium, Some(DetectorMask::none()));

        // store_state replaces wholesale.
        let new_state = MaskState::new(DetectorMask::all_enabled());
        s.store_state(new_state);
        assert_eq!(s.resolve(Some(Tier::Medium)), DetectorMask::all_enabled());
    }
}
