//! Per-IP risk tracker with lifetime strikes + trust recovery
//! (P6 of the security-toggle plan).
//!
//! # Design
//!
//! The existing [`super::RiskEngine`] operates on a `StateBackend`
//! and is the right surface for distributed deployments where the
//! score must survive a single-node restart. P6's adaptive
//! mitigation needs three more invariants the legacy engine doesn't
//! offer:
//!
//! 1. **Lifetime strikes** — every malicious detection increments
//!    a counter that *never* decays. Once it crosses
//!    `strikes.block_at`, the client is permanently blocked
//!    regardless of how much the float-score has decayed.
//! 2. **Trust recovery** — clean traffic claws back score, but
//!    capped at `trust_recovery.per_hour` to stop a single benign
//!    request from resetting a flagged client.
//! 3. **Adaptive mitigation** — a single `level()` call returns
//!    `Allow` / `Challenge` / `Block` against the configured
//!    `RiskThresholds`, plus a `Block` short-circuit when the
//!    strike counter is exhausted.
//!
//! This module ships an in-process `DashMap`-backed implementation
//! tuned for the hot path. The next iteration replaces the
//! `DashMap` shard with a `StateBackend`-backed shim once cluster
//! membership lands; the public surface stays put.

#![allow(dead_code)]

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aegis_core::config::{RiskConfig, RiskThresholds, StrikeConfig, TrustRecoveryConfig};
use dashmap::DashMap;

use super::RiskLevel;

const DEFAULT_TRUST_PER_HOUR: u32 = 30;

/// Snapshot of one client's risk state. Returned from every
/// mutating call so the caller can act on the post-state without
/// a follow-up read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RiskState {
    pub score: u32,
    pub strikes: u32,
    pub last_seen: Instant,
}

/// Wire-friendly snapshot for `/api/risk` responses.
///
/// 2026-05-19 — `device_fp` + `session` surfaced so the dashboard's
/// Top Attackers table can distinguish two browsers on the same
/// NAT'd IP. Both fields are `Option<String>` and use
/// `skip_serializing_if = "Option::is_none"` so legacy JSON
/// consumers continue to see the IP-only shape on rows where the
/// composite axes are absent (plain-HTTP traffic, anonymous
/// public endpoints).
#[derive(Clone, Debug, serde::Serialize)]
pub struct RiskSnapshot {
    pub ip: String,
    /// 16-hex-char blake3 prefix of `(JA4 ‖ User-Agent)`. Stable
    /// across requests within a TLS session. Absent on plain HTTP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_fp: Option<String>,
    /// Session cookie value (typically a short opaque id). Absent
    /// when no recognised session cookie is sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    pub score: u32,
    pub strikes: u32,
    /// Seconds since the client's last request — useful for the
    /// dashboard "stale row" indicator. `last_seen` itself isn't
    /// surfaced because `Instant` doesn't serialise; we expose the
    /// elapsed delta instead.
    pub idle_seconds: u64,
    pub level: &'static str,
    pub strike_blocked: bool,
}

/// In-process per-IP risk store. Cheap to clone (Arc-shared).
#[derive(Clone)]
pub struct RiskTracker {
    inner: Arc<TrackerInner>,
}

struct TrackerInner {
    /// 2026-05-18 F-CRITICAL-001 (security audit, Phase E): the
    /// store key is now `RiskKey` (composite of IP + device_fp +
    /// session + tenant) instead of bare `IpAddr`. Storage shape
    /// upgrade only — the IP-only methods (`record_malicious(ip)`,
    /// `level(ip)`, …) keep working by constructing
    /// `RiskKey::from_ip(ip)` internally. The new `*_with_key`
    /// methods take the full composite key. IP-only and composite
    /// callers populate DIFFERENT buckets (different keys), which
    /// is exactly the audit's intent: "don't conflate sessions on
    /// the same NAT'd IP".
    map: DashMap<aegis_core::risk::RiskKey, Slot>,
    /// CI-T12 — thresholds are atomically swappable so
    /// `PUT /api/risk/thresholds` can hot-apply new values
    /// without a restart. Reads through `Arc::clone` (free)
    /// and the inner clone is cheap (3 u32s).
    thresholds: arc_swap::ArcSwap<RiskThresholds>,
    trust: TrustRecoveryConfig,
    /// 2026-05-10 — wrapped in ArcSwap so `PUT /api/gates/strikes`
    /// can hot-flip `enabled` and tune `block_at` without a
    /// restart. Per-IP strike *state* in `map` is preserved
    /// across edits — operators tightening thresholds don't
    /// reset every accumulating IP.
    strikes: arc_swap::ArcSwap<StrikeConfig>,
}

#[derive(Copy, Clone, Debug)]
struct Slot {
    score: u32,
    strikes: u32,
    last_seen: Instant,
}

impl RiskTracker {
    /// Build a tracker from a config snapshot. Fields not present
    /// in `RiskConfig` (e.g. trust recovery off) fall back to
    /// sensible defaults — the legacy engine still runs alongside.
    pub fn new(cfg: &RiskConfig) -> Self {
        Self {
            inner: Arc::new(TrackerInner {
                map: DashMap::new(),
                thresholds: arc_swap::ArcSwap::from_pointee(cfg.thresholds.clone()),
                trust: cfg.trust_recovery.clone().unwrap_or_default(),
                strikes: arc_swap::ArcSwap::from_pointee(
                    cfg.strikes.clone().unwrap_or_default(),
                ),
            }),
        }
    }

    /// 2026-05-10 — atomic Strike-Block config swap. The next
    /// `is_strike_blocked()` call sees the new `enabled` /
    /// `block_at`. Per-IP strike counters in `map` survive the
    /// swap: operators flipping the gate on/off or tightening
    /// the threshold mid-incident don't get a free reset.
    pub fn set_strike_config(&self, c: StrikeConfig) {
        self.inner.strikes.store(Arc::new(c));
    }

    /// Snapshot the current Strike-Block config — used by
    /// `/api/gates/strikes` GET, the `before` capture in the
    /// audit-mutated PUT, and tests.
    pub fn strike_config_snapshot(&self) -> StrikeConfig {
        (**self.inner.strikes.load()).clone()
    }

    /// CI-T12 — atomic threshold swap. The next `level()` /
    /// `record_*` call sees the new values; in-flight observations
    /// finish on whichever pointer they captured. `max` is enforced
    /// going forward only (existing scores aren't re-clamped).
    pub fn set_thresholds(&self, t: RiskThresholds) {
        self.inner.thresholds.store(Arc::new(t));
    }

    /// Snapshot the current thresholds — used by `/api/risk/thresholds`
    /// GET and tests.
    pub fn thresholds(&self) -> RiskThresholds {
        (**self.inner.thresholds.load()).clone()
    }

    /// Register a malicious event. Adds `delta` to the score
    /// (clamped at `max`) and increments the lifetime strike
    /// counter by one. Returns the post-state.
    pub fn record_malicious(&self, ip: IpAddr, delta: u32) -> RiskState {
        self.record_malicious_at(ip, delta, Instant::now())
    }

    /// `record_malicious` with an explicit clock — kept public for
    /// deterministic tests.
    pub fn record_malicious_at(
        &self,
        ip: IpAddr,
        delta: u32,
        now: Instant,
    ) -> RiskState {
        self.record_malicious_at_with_key(
            aegis_core::risk::RiskKey::from_ip(ip),
            delta,
            now,
        )
    }

    /// 2026-05-18 F-CRITICAL-001 (security audit, Phase E):
    /// composite-key variant of [`record_malicious`]. Caller
    /// builds the full `RiskKey` (IP + device_fp + session +
    /// tenant) and gets a bucket scoped to that exact tuple. Two
    /// sessions on the same NAT'd IP accumulate independent risk.
    pub fn record_malicious_with_key(
        &self,
        key: aegis_core::risk::RiskKey,
        delta: u32,
    ) -> RiskState {
        self.record_malicious_at_with_key(key, delta, Instant::now())
    }

    /// Composite-key + explicit-clock variant (deterministic tests).
    pub fn record_malicious_at_with_key(
        &self,
        key: aegis_core::risk::RiskKey,
        delta: u32,
        now: Instant,
    ) -> RiskState {
        let mut entry = self.inner.map.entry(key).or_insert(Slot {
            score: 0,
            strikes: 0,
            last_seen: now,
        });
        entry.score = (entry.score + delta).min(self.inner.thresholds.load().max);
        entry.strikes = entry.strikes.saturating_add(1);
        entry.last_seen = now;
        slot_to_state(*entry)
    }

    /// Register a clean request. Applies the trust-recovery cap
    /// based on time since the last touch. Strikes never change
    /// here — only score decays.
    pub fn record_clean(&self, ip: IpAddr) -> RiskState {
        self.record_clean_at(ip, Instant::now())
    }

    pub fn record_clean_at(&self, ip: IpAddr, now: Instant) -> RiskState {
        self.record_clean_at_with_key(
            aegis_core::risk::RiskKey::from_ip(ip),
            now,
        )
    }

    /// Composite-key variant of [`record_clean`]. See
    /// `record_malicious_with_key` for the migration rationale.
    pub fn record_clean_with_key(
        &self,
        key: aegis_core::risk::RiskKey,
    ) -> RiskState {
        self.record_clean_at_with_key(key, Instant::now())
    }

    pub fn record_clean_at_with_key(
        &self,
        key: aegis_core::risk::RiskKey,
        now: Instant,
    ) -> RiskState {
        let mut entry = self.inner.map.entry(key).or_insert(Slot {
            score: 0,
            strikes: 0,
            last_seen: now,
        });
        let elapsed = now.saturating_duration_since(entry.last_seen);
        let recovery = trust_decay_points(elapsed, self.inner.trust.per_hour);
        entry.score = entry.score.saturating_sub(recovery);
        entry.last_seen = now;
        slot_to_state(*entry)
    }

    /// Read the current state without mutating.
    pub fn snapshot(&self, ip: IpAddr) -> Option<RiskState> {
        self.snapshot_with_key(&aegis_core::risk::RiskKey::from_ip(ip))
    }

    /// Composite-key variant of [`snapshot`].
    pub fn snapshot_with_key(
        &self,
        key: &aegis_core::risk::RiskKey,
    ) -> Option<RiskState> {
        self.inner.map.get(key).map(|e| slot_to_state(*e))
    }

    /// Adaptive mitigation decision for a given IP. Strike-block
    /// short-circuits to `Block` regardless of score — that's the
    /// "permanent block on repeated offence" guarantee from the
    /// requirements.
    pub fn level(&self, ip: IpAddr) -> RiskLevel {
        self.level_for_key(&aegis_core::risk::RiskKey::from_ip(ip))
    }

    /// Composite-key variant of [`level`].
    pub fn level_for_key(&self, key: &aegis_core::risk::RiskKey) -> RiskLevel {
        let Some(state) = self.snapshot_with_key(key) else {
            return RiskLevel::Allow;
        };
        if self.is_strike_blocked_for_key(key) {
            return RiskLevel::Block;
        }
        let t = self.inner.thresholds.load();
        if state.score >= t.block_at {
            RiskLevel::Block
        } else if state.score >= t.challenge_at {
            RiskLevel::Challenge
        } else {
            RiskLevel::Allow
        }
    }

    /// 2026-05-10 — Option B per-tier evaluation. Same shape as
    /// [`level`] but uses caller-supplied `challenge_at` /
    /// `block_at` thresholds instead of the global config. Used by
    /// the data plane after route resolution to honor per-tier
    /// `cumulative_challenge_at` / `cumulative_block_at` overrides.
    /// Strike-block check is unchanged (it doesn't have a per-tier
    /// concept — it's a gate-level shedder).
    pub fn level_with(&self, ip: IpAddr, challenge_at: u32, block_at: u32) -> RiskLevel {
        self.level_with_for_key(
            &aegis_core::risk::RiskKey::from_ip(ip),
            challenge_at,
            block_at,
        )
    }

    /// Composite-key variant of [`level_with`].
    pub fn level_with_for_key(
        &self,
        key: &aegis_core::risk::RiskKey,
        challenge_at: u32,
        block_at: u32,
    ) -> RiskLevel {
        if self.is_strike_blocked_for_key(key) {
            return RiskLevel::Block;
        }
        let Some(state) = self.snapshot_with_key(key) else {
            return RiskLevel::Allow;
        };
        if state.score >= block_at {
            RiskLevel::Block
        } else if state.score >= challenge_at {
            RiskLevel::Challenge
        } else {
            RiskLevel::Allow
        }
    }

    /// `true` when the IP's lifetime strike counter has crossed
    /// the configured threshold AND the Strike-Block gate is
    /// enabled. With `enabled = false` (the 2026-05-10 default)
    /// this always returns `false` regardless of strike count
    /// — the counter still climbs in `/api/risk` for forensics
    /// but the data plane does not 403.
    pub fn is_strike_blocked(&self, ip: IpAddr) -> bool {
        self.is_strike_blocked_for_key(&aegis_core::risk::RiskKey::from_ip(ip))
    }

    /// Composite-key variant of [`is_strike_blocked`].
    pub fn is_strike_blocked_for_key(
        &self,
        key: &aegis_core::risk::RiskKey,
    ) -> bool {
        let cfg = self.inner.strikes.load();
        if !cfg.enabled {
            return false;
        }
        self.snapshot_with_key(key)
            .map(|s| s.strikes >= cfg.block_at)
            .unwrap_or(false)
    }

    /// Operator override: clear an IP's strikes and zero its
    /// score. Returns `true` if a row was removed. Gated by the
    /// `AuditedMutate` pipeline at the API layer.
    pub fn reset(&self, ip: IpAddr) -> bool {
        self.reset_with_key(&aegis_core::risk::RiskKey::from_ip(ip))
    }

    /// Composite-key variant of [`reset`].
    pub fn reset_with_key(&self, key: &aegis_core::risk::RiskKey) -> bool {
        self.inner.map.remove(key).is_some()
    }

    /// Drop every tracked IP — score, strikes, last-seen.
    /// Used by the external control plane's `reset_state` to
    /// wipe runtime state between phases.
    pub fn reset_all(&self) {
        self.inner.map.clear();
    }

    /// Top-N riskiest IPs sorted by `(strikes desc, score desc)`.
    /// `level` is recomputed inline so callers can render the
    /// snapshot without a follow-up `level()` call per row.
    pub fn top(&self, n: usize) -> Vec<RiskSnapshot> {
        let now = Instant::now();
        // 2026-05-18 F-CRITICAL-001: iterate composite-key map.
        // The wire-shape snapshot renders only the IP for backward
        // compatibility (the dashboard's Top Attackers list reads
        // `ip` to build deep-links). Composite-key dimensions
        // (device_fp / session / tenant_id) are dropped from the
        // wire shape today; if the dashboard wants per-session
        // resolution later, extend `RiskSnapshot` and the
        // `/api/risk/top` JSON shape additively (Phase E follow-up).
        let mut all: Vec<(aegis_core::risk::RiskKey, Slot)> = self
            .inner
            .map
            .iter()
            .map(|kv| (kv.key().clone(), *kv.value()))
            .collect();
        all.sort_by(|a, b| {
            b.1.strikes
                .cmp(&a.1.strikes)
                .then_with(|| b.1.score.cmp(&a.1.score))
        });
        let t = self.inner.thresholds.load();
        let block_at = t.block_at;
        let challenge_at = t.challenge_at;
        drop(t);
        let strikes_cfg = self.inner.strikes.load();
        let strikes_enabled = strikes_cfg.enabled;
        let strikes_block_at = strikes_cfg.block_at;
        drop(strikes_cfg);
        all.into_iter()
            .take(n)
            .map(|(key, slot)| {
                let strike_blocked =
                    strikes_enabled && slot.strikes >= strikes_block_at;
                let level = if strike_blocked || slot.score >= block_at {
                    "block"
                } else if slot.score >= challenge_at {
                    "challenge"
                } else {
                    "allow"
                };
                RiskSnapshot {
                    ip: key.ip.to_string(),
                    // 2026-05-19 — composite-key axes now surfaced
                    // so the dashboard can render one row per
                    // (ip, device_fp, session) bucket. The plan
                    // is for the SPA to truncate device_fp to the
                    // first 8 hex chars for display; we ship the
                    // full 16-char value here so future tooling
                    // (e.g. the surgical reset endpoint) doesn't
                    // need a round-trip to disambiguate.
                    device_fp: key.device_fp.clone(),
                    session: key.session.clone(),
                    score: slot.score,
                    strikes: slot.strikes,
                    idle_seconds: now
                        .saturating_duration_since(slot.last_seen)
                        .as_secs(),
                    level,
                    strike_blocked,
                }
            })
            .collect()
    }

    /// Number of tracked IPs. Used for the dashboard summary +
    /// metrics export.
    pub fn len(&self) -> usize {
        self.inner.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.map.is_empty()
    }

    /// Render a single IP's snapshot in the wire shape. `None` if
    /// the IP isn't tracked.
    pub fn snapshot_wire(&self, ip: IpAddr) -> Option<RiskSnapshot> {
        let now = Instant::now();
        let state = self.snapshot(ip)?;
        let strike_blocked = self.is_strike_blocked(ip);
        let t = self.inner.thresholds.load();
        let level = if strike_blocked || state.score >= t.block_at {
            "block"
        } else if state.score >= t.challenge_at {
            "challenge"
        } else {
            "allow"
        };
        Some(RiskSnapshot {
            ip: ip.to_string(),
            // IP-only API → composite axes are unknown here.
            device_fp: None,
            session: None,
            score: state.score,
            strikes: state.strikes,
            idle_seconds: now
                .saturating_duration_since(state.last_seen)
                .as_secs(),
            level,
            strike_blocked,
        })
    }
}

fn slot_to_state(slot: Slot) -> RiskState {
    RiskState {
        score: slot.score,
        strikes: slot.strikes,
        last_seen: slot.last_seen,
    }
}

/// Trust-recovery formula. Linear ramp at `per_hour` points per
/// hour of clean traffic. Sub-second elapsed time still
/// contributes (microsecond precision) so a burst of clean
/// requests during a steady stream can pull a flagged client back
/// down — the cap prevents one request from doing it all.
fn trust_decay_points(elapsed: Duration, per_hour: u32) -> u32 {
    if per_hour == 0 {
        return 0;
    }
    let secs = elapsed.as_secs_f64();
    let recovery = secs * (per_hour as f64) / 3600.0;
    recovery.floor().clamp(0.0, u32::MAX as f64) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn cfg() -> RiskConfig {
        let mut c = RiskConfig::default();
        c.trust_recovery = Some(TrustRecoveryConfig { per_hour: 30 });
        // 2026-05-10 — explicitly enable Strike-Block. The
        // production default is `enabled: false` (gate is opt-in),
        // but these tests are about verifying the mechanism, so we
        // turn it on here. See `strike_block_disabled_by_default_*`
        // tests below for the off-by-default behavior.
        c.strikes = Some(StrikeConfig { enabled: true, block_at: 5 });
        c
    }

    #[test]
    fn snapshot_returns_none_for_unknown_ip() {
        let t = RiskTracker::new(&cfg());
        assert!(t.snapshot(ip("1.1.1.1")).is_none());
        assert_eq!(t.level(ip("1.1.1.1")), RiskLevel::Allow);
    }

    #[test]
    fn record_malicious_increments_score_and_strikes() {
        let t = RiskTracker::new(&cfg());
        let s1 = t.record_malicious(ip("10.0.0.1"), 20);
        assert_eq!(s1.score, 20);
        assert_eq!(s1.strikes, 1);
        let s2 = t.record_malicious(ip("10.0.0.1"), 25);
        assert_eq!(s2.score, 45);
        assert_eq!(s2.strikes, 2);
    }

    #[test]
    fn score_clamps_to_thresholds_max() {
        let t = RiskTracker::new(&cfg());
        for _ in 0..50 {
            t.record_malicious(ip("10.0.0.1"), 50);
        }
        let s = t.snapshot(ip("10.0.0.1")).unwrap();
        assert_eq!(s.score, 100); // RiskThresholds default max=100
    }

    #[test]
    fn record_clean_decays_score_within_hourly_cap() {
        // Score=80, per_hour=30. After 30 minutes of clean traffic
        // the cap allows up to 15 points of recovery.
        let t = RiskTracker::new(&cfg());
        let now = Instant::now();
        t.record_malicious_at(ip("10.0.0.1"), 80, now);
        let later = now + Duration::from_secs(1800); // 30 min
        let state = t.record_clean_at(ip("10.0.0.1"), later);
        assert_eq!(state.score, 65); // 80 - 15
    }

    #[test]
    fn record_clean_caps_recovery_at_per_hour() {
        let t = RiskTracker::new(&cfg());
        let now = Instant::now();
        t.record_malicious_at(ip("10.0.0.1"), 80, now);
        // Far more than an hour passes, but we only ever recover
        // 30 points per hour of elapsed time — here, 2h = 60.
        let later = now + Duration::from_secs(2 * 3600);
        let state = t.record_clean_at(ip("10.0.0.1"), later);
        assert_eq!(state.score, 20); // 80 - 60
    }

    #[test]
    fn record_clean_does_not_underflow() {
        let t = RiskTracker::new(&cfg());
        let now = Instant::now();
        t.record_malicious_at(ip("10.0.0.1"), 5, now);
        let later = now + Duration::from_secs(3600);
        let state = t.record_clean_at(ip("10.0.0.1"), later);
        assert_eq!(state.score, 0);
    }

    #[test]
    fn record_clean_does_not_decrement_strikes() {
        let t = RiskTracker::new(&cfg());
        for _ in 0..3 {
            t.record_malicious(ip("10.0.0.1"), 10);
        }
        // Even after enough clean traffic to fully decay the
        // score, strikes stick around — that's the lifetime
        // invariant.
        let now = Instant::now();
        for _ in 0..50 {
            t.record_clean_at(ip("10.0.0.1"), now + Duration::from_secs(7200));
        }
        let s = t.snapshot(ip("10.0.0.1")).unwrap();
        assert_eq!(s.strikes, 3);
    }

    #[test]
    fn level_classifies_against_thresholds() {
        let t = RiskTracker::new(&cfg());
        // 2026-05-17 F-CRITICAL-007: RiskThresholds defaults are now
        // challenge_at=30, block_at=70 (v2.3 spec). Test updated to
        // match — see crates/aegis-core/src/config.rs.
        let target = ip("10.0.0.1");
        assert_eq!(t.level(target), RiskLevel::Allow);

        t.record_malicious(target, 20);
        assert_eq!(t.level(target), RiskLevel::Allow);

        t.record_malicious(target, 15);
        assert_eq!(t.level(target), RiskLevel::Challenge);

        t.record_malicious(target, 40);
        assert_eq!(t.level(target), RiskLevel::Block);
    }

    #[test]
    fn strike_block_short_circuits_to_block_even_when_score_low() {
        let t = RiskTracker::new(&cfg());
        let target = ip("10.0.0.1");
        // 5 strikes worth `block_at = 5` but tiny score deltas.
        for _ in 0..5 {
            t.record_malicious(target, 1);
        }
        let s = t.snapshot(target).unwrap();
        assert_eq!(s.score, 5); // far below challenge_at=40
        assert!(t.is_strike_blocked(target));
        assert_eq!(t.level(target), RiskLevel::Block);
    }

    #[test]
    fn strike_block_persists_after_score_decay() {
        // Strikes never decay even if score recovers — repeated
        // offenders stay blocked until an operator resets.
        let t = RiskTracker::new(&cfg());
        let target = ip("10.0.0.1");
        let now = Instant::now();
        for i in 0..5 {
            t.record_malicious_at(target, 5, now + Duration::from_secs(i));
        }
        for _ in 0..100 {
            t.record_clean_at(target, now + Duration::from_secs(36_000));
        }
        let s = t.snapshot(target).unwrap();
        assert_eq!(s.score, 0); // fully decayed
        assert_eq!(s.strikes, 5);
        assert_eq!(t.level(target), RiskLevel::Block);
    }

    #[test]
    fn reset_clears_strikes_and_score() {
        let t = RiskTracker::new(&cfg());
        let target = ip("10.0.0.1");
        for _ in 0..5 {
            t.record_malicious(target, 10);
        }
        assert!(t.is_strike_blocked(target));
        assert!(t.reset(target));
        assert!(t.snapshot(target).is_none());
        assert_eq!(t.level(target), RiskLevel::Allow);
        assert!(!t.reset(target), "second reset is a no-op");
    }

    #[test]
    fn top_sorts_by_strikes_then_score() {
        let t = RiskTracker::new(&cfg());
        // ip A: 1 strike, score 90 (challenge tier high)
        t.record_malicious(ip("10.0.0.1"), 90);
        // ip B: 4 strikes, score 30 (challenge_at boundary)
        for _ in 0..4 {
            t.record_malicious(ip("10.0.0.2"), 8);
        }
        // ip C: 3 strikes, score 60
        for _ in 0..3 {
            t.record_malicious(ip("10.0.0.3"), 20);
        }
        let top = t.top(10);
        let ips: Vec<&str> = top.iter().map(|s| s.ip.as_str()).collect();
        // Order: B (4 strikes) > C (3 strikes) > A (1 strike).
        assert_eq!(ips, vec!["10.0.0.2", "10.0.0.3", "10.0.0.1"]);
    }

    #[test]
    fn top_respects_limit() {
        let t = RiskTracker::new(&cfg());
        for i in 0..20u8 {
            t.record_malicious(ip(&format!("10.0.0.{i}")), 10);
        }
        assert_eq!(t.top(5).len(), 5);
        assert_eq!(t.top(50).len(), 20);
    }

    #[test]
    fn snapshot_wire_renders_all_fields() {
        let t = RiskTracker::new(&cfg());
        let target = ip("10.0.0.1");
        for _ in 0..5 {
            t.record_malicious(target, 1);
        }
        let snap = t.snapshot_wire(target).unwrap();
        assert_eq!(snap.ip, "10.0.0.1");
        assert_eq!(snap.strikes, 5);
        assert!(snap.strike_blocked);
        assert_eq!(snap.level, "block");
    }

    #[test]
    fn trust_decay_points_caps_at_per_hour() {
        assert_eq!(trust_decay_points(Duration::from_secs(3600), 30), 30);
        assert_eq!(trust_decay_points(Duration::from_secs(7200), 30), 60);
        assert_eq!(trust_decay_points(Duration::from_secs(60), 30), 0);
        // 5 minutes of clean traffic at 30/hr → 2 points.
        assert_eq!(trust_decay_points(Duration::from_secs(300), 30), 2);
    }

    #[test]
    fn trust_decay_zero_per_hour_means_no_recovery() {
        // Operator can disable trust recovery by setting per_hour=0
        // — score then only ever goes up (legacy half-life still
        // applies separately via RiskEngine).
        assert_eq!(trust_decay_points(Duration::from_secs(36_000), 0), 0);
    }

    // ---------- 2026-05-10 — Strike-Block enable/disable wiring ----------

    fn cfg_strikes_disabled() -> RiskConfig {
        let mut c = RiskConfig::default();
        c.trust_recovery = Some(TrustRecoveryConfig { per_hour: 30 });
        c.strikes = Some(StrikeConfig { enabled: false, block_at: 5 });
        c
    }

    #[test]
    fn strike_block_disabled_does_not_fire_even_at_threshold() {
        let t = RiskTracker::new(&cfg_strikes_disabled());
        let target = ip("10.0.0.42");
        for _ in 0..10 {
            t.record_malicious(target, 1);
        }
        let s = t.snapshot(target).unwrap();
        assert_eq!(s.strikes, 10);
        assert!(
            !t.is_strike_blocked(target),
            "Strike-Block must not fire when enabled=false"
        );
        // level() also gets the score-based path because the gate
        // is off — score is 10 (below challenge_at=40).
        assert_eq!(t.level(target), RiskLevel::Allow);
    }

    #[test]
    fn strike_config_snapshot_reads_live_config() {
        let t = RiskTracker::new(&cfg());
        let snap = t.strike_config_snapshot();
        assert!(snap.enabled);
        assert_eq!(snap.block_at, 5);
    }

    #[test]
    fn set_strike_config_hot_swaps_without_reset() {
        let t = RiskTracker::new(&cfg());
        let target = ip("10.0.0.99");
        // Accumulate 5 strikes — gate is enabled with block_at=5.
        for _ in 0..5 {
            t.record_malicious(target, 1);
        }
        assert!(t.is_strike_blocked(target));
        // Hot-flip the gate off; the IP is no longer blocked at
        // the gate even though its lifetime counter is unchanged.
        t.set_strike_config(StrikeConfig { enabled: false, block_at: 5 });
        assert!(!t.is_strike_blocked(target));
        let s = t.snapshot(target).unwrap();
        assert_eq!(s.strikes, 5, "per-IP state preserved across swap");
        // Hot-flip back on — the same accumulated count fires
        // immediately, no reset needed.
        t.set_strike_config(StrikeConfig { enabled: true, block_at: 5 });
        assert!(t.is_strike_blocked(target));
    }

    #[test]
    fn set_strike_config_can_tighten_threshold_mid_incident() {
        let t = RiskTracker::new(&cfg());
        let target = ip("10.0.0.55");
        // 3 strikes at block_at=5 — not yet blocked.
        for _ in 0..3 {
            t.record_malicious(target, 1);
        }
        assert!(!t.is_strike_blocked(target));
        // Tighten threshold to 3 — the IP is now over the limit
        // without any new attack signals.
        t.set_strike_config(StrikeConfig { enabled: true, block_at: 3 });
        assert!(t.is_strike_blocked(target));
    }

    // ---------- 2026-05-10 — level_with (Option B per-tier) -------------

    #[test]
    fn level_with_uses_caller_supplied_thresholds() {
        // Use the strikes-disabled fixture so the lifetime
        // strike check doesn't short-circuit before we get to
        // the threshold comparison. The point of this test is
        // to verify the per-tier cumulative thresholds, not the
        // strike-block interaction (covered in level_with_strike_block_*).
        let t = RiskTracker::new(&cfg_strikes_disabled());
        let target = ip("10.0.0.20");
        // Drive the cumulative score to 50 with two hits.
        t.record_malicious(target, 30);
        t.record_malicious(target, 20);
        let s = t.snapshot(target).unwrap();
        assert_eq!(s.score, 50);
        // Strict tier thresholds (challenge=20, block=40) → Block.
        assert_eq!(
            t.level_with(target, 20, 40),
            RiskLevel::Block,
            "score 50 should block when tier block_at=40"
        );
        // Permissive tier thresholds (challenge=80, block=99) → Allow.
        assert_eq!(
            t.level_with(target, 80, 99),
            RiskLevel::Allow,
            "score 50 should pass when tier challenge_at=80"
        );
        // Mid-bucket tier thresholds (challenge=40, block=80) → Challenge.
        assert_eq!(
            t.level_with(target, 40, 80),
            RiskLevel::Challenge,
            "score 50 should challenge between tier challenge_at=40 and block_at=80"
        );
    }

    #[test]
    fn level_with_returns_allow_for_unknown_ip() {
        let t = RiskTracker::new(&cfg());
        assert_eq!(t.level_with(ip("8.8.8.8"), 40, 80), RiskLevel::Allow);
    }

    #[test]
    fn level_with_strike_block_still_short_circuits() {
        // Strike-block is gate-level — it ignores per-tier
        // thresholds. Even with permissive tier bounds, a
        // strike-blocked IP returns Block.
        let t = RiskTracker::new(&cfg());
        let target = ip("10.0.0.21");
        for _ in 0..5 {
            t.record_malicious(target, 1);
        }
        assert!(t.is_strike_blocked(target));
        assert_eq!(
            t.level_with(target, 99, 100),
            RiskLevel::Block,
            "strike-block must override permissive tier thresholds"
        );
    }

    #[test]
    fn snapshot_wire_strike_blocked_false_when_gate_disabled() {
        let t = RiskTracker::new(&cfg_strikes_disabled());
        let target = ip("10.0.0.7");
        for _ in 0..6 {
            t.record_malicious(target, 1);
        }
        let snap = t.snapshot_wire(target).unwrap();
        assert_eq!(snap.strikes, 6);
        assert!(!snap.strike_blocked);
        // score is 6 (well below challenge_at=40), so level=allow.
        assert_eq!(snap.level, "allow");
    }

    // ---- 2026-05-18 F-CRITICAL-001 Phase E composite-key tests ----

    fn key_with(ip_str: &str, device_fp: Option<&str>, session: Option<&str>) -> aegis_core::risk::RiskKey {
        aegis_core::risk::RiskKey {
            ip: ip(ip_str),
            device_fp: device_fp.map(String::from),
            session: session.map(String::from),
        }
    }

    /// Composite-key isolation: two sessions on the same NAT'd IP
    /// accumulate INDEPENDENT risk. Pre-fix both hit the same
    /// IP-only bucket — one user's malicious activity tarred the
    /// whole NAT.
    #[test]
    fn composite_key_isolates_sessions_on_same_ip() {
        let t = RiskTracker::new(&cfg());
        let alice = key_with("10.0.0.1", Some("fp-alice"), Some("sess-alice"));
        let bob = key_with("10.0.0.1", Some("fp-bob"), Some("sess-bob"));

        // Alice goes malicious; Bob does not.
        t.record_malicious_with_key(alice.clone(), 60);
        t.record_malicious_with_key(alice.clone(), 20);
        // Bob is fine.
        let bob_state = t.snapshot_with_key(&bob);
        assert!(bob_state.is_none(), "bob should have no tracked risk");
        assert_eq!(t.level_for_key(&bob), RiskLevel::Allow);

        // Alice is over the block threshold.
        let alice_state = t.snapshot_with_key(&alice).unwrap();
        assert_eq!(alice_state.score, 80);
        // With default thresholds challenge_at=30, block_at=70 →
        // Alice's 80 is Block.
        assert_eq!(t.level_for_key(&alice), RiskLevel::Block);
    }

    /// Different IPs with the SAME session still get independent
    /// buckets — IP rotation by the same attacker doesn't merge,
    /// because the IP axis IS still part of the key. This is the
    /// "Distributed credential stuffing with IP rotation" lifetime-
    /// strikes invariant in §5.5.
    ///
    /// (When operators want the inverse semantic — "same device,
    /// different IPs should accumulate" — they construct a
    /// RiskKey with the IP normalized to a placeholder. That's a
    /// future composite-by-device variant.)
    #[test]
    fn composite_key_with_different_ips_dont_merge() {
        let t = RiskTracker::new(&cfg());
        let same_device = "fp-attacker";
        let ip_a = key_with("203.0.113.1", Some(same_device), None);
        let ip_b = key_with("203.0.113.2", Some(same_device), None);
        t.record_malicious_with_key(ip_a.clone(), 60);
        // ip_b has nothing.
        assert!(t.snapshot_with_key(&ip_b).is_none());
        // ip_a has 60.
        assert_eq!(t.snapshot_with_key(&ip_a).unwrap().score, 60);
    }

    /// IP-only and composite-key calls populate DIFFERENT buckets
    /// even when the IP matches. Auditor's intent: don't conflate.
    #[test]
    fn ip_only_call_and_composite_call_populate_different_buckets() {
        let t = RiskTracker::new(&cfg());
        let p = ip("10.0.0.1");
        let composite = key_with("10.0.0.1", Some("fp-x"), Some("sess-x"));

        // IP-only bucket: 60 → Challenge (60 ≥ challenge_at=30).
        t.record_malicious(p, 60);
        // Composite bucket: 10 → Allow (10 < challenge_at=30).
        t.record_malicious_with_key(composite.clone(), 10);

        assert_eq!(t.snapshot(p).unwrap().score, 60);
        assert_eq!(t.snapshot_with_key(&composite).unwrap().score, 10);
        assert_eq!(t.level(p), RiskLevel::Challenge);
        assert_eq!(t.level_for_key(&composite), RiskLevel::Allow);
    }

    /// Composite-key + threshold-based level gating uses the
    /// composite bucket's score, not the IP-only bucket's.
    #[test]
    fn level_for_key_reads_composite_bucket() {
        let t = RiskTracker::new(&cfg());
        let p = ip("10.0.0.42");
        let k = key_with("10.0.0.42", Some("fp"), None);

        // IP-only bucket: high risk.
        t.record_malicious(p, 80);
        // Composite bucket: clean.
        // level(ip) → Block; level_for_key(composite) → Allow.
        assert_eq!(t.level(p), RiskLevel::Block);
        assert_eq!(t.level_for_key(&k), RiskLevel::Allow);
    }

    /// `reset_with_key` clears one composite bucket without
    /// touching the IP-only bucket or other composites.
    #[test]
    fn reset_with_key_drops_only_target_bucket() {
        let t = RiskTracker::new(&cfg());
        let p = ip("10.0.0.5");
        let k1 = key_with("10.0.0.5", Some("fp1"), None);
        let k2 = key_with("10.0.0.5", Some("fp2"), None);
        t.record_malicious(p, 10);
        t.record_malicious_with_key(k1.clone(), 20);
        t.record_malicious_with_key(k2.clone(), 30);

        assert!(t.reset_with_key(&k1));
        // k1 gone; k2 + ip-only untouched.
        assert!(t.snapshot_with_key(&k1).is_none());
        assert!(t.snapshot_with_key(&k2).is_some());
        assert!(t.snapshot(p).is_some());
    }

    /// 2026-05-19 — `top()` surfaces device_fp + session in the
    /// wire shape so the dashboard can render one row per
    /// composite-key bucket.
    #[test]
    fn top_populates_composite_axes_in_snapshot() {
        let t = RiskTracker::new(&cfg());
        let alice = key_with("10.0.0.10", Some("fp-alice-1234"), Some("sess-alice"));
        let bob = key_with("10.0.0.10", Some("fp-bob-5678"), Some("sess-bob"));
        let anon = key_with("10.0.0.11", None, None);
        t.record_malicious_with_key(alice.clone(), 25);
        t.record_malicious_with_key(bob.clone(), 35);
        t.record_malicious_with_key(anon.clone(), 15);

        let rows = t.top(10);
        // Two NAT'd-IP buckets + one IP-only bucket = 3 rows.
        assert_eq!(rows.len(), 3);
        let alice_row = rows
            .iter()
            .find(|r| r.device_fp.as_deref() == Some("fp-alice-1234"))
            .expect("alice row");
        assert_eq!(alice_row.ip, "10.0.0.10");
        assert_eq!(alice_row.session.as_deref(), Some("sess-alice"));
        let bob_row = rows
            .iter()
            .find(|r| r.device_fp.as_deref() == Some("fp-bob-5678"))
            .expect("bob row");
        assert_eq!(bob_row.ip, "10.0.0.10");
        assert_eq!(bob_row.session.as_deref(), Some("sess-bob"));
        let anon_row = rows
            .iter()
            .find(|r| r.ip == "10.0.0.11")
            .expect("anon row");
        assert!(anon_row.device_fp.is_none(), "no TLS → device_fp is None");
        assert!(anon_row.session.is_none(), "no cookie → session is None");
    }
}
