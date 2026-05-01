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
#[derive(Clone, Debug, serde::Serialize)]
pub struct RiskSnapshot {
    pub ip: String,
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
    map: DashMap<IpAddr, Slot>,
    /// CI-T12 — thresholds are atomically swappable so
    /// `PUT /api/risk/thresholds` can hot-apply new values
    /// without a restart. Reads through `Arc::clone` (free)
    /// and the inner clone is cheap (3 u32s).
    thresholds: arc_swap::ArcSwap<RiskThresholds>,
    trust: TrustRecoveryConfig,
    strikes: StrikeConfig,
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
                strikes: cfg.strikes.clone().unwrap_or_default(),
            }),
        }
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
        let mut entry = self.inner.map.entry(ip).or_insert(Slot {
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
        let mut entry = self.inner.map.entry(ip).or_insert(Slot {
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
        self.inner.map.get(&ip).map(|e| slot_to_state(*e))
    }

    /// Adaptive mitigation decision for a given IP. Strike-block
    /// short-circuits to `Block` regardless of score — that's the
    /// "permanent block on repeated offence" guarantee from the
    /// requirements.
    pub fn level(&self, ip: IpAddr) -> RiskLevel {
        let Some(state) = self.snapshot(ip) else {
            return RiskLevel::Allow;
        };
        if self.is_strike_blocked(ip) {
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

    /// `true` when the IP's lifetime strike counter has crossed
    /// the configured threshold.
    pub fn is_strike_blocked(&self, ip: IpAddr) -> bool {
        self.snapshot(ip)
            .map(|s| s.strikes >= self.inner.strikes.block_at)
            .unwrap_or(false)
    }

    /// Operator override: clear an IP's strikes and zero its
    /// score. Returns `true` if a row was removed. Gated by the
    /// `AuditedMutate` pipeline at the API layer.
    pub fn reset(&self, ip: IpAddr) -> bool {
        self.inner.map.remove(&ip).is_some()
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
        let mut all: Vec<(IpAddr, Slot)> = self
            .inner
            .map
            .iter()
            .map(|kv| (*kv.key(), *kv.value()))
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
        all.into_iter()
            .take(n)
            .map(|(ip, slot)| {
                let strike_blocked = slot.strikes >= self.inner.strikes.block_at;
                let level = if strike_blocked || slot.score >= block_at {
                    "block"
                } else if slot.score >= challenge_at {
                    "challenge"
                } else {
                    "allow"
                };
                RiskSnapshot {
                    ip: ip.to_string(),
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
        c.strikes = Some(StrikeConfig { block_at: 5 });
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
        // RiskThresholds default: challenge_at=40, block_at=80.
        let target = ip("10.0.0.1");
        assert_eq!(t.level(target), RiskLevel::Allow);

        t.record_malicious(target, 30);
        assert_eq!(t.level(target), RiskLevel::Allow);

        t.record_malicious(target, 15);
        assert_eq!(t.level(target), RiskLevel::Challenge);

        t.record_malicious(target, 50);
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
}
