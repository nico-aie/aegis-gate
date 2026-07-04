//! AC-P2-d (2026-07-04) — endpoint-enumeration / directory-scan
//! detector. `recon` catches *known-bad* path signatures; this catches
//! the shape `recon` misses: one source hitting a large number of
//! **distinct** paths in a short window (a scanner walking an endpoint
//! space, most of which aren't signatured).
//!
//! ## Cardinality safety (the load-bearing constraint)
//!
//! "Distinct paths per IP" is a classic cardinality trap — a unique-path
//! flood could OOM an unbounded `HashSet<String>`. This detector is
//! bounded on **both** axes:
//!
//! - **Per-IP:** a `HashSet<u64>` of path *hashes* (not strings), hard-
//!   capped at [`Self::per_ip_cap`]. Once at the cap we stop inserting —
//!   the distinct count is already past the detection threshold, so
//!   nothing is lost. Memory per IP is `cap × 8 bytes`.
//! - **Fleet:** the outer per-IP map is capped at [`Self::max_tracked`];
//!   at the ceiling a new IP evicts an arbitrary existing entry rather
//!   than growing. Mirrors `behavior_signals` / `risk::tracker`.
//!
//! A 10 000-unique-path flood therefore costs `cap × 8` bytes for that
//! IP and never grows the map beyond the ceiling.
//!
//! ## Signal
//!
//! Fires `enumeration` (score [`SCORE`]) once an IP's distinct-path count
//! **and** its origin-404 count in the current window both exceed
//! `threshold` — "many distinct paths, mostly 404" is the enumeration
//! shape. A legitimate crawler walking many *real* (200) pages never
//! accumulates the 404 side and stays silent. Fixed 60 s window (reset on
//! roll-over) — a coarse accumulation signal, not a single-hit block.
//! **Default-OFF** (boot toggle `detectors.enumeration`) until tuned
//! against the benchmark FP corpus.
//!
//! ## Wiring (AC-P2-d 404-rate refinement, 2026-07-04)
//!
//! Not a chain [`Detector`](super::Detector) — the outcome half needs the
//! upstream status, which only the AC-P3-b response-outcome hook in the
//! data plane's single-exit wrapper sees. So this lives on `ProxyContext`
//! (mirroring `BehavioralAnalyzer`): [`Self::observe_path`] runs inbound
//! next to `behavior_analyzer.observe(...)`, and [`Self::observe_outcome`]
//! runs in the wrapper alongside `ba.observe_outcome(...)`, gated on
//! `Action::Allow` so WAF-origin 403/429s never count as origin 404s.

use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::Signal;

/// Score emitted on an enumeration hit — above the accumulation floor so
/// it stacks toward a cumulative block, but not a single-hit blocker.
pub const SCORE: u32 = 40;

const DEFAULT_MAX_TRACKED: usize = 100_000;
const DEFAULT_PER_IP_CAP: usize = 128;
const DEFAULT_THRESHOLD: u32 = 40;
const WINDOW: Duration = Duration::from_secs(60);

struct IpPaths {
    /// Path hashes seen this window, capped at `per_ip_cap`.
    hashes: HashSet<u64>,
    /// Origin 404 responses observed this window (AC-P2-d refinement).
    /// A plain counter — no cardinality risk — reset with the window.
    count_404: u32,
    /// Window anchor; the state resets when `WINDOW` elapses.
    window_start: Instant,
}

pub struct EnumerationDetector {
    state: Mutex<HashMap<IpAddr, IpPaths>>,
    max_tracked: usize,
    per_ip_cap: usize,
    threshold: u32,
}

impl EnumerationDetector {
    pub fn new() -> Self {
        Self::with_caps(DEFAULT_MAX_TRACKED, DEFAULT_PER_IP_CAP, DEFAULT_THRESHOLD)
    }

    pub fn with_caps(max_tracked: usize, per_ip_cap: usize, threshold: u32) -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
            max_tracked,
            per_ip_cap,
            threshold,
        }
    }

    /// Test accessor — number of tracked source IPs.
    pub fn tracked_ips(&self) -> usize {
        self.state.lock().unwrap().len()
    }

    /// Test accessor — the largest per-IP hash-set size (must never
    /// exceed `per_ip_cap`, proving the cardinality bound holds).
    pub fn peak_per_ip_paths(&self) -> usize {
        self.state
            .lock()
            .unwrap()
            .values()
            .map(|p| p.hashes.len())
            .max()
            .unwrap_or(0)
    }

    /// Drop all tracked state (wired into the v2.3 `reset_state` path).
    pub fn clear(&self) {
        self.state.lock().unwrap().clear();
    }

    fn hash_path(path: &str) -> u64 {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        path.hash(&mut h);
        h.finish()
    }
}

impl Default for EnumerationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl EnumerationDetector {
    /// Inbound half — record `path` for `ip` and return the enumeration
    /// signal when BOTH the distinct-path count and the origin-404 count
    /// for this window exceed `threshold`. Called from the data plane's
    /// pre-forward signal block (peer of `behavior_analyzer.observe`).
    pub fn observe_path(&self, ip: IpAddr, path: &str) -> Vec<Signal> {
        let hash = Self::hash_path(path);
        let now = Instant::now();

        let mut state = self.state.lock().unwrap();

        // Fleet cardinality bound: at the ceiling, evict an arbitrary entry
        // before admitting a brand-new IP (mirrors behavior_signals).
        if !state.contains_key(&ip) && state.len() >= self.max_tracked {
            if let Some(k) = state.keys().next().copied() {
                state.remove(&k);
            }
        }

        let entry = state.entry(ip).or_insert_with(|| IpPaths {
            hashes: HashSet::new(),
            count_404: 0,
            window_start: now,
        });

        // Fixed-window reset: a fresh window drops the prior path set.
        if now.duration_since(entry.window_start) > WINDOW {
            entry.hashes.clear();
            entry.count_404 = 0;
            entry.window_start = now;
        }

        // Per-IP cardinality bound: stop inserting at the cap. The distinct
        // count is already past `threshold` by then, so detection is intact
        // and memory can't grow with attacker-chosen paths.
        if entry.hashes.len() < self.per_ip_cap {
            entry.hashes.insert(hash);
        }

        // The refined gate: many distinct paths AND mostly-404 outcomes.
        // Distinct-only would FP on a legit crawler walking real (200)
        // pages; the 404 side only accumulates when the origin keeps
        // answering "no such endpoint" — the enumeration shape.
        if entry.hashes.len() as u32 > self.threshold && entry.count_404 > self.threshold {
            return vec![Signal {
                score: SCORE,
                tag: "enumeration".into(),
                field: format!(
                    "distinct_paths:{},404s:{}",
                    entry.hashes.len(),
                    entry.count_404,
                ),
            }];
        }
        Vec::new()
    }

    /// Outcome half — bump the per-IP 404 counter when the origin answered
    /// 404. Fed from the AC-P3-b response-outcome hook (Allow-gated, so
    /// WAF-origin blocks never land here). Only updates an IP that
    /// `observe_path` already admitted — an outcome can't grow the map.
    pub fn observe_outcome(&self, ip: IpAddr, is_404: bool) {
        if !is_404 {
            return;
        }
        let mut state = self.state.lock().unwrap();
        if let Some(entry) = state.get_mut(&ip) {
            // A stale-window entry gets its reset on the next observe_path;
            // don't credit an old window's 404 into the new one.
            if Instant::now().duration_since(entry.window_start) <= WINDOW {
                entry.count_404 = entry.count_404.saturating_add(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Drive `paths` through the inbound half; when `outcome_404` is
    /// `Some(is_404)` each request also gets that origin outcome fed back
    /// (mirroring the data plane's Allow-gated response hook).
    fn drive(
        d: &EnumerationDetector,
        src: &str,
        paths: impl Iterator<Item = String>,
        outcome_404: Option<bool>,
    ) -> Vec<Signal> {
        let src = ip(src);
        let mut last = Vec::new();
        for path in paths {
            last = d.observe_path(src, &path);
            if let Some(is_404) = outcome_404 {
                d.observe_outcome(src, is_404);
            }
        }
        last
    }

    #[test]
    fn enumeration_across_many_404_paths_scores() {
        // AC-P2-d refinement: 50 distinct paths that the origin all 404s
        // is the enumeration shape — scores.
        let d = EnumerationDetector::with_caps(1000, 128, 40);
        let sig = drive(
            &d,
            "203.0.113.10",
            (0..50).map(|i| format!("/scan/path-{i}")),
            Some(true),
        );
        assert!(
            sig.iter().any(|s| s.tag == "enumeration" && s.score == SCORE),
            "50 distinct all-404 paths from one IP must score enumeration: {sig:?}",
        );
    }

    #[test]
    fn crawler_across_many_200_paths_does_not_score() {
        // The FP this refinement kills: a legit crawler hitting many
        // distinct REAL pages (origin 200s) must stay silent.
        let d = EnumerationDetector::with_caps(1000, 128, 40);
        let sig = drive(
            &d,
            "203.0.113.14",
            (0..50).map(|i| format!("/article/{i}")),
            Some(false),
        );
        assert!(
            !sig.iter().any(|s| s.tag == "enumeration"),
            "50 distinct paths that all 200 (real content) must not score: {sig:?}",
        );
    }

    #[test]
    fn legit_browsing_stays_under_threshold() {
        let d = EnumerationDetector::with_caps(1000, 128, 40);
        let sig = drive(
            &d,
            "203.0.113.11",
            (0..10).map(|i| format!("/page/{i}")),
            Some(true),
        );
        assert!(
            !sig.iter().any(|s| s.tag == "enumeration"),
            "10 distinct paths (normal browsing) must not score: {sig:?}",
        );
    }

    #[test]
    fn repeated_same_path_is_not_enumeration() {
        // Hammering ONE path — even one that 404s every time — is a
        // rate/flood concern, not enumeration (distinct count stays 1).
        let d = EnumerationDetector::with_caps(1000, 128, 40);
        let sig = drive(
            &d,
            "203.0.113.12",
            (0..200).map(|_| "/api/login".to_string()),
            Some(true),
        );
        assert!(
            !sig.iter().any(|s| s.tag == "enumeration"),
            "same path repeated is not enumeration: {sig:?}",
        );
    }

    #[test]
    fn bounded_memory_under_unique_path_flood() {
        // 10k unique paths from one IP must NOT grow the per-IP set past
        // the cap — the cardinality-trap guard.
        let d = EnumerationDetector::with_caps(1000, 64, 40);
        let _ = drive(
            &d,
            "203.0.113.13",
            (0..10_000).map(|i| format!("/u/{i}")),
            Some(true),
        );
        assert!(
            d.peak_per_ip_paths() <= 64,
            "per-IP hash set must stay within the cap under a unique-path flood, got {}",
            d.peak_per_ip_paths(),
        );
        // ...and it still fires (count reached the cap, well past threshold,
        // and the 404 side accumulated alongside).
        let sig = d.observe_path(ip("203.0.113.13"), "/u/final");
        assert!(sig.iter().any(|s| s.tag == "enumeration"));
    }

    #[test]
    fn bounded_tracked_ips() {
        // Cap tracked IPs at 3; a flood of distinct IPs must not grow past it.
        let d = EnumerationDetector::with_caps(3, 128, 40);
        for octet in 1..=50u8 {
            let _ = d.observe_path(ip(&format!("203.0.113.{octet}")), "/x");
        }
        assert!(d.tracked_ips() <= 3, "tracked IPs must stay within the cap, got {}", d.tracked_ips());
    }

    #[test]
    fn outcome_for_untracked_ip_does_not_grow_map() {
        // The outcome hook can race a reset/eviction; a 404 outcome for an
        // IP `observe_path` never admitted must not create an entry.
        let d = EnumerationDetector::with_caps(1000, 128, 40);
        d.observe_outcome(ip("203.0.113.99"), true);
        assert_eq!(d.tracked_ips(), 0, "outcomes must never admit new IPs");
    }
}
