//! EG-2 T5 (2026-07-05) — response **egress-volume** accounting.
//!
//! The slow-drip / bulk-exfil signal from the EG-1 design (§2 T5, §4 detector
//! #2): a client pulling an anomalous *volume* of bytes out across a window —
//! a compromised session sweeping 10⁴ rows where the route normally returns
//! 10¹, or sustained elevated bytes-out to one high-risk client.
//!
//! ## Why this needs no body access (the perf win)
//!
//! Volume is a **size** signal, and the response size is already known at the
//! outcome hook (Content-Length on buffered responses) — so T5 never touches
//! the body. That keeps it in the cheap perf tier (design §4: "≤ 1 % p99").
//! Streaming responses (unknown size) contribute 0 and are effectively
//! exempt, matching the design's streaming-exempt rule.
//!
//! ## The false-positive guard (the load-bearing constraint)
//!
//! A legitimate large download (a CDN asset, a report export) is high-volume
//! but benign. Raw volume alone would false-positive on all of them. So T5
//! fires only when window volume crosses the threshold **AND the client's
//! risk is already elevated** — mirroring the design's "feeds the existing
//! per-IP risk model … a risk-scored response signal". A clean client can
//! pull any volume and never score; a client already flagged by request-side
//! detectors that *then* pulls a large volume is the exfil shape. The risk
//! score is passed in (the outcome hook holds the `RiskTracker`), so the
//! AND-gate is unit-tested here rather than split into the wiring.
//!
//! Fires **once per window** per IP (no repeat spam while the window's total
//! stays over threshold). Log/score only; **default OFF** until FP-tuned.

use super::Signal;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Score emitted on a volume anomaly — an accumulation signal, not a
/// single-hit blocker.
pub const SCORE: u32 = 25;

/// Default per-window bytes-out threshold (50 MiB). Above a normal
/// page/API response by orders of magnitude; tune per deployment.
pub const DEFAULT_THRESHOLD_BYTES: u64 = 50 * 1024 * 1024;

/// Default minimum client risk score for the AND-gate. Below the block band
/// but above clean — "this client is already suspicious".
pub const DEFAULT_RISK_GATE: u32 = 30;

const DEFAULT_MAX_TRACKED: usize = 100_000;
const WINDOW: Duration = Duration::from_secs(60);

struct IpVolume {
    /// Bytes-out accumulated in the current window.
    bytes: u64,
    /// Window anchor; state resets when `WINDOW` elapses.
    window_start: Instant,
    /// Whether the anomaly already fired this window (fire-once).
    fired: bool,
}

pub struct EgressVolumeTracker {
    state: Mutex<HashMap<IpAddr, IpVolume>>,
    threshold_bytes: u64,
    risk_gate: u32,
    max_tracked: usize,
}

impl EgressVolumeTracker {
    pub fn new() -> Self {
        Self::with_config(DEFAULT_THRESHOLD_BYTES, DEFAULT_RISK_GATE, DEFAULT_MAX_TRACKED)
    }

    pub fn with_config(threshold_bytes: u64, risk_gate: u32, max_tracked: usize) -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
            threshold_bytes,
            risk_gate,
            max_tracked,
        }
    }

    /// Record `bytes` egressed to `ip` (this response) and return a [`Signal`]
    /// iff the window total just crossed the threshold **and** the client's
    /// current `client_risk` is at/above the gate — fired at most once per
    /// window. `bytes == 0` (streaming / unknown size) only touches the map.
    pub fn observe(&self, ip: IpAddr, bytes: u64, client_risk: u32) -> Option<Signal> {
        // RED stub — real accounting lands in the GREEN step.
        let _ = (ip, bytes, client_risk);
        None
    }

    /// Drop all tracked state (wired into the `reset_state` path).
    pub fn clear(&self) {
        self.state.lock().unwrap().clear();
    }

    /// Test accessor — number of tracked IPs.
    pub fn tracked_ips(&self) -> usize {
        self.state.lock().unwrap().len()
    }
}

impl Default for EgressVolumeTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    // 50 MiB threshold, risk gate 30, small map for the bound test.
    fn tracker() -> EgressVolumeTracker {
        EgressVolumeTracker::with_config(50 * 1024 * 1024, 30, 1000)
    }

    #[test]
    fn under_threshold_never_fires() {
        let t = tracker();
        // Ten 1 MiB responses = 10 MiB, well under 50 MiB — no signal even
        // for a high-risk client.
        for _ in 0..10 {
            assert!(t.observe(ip("203.0.113.1"), 1024 * 1024, 90).is_none());
        }
    }

    #[test]
    fn over_threshold_with_elevated_risk_fires() {
        let t = tracker();
        // 60 MiB in one response to an already-risky client → exfil shape.
        let sig = t.observe(ip("203.0.113.2"), 60 * 1024 * 1024, 90);
        assert!(sig.is_some(), "over-threshold volume from a risky client must score");
        let sig = sig.unwrap();
        assert_eq!(sig.tag, "egress_volume");
        assert_eq!(sig.score, SCORE);
    }

    #[test]
    fn over_threshold_clean_client_does_not_fire() {
        // The FP guard: a legit large download (clean client, risk 0) must
        // NOT score no matter the volume.
        let t = tracker();
        assert!(
            t.observe(ip("203.0.113.3"), 500 * 1024 * 1024, 0).is_none(),
            "a clean client's large download must not score (FP guard)",
        );
    }

    #[test]
    fn accumulates_across_responses_then_fires() {
        // Volume builds across many responses (the slow-drip shape), then
        // crosses the threshold on the response that tips it over.
        let t = tracker();
        let src = ip("203.0.113.4");
        // 49 × 1 MiB = 49 MiB — still under.
        for _ in 0..49 {
            assert!(t.observe(src, 1024 * 1024, 80).is_none());
        }
        // The 51st MiB crosses 50 MiB → fires.
        assert!(t.observe(src, 2 * 1024 * 1024, 80).is_some());
    }

    #[test]
    fn fires_once_per_window() {
        let t = tracker();
        let src = ip("203.0.113.5");
        assert!(t.observe(src, 60 * 1024 * 1024, 90).is_some(), "first crossing fires");
        // Still over threshold, same window — must not spam.
        assert!(
            t.observe(src, 10 * 1024 * 1024, 90).is_none(),
            "must fire at most once per window",
        );
    }

    #[test]
    fn zero_bytes_streaming_only_tracks() {
        // Streaming / unknown-size responses (bytes == 0) never fire.
        let t = tracker();
        for _ in 0..100 {
            assert!(t.observe(ip("203.0.113.6"), 0, 90).is_none());
        }
    }

    #[test]
    fn tracked_ips_bounded() {
        let t = EgressVolumeTracker::with_config(50 * 1024 * 1024, 30, 3);
        for octet in 1..=50u8 {
            t.observe(ip(&format!("203.0.113.{octet}")), 1024, 10);
        }
        assert!(t.tracked_ips() <= 3, "tracked IPs must stay within the cap");
    }

    #[test]
    fn clear_drops_state() {
        let t = tracker();
        t.observe(ip("203.0.113.7"), 1024, 10);
        assert!(t.tracked_ips() > 0);
        t.clear();
        assert_eq!(t.tracked_ips(), 0);
    }
}
