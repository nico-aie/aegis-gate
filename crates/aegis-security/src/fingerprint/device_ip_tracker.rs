//! 2026-05-18 (QC Sprint 3.1 — F-CRITICAL-010) — device→IP
//! reverse map. The audit's §5.2 #08 mandate: detect when the
//! same device fingerprint appears from N distinct source IPs
//! within a time window — the canonical "same client rotating IPs
//! to evade per-IP rate limits" attack shape (the Attack Battle
//! scenario 04 distributed-IP-rotation).
//!
//! Per-device-fp state: `Vec<(IpAddr, Instant)>` capped at
//! `MAX_PER_DEVICE` entries with sliding-window eviction. On each
//! observe(), the tracker:
//!
//! 1. prunes entries older than `window` from the device's list,
//! 2. dedupes the incoming `(device_fp, ip)` pair against the
//!    list (the SAME IP retrying within window doesn't count),
//! 3. appends the new entry,
//! 4. counts the number of DISTINCT IPs in the (now-pruned) list,
//! 5. emits a `Signal { score, tag: "device_ip_rotation" }` when
//!    the count crosses `threshold_distinct_ips`.
//!
//! The tracker is a standalone module (not a `Detector` trait
//! impl) because:
//! - the JA4-based device id needs to be computed inline at the
//!   TLS handshake point, before the detector chain — the data
//!   plane fills it in via the existing `device_id()` helper in
//!   this module's parent.
//! - the wire-up sequence is: TLS handshake → compute device_id →
//!   forward into the detector chain via `RequestView.tls`.
//!   `device_id` is already in scope by the time the detector
//!   chain runs, so the data plane calls
//!   `tracker.observe(&device_id, peer_ip)` directly.
//!
//! State map is bounded at `MAX_DEVICES` entries (default 100 000)
//! with random-ish eviction matching `BehaviorSignalsDetector` +
//! `VelocitySequenceDetector` shape.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::detectors::Signal;

/// Cap on entries per device in the rolling window. Bounds memory
/// even if a single device starts hammering the gateway from
/// thousands of IPs — once the cap is hit we'd already have fired
/// the signal multiple times.
const MAX_PER_DEVICE: usize = 64;

/// Default cap on total tracked devices. Random eviction on
/// overflow.
const DEFAULT_MAX_DEVICES: usize = 100_000;

/// Default rotation-detection threshold (distinct IPs per device
/// within the window). Conservative — a real user roaming between
/// home Wi-Fi and mobile network might briefly hit 2-3 distinct
/// IPs. 5 is the floor where "device rotation" is the most likely
/// explanation.
const DEFAULT_THRESHOLD_DISTINCT_IPS: usize = 5;

/// Default sliding window. Aligns with the v2.3 § 5.2 #08 example
/// of "5 distinct IPs in 60 seconds".
const DEFAULT_WINDOW: Duration = Duration::from_secs(60);

/// Score emitted when the device-IP-rotation threshold is crossed.
/// Score 60 → over `challenge_at` (30) but under `block_at` (70);
/// stacks with detector signals to push into Block territory.
const DEFAULT_SCORE: u32 = 60;

/// Reverse map device_id → recent (IP, Instant) observations.
pub struct DeviceIpTracker {
    state: Mutex<HashMap<String, Vec<(IpAddr, Instant)>>>,
    threshold_distinct_ips: usize,
    window: Duration,
    max_devices: usize,
    score: u32,
}

impl DeviceIpTracker {
    /// Default tuning per the v2.3 §5.2 #08 example.
    pub fn new() -> Self {
        Self::with_tuning(
            DEFAULT_THRESHOLD_DISTINCT_IPS,
            DEFAULT_WINDOW,
            DEFAULT_MAX_DEVICES,
            DEFAULT_SCORE,
        )
    }

    pub fn with_tuning(
        threshold_distinct_ips: usize,
        window: Duration,
        max_devices: usize,
        score: u32,
    ) -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
            threshold_distinct_ips,
            window,
            max_devices,
            score,
        }
    }

    /// Number of currently tracked devices. Test + metrics
    /// observability helper.
    pub fn tracked_count(&self) -> usize {
        self.state.lock().unwrap().len()
    }

    /// Drop all tracked state. Wired into the v2.3 `reset_state`
    /// control plane callback so benchmark phases start clean.
    pub fn clear(&self) {
        self.state.lock().unwrap().clear();
    }

    /// Record a (device_fp, ip) observation; return `Some(Signal)`
    /// when the device has now been seen from
    /// `threshold_distinct_ips` distinct IPs within `window`.
    ///
    /// Returns `None` for empty `device_fp` (callers without a
    /// fingerprint — e.g. plaintext admin port — shouldn't
    /// participate in the tracker).
    pub fn observe(&self, device_fp: &str, ip: IpAddr) -> Option<Signal> {
        if device_fp.is_empty() {
            return None;
        }
        let now = Instant::now();
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        let mut state = self.state.lock().unwrap();

        // Cap total tracked devices.
        if !state.contains_key(device_fp) && state.len() >= self.max_devices {
            if let Some(k) = state.keys().next().cloned() {
                state.remove(&k);
            }
        }

        let entry = state.entry(device_fp.to_string()).or_default();
        // Prune entries outside the window.
        entry.retain(|&(_, t)| t >= cutoff);
        // Dedupe — same IP retrying doesn't inflate the distinct
        // count (and doesn't extend the window either; we keep
        // the FIRST seen Instant per IP).
        if !entry.iter().any(|(seen_ip, _)| *seen_ip == ip) {
            entry.push((ip, now));
        }
        // Bound per-device entries.
        if entry.len() > MAX_PER_DEVICE {
            let drop_n = entry.len() - MAX_PER_DEVICE;
            entry.drain(0..drop_n);
        }
        let distinct = entry.len();

        if distinct > self.threshold_distinct_ips {
            Some(Signal {
                score: self.score,
                tag: "device_ip_rotation".into(),
                field: format!(
                    "device:{}:ips:{}",
                    &device_fp[..device_fp.len().min(16)],
                    distinct,
                ),
            })
        } else {
            None
        }
    }
}

impl Default for DeviceIpTracker {
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

    #[test]
    fn empty_device_fp_returns_none() {
        let t = DeviceIpTracker::new();
        assert!(t.observe("", ip("10.0.0.1")).is_none());
        assert_eq!(t.tracked_count(), 0);
    }

    /// The headline regression: one device fingerprint appearing
    /// from 6 distinct IPs in the window crosses the default
    /// threshold of 5. Returns `device_ip_rotation` signal.
    #[test]
    fn rotation_fires_when_distinct_ips_exceed_threshold() {
        let t = DeviceIpTracker::new();
        let fp = "device-abc-123";
        for octet in 1..=5 {
            let s = t.observe(fp, ip(&format!("203.0.113.{octet}")));
            assert!(s.is_none(), "no signal at {octet} IPs");
        }
        // 6th distinct IP fires.
        let s = t.observe(fp, ip("203.0.113.6"));
        let signal = s.expect("expected rotation signal");
        assert_eq!(signal.tag, "device_ip_rotation");
        assert_eq!(signal.score, 60);
        assert!(signal.field.contains("ips:6"));
    }

    /// Same device retrying from the SAME IP doesn't inflate the
    /// distinct-IP count. A real Chrome browser with a stable IP
    /// might make 1000 requests within the window — none of them
    /// trigger rotation.
    #[test]
    fn same_ip_retry_does_not_trip_rotation() {
        let t = DeviceIpTracker::new();
        let fp = "device-xyz";
        let ip = ip("203.0.113.99");
        for _ in 0..50 {
            assert!(t.observe(fp, ip).is_none());
        }
    }

    /// Different devices each on their own IP — none rotate. Two
    /// separate users sharing the same office network should NOT
    /// trip each other's tracker.
    #[test]
    fn different_devices_tracked_independently() {
        let t = DeviceIpTracker::with_tuning(2, DEFAULT_WINDOW, 1000, 60);
        // device_a from 3 IPs → would fire.
        assert!(t.observe("device-a", ip("10.0.0.1")).is_none());
        assert!(t.observe("device-a", ip("10.0.0.2")).is_none());
        let s = t.observe("device-a", ip("10.0.0.3"));
        assert!(s.is_some());

        // device_b from 1 IP → never fires.
        assert!(t.observe("device-b", ip("10.0.0.1")).is_none());
        assert!(t.observe("device-b", ip("10.0.0.1")).is_none());
    }

    /// Entries older than `window` are pruned. After a long
    /// enough sleep the same fp from a fresh IP starts a clean
    /// counter.
    #[test]
    fn old_entries_pruned_after_window() {
        let t = DeviceIpTracker::with_tuning(
            1,
            Duration::from_millis(20),
            1000,
            60,
        );
        let fp = "device-clock";
        for octet in 1..=2 {
            let _ = t.observe(fp, ip(&format!("203.0.113.{octet}")));
        }
        // Sleep past the window.
        std::thread::sleep(Duration::from_millis(30));
        // Fresh request should NOT fire — the previous 2 entries
        // have been pruned, so this is the only distinct IP.
        let s = t.observe(fp, ip("203.0.113.3"));
        assert!(s.is_none(), "expected pruned window to reset counter");
    }

    #[test]
    fn tracked_count_grows_with_distinct_devices() {
        let t = DeviceIpTracker::new();
        for d in 0..10 {
            let _ = t.observe(&format!("dev-{d}"), ip("10.0.0.1"));
        }
        assert_eq!(t.tracked_count(), 10);
    }

    #[test]
    fn clear_drops_all_state() {
        let t = DeviceIpTracker::new();
        let _ = t.observe("a", ip("1.1.1.1"));
        let _ = t.observe("b", ip("1.1.1.2"));
        assert_eq!(t.tracked_count(), 2);
        t.clear();
        assert_eq!(t.tracked_count(), 0);
    }

    #[test]
    fn max_devices_caps_growth() {
        let t = DeviceIpTracker::with_tuning(5, DEFAULT_WINDOW, 3, 60);
        for d in 0..10 {
            let _ = t.observe(&format!("dev-{d}"), ip("1.1.1.1"));
        }
        assert!(t.tracked_count() <= 3);
    }

    /// Signal field shape includes truncated device fp + count
    /// for the audit log.
    #[test]
    fn signal_field_format() {
        let t = DeviceIpTracker::with_tuning(1, DEFAULT_WINDOW, 1000, 60);
        let fp = "abcdef0123456789longer";
        let _ = t.observe(fp, ip("1.1.1.1"));
        let s = t.observe(fp, ip("1.1.1.2")).unwrap();
        // Truncated to 16 chars.
        assert!(s.field.starts_with("device:abcdef0123456789:"));
        assert!(s.field.contains("ips:2"));
    }
}
