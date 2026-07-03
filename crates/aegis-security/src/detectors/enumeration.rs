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
//! in the current window exceeds `threshold`. Fixed 60 s window (reset on
//! roll-over) — a coarse accumulation signal, not a single-hit block.
//! **Default-OFF** (boot toggle `detectors.enumeration`) until tuned
//! against the benchmark FP corpus, since a legitimate asset-heavy SPA
//! can hit a naive distinct-path threshold.
//!
//! ## Response-status follow-on
//!
//! This ships the inbound *proxy* signal — distinct request paths per IP.
//! True 404-rate (only counting paths the origin 404s) needs the
//! response-outcome channel (AC-P3-b, now landed) fed into a peer
//! `observe_outcome`; that upgrade is a follow-on.

use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use aegis_core::pipeline::RequestView;

use super::{Detector, Signal};

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
    /// Window anchor; the set resets when `WINDOW` elapses.
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

impl Detector for EnumerationDetector {
    fn id(&self) -> &'static str {
        // Not a `DetectorClass` (stateful/data-driven, like behavior_signals)
        // → `mask.is_enabled_id` runs it unconditionally; it's only in the
        // chain at all when the boot toggle enabled it.
        "enumeration"
    }

    fn inspect(&self, _req: &RequestView<'_>) -> Vec<Signal> {
        // AC-P2-d stub — implemented in the GREEN step.
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::pipeline::BodyPeek;

    fn parts(path: &str, ip: &str) -> (http::Method, http::Uri, http::HeaderMap, BodyPeek, std::net::SocketAddr) {
        (
            http::Method::GET,
            path.parse().unwrap(),
            http::HeaderMap::new(),
            BodyPeek::empty(),
            std::net::SocketAddr::new(ip.parse().unwrap(), 0),
        )
    }

    fn view<'a>(
        m: &'a http::Method,
        u: &'a http::Uri,
        h: &'a http::HeaderMap,
        b: &'a BodyPeek,
        p: std::net::SocketAddr,
    ) -> RequestView<'a> {
        RequestView { method: m, uri: u, version: http::Version::HTTP_11, headers: h, peer: p, tls: None, body: b }
    }

    fn drive(d: &EnumerationDetector, ip: &str, paths: impl Iterator<Item = String>) -> Vec<Signal> {
        let mut last = Vec::new();
        for path in paths {
            let (m, u, h, b, p) = parts(&path, ip);
            last = d.inspect(&view(&m, &u, &h, &b, p));
        }
        last
    }

    #[test]
    fn enumeration_across_many_distinct_paths_scores() {
        let d = EnumerationDetector::with_caps(1000, 128, 40);
        let sig = drive(&d, "203.0.113.10", (0..50).map(|i| format!("/scan/path-{i}")));
        assert!(
            sig.iter().any(|s| s.tag == "enumeration" && s.score == SCORE),
            "50 distinct paths from one IP must score enumeration: {sig:?}",
        );
    }

    #[test]
    fn legit_browsing_stays_under_threshold() {
        let d = EnumerationDetector::with_caps(1000, 128, 40);
        let sig = drive(&d, "203.0.113.11", (0..10).map(|i| format!("/page/{i}")));
        assert!(
            !sig.iter().any(|s| s.tag == "enumeration"),
            "10 distinct paths (normal browsing) must not score: {sig:?}",
        );
    }

    #[test]
    fn repeated_same_path_is_not_enumeration() {
        // Hammering ONE path is a rate/flood concern, not enumeration.
        let d = EnumerationDetector::with_caps(1000, 128, 40);
        let sig = drive(&d, "203.0.113.12", (0..200).map(|_| "/api/login".to_string()));
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
        let _ = drive(&d, "203.0.113.13", (0..10_000).map(|i| format!("/u/{i}")));
        assert!(
            d.peak_per_ip_paths() <= 64,
            "per-IP hash set must stay within the cap under a unique-path flood, got {}",
            d.peak_per_ip_paths(),
        );
        // ...and it still fires (count reached the cap, well past threshold).
        let (m, u, h, b, p) = parts("/u/final", "203.0.113.13");
        let sig = d.inspect(&view(&m, &u, &h, &b, p));
        assert!(sig.iter().any(|s| s.tag == "enumeration"));
    }

    #[test]
    fn bounded_tracked_ips() {
        // Cap tracked IPs at 3; a flood of distinct IPs must not grow past it.
        let d = EnumerationDetector::with_caps(3, 128, 40);
        for octet in 1..=50u8 {
            let (m, u, h, b, p) = parts("/x", &format!("203.0.113.{octet}"));
            let _ = d.inspect(&view(&m, &u, &h, &b, p));
        }
        assert!(d.tracked_ips() <= 3, "tracked IPs must stay within the cap, got {}", d.tracked_ips());
    }
}
