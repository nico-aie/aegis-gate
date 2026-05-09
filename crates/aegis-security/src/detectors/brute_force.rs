//! Login brute-force detector. Per-IP windowed counter on
//! authentication paths.
//!
//! Fires when the same source IP makes more than `threshold`
//! POSTs to a known login path inside `window_secs` seconds. The
//! signal is at the detector layer (independent of risk-strikes
//! and the global rate-limit) so operators can mask brute-force
//! per-tier without changing the global rate-limit budget.
//!
//! Approach: small in-process sliding-window counter keyed on
//! `peer_ip` only (path-aware match runs first; if the path
//! isn't an auth path the request is ignored). Old timestamps
//! are pruned lazily on each `inspect()` call so memory stays
//! bounded.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use aegis_core::pipeline::RequestView;

use super::{Detector, Signal};

/// Brute-force detector. Stateful — owns a per-IP counter map.
pub struct BruteForceDetector {
    /// Number of requests within `window` that flips the
    /// detector. The corpus probes 1 attempt per attacker
    /// iteration, but real attackers come in bursts —
    /// 10 in 60 s is a conservative bar that avoids tripping
    /// real users mistyping their password three times.
    pub threshold: u32,
    /// Sliding-window length.
    pub window: Duration,
    /// Score emitted on a hit. Risk-tier is the same as the
    /// other detectors (mid-tens) so a single brute-force
    /// fingerprint plus another signal compounds into a block.
    pub score: u32,
    state: Mutex<HashMap<IpAddr, Vec<Instant>>>,
}

impl Default for BruteForceDetector {
    fn default() -> Self {
        Self::new(
            10,
            Duration::from_secs(60),
            super::scores::brute_force::DEFAULT,
        )
    }
}

impl BruteForceDetector {
    pub fn new(threshold: u32, window: Duration, score: u32) -> Self {
        Self {
            threshold,
            window,
            score,
            state: Mutex::new(HashMap::new()),
        }
    }

    fn record_and_check(&self, peer_ip: IpAddr) -> bool {
        let now = Instant::now();
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        let mut state = self.state.lock().expect("brute-force state poisoned");
        let entry = state.entry(peer_ip).or_default();
        // Prune entries outside the window.
        entry.retain(|&t| t >= cutoff);
        entry.push(now);
        // Cap the per-IP vec length so a single attacker can't
        // grow memory unboundedly while we wait for the window
        // to roll. `threshold * 2` is plenty: anything above
        // threshold is already a hit.
        let cap = (self.threshold * 2).max(20) as usize;
        if entry.len() > cap {
            let drop_n = entry.len() - cap;
            entry.drain(0..drop_n);
        }
        entry.len() as u32 > self.threshold
    }
}

impl Detector for BruteForceDetector {
    fn id(&self) -> &'static str {
        "brute_force"
    }

    fn inspect(&self, req: &RequestView<'_>) -> Vec<Signal> {
        // Only score POSTs to known auth paths. GETs to /login
        // (the page render) shouldn't count.
        if req.method != http::Method::POST {
            return Vec::new();
        }
        let path = req.uri.path();
        if !is_auth_path(path) {
            return Vec::new();
        }
        let peer_ip = req.peer.ip();
        if self.record_and_check(peer_ip) {
            return vec![Signal {
                score: self.score,
                tag: "brute_force".into(),
                field: "auth".into(),
            }];
        }
        Vec::new()
    }
}

fn is_auth_path(path: &str) -> bool {
    // Common login routes across the openapi.public.yaml target
    // and the broader hackathon corpus. Trailing slash + case-
    // insensitive match. Order picked for early-out (most
    // common first).
    let p = path.trim_end_matches('/').to_ascii_lowercase();
    matches!(
        p.as_str(),
        "/login"
            | "/api/login"
            | "/signin"
            | "/sign-in"
            | "/api/signin"
            | "/auth"
            | "/auth/login"
            | "/api/auth"
            | "/api/auth/login"
            | "/api/v1/login"
            | "/api/v2/login"
            | "/account/login"
            | "/user/login"
            | "/users/login"
            | "/session"
            | "/sessions"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::pipeline::BodyPeek;

    fn make_req(method: http::Method, path: &str) -> (http::Method, http::Uri, http::HeaderMap, BodyPeek) {
        (method, path.parse().unwrap(), http::HeaderMap::new(), BodyPeek::empty())
    }
    fn view<'a>(
        m: &'a http::Method,
        u: &'a http::Uri,
        h: &'a http::HeaderMap,
        b: &'a BodyPeek,
        peer: &str,
    ) -> RequestView<'a> {
        RequestView {
            method: m,
            uri: u,
            version: http::Version::HTTP_11,
            headers: h,
            peer: peer.parse().unwrap(),
            tls: None,
            body: b,
        }
    }

    #[test]
    fn fires_after_threshold_in_window() {
        let d = BruteForceDetector::new(3, Duration::from_secs(60), 40);
        let (m, u, h, b) = make_req(http::Method::POST, "/login");
        // 3 requests still within threshold (≤ threshold).
        for _ in 0..3 {
            assert!(d.inspect(&view(&m, &u, &h, &b, "1.1.1.1:443")).is_empty());
        }
        // 4th tips over → fire.
        let signals = d.inspect(&view(&m, &u, &h, &b, "1.1.1.1:443"));
        assert!(signals.iter().any(|s| s.tag == "brute_force"));
    }

    #[test]
    fn does_not_fire_for_get() {
        let d = BruteForceDetector::new(2, Duration::from_secs(60), 40);
        let (m, u, h, b) = make_req(http::Method::GET, "/login");
        for _ in 0..10 {
            assert!(d.inspect(&view(&m, &u, &h, &b, "2.2.2.2:443")).is_empty());
        }
    }

    #[test]
    fn does_not_fire_for_non_auth_path() {
        let d = BruteForceDetector::new(2, Duration::from_secs(60), 40);
        let (m, u, h, b) = make_req(http::Method::POST, "/api/profile");
        for _ in 0..10 {
            assert!(d.inspect(&view(&m, &u, &h, &b, "3.3.3.3:443")).is_empty());
        }
    }

    #[test]
    fn separate_ips_track_independently() {
        let d = BruteForceDetector::new(2, Duration::from_secs(60), 40);
        let (m, u, h, b) = make_req(http::Method::POST, "/login");
        for _ in 0..2 {
            d.inspect(&view(&m, &u, &h, &b, "5.5.5.5:443"));
        }
        // Different IP — fresh counter.
        for _ in 0..2 {
            assert!(d.inspect(&view(&m, &u, &h, &b, "6.6.6.6:443")).is_empty());
        }
    }

    #[test]
    fn auth_path_aliases_match() {
        let d = BruteForceDetector::new(1, Duration::from_secs(60), 40);
        for path in [
            "/login", "/api/login", "/signin", "/sign-in", "/auth",
            "/auth/login", "/api/auth", "/api/auth/login",
            "/api/v1/login", "/api/v2/login", "/account/login",
            "/user/login", "/users/login", "/session", "/sessions",
        ] {
            // Each path uses a unique IP so the counter doesn't
            // bleed across iterations.
            let ip = format!("9.0.0.{}:443", path.len() % 250);
            let (m, u, h, b) = make_req(http::Method::POST, path);
            d.inspect(&view(&m, &u, &h, &b, &ip));
            let signals = d.inspect(&view(&m, &u, &h, &b, &ip));
            assert!(
                signals.iter().any(|s| s.tag == "brute_force"),
                "path {path} should be a brute-force trigger"
            );
        }
    }

    #[test]
    fn auth_path_negative() {
        let d = BruteForceDetector::new(1, Duration::from_secs(60), 40);
        for path in [
            "/api/profile", "/api/transactions", "/health", "/static/app.js",
            "/sitemap.xml", "/about", "/api/feedback", "/game/list",
        ] {
            let ip = format!("8.0.0.{}:443", path.len() % 250);
            let (m, u, h, b) = make_req(http::Method::POST, path);
            d.inspect(&view(&m, &u, &h, &b, &ip));
            let signals = d.inspect(&view(&m, &u, &h, &b, &ip));
            assert!(
                signals.is_empty(),
                "path {path} should NOT be a brute-force trigger"
            );
        }
    }

    #[test]
    fn old_entries_pruned() {
        // Window of 1ms — anything older than 1ms is pruned.
        let d = BruteForceDetector::new(2, Duration::from_millis(1), 40);
        let (m, u, h, b) = make_req(http::Method::POST, "/login");
        for _ in 0..3 {
            d.inspect(&view(&m, &u, &h, &b, "7.7.7.7:443"));
        }
        // Sleep longer than window — old timestamps prune away.
        std::thread::sleep(Duration::from_millis(5));
        // Fresh request → counter should reset.
        let signals = d.inspect(&view(&m, &u, &h, &b, "7.7.7.7:443"));
        assert!(signals.is_empty());
    }
}
