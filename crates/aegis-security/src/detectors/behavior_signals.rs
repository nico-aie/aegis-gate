//! 2026-05-18 F-CRITICAL-004 (security audit, Phase F) — §5.2
//! behavior-signals detector. The audit flagged that the existing
//! `BehavioralAnalyzer` in `crates/aegis-security/src/behavior.rs`
//! emits *different* signals than the four §5.2 spec mandates.
//! `BehavioralAnalyzer` stays untouched (still wireable for richer
//! analytics later); this is the small, fast, per-request peer that
//! emits the four spec-mandated signals.
//!
//! ## Signals
//!
//! | Tag | Score | Trigger |
//! |---|---|---|
//! | `behavior_burst` | 25 | Same peer IP made another request <`burst_threshold_ms` (default 50 ms) ago — automated client signature |
//! | `behavior_no_ua` | 15 | Request has no `User-Agent` header, or it's empty / whitespace-only |
//! | `behavior_missing_referer` | 20 | Mutation method (POST / PUT / PATCH / DELETE) without a `Referer` header — CSRF-shaped traffic |
//! | `behavior_zero_depth` | 15 | First request from a peer with NO `Cookie` AND NO `Referer` — fresh stateless touch typical of crawlers/scanners |
//!
//! All four signals stack. A burst from a no-UA + no-referer
//! crawler accumulates 75 points → over the v2.3 `block_at: 70`
//! threshold in one hit.
//!
//! ## State
//!
//! `behavior_burst` and `behavior_zero_depth` need per-IP memory.
//! Stored in a single `parking_lot::Mutex<HashMap<IpAddr,
//! LastSeen>>` (mirrors `RiskTracker` shape). Bounded to
//! `max_tracked` entries with simple eviction-on-grow; the steady-
//! state cost is one map lookup + one update per request.
//!
//! The detector is intentionally simple — no LRU heap, no
//! atomic-per-cell shenanigans. At 10k QPS the Mutex contention
//! cost is dominated by the map ops themselves. If profile shows
//! contention later, the obvious next step is sharding (key
//! by `peer_ip.hash() % N_SHARDS`).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use aegis_core::pipeline::RequestView;

use super::{Detector, Signal};

/// Per-IP state the detector keeps between requests.
#[derive(Clone)]
struct LastSeen {
    at: Instant,
    /// `true` after the first request — used by the
    /// `behavior_zero_depth` signal to fire only on the FIRST
    /// touch (where no prior session state would exist).
    pub_warmed: bool,
}

pub struct BehaviorSignalsDetector {
    state: Mutex<HashMap<IpAddr, LastSeen>>,
    burst_threshold: Duration,
    max_tracked: usize,
}

impl BehaviorSignalsDetector {
    /// Default tuning per the §5.2 audit: 50 ms burst threshold,
    /// 100 000 tracked peer IPs (matches `BehavioralAnalyzer`'s
    /// max session bound).
    pub fn new() -> Self {
        Self::with_tuning(Duration::from_millis(50), 100_000)
    }

    pub fn with_tuning(burst_threshold: Duration, max_tracked: usize) -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
            burst_threshold,
            max_tracked,
        }
    }

    /// Number of currently tracked peer IPs. Test-only accessor;
    /// production callers don't need this.
    pub fn tracked_count(&self) -> usize {
        self.state.lock().unwrap().len()
    }

    /// Drop all tracked state. Wired into the v2.3 control plane
    /// `reset_state` path so benchmark phases start clean.
    pub fn clear(&self) {
        self.state.lock().unwrap().clear();
    }
}

impl Default for BehaviorSignalsDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for BehaviorSignalsDetector {
    fn id(&self) -> &'static str {
        // Not in `DetectorClass` (data-driven / stateful peer of
        // OWASP detectors). Mask treats unknown ids as
        // "always on" — see crates/aegis-security/src/detectors/mask.rs.
        "behavior_signals"
    }

    fn inspect(&self, req: &RequestView<'_>) -> Vec<Signal> {
        let mut signals = Vec::new();
        let peer_ip = req.peer.ip();
        let now = Instant::now();

        // ---- signal: burst ------------------------------------------------
        // Drop the lock before doing any other work — we only need
        // the previous `LastSeen` and the warmed flag.
        let (prev_at, was_warmed) = {
            let mut state = self.state.lock().unwrap();
            // Cheap bound: when we'd add an entry past the cap, drop
            // one to make room. Random-ish eviction (HashMap iteration
            // order) is fine for a security telemetry tracker —
            // attackers can't pin a slot.
            if !state.contains_key(&peer_ip) && state.len() >= self.max_tracked {
                if let Some(k) = state.keys().next().cloned() {
                    state.remove(&k);
                }
            }
            let prev = state.get(&peer_ip).cloned();
            state.insert(
                peer_ip,
                LastSeen {
                    at: now,
                    pub_warmed: true,
                },
            );
            match prev {
                Some(p) => (Some(p.at), p.pub_warmed),
                None => (None, false),
            }
        };

        if let Some(prev) = prev_at {
            let delta = now.saturating_duration_since(prev);
            if delta < self.burst_threshold {
                signals.push(Signal {
                    score: 25,
                    tag: "behavior_burst".into(),
                    field: format!("delta_ms:{}", delta.as_millis()),
                });
            }
        }

        // ---- signal: missing User-Agent -----------------------------------
        let ua_empty = req
            .headers
            .get(http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().is_empty())
            .unwrap_or(true);
        if ua_empty {
            signals.push(Signal {
                score: 15,
                tag: "behavior_no_ua".into(),
                field: "user-agent".into(),
            });
        }

        // ---- signal: missing Referer on mutation methods ------------------
        let is_mutation = matches!(
            *req.method,
            http::Method::POST
                | http::Method::PUT
                | http::Method::PATCH
                | http::Method::DELETE
        );
        let referer_present = req
            .headers
            .get(http::header::REFERER)
            .and_then(|v| v.to_str().ok())
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        if is_mutation && !referer_present {
            signals.push(Signal {
                score: 20,
                tag: "behavior_missing_referer".into(),
                field: "referer".into(),
            });
        }

        // ---- signal: zero-depth session -----------------------------------
        // First request from this peer (state.was_warmed was false
        // before the update above) AND no Cookie AND no Referer.
        if !was_warmed {
            let no_cookie = req
                .headers
                .get(http::header::COOKIE)
                .map(|_| false)
                .unwrap_or(true);
            // referer_present was computed above.
            if no_cookie && !referer_present {
                signals.push(Signal {
                    score: 15,
                    tag: "behavior_zero_depth".into(),
                    field: "first-touch".into(),
                });
            }
        }

        signals
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::pipeline::{BodyPeek, RequestView};

    fn parts(
        method: http::Method,
        path: &str,
        peer_ip: &str,
        headers: &[(&str, &str)],
    ) -> (
        http::Method,
        http::Uri,
        http::HeaderMap,
        BodyPeek,
        std::net::SocketAddr,
    ) {
        let uri: http::Uri = path.parse().unwrap();
        let mut hmap = http::HeaderMap::new();
        for (k, v) in headers {
            hmap.insert(
                http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        let socket = std::net::SocketAddr::new(peer_ip.parse().unwrap(), 0);
        (method, uri, hmap, BodyPeek::empty(), socket)
    }

    fn view<'a>(
        method: &'a http::Method,
        uri: &'a http::Uri,
        headers: &'a http::HeaderMap,
        body: &'a BodyPeek,
        peer: std::net::SocketAddr,
    ) -> RequestView<'a> {
        RequestView {
            method,
            uri,
            version: http::Version::HTTP_11,
            headers,
            peer,
            tls: None,
            body,
        }
    }

    #[test]
    fn no_signals_for_clean_browser_request() {
        let d = BehaviorSignalsDetector::new();
        // Pre-warm so zero_depth doesn't fire.
        let (m, u, h, b, p) = parts(
            http::Method::GET,
            "/page",
            "203.0.113.7",
            &[("user-agent", "Mozilla/5.0"), ("referer", "https://example.com/")],
        );
        let _ = d.inspect(&view(&m, &u, &h, &b, p));

        // Now a clean GET with UA + Cookie should fire nothing
        // (after the burst-threshold window).
        std::thread::sleep(Duration::from_millis(60));
        let (m, u, h, b, p) = parts(
            http::Method::GET,
            "/page2",
            "203.0.113.7",
            &[
                ("user-agent", "Mozilla/5.0"),
                ("cookie", "sess=abc"),
                ("referer", "https://example.com/"),
            ],
        );
        let signals = d.inspect(&view(&m, &u, &h, &b, p));
        assert!(signals.is_empty(), "unexpected signals: {signals:?}");
    }

    #[test]
    fn burst_detected_on_rapid_repeat_from_same_ip() {
        let d = BehaviorSignalsDetector::new();
        let (m, u, h, b, p) = parts(
            http::Method::GET,
            "/page",
            "203.0.113.42",
            &[("user-agent", "Mozilla/5.0"), ("referer", "https://x.com/")],
        );
        // Pre-warm with first request.
        let _ = d.inspect(&view(&m, &u, &h, &b, p));
        // Immediate second request — same IP, under 50 ms.
        let signals = d.inspect(&view(&m, &u, &h, &b, p));
        assert!(
            signals.iter().any(|s| s.tag == "behavior_burst"),
            "expected burst signal, got {signals:?}",
        );
    }

    #[test]
    fn no_user_agent_fires() {
        let d = BehaviorSignalsDetector::new();
        let (m, u, h, b, p) = parts(
            http::Method::GET,
            "/api",
            "203.0.113.8",
            &[("referer", "https://x.com/")],
        );
        let signals = d.inspect(&view(&m, &u, &h, &b, p));
        assert!(signals.iter().any(|s| s.tag == "behavior_no_ua"));
    }

    #[test]
    fn empty_user_agent_fires() {
        let d = BehaviorSignalsDetector::new();
        let (m, u, h, b, p) = parts(
            http::Method::GET,
            "/api",
            "203.0.113.9",
            &[("user-agent", "   "), ("referer", "https://x.com/")],
        );
        let signals = d.inspect(&view(&m, &u, &h, &b, p));
        assert!(signals.iter().any(|s| s.tag == "behavior_no_ua"));
    }

    #[test]
    fn missing_referer_on_post_fires() {
        let d = BehaviorSignalsDetector::new();
        let (m, u, h, b, p) = parts(
            http::Method::POST,
            "/api/transfer",
            "203.0.113.10",
            &[("user-agent", "Mozilla/5.0")], // No Referer
        );
        let signals = d.inspect(&view(&m, &u, &h, &b, p));
        assert!(
            signals.iter().any(|s| s.tag == "behavior_missing_referer"),
            "expected missing_referer on POST, got {signals:?}",
        );
    }

    #[test]
    fn referer_present_on_post_does_not_fire_missing_referer() {
        let d = BehaviorSignalsDetector::new();
        let (m, u, h, b, p) = parts(
            http::Method::POST,
            "/api/transfer",
            "203.0.113.11",
            &[
                ("user-agent", "Mozilla/5.0"),
                ("referer", "https://x.com/"),
            ],
        );
        let signals = d.inspect(&view(&m, &u, &h, &b, p));
        assert!(!signals.iter().any(|s| s.tag == "behavior_missing_referer"));
    }

    #[test]
    fn get_method_does_not_fire_missing_referer() {
        let d = BehaviorSignalsDetector::new();
        let (m, u, h, b, p) = parts(
            http::Method::GET,
            "/api/list",
            "203.0.113.12",
            &[("user-agent", "Mozilla/5.0")],
        );
        let signals = d.inspect(&view(&m, &u, &h, &b, p));
        assert!(!signals.iter().any(|s| s.tag == "behavior_missing_referer"));
    }

    #[test]
    fn zero_depth_fires_on_first_touch_with_no_cookie_no_referer() {
        let d = BehaviorSignalsDetector::new();
        let (m, u, h, b, p) = parts(
            http::Method::GET,
            "/api",
            "203.0.113.13",
            &[("user-agent", "Mozilla/5.0")], // no cookie, no referer
        );
        let signals = d.inspect(&view(&m, &u, &h, &b, p));
        assert!(
            signals.iter().any(|s| s.tag == "behavior_zero_depth"),
            "expected zero_depth, got {signals:?}",
        );
    }

    #[test]
    fn zero_depth_does_not_fire_after_warming() {
        let d = BehaviorSignalsDetector::new();
        let (m, u, h, b, p) = parts(
            http::Method::GET,
            "/api",
            "203.0.113.14",
            &[("user-agent", "Mozilla/5.0")],
        );
        let _ = d.inspect(&view(&m, &u, &h, &b, p));
        std::thread::sleep(Duration::from_millis(60));
        let signals = d.inspect(&view(&m, &u, &h, &b, p));
        assert!(!signals.iter().any(|s| s.tag == "behavior_zero_depth"));
    }

    #[test]
    fn zero_depth_does_not_fire_with_cookie() {
        let d = BehaviorSignalsDetector::new();
        let (m, u, h, b, p) = parts(
            http::Method::GET,
            "/api",
            "203.0.113.15",
            &[("user-agent", "Mozilla/5.0"), ("cookie", "sess=abc")],
        );
        let signals = d.inspect(&view(&m, &u, &h, &b, p));
        assert!(!signals.iter().any(|s| s.tag == "behavior_zero_depth"));
    }

    #[test]
    fn signals_stack_on_bot_post() {
        // POST with no UA, no Referer, no Cookie, from a fresh IP.
        // Expect: missing_referer + no_ua + zero_depth.
        let d = BehaviorSignalsDetector::new();
        let (m, u, h, b, p) =
            parts(http::Method::POST, "/login", "203.0.113.99", &[]);
        let signals = d.inspect(&view(&m, &u, &h, &b, p));
        let tags: Vec<&str> = signals.iter().map(|s| s.tag.as_str()).collect();
        assert!(tags.contains(&"behavior_no_ua"));
        assert!(tags.contains(&"behavior_missing_referer"));
        assert!(tags.contains(&"behavior_zero_depth"));
        // Total accumulated score 15 + 20 + 15 = 50 — over
        // challenge_at (30) but under block_at (70). One more
        // strike from any detector pushes over block.
        let total: u32 = signals.iter().map(|s| s.score).sum();
        assert_eq!(total, 50);
    }

    #[test]
    fn id_is_behavior_signals() {
        let d = BehaviorSignalsDetector::new();
        assert_eq!(d.id(), "behavior_signals");
    }

    #[test]
    fn clear_drops_tracked_state() {
        let d = BehaviorSignalsDetector::new();
        let (m, u, h, b, p) = parts(http::Method::GET, "/x", "203.0.113.1", &[]);
        let _ = d.inspect(&view(&m, &u, &h, &b, p));
        let (m, u, h, b, p) = parts(http::Method::GET, "/x", "203.0.113.2", &[]);
        let _ = d.inspect(&view(&m, &u, &h, &b, p));
        assert_eq!(d.tracked_count(), 2);
        d.clear();
        assert_eq!(d.tracked_count(), 0);
    }

    #[test]
    fn max_tracked_caps_growth() {
        let d = BehaviorSignalsDetector::with_tuning(Duration::from_millis(50), 3);
        for octet in 1u8..=10 {
            let ip = format!("203.0.113.{octet}");
            let (m, u, h, b, p) = parts(http::Method::GET, "/x", &ip, &[]);
            let _ = d.inspect(&view(&m, &u, &h, &b, p));
        }
        // Cap is 3 — eviction kicks in beyond that.
        assert!(d.tracked_count() <= 3);
    }
}
