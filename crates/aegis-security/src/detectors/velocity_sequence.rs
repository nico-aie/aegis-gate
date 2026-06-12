//! 2026-05-18 F-CRITICAL-003 (security audit, Phase F) — velocity
//! sequence engine. The existing `crates/aegis-security/src/velocity.rs`
//! is a per-action rate cap ("max N withdrawals in 10 minutes"); the
//! audit flagged that it can't detect **shape attacks** like
//! `Login → Deposit < 5 s` — distinct endpoints hit in fast
//! succession that don't individually trip a rate cap but together
//! reveal a credential-stuffer / account-takeover sequence.
//!
//! This detector ships the sequence engine as a peer of the OWASP
//! detectors. It runs always-on with a small built-in ruleset:
//!
//! | Sequence | Window | Score | Why suspicious |
//! |---|---|---|---|
//! | `login → deposit` | 5 s | 60 | Credential-stuffer monetising a successful login |
//! | `login → withdrawal` | 5 s | 70 | ATO cashout — even faster + higher value than deposit |
//! | `otp → deposit` | 5 s | 50 | Same shape after OTP step (most ATOs go through 2FA) |
//! | `otp → withdrawal` | 5 s | 60 | Same shape, cashout |
//!
//! The ruleset is hardcoded for v1 — operator-tunable config lands
//! when `aegis_core::config::VelocitySequenceConfig` is wired (a
//! TODO once the schema design call settles). The hardcoded list
//! covers the audit's explicit example (`Login → Deposit < 5 s`).
//!
//! ## Per-IP state
//!
//! Each peer IP gets a small ring buffer (`MAX_HISTORY = 8`) of
//! `(endpoint_tag, timestamp)` tuples. Old entries roll off; new
//! requests append. On each request we walk the buffer for any
//! configured `(prev_tag, this_tag, window)` sequence and emit a
//! signal if the window holds.
//!
//! State map is bounded at `max_tracked` peers (default 100 000),
//! matching `behavior_signals` shape. Random eviction.
//!
//! ## Endpoint tagging
//!
//! Each request path is mapped to an `EndpointTag` via simple
//! substring heuristics:
//!
//! | Contains | Tag |
//! |---|---|
//! | `login` | `Login` |
//! | `/auth/`, `signin` | `Login` |
//! | `otp`, `2fa`, `verify` | `Otp` |
//! | `deposit`, `topup`, `recharge` | `Deposit` |
//! | `withdraw`, `cashout`, `payout` | `Withdrawal` |
//! | `transfer`, `send-money` | `Withdrawal` (treated as cash movement) |
//! | (anything else) | `Other` (not stored — keeps the ring buffer focused) |
//!
//! Only "interesting" tags go into the ring buffer; the `Other`
//! filter keeps the buffer small even on chatty browse flows.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use aegis_core::pipeline::RequestView;

use super::{Detector, Signal};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum EndpointTag {
    Login,
    Otp,
    Deposit,
    Withdrawal,
}

impl EndpointTag {
    fn classify(path: &str) -> Option<Self> {
        // Lowercase the path's substring checks — the tagging
        // heuristic is intentionally generous; false-positive on
        // an English word in a non-financial route is fine because
        // the SEQUENCE itself is what's load-bearing.
        let p = path.to_ascii_lowercase();
        if p.contains("withdraw") || p.contains("cashout") || p.contains("payout")
            || p.contains("transfer") || p.contains("send-money")
        {
            return Some(Self::Withdrawal);
        }
        if p.contains("deposit") || p.contains("topup") || p.contains("recharge") {
            return Some(Self::Deposit);
        }
        if p.contains("otp") || p.contains("2fa") || p.contains("verify") {
            return Some(Self::Otp);
        }
        if p.contains("login") || p.contains("/auth/") || p.contains("signin") {
            return Some(Self::Login);
        }
        None
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Otp => "otp",
            Self::Deposit => "deposit",
            Self::Withdrawal => "withdrawal",
        }
    }
}

/// One configured sequence rule.
struct SequenceRule {
    prev: EndpointTag,
    next: EndpointTag,
    window: Duration,
    score: u32,
}

const RULES: &[SequenceRule] = &[
    SequenceRule {
        prev: EndpointTag::Login,
        next: EndpointTag::Deposit,
        window: Duration::from_secs(5),
        score: 60,
    },
    SequenceRule {
        prev: EndpointTag::Login,
        next: EndpointTag::Withdrawal,
        window: Duration::from_secs(5),
        score: 70,
    },
    SequenceRule {
        prev: EndpointTag::Otp,
        next: EndpointTag::Deposit,
        window: Duration::from_secs(5),
        score: 50,
    },
    SequenceRule {
        prev: EndpointTag::Otp,
        next: EndpointTag::Withdrawal,
        window: Duration::from_secs(5),
        score: 60,
    },
];

const MAX_HISTORY: usize = 8;

#[derive(Clone)]
struct History {
    /// Newest-first VecDeque-style — push to front, drop from back.
    /// `MAX_HISTORY` so the bound never grows.
    entries: Vec<(EndpointTag, Instant)>,
}

impl History {
    fn new() -> Self {
        Self {
            entries: Vec::with_capacity(MAX_HISTORY),
        }
    }

    fn push(&mut self, tag: EndpointTag, at: Instant) {
        if self.entries.len() == MAX_HISTORY {
            self.entries.pop(); // drop oldest
        }
        self.entries.insert(0, (tag, at));
    }

    /// Most recent prior entry (if any), excluding the head if the
    /// head IS the new entry being added. Caller passes the new
    /// entry's tag and timestamp; we look for the newest entry
    /// matching `prev_tag` strictly before `at` and within `window`.
    fn find_recent(
        &self,
        prev_tag: EndpointTag,
        before: Instant,
        window: Duration,
    ) -> bool {
        for (tag, ts) in &self.entries {
            // Skip future timestamps (defensive; shouldn't happen
            // with monotonic Instant but harmless).
            if *ts > before {
                continue;
            }
            // Past the window → ring buffer ordering means no
            // earlier entry will be in-window either.
            if before.saturating_duration_since(*ts) > window {
                return false;
            }
            if *tag == prev_tag {
                return true;
            }
        }
        false
    }
}

pub struct VelocitySequenceDetector {
    state: Mutex<HashMap<IpAddr, History>>,
    max_tracked: usize,
}

impl VelocitySequenceDetector {
    pub fn new() -> Self {
        Self::with_capacity(100_000)
    }

    pub fn with_capacity(max_tracked: usize) -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
            max_tracked,
        }
    }

    pub fn tracked_count(&self) -> usize {
        self.state.lock().unwrap().len()
    }

    /// Drop all tracked history. Wired into the v2.3 `reset_state`
    /// callback so benchmark phases start clean.
    pub fn clear(&self) {
        self.state.lock().unwrap().clear();
    }
}

impl Default for VelocitySequenceDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for VelocitySequenceDetector {
    fn id(&self) -> &'static str {
        // MUST equal `DetectorClass::Velocity::as_str()` ("velocity").
        // The dispatcher gates each detector with
        // `mask.is_enabled_id(d.id())`, which maps the id back to a
        // class; a mismatch makes `from_id` return `None` and the
        // detector runs UNCONDITIONALLY (unknown-id fallback), bypassing
        // the mask entirely. Was "velocity_sequence" → the Velocity mask
        // bit never gated it, so it kept emitting `velocity_*` blocks
        // even with all detectors disabled (VELOCITY_SEQUENCE_BUG_REPORT,
        // 2026-06-12). The `all_registered_detectors_map_to_a_class`
        // drift-guard test in `detectors/mod.rs` now enforces this.
        "velocity"
    }

    fn inspect(&self, req: &RequestView<'_>) -> Vec<Signal> {
        let peer_ip = req.peer.ip();
        let Some(tag) = EndpointTag::classify(req.uri.path()) else {
            // No tag → don't touch state, don't fire.
            return Vec::new();
        };
        let now = Instant::now();

        // Update state + collect history snapshot for rule eval.
        let history = {
            let mut state = self.state.lock().unwrap();
            if !state.contains_key(&peer_ip) && state.len() >= self.max_tracked {
                if let Some(k) = state.keys().next().cloned() {
                    state.remove(&k);
                }
            }
            let h = state.entry(peer_ip).or_insert_with(History::new);
            // Snapshot BEFORE the push so we don't trip on the
            // event we just added.
            let snap = h.clone();
            h.push(tag, now);
            snap
        };

        let mut signals = Vec::new();
        for rule in RULES {
            if rule.next != tag {
                continue;
            }
            if history.find_recent(rule.prev, now, rule.window) {
                signals.push(Signal {
                    score: rule.score,
                    tag: format!("velocity_{}_to_{}", rule.prev.as_str(), rule.next.as_str()),
                    field: format!(
                        "window_s:{}",
                        rule.window.as_secs(),
                    ),
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
    ) -> (http::Method, http::Uri, http::HeaderMap, BodyPeek, std::net::SocketAddr) {
        let uri: http::Uri = path.parse().unwrap();
        let socket = std::net::SocketAddr::new(peer_ip.parse().unwrap(), 0);
        (method, uri, http::HeaderMap::new(), BodyPeek::empty(), socket)
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
    fn classify_handles_common_tags() {
        assert_eq!(EndpointTag::classify("/login"), Some(EndpointTag::Login));
        assert_eq!(EndpointTag::classify("/auth/signin"), Some(EndpointTag::Login));
        assert_eq!(EndpointTag::classify("/otp"), Some(EndpointTag::Otp));
        assert_eq!(EndpointTag::classify("/api/2fa/verify"), Some(EndpointTag::Otp));
        assert_eq!(EndpointTag::classify("/api/deposit"), Some(EndpointTag::Deposit));
        assert_eq!(EndpointTag::classify("/withdraw"), Some(EndpointTag::Withdrawal));
        assert_eq!(EndpointTag::classify("/api/transfer"), Some(EndpointTag::Withdrawal));
        assert_eq!(EndpointTag::classify("/health"), None);
        assert_eq!(EndpointTag::classify("/api/profile"), None);
    }

    #[test]
    fn login_to_deposit_within_5s_fires() {
        let d = VelocitySequenceDetector::new();
        let (m, u, h, b, p) = parts(http::Method::POST, "/login", "203.0.113.5");
        let _ = d.inspect(&view(&m, &u, &h, &b, p));
        // Same IP, immediately calls /deposit.
        let (m, u, h, b, p) = parts(http::Method::POST, "/api/deposit", "203.0.113.5");
        let signals = d.inspect(&view(&m, &u, &h, &b, p));
        assert!(
            signals.iter().any(|s| s.tag == "velocity_login_to_deposit" && s.score == 60),
            "expected login_to_deposit signal: {signals:?}",
        );
    }

    #[test]
    fn login_to_withdrawal_within_5s_fires_at_higher_score() {
        let d = VelocitySequenceDetector::new();
        let (m, u, h, b, p) = parts(http::Method::POST, "/login", "203.0.113.6");
        let _ = d.inspect(&view(&m, &u, &h, &b, p));
        let (m, u, h, b, p) = parts(http::Method::POST, "/withdrawal", "203.0.113.6");
        let signals = d.inspect(&view(&m, &u, &h, &b, p));
        assert!(
            signals.iter().any(|s| s.tag == "velocity_login_to_withdrawal" && s.score == 70),
            "expected login_to_withdrawal signal: {signals:?}",
        );
    }

    #[test]
    fn otp_to_deposit_fires() {
        let d = VelocitySequenceDetector::new();
        let (m, u, h, b, p) = parts(http::Method::POST, "/api/2fa/verify", "203.0.113.7");
        let _ = d.inspect(&view(&m, &u, &h, &b, p));
        let (m, u, h, b, p) = parts(http::Method::POST, "/deposit", "203.0.113.7");
        let signals = d.inspect(&view(&m, &u, &h, &b, p));
        assert!(signals.iter().any(|s| s.tag == "velocity_otp_to_deposit"));
    }

    #[test]
    fn deposit_alone_does_not_fire() {
        let d = VelocitySequenceDetector::new();
        // Single deposit with no prior login.
        let (m, u, h, b, p) = parts(http::Method::POST, "/deposit", "203.0.113.8");
        let signals = d.inspect(&view(&m, &u, &h, &b, p));
        assert!(signals.is_empty(), "deposit alone fired: {signals:?}");
    }

    #[test]
    fn login_to_deposit_after_window_does_not_fire() {
        // Manually backdate the prior login by ~6 s to simulate
        // the user actually browsing between steps. We can't
        // sleep 6 s in a test, so we drive the History directly.
        let d = VelocitySequenceDetector::new();
        let peer_ip: IpAddr = "203.0.113.9".parse().unwrap();
        {
            let mut state = d.state.lock().unwrap();
            let h = state.entry(peer_ip).or_insert_with(History::new);
            // Backdate login 6 s ago.
            h.entries.push((
                EndpointTag::Login,
                Instant::now() - Duration::from_secs(6),
            ));
        }
        let (m, u, h, b, p) = parts(http::Method::POST, "/deposit", "203.0.113.9");
        let signals = d.inspect(&view(&m, &u, &h, &b, p));
        assert!(signals.is_empty(), "expected no signal beyond window: {signals:?}");
    }

    #[test]
    fn different_ips_do_not_chain() {
        let d = VelocitySequenceDetector::new();
        // Attacker A logs in.
        let (m, u, h, b, p) = parts(http::Method::POST, "/login", "203.0.113.10");
        let _ = d.inspect(&view(&m, &u, &h, &b, p));
        // Different IP deposits.
        let (m, u, h, b, p) = parts(http::Method::POST, "/deposit", "203.0.113.11");
        let signals = d.inspect(&view(&m, &u, &h, &b, p));
        assert!(signals.is_empty(), "different IPs should not chain: {signals:?}");
    }

    #[test]
    fn unrelated_paths_dont_touch_state() {
        let d = VelocitySequenceDetector::new();
        let (m, u, h, b, p) = parts(http::Method::GET, "/health", "203.0.113.12");
        let _ = d.inspect(&view(&m, &u, &h, &b, p));
        assert_eq!(d.tracked_count(), 0, "unrelated paths should not create state");
    }

    #[test]
    fn intermediate_unrelated_hits_dont_break_chain() {
        // Real attack: login → GET /api/profile → deposit. The
        // intermediate /api/profile shouldn't reset the sequence
        // because /api/profile classifies as None (no tag) and
        // we don't touch state for None.
        let d = VelocitySequenceDetector::new();
        let (m, u, h, b, p) = parts(http::Method::POST, "/login", "203.0.113.13");
        let _ = d.inspect(&view(&m, &u, &h, &b, p));
        let (m, u, h, b, p) = parts(http::Method::GET, "/api/profile", "203.0.113.13");
        let _ = d.inspect(&view(&m, &u, &h, &b, p));
        let (m, u, h, b, p) = parts(http::Method::POST, "/deposit", "203.0.113.13");
        let signals = d.inspect(&view(&m, &u, &h, &b, p));
        assert!(signals.iter().any(|s| s.tag == "velocity_login_to_deposit"));
    }

    #[test]
    fn id_matches_velocity_class() {
        // Must equal DetectorClass::Velocity::as_str() so the mask gates
        // it — see the comment on `id()` and the drift-guard test.
        assert_eq!(VelocitySequenceDetector::new().id(), "velocity");
    }

    #[test]
    fn clear_drops_tracked_state() {
        let d = VelocitySequenceDetector::new();
        let (m, u, h, b, p) = parts(http::Method::POST, "/login", "203.0.113.14");
        let _ = d.inspect(&view(&m, &u, &h, &b, p));
        assert_eq!(d.tracked_count(), 1);
        d.clear();
        assert_eq!(d.tracked_count(), 0);
    }

    #[test]
    fn max_tracked_caps_growth() {
        let d = VelocitySequenceDetector::with_capacity(3);
        for octet in 1u8..=10 {
            let ip = format!("203.0.113.{octet}");
            let (m, u, h, b, p) = parts(http::Method::POST, "/login", &ip);
            let _ = d.inspect(&view(&m, &u, &h, &b, p));
        }
        assert!(d.tracked_count() <= 3);
    }
}
