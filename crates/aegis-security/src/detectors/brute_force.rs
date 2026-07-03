//! Login brute-force detector. Per-IP + per-user + per-device
//! windowed counters on authentication paths.
//!
//! 2026-05-18 (QC Sprint 2.3 — F-CRITICAL-014): three independent
//! axes track separate attacker shapes:
//!
//! - **per-IP** — classic single-source brute-force. Fires when
//!   one IP makes >`ip_threshold` auth attempts in `window`.
//! - **per-user** — password-spraying detection. Fires when one
//!   username sees auth attempts from >`user_threshold` distinct
//!   IPs in `window`. Catches the credential-stuffing shape where
//!   the attacker rotates IPs across a CIDR but targets a single
//!   high-value account.
//! - **per-device** — distributed credential-stuffing detection.
//!   Fires when one device fingerprint (JA4) appears across
//!   >`device_threshold` distinct IPs in `window`. Catches the
//!   shape where the attacker rotates both IPs and usernames but
//!   reuses the same TLS client library.
//!
//! Method allowlist expanded beyond POST-only: POST, PUT, PATCH,
//! and any method carrying an `Authorization: Basic …` header.
//! Pre-fix, RFC 7617 Basic-auth probes on GET were silently
//! ignored by the brute-force detector — exactly the shape the
//! `hydra` / `medusa` tooling defaults to.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use aegis_core::pipeline::RequestView;

use super::{Detector, Signal};

/// Brute-force detector. Stateful — owns three counter maps.
pub struct BruteForceDetector {
    /// Number of POSTs in `window` from one IP that fires.
    pub threshold: u32,
    /// Number of distinct IPs in `window` per username that
    /// fires (password-spraying).
    pub user_threshold: u32,
    /// Number of distinct IPs in `window` per device fingerprint
    /// that fires (distributed credential stuffing).
    pub device_threshold: u32,
    /// Sliding-window length.
    pub window: Duration,
    /// Score emitted on a hit. Risk-tier is the same as the
    /// other detectors (mid-tens) so a single brute-force
    /// fingerprint plus another signal compounds into a block.
    pub score: u32,
    /// Per-IP counter (classic single-source brute-force).
    state: Mutex<HashMap<IpAddr, Vec<Instant>>>,
    /// Per-username → set of (IP, Instant) tuples observed
    /// within `window` (password-spraying tracker).
    user_state: Mutex<HashMap<String, Vec<(IpAddr, Instant)>>>,
    /// Per-device-fingerprint → same shape as user_state
    /// (distributed credential stuffing tracker).
    device_state: Mutex<HashMap<String, Vec<(IpAddr, Instant)>>>,
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
            // 2026-05-18 (QC Sprint 2.3): default thresholds for
            // the two new axes. Conservative so we don't fire on
            // legitimate small-team office traffic but tight
            // enough that real credential-stuffers cross within
            // the first minute.
            user_threshold: 5,
            device_threshold: 10,
            window,
            score,
            state: Mutex::new(HashMap::new()),
            user_state: Mutex::new(HashMap::new()),
            device_state: Mutex::new(HashMap::new()),
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

    /// 2026-05-18 (QC Sprint 2.3 — F-CRITICAL-014, password-
    /// spraying axis): record that `peer_ip` attempted to auth
    /// as `username` and return `true` when distinct-IP count for
    /// this user crosses `user_threshold` within `window`.
    fn record_user_and_check(&self, username: &str, peer_ip: IpAddr) -> bool {
        if username.is_empty() {
            return false;
        }
        let now = Instant::now();
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        let mut state = self.user_state.lock().expect("user state poisoned");
        let entry = state.entry(username.to_string()).or_default();
        entry.retain(|&(_, t)| t >= cutoff);
        // Skip duplicate IP records within the window — we count
        // DISTINCT IPs, not raw attempts.
        if !entry.iter().any(|(ip, _)| *ip == peer_ip) {
            entry.push((peer_ip, now));
        }
        let cap = (self.user_threshold * 2).max(20) as usize;
        if entry.len() > cap {
            let drop_n = entry.len() - cap;
            entry.drain(0..drop_n);
        }
        let distinct_ips: HashSet<IpAddr> =
            entry.iter().map(|(ip, _)| *ip).collect();
        distinct_ips.len() as u32 > self.user_threshold
    }

    /// 2026-05-18 (QC Sprint 2.3 — F-CRITICAL-014, distributed
    /// credential-stuffing axis): same shape as user-axis but
    /// keyed by device fingerprint. Fires when one device sees
    /// auth attempts from >`device_threshold` distinct IPs in
    /// `window`.
    fn record_device_and_check(&self, device_fp: &str, peer_ip: IpAddr) -> bool {
        if device_fp.is_empty() {
            return false;
        }
        let now = Instant::now();
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        let mut state = self.device_state.lock().expect("device state poisoned");
        let entry = state.entry(device_fp.to_string()).or_default();
        entry.retain(|&(_, t)| t >= cutoff);
        if !entry.iter().any(|(ip, _)| *ip == peer_ip) {
            entry.push((peer_ip, now));
        }
        let cap = (self.device_threshold * 2).max(20) as usize;
        if entry.len() > cap {
            let drop_n = entry.len() - cap;
            entry.drain(0..drop_n);
        }
        let distinct_ips: HashSet<IpAddr> =
            entry.iter().map(|(ip, _)| *ip).collect();
        distinct_ips.len() as u32 > self.device_threshold
    }
}

impl Detector for BruteForceDetector {
    fn id(&self) -> &'static str {
        "brute_force"
    }

    fn inspect(&self, req: &RequestView<'_>) -> Vec<Signal> {
        // 2026-05-18 (QC Sprint 2.3 — F-CRITICAL-014): method
        // allowlist. Pre-fix only POST counted; that missed Basic-
        // auth probes on GET (default for `hydra` / `medusa`) and
        // PUT/PATCH-style password-change endpoints. The current
        // shape: any auth-path request with an Authorization
        // header OR a method that typically carries credentials
        // (POST / PUT / PATCH) counts.
        let path = req.uri.path();
        if !is_auth_path(path) {
            return Vec::new();
        }
        let has_auth_header = req.headers.contains_key(http::header::AUTHORIZATION);
        let mutation_method = matches!(
            *req.method,
            http::Method::POST | http::Method::PUT | http::Method::PATCH,
        );
        if !mutation_method && !has_auth_header {
            // GET / HEAD / OPTIONS without Authorization header → page
            // render, not an auth attempt.
            return Vec::new();
        }

        let peer_ip = req.peer.ip();

        // ---- per-IP axis (classic single-source) -------------
        let ip_fired = self.record_and_check(peer_ip);

        // ---- per-user axis (password-spraying) ---------------
        // Parse a `username=` form-body or `Authorization: Basic
        // <base64(user:pass)>` header. Body inspection is cheap
        // — RequestView.body.peek() returns the buffered bytes
        // the detector chain already collected.
        let username = extract_username(req);
        let user_fired = match &username {
            Some(u) => self.record_user_and_check(u, peer_ip),
            None => false,
        };

        // ---- per-device axis (distributed credential stuffing) -
        // Device fingerprint comes from the TLS layer's JA4 hash.
        // Today the data plane doesn't pipe JA4 into `RequestView`
        // for non-TLS connections (admin port is plaintext); when
        // tls is `None` we skip this axis.
        let device_fp = req
            .tls
            .as_ref()
            .map(|t| t.ja4.clone())
            .filter(|s| !s.is_empty());
        let device_fired = match &device_fp {
            Some(fp) => self.record_device_and_check(fp, peer_ip),
            None => false,
        };

        // Stack signals so an attack matching multiple axes
        // accumulates score. Each axis emits with its own tag so
        // the audit log shows which axis caught the attack.
        let mut signals = Vec::new();
        if ip_fired {
            signals.push(Signal {
                score: self.score,
                tag: "brute_force".into(),
                field: format!("ip:{peer_ip}"),
            });
        }
        if user_fired {
            if let Some(u) = &username {
                signals.push(Signal {
                    score: self.score,
                    tag: "brute_force_user".into(),
                    field: format!("user:{u}"),
                });
            }
        }
        if device_fired {
            if let Some(fp) = &device_fp {
                signals.push(Signal {
                    score: self.score,
                    tag: "brute_force_device".into(),
                    // Truncate JA4 to first 16 chars for the
                    // audit field — full string is in the audit
                    // event's optional fields blob.
                    field: format!("device:{}", &fp[..fp.len().min(16)]),
                });
            }
        }
        signals
    }
}

/// 2026-05-18 (QC Sprint 2.3 — F-CRITICAL-014): pull a username
/// out of the request. Two sources, in order:
///
/// 1. `Authorization: Basic <base64>` header — RFC 7617.
/// 2. Body parsing for `username=` in `application/x-www-form-
///    urlencoded` or top-level `"username":"…"` in JSON.
///
/// Returns `None` when no recognisable username appears. We don't
/// canonicalise (lowercase / trim) — the per-user counter keys on
/// the exact string the attacker sent, which is the same shape an
/// upstream auth server would see.
fn extract_username(req: &RequestView<'_>) -> Option<String> {
    // 1. Basic auth header.
    if let Some(auth) = req
        .headers
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(b64) = auth
            .strip_prefix("Basic ")
            .or_else(|| auth.strip_prefix("basic "))
        {
            // Base64 decode + split on first colon.
            use base64::Engine as _;
            if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) {
                if let Ok(s) = std::str::from_utf8(&bytes) {
                    if let Some((user, _)) = s.split_once(':') {
                        if !user.is_empty() {
                            return Some(user.to_string());
                        }
                    }
                }
            }
        }
    }

    // 2. Body parsing — only the first few KB to keep cost
    // bounded. The detector chain has already buffered the body
    // for SSRF / SQLi / XSS inspection so this is reading already-
    // hot memory.
    let body = req.body.peek(8 * 1024);
    if body.is_empty() {
        return None;
    }

    // JSON: `"username":"…"` or `"user":"…"`. Cheap substring
    // search; no full JSON parse since attackers don't pretty-
    // print and the body may be malformed.
    if let Ok(text) = std::str::from_utf8(body) {
        for key in &["\"username\"", "\"user\""] {
            if let Some(idx) = text.find(key) {
                let tail = &text[idx + key.len()..];
                // Skip `:` + whitespace + `"`.
                let tail = tail.trim_start_matches(|c: char| {
                    c.is_whitespace() || c == ':' || c == '"'
                });
                if let Some(end) = tail.find('"') {
                    let user = &tail[..end];
                    if !user.is_empty() && user.len() < 256 {
                        return Some(user.to_string());
                    }
                }
            }
        }
        // Form-urlencoded: `username=…&…`.
        for pair in text.split('&') {
            if let Some(val) = pair
                .strip_prefix("username=")
                .or_else(|| pair.strip_prefix("user="))
            {
                if !val.is_empty() {
                    return Some(val.to_string());
                }
            }
        }
    }

    None
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

    // ---- 2026-05-18 QC Sprint 2.3 — F-CRITICAL-014 ----

    fn view_with_body<'a>(
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

    /// GET with `Authorization: Basic …` to an auth path now
    /// counts toward the per-IP axis (default `hydra` shape).
    /// Pre-fix only POST counted; this is the §5.3 OWASP fix.
    #[test]
    fn basic_auth_get_counts_per_ip() {
        let d = BruteForceDetector::new(2, Duration::from_secs(60), 40);
        let (m, u, _, b) = make_req(http::Method::GET, "/login");
        let mut h = http::HeaderMap::new();
        // base64("alice:wrong") = YWxpY2U6d3Jvbmc=
        h.insert(
            http::header::AUTHORIZATION,
            "Basic YWxpY2U6d3Jvbmc=".parse().unwrap(),
        );
        for _ in 0..2 {
            assert!(d.inspect(&view(&m, &u, &h, &b, "11.0.0.1:443")).is_empty());
        }
        // Third request fires the per-IP axis.
        let signals = d.inspect(&view(&m, &u, &h, &b, "11.0.0.1:443"));
        assert!(signals.iter().any(|s| s.tag == "brute_force"));
    }

    /// PUT to a password-change auth path counts (POST/PUT/PATCH
    /// allowlist).
    #[test]
    fn put_to_auth_path_counts() {
        let d = BruteForceDetector::new(2, Duration::from_secs(60), 40);
        let (m, u, h, b) = make_req(http::Method::PUT, "/login");
        for _ in 0..2 {
            assert!(d.inspect(&view(&m, &u, &h, &b, "12.0.0.1:443")).is_empty());
        }
        let signals = d.inspect(&view(&m, &u, &h, &b, "12.0.0.1:443"));
        assert!(signals.iter().any(|s| s.tag == "brute_force"));
    }

    /// Per-user axis: 6 distinct IPs auth-attempt for the same
    /// username → fires `brute_force_user`. The classic
    /// password-spraying shape — one user, rotating IP.
    #[test]
    fn password_spraying_fires_per_user_axis() {
        let mut d = BruteForceDetector::new(100, Duration::from_secs(60), 40);
        d.user_threshold = 3; // tighter for the test
        let body = BodyPeek::new(
            br#"{"username":"alice","password":"x"}"#.to_vec(),
            None,
            false,
        );
        let (m, u, h, _) = make_req(http::Method::POST, "/login");

        // Three distinct IPs — under threshold.
        for octet in 1..=3 {
            let ip = format!("13.0.0.{octet}:443");
            d.inspect(&view_with_body(&m, &u, &h, &body, &ip));
        }
        // 4th distinct IP for same user → fires.
        let signals =
            d.inspect(&view_with_body(&m, &u, &h, &body, "13.0.0.4:443"));
        assert!(
            signals.iter().any(|s| s.tag == "brute_force_user"),
            "expected brute_force_user signal, got {signals:?}",
        );
    }

    /// Per-user axis ignores duplicate IPs — the SAME IP retrying
    /// the same username doesn't inflate the distinct-IP count.
    #[test]
    fn per_user_axis_dedupes_repeated_ip() {
        let mut d = BruteForceDetector::new(100, Duration::from_secs(60), 40);
        d.user_threshold = 2;
        let body = BodyPeek::new(
            b"username=carol&password=x".to_vec(),
            None,
            false,
        );
        let (m, u, h, _) = make_req(http::Method::POST, "/login");
        // 10 attempts from the same IP — distinct-IP count is 1.
        for _ in 0..10 {
            let s =
                d.inspect(&view_with_body(&m, &u, &h, &body, "14.0.0.1:443"));
            assert!(
                !s.iter().any(|sig| sig.tag == "brute_force_user"),
                "single-IP retry must not trip user axis",
            );
        }
    }

    /// AC-P1-c (2026-07-03) — spray-evasion fix. The per-user axis
    /// keyed on the raw wire string, so `Alice` / `alice` / `ALICE`
    /// counted as three separate users and a case-rotating sprayer
    /// never crossed the distinct-IP threshold. The KEY is now
    /// canonicalized (trim + ASCII-lowercase); the audit field keeps
    /// the raw submitted string (see the companion test below).
    #[test]
    fn spray_with_case_and_whitespace_variants_counts_as_one_user() {
        let mut d = BruteForceDetector::new(100, Duration::from_secs(60), 40);
        d.user_threshold = 3;
        let (m, u, h, _) = make_req(http::Method::POST, "/login");

        // Three case variants from three distinct IPs — same user,
        // still under threshold (3 not > 3).
        for (octet, name) in [(1, "Alice"), (2, "alice"), (3, "ALICE")] {
            let body = BodyPeek::new(
                format!(r#"{{"username":"{name}","password":"x"}}"#).into_bytes(),
                None,
                false,
            );
            let s = d.inspect(&view_with_body(&m, &u, &h, &body, &format!("16.0.0.{octet}:443")));
            assert!(
                !s.iter().any(|sig| sig.tag == "brute_force_user"),
                "under threshold at {octet} distinct IPs: {s:?}",
            );
        }
        // 4th distinct IP submits a whitespace variant via a form
        // body (form extraction preserves the padding) → 4 distinct
        // IPs for the canonical user → fires.
        let body = BodyPeek::new(b"username=alice &password=x".to_vec(), None, false);
        let signals =
            d.inspect(&view_with_body(&m, &u, &h, &body, "16.0.0.4:443"));
        assert!(
            signals.iter().any(|s| s.tag == "brute_force_user"),
            "case/whitespace variants must aggregate as ONE user: {signals:?}",
        );
    }

    /// AC-P1-c — canonicalize the KEY only: the audit signal still
    /// reports the raw submitted username so ops see what was sent
    /// on the wire (and the naive fix — canonicalizing inside
    /// `extract_username` — stays caught).
    #[test]
    fn signal_field_reports_raw_submitted_username() {
        let mut d = BruteForceDetector::new(100, Duration::from_secs(60), 40);
        d.user_threshold = 1;
        let (m, u, h, _) = make_req(http::Method::POST, "/login");
        let body_lower = BodyPeek::new(
            br#"{"username":"alice","password":"x"}"#.to_vec(),
            None,
            false,
        );
        let _ = d.inspect(&view_with_body(&m, &u, &h, &body_lower, "17.0.0.1:443"));
        // Second distinct IP crosses threshold (2 > 1) with the
        // MiXeD-case variant — the field must echo that raw form.
        let body_mixed = BodyPeek::new(
            br#"{"username":"AliCe","password":"x"}"#.to_vec(),
            None,
            false,
        );
        let signals =
            d.inspect(&view_with_body(&m, &u, &h, &body_mixed, "17.0.0.2:443"));
        let field = signals
            .iter()
            .find(|s| s.tag == "brute_force_user")
            .map(|s| s.field.clone());
        assert_eq!(
            field.as_deref(),
            Some("user:AliCe"),
            "audit field must keep the raw wire username",
        );
    }

    /// AC-P1-c — canonicalization must NOT merge genuinely distinct
    /// users: bob's attempts don't inherit alice's distinct-IP count.
    #[test]
    fn distinct_users_still_track_independently() {
        let mut d = BruteForceDetector::new(100, Duration::from_secs(60), 40);
        d.user_threshold = 2;
        let (m, u, h, _) = make_req(http::Method::POST, "/login");
        for octet in 1..=3 {
            let body = BodyPeek::new(
                br#"{"username":"alice","password":"x"}"#.to_vec(),
                None,
                false,
            );
            let _ = d.inspect(&view_with_body(&m, &u, &h, &body, &format!("18.0.0.{octet}:443")));
        }
        // bob from ONE fresh IP — nowhere near his own threshold.
        let body = BodyPeek::new(
            br#"{"username":"bob","password":"x"}"#.to_vec(),
            None,
            false,
        );
        let signals =
            d.inspect(&view_with_body(&m, &u, &h, &body, "18.0.0.9:443"));
        assert!(
            !signals.iter().any(|s| s.tag == "brute_force_user"),
            "bob must not inherit alice's distinct-IP count: {signals:?}",
        );
    }

    /// Per-user axis pulls username from JSON body.
    #[test]
    fn extract_username_from_json_body() {
        let body = BodyPeek::new(
            br#"{"username":"bob","password":"hunter2"}"#.to_vec(),
            None,
            false,
        );
        let (m, u, h, _) = make_req(http::Method::POST, "/login");
        let view = view_with_body(&m, &u, &h, &body, "15.0.0.1:443");
        assert_eq!(extract_username(&view).as_deref(), Some("bob"));
    }

    /// Per-user axis pulls username from form-urlencoded body.
    #[test]
    fn extract_username_from_form_body() {
        let body = BodyPeek::new(
            b"username=charlie&password=hunter2".to_vec(),
            None,
            false,
        );
        let (m, u, h, _) = make_req(http::Method::POST, "/login");
        let view = view_with_body(&m, &u, &h, &body, "15.0.0.2:443");
        assert_eq!(extract_username(&view).as_deref(), Some("charlie"));
    }

    /// Per-user axis pulls username from Basic-auth header. The
    /// header path wins over body if both present.
    #[test]
    fn extract_username_from_basic_auth() {
        let mut h = http::HeaderMap::new();
        // base64("dave:wrong") = ZGF2ZTp3cm9uZw==
        h.insert(
            http::header::AUTHORIZATION,
            "Basic ZGF2ZTp3cm9uZw==".parse().unwrap(),
        );
        let body = BodyPeek::empty();
        let (m, u, _, _) = make_req(http::Method::GET, "/login");
        let view = view_with_body(&m, &u, &h, &body, "15.0.0.3:443");
        assert_eq!(extract_username(&view).as_deref(), Some("dave"));
    }

    /// `extract_username` returns None when no recognisable
    /// username appears anywhere.
    #[test]
    fn extract_username_returns_none_when_absent() {
        let body = BodyPeek::new(b"nothing-useful-here".to_vec(), None, false);
        let (m, u, h, _) = make_req(http::Method::POST, "/login");
        let view = view_with_body(&m, &u, &h, &body, "15.0.0.4:443");
        assert_eq!(extract_username(&view), None);
    }
}
