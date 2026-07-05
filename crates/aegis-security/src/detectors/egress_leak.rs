//! EG-2 T4 (2026-07-05) — response-path **error-leak** detector.
//!
//! The observability twin of [`crate::response_filter::scrub_stack_traces`]
//! / [`crate::response_filter::mask_internal_ips`]: instead of silently
//! rewriting a leaked stack trace / framework debug banner / internal IP on
//! an error response, this **counts + attributes** the leak so an operator
//! can see when the origin is spilling internals — the cheap, high-value
//! response-path signal from the EG-1 design (§2 T4, §4 detector #1).
//!
//! ## Scope (hard rules — design §4)
//!
//! - **Server errors only.** Runs on `status >= 500`; a debug/stack-trace
//!   page is an error-handler artifact, and gating on 5xx keeps the scan off
//!   the 200-heavy hot path entirely.
//! - **Structured-text bodies only.** Content-type must be `text/html`,
//!   `application/json` (or `*+json`), or `text/*`. Opaque/binary error
//!   bodies are skipped (same posture as the request-side body gate).
//! - **Size-capped.** Only the first `max_scan_bytes` of the body are
//!   scanned, so a huge error stream can't blow the perf budget.
//! - **Log/score only.** The detector never blocks — it emits a [`Signal`]
//!   the caller turns into a Detection-class audit row + a per-IP risk
//!   delta. Rewriting/redaction stays the `response_filter` path's job; this
//!   detector must observe **before** that rewrite (design §4 "observe-
//!   before-redact") or it would only ever see `[REDACTED]`.
//! - **Default OFF** (config toggle `detectors.egress_error_leak`), like
//!   `enumeration` / `behavior_analyzer`, until FP-tuned.
//!
//! Stateless: the leak signal is per-response, so there's no per-IP map to
//! bound (unlike `enumeration` / T5 egress-volume).

use super::Signal;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

/// Fleet cardinality bound for the pending-risk bridge map (mirrors
/// `enumeration` / `behavior_signals`). At the ceiling a new IP evicts an
/// arbitrary existing entry rather than growing.
const DEFAULT_MAX_TRACKED: usize = 100_000;

/// Score emitted per error-leak hit — an accumulation signal (stacks toward
/// a cumulative block) rather than a single-hit blocker, matching the
/// `enumeration` posture.
pub const SCORE: u32 = 30;

/// Default body-scan cap (bytes). A 5xx error page that leaks a stack trace
/// puts it near the top of the body, so the first 64 KiB is ample and bounds
/// the regex cost.
pub const DEFAULT_MAX_SCAN_BYTES: usize = 64 * 1024;

/// What leaked, for the audit `field` — high-signal, low-cardinality.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeakKind {
    /// Language/runtime stack trace (reuses the `response_filter` patterns).
    StackTrace,
    /// A framework debug/exception banner (Flask/Werkzeug, Rails, ASP.NET…).
    DebugBanner,
    /// An RFC-1918 / loopback / link-local address in the error body.
    InternalIp,
}

impl LeakKind {
    fn tag(self) -> &'static str {
        match self {
            LeakKind::StackTrace => "stack_trace",
            LeakKind::DebugBanner => "debug_banner",
            LeakKind::InternalIp => "internal_ip",
        }
    }
}

/// Framework debug/exception banners that stack-trace regexes don't cover —
/// the "your app is running in debug mode" tells. Deliberately multi-word,
/// low benign-collision phrases so a normal 5xx JSON error message
/// (`{"error":"internal error"}`) never trips them.
const DEBUG_BANNERS: &[&str] = &[
    "Whoops, looks like something went wrong",   // Laravel / Symfony
    "Werkzeug Debugger",                          // Flask
    "Server Error in '/' Application",            // ASP.NET yellow-screen
    "Exception Details:",                          // ASP.NET
    "ActionController::",                          // Rails
    "better_errors",                               // Rails better_errors
    "org.springframework",                         // Spring stacktrace body
    "nested exception is",                         // Spring
    "Fatal error:",                                // PHP
    "Warning: require(",                           // PHP include leak
    "DEBUG = True",                                // Django settings echo
    "You're seeing this error because you have",   // Django debug page
];

/// EG-2 T4 detector. Holds only the scan cap; the on/off decision is the
/// `Option<Arc<…>>` presence on `ProxyContext` (like `enumeration`).
pub struct ErrorLeakDetector {
    max_scan_bytes: usize,
    /// Per-IP risk delta accumulated on the response side, awaiting the
    /// data-plane's outcome hook to drain it into the `RiskTracker` (which
    /// the response-body site doesn't hold). Bounded at `max_tracked`.
    /// Mirrors `behavior_analyzer.observe_outcome`: record on the response,
    /// fold into risk where `risk` is in scope.
    pending: Mutex<HashMap<IpAddr, u32>>,
    max_tracked: usize,
}

impl ErrorLeakDetector {
    pub fn new() -> Self {
        Self {
            max_scan_bytes: DEFAULT_MAX_SCAN_BYTES,
            pending: Mutex::new(HashMap::new()),
            max_tracked: DEFAULT_MAX_TRACKED,
        }
    }

    pub fn with_cap(max_scan_bytes: usize) -> Self {
        Self { max_scan_bytes, ..Self::new() }
    }

    /// Scan a response for error-page information leaks. Returns one
    /// [`Signal`] per distinct [`LeakKind`] found (so audit attribution is
    /// specific), or empty when the gate rejects the response or nothing
    /// leaked. `content_type` is the raw header value (or `None`).
    pub fn scan(&self, status: u16, content_type: Option<&str>, body: &[u8]) -> Vec<Signal> {
        if !is_server_error(status) {
            return Vec::new();
        }
        if !content_type.is_some_and(is_scannable_error_ct) {
            return Vec::new();
        }
        // Bound the scan window, then decode lossily just once.
        let window = &body[..body.len().min(self.max_scan_bytes)];
        let text = String::from_utf8_lossy(window);

        let mut signals = Vec::new();
        let mut push = |kind: LeakKind| {
            signals.push(Signal {
                score: SCORE,
                tag: "egress_error_leak".into(),
                field: format!("kind:{},status:{}", kind.tag(), status),
            });
        };

        if crate::response_filter::has_stack_trace(&text) {
            push(LeakKind::StackTrace);
        }
        if has_debug_banner(&text) {
            push(LeakKind::DebugBanner);
        }
        if crate::response_filter::has_internal_ip(&text) {
            push(LeakKind::InternalIp);
        }
        signals
    }

    /// Response-side entry point: [`scan`](Self::scan) the response and, on
    /// any hit, accumulate the summed score into the per-IP pending map for
    /// the outcome hook to fold into risk. Returns the signals so the caller
    /// emits one Detection-class audit row per leak. No allocation / lock on
    /// the clean path (empty signals → early return before touching the map).
    pub fn observe(
        &self,
        ip: IpAddr,
        status: u16,
        content_type: Option<&str>,
        body: &[u8],
    ) -> Vec<Signal> {
        let signals = self.scan(status, content_type, body);
        if signals.is_empty() {
            return signals;
        }
        let delta: u32 = signals.iter().map(|s| s.score).sum();
        let mut map = self.pending.lock().unwrap();
        // Fleet bound: evict an arbitrary entry before admitting a new IP.
        if !map.contains_key(&ip) && map.len() >= self.max_tracked {
            if let Some(k) = map.keys().next().copied() {
                map.remove(&k);
            }
        }
        let e = map.entry(ip).or_insert(0);
        *e = e.saturating_add(delta);
        signals
    }

    /// Take and clear the pending risk delta for `ip` (0 when none). Called
    /// from the data-plane outcome hook where the `RiskTracker` is in scope.
    pub fn drain_risk_delta(&self, ip: IpAddr) -> u32 {
        self.pending.lock().unwrap().remove(&ip).unwrap_or(0)
    }

    /// Drop all pending state (wired into the `reset_state` path).
    pub fn clear(&self) {
        self.pending.lock().unwrap().clear();
    }
}

impl Default for ErrorLeakDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// 5xx — the class where debug/stack-trace pages appear. A 4xx error page is
/// a client mistake (404/403) and rarely carries a server stack trace; 5xx is
/// where the origin's unhandled-exception handler leaks internals.
fn is_server_error(status: u16) -> bool {
    (500..600).contains(&status)
}

/// Content-type gate: only structured text the origin renders as a page /
/// JSON error. Drops any `; charset=…` param and normalises case.
fn is_scannable_error_ct(ct: &str) -> bool {
    let ct = ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    ct.starts_with("text/")
        || ct == "application/json"
        || ct.ends_with("+json")
        || ct == "application/xml"
        || ct.ends_with("+xml")
}

fn has_debug_banner(text: &str) -> bool {
    DEBUG_BANNERS.iter().any(|b| text.contains(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HTML: &str = "text/html; charset=utf-8";
    const JSON: &str = "application/json";

    fn tags(sigs: &[Signal]) -> Vec<String> {
        sigs.iter().map(|s| s.field.clone()).collect()
    }

    #[test]
    fn python_traceback_on_500_html_scores() {
        let d = ErrorLeakDetector::new();
        let body = b"<html><body>Traceback (most recent call last)\n  File \"/app/views.py\", line 42\n</body></html>";
        let sigs = d.scan(500, Some(HTML), body);
        assert!(
            sigs.iter().any(|s| s.tag == "egress_error_leak" && s.field.contains("stack_trace")),
            "a Python traceback on a 500 HTML response must score: {:?}",
            tags(&sigs),
        );
        assert_eq!(sigs[0].score, SCORE);
    }

    #[test]
    fn jvm_stack_trace_on_502_scores() {
        let d = ErrorLeakDetector::new();
        let body = b"    at com.example.App.main(App.java:25)\n    at java.base/Thread.run(Thread.java:833)";
        let sigs = d.scan(502, Some(HTML), body);
        assert!(sigs.iter().any(|s| s.field.contains("stack_trace")));
    }

    #[test]
    fn flask_debug_banner_scores() {
        let d = ErrorLeakDetector::new();
        let body = b"<title>Werkzeug Debugger</title><div>...</div>";
        let sigs = d.scan(500, Some(HTML), body);
        assert!(
            sigs.iter().any(|s| s.field.contains("debug_banner")),
            "a Flask/Werkzeug debug page must score: {:?}",
            tags(&sigs),
        );
    }

    #[test]
    fn internal_ip_leak_on_500_json_scores() {
        let d = ErrorLeakDetector::new();
        let body = br#"{"error":"upstream connect to 10.0.3.14 failed"}"#;
        let sigs = d.scan(500, Some(JSON), body);
        assert!(
            sigs.iter().any(|s| s.field.contains("internal_ip")),
            "an internal IP in a 500 JSON body must score: {:?}",
            tags(&sigs),
        );
    }

    #[test]
    fn multiple_leaks_emit_distinct_signals() {
        // A debug page with both a stack trace AND an internal IP → two
        // distinct signals so audit attribution is specific.
        let d = ErrorLeakDetector::new();
        let body = b"Traceback (most recent call last)\n  File \"/srv/a.py\", line 9\nconnect 192.168.1.5";
        let sigs = d.scan(500, Some(HTML), body);
        assert!(sigs.iter().any(|s| s.field.contains("stack_trace")));
        assert!(sigs.iter().any(|s| s.field.contains("internal_ip")));
        assert_eq!(sigs.len(), 2, "one signal per kind: {:?}", tags(&sigs));
    }

    // ---- gates ----

    #[test]
    fn clean_200_response_never_scanned() {
        // The hot path: a normal 200 with an internal-looking string must
        // never be scanned (status gate rejects before any regex runs).
        let d = ErrorLeakDetector::new();
        let body = b"ok connecting to 10.0.0.1";
        assert!(d.scan(200, Some(JSON), body).is_empty());
    }

    #[test]
    fn client_error_4xx_not_scanned() {
        // 4xx is a client mistake, not a server leak surface.
        let d = ErrorLeakDetector::new();
        let body = b"Traceback (most recent call last)\n  File \"/x.py\", line 1";
        assert!(d.scan(404, Some(HTML), body).is_empty());
    }

    #[test]
    fn binary_content_type_not_scanned() {
        let d = ErrorLeakDetector::new();
        let body = b"Traceback (most recent call last)\n  File \"/x.py\", line 1";
        assert!(d.scan(500, Some("application/octet-stream"), body).is_empty());
        assert!(d.scan(500, Some("image/png"), body).is_empty());
    }

    #[test]
    fn missing_content_type_not_scanned() {
        let d = ErrorLeakDetector::new();
        let body = b"Traceback (most recent call last)\n  File \"/x.py\", line 1";
        assert!(d.scan(500, None, body).is_empty());
    }

    #[test]
    fn clean_500_error_page_does_not_score() {
        // The FP guard: a normal JSON 500 that leaks nothing must stay silent.
        let d = ErrorLeakDetector::new();
        let body = br#"{"error":"internal server error","request_id":"abc123"}"#;
        assert!(
            d.scan(500, Some(JSON), body).is_empty(),
            "a clean 500 error body must not score",
        );
    }

    // ---- observe / drain risk bridge ----

    fn ip(s: &str) -> std::net::IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn observe_accumulates_pending_risk_and_drains_once() {
        let d = ErrorLeakDetector::new();
        let body = b"Traceback (most recent call last)\n  File \"/a.py\", line 1";
        let sigs = d.observe(ip("203.0.113.7"), 500, Some(HTML), body);
        assert!(!sigs.is_empty(), "observe returns signals for the audit row");
        // The pending delta equals the summed signal score.
        let delta = d.drain_risk_delta(ip("203.0.113.7"));
        assert_eq!(delta, sigs.iter().map(|s| s.score).sum::<u32>());
        // Draining is one-shot — a second drain yields nothing.
        assert_eq!(d.drain_risk_delta(ip("203.0.113.7")), 0);
    }

    #[test]
    fn observe_on_clean_response_records_nothing() {
        let d = ErrorLeakDetector::new();
        let body = br#"{"error":"internal server error"}"#;
        assert!(d.observe(ip("203.0.113.8"), 500, Some(JSON), body).is_empty());
        assert_eq!(d.drain_risk_delta(ip("203.0.113.8")), 0, "no leak → no pending risk");
    }

    #[test]
    fn drain_for_unknown_ip_is_zero() {
        let d = ErrorLeakDetector::new();
        assert_eq!(d.drain_risk_delta(ip("203.0.113.9")), 0);
    }

    #[test]
    fn pending_map_is_bounded() {
        let d = ErrorLeakDetector { max_tracked: 3, ..ErrorLeakDetector::new() };
        let body = b"Traceback (most recent call last)\n  File \"/a.py\", line 1";
        for octet in 1..=50u8 {
            d.observe(ip(&format!("203.0.113.{octet}")), 500, Some(HTML), body);
        }
        assert!(
            d.pending.lock().unwrap().len() <= 3,
            "pending map must stay within max_tracked",
        );
    }

    #[test]
    fn scan_is_capped_at_max_bytes() {
        // A leak PAST the cap must not be seen — proves the size bound holds.
        let d = ErrorLeakDetector::with_cap(32);
        let mut body = vec![b' '; 64];
        body.extend_from_slice(b"Traceback (most recent call last)\n  File \"/x.py\", line 1");
        assert!(
            d.scan(500, Some(HTML), &body).is_empty(),
            "a leak beyond max_scan_bytes must not be scanned",
        );
        // ...but the same leak within the cap is caught.
        let d2 = ErrorLeakDetector::with_cap(4096);
        assert!(!d2.scan(500, Some(HTML), &body).is_empty());
    }
}
