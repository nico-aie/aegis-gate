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
}

impl ErrorLeakDetector {
    pub fn new() -> Self {
        Self { max_scan_bytes: DEFAULT_MAX_SCAN_BYTES }
    }

    pub fn with_cap(max_scan_bytes: usize) -> Self {
        Self { max_scan_bytes }
    }

    /// Scan a response for error-page information leaks. Returns one
    /// [`Signal`] per distinct [`LeakKind`] found (so audit attribution is
    /// specific), or empty when the gate rejects the response or nothing
    /// leaked. `content_type` is the raw header value (or `None`).
    pub fn scan(&self, _status: u16, _content_type: Option<&str>, _body: &[u8]) -> Vec<Signal> {
        // RED stub — real detection lands in the GREEN step.
        Vec::new()
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
