//! Cookie injection detector (WS report P2).
//!
//! 2026-06-12 — SQLi / NoSQLi payloads smuggled in a **session** cookie
//! value (`Cookie: sid=' WAITFOR DELAY '0:0:5'--`). The WebSocket attack
//! report flagged these because no detector scans cookie values: the
//! content detectors scan URI + body (gated on a scannable content-type),
//! and `jwt_inspection` only decodes JWT-shaped cookies.
//!
//! ## Why a dedicated, default-OFF class
//! Baseline sqli/nosql cookie scanning was REMOVED earlier (it false-
//! positived on adtech / telemetry cookies whose structured values
//! coincidentally match injection regexes — see `sqli.rs`). This detector
//! avoids that by (a) scoping to a small allowlist of **session** cookie
//! names (never `_ga`, `_fbp`, …), (b) using a tight, high-confidence
//! pattern set (a legit session token is opaque base64/hex/UUID, so a
//! quote / SQL keyword / `$`-operator is anomalous), and (c) defaulting
//! the whole `DetectorClass::CookieInjection` **off** so operators opt in
//! and review FP before relying on it.

use aegis_core::pipeline::RequestView;
use regex::Regex;
use std::sync::LazyLock;

use super::{scores, Detector, Signal};

/// Cookie names whose value is a session credential and should never
/// legitimately contain SQL/NoSQL metacharacters. Matched case-insensitively.
const SESSION_COOKIE_NAMES: &[&str] = &[
    "sid",
    "session",
    "sessionid",
    "session_id",
    "sess",
    "jsessionid",
    "phpsessid",
    "connect.sid",
    "auth",
    "auth_token",
    "authtoken",
    "token",
    "access_token",
    "accesstoken",
    "refresh_token",
    "csrf",
    "xsrf",
];

/// High-confidence SQLi / NoSQLi shapes. A session-cookie value is an
/// opaque token (base64/hex/UUID) — none of these appear in one
/// legitimately. Base64 chars (`+`, `/`, `=`, `-`, `_`) are deliberately
/// NOT triggers.
static COOKIE_INJECTION_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"'",                                  // single quote
        r"--",                                 // SQL line comment
        r"/\*",                                // SQL block comment
        r"(?i)\bunion\b.*\bselect\b",          // UNION … SELECT
        r"(?i)\bor\b\s+['\d]",                 // OR '1' / OR 1
        r"(?i)\bwaitfor\s+delay\b",            // time-based MSSQL
        r"(?i)\bsleep\s*\(",                   // time-based MySQL
        r"(?i)\bbenchmark\s*\(",               // time-based MySQL
        r"(?i)\$(?:ne|gt|lt|gte|lte|eq|where|regex|or|and|in|nin)\b", // Mongo ops
        r#"[\{\[]\s*['"]?\$"#,                 // {"$… / [$…
    ]
    .iter()
    .map(|p| Regex::new(p).expect("cookie-injection regex compiles"))
    .collect()
});

/// SQLi / NoSQLi in session-cookie values. Gated by the
/// `DetectorClass::CookieInjection` mask bit (default OFF).
pub struct CookieInjectionDetector;

impl Detector for CookieInjectionDetector {
    fn id(&self) -> &'static str {
        "cookie_injection"
    }

    fn inspect(&self, req: &RequestView<'_>) -> Vec<Signal> {
        let mut signals = Vec::new();

        let Some(cookie) = req.headers.get("cookie").and_then(|v| v.to_str().ok()) else {
            return signals;
        };

        for pair in cookie.split(';') {
            let Some((name, value)) = pair.trim().split_once('=') else {
                continue;
            };
            let name = name.trim();
            let value = value.trim();
            if !is_session_cookie(name) || value.is_empty() {
                continue;
            }
            if value_is_injection(value) {
                signals.push(Signal {
                    score: scores::cookie_injection::COOKIE_INJECTION,
                    tag: "cookie_injection".into(),
                    field: format!("cookie:{name}"),
                });
                // One signal per request — no amplification across cookies.
                break;
            }
        }

        signals
    }
}

fn is_session_cookie(name: &str) -> bool {
    SESSION_COOKIE_NAMES
        .iter()
        .any(|n| name.eq_ignore_ascii_case(n))
}

fn value_is_injection(value: &str) -> bool {
    COOKIE_INJECTION_PATTERNS.iter().any(|re| re.is_match(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::pipeline::BodyPeek;

    fn signals_for_cookie(header: &str) -> Vec<Signal> {
        let mut h = http::HeaderMap::new();
        h.insert("cookie", header.parse().unwrap());
        let m = http::Method::GET;
        let u: http::Uri = "/".parse().unwrap();
        let b = BodyPeek::empty();
        let req = RequestView {
            method: &m,
            uri: &u,
            version: http::Version::HTTP_11,
            headers: &h,
            peer: "127.0.0.1:1".parse().unwrap(),
            tls: None,
            body: &b,
        };
        CookieInjectionDetector.inspect(&req)
    }

    fn flags(header: &str) -> bool {
        signals_for_cookie(header).iter().any(|s| s.tag == "cookie_injection")
    }

    // ---- positives: SQLi/NoSQLi in a session cookie -----------------

    #[test]
    fn sqli_waitfor_in_sid() {
        assert!(flags("sid=' WAITFOR DELAY '0:0:5'--"));
    }

    #[test]
    fn sqli_or_1_eq_1() {
        assert!(flags("session=' OR '1'='1"));
    }

    #[test]
    fn sqli_union_select() {
        assert!(flags("token=1 UNION SELECT password FROM users"));
    }

    #[test]
    fn nosqli_where_operator() {
        assert!(flags(r#"auth={"$where":"this.x>0"}"#));
    }

    #[test]
    fn nosqli_ne_operator() {
        assert!(flags("access_token=$ne"));
    }

    #[test]
    fn flags_on_jsessionid() {
        assert!(flags("JSESSIONID='; DROP TABLE sessions--"));
    }

    #[test]
    fn score_is_high_tier_and_field_names_cookie() {
        let s = signals_for_cookie("sid=' OR 1=1--");
        let sig = s.iter().find(|s| s.tag == "cookie_injection").expect("signal");
        assert_eq!(sig.score, 50);
        assert_eq!(sig.field, "cookie:sid");
    }

    // ---- negatives: legit session cookies + non-session cookies ------

    #[test]
    fn opaque_session_token_is_clean() {
        // base64url / hex / UUID tokens contain none of the triggers.
        for c in [
            "sid=eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYSJ9.sig", // JWT-ish
            "session=dGhpcytpcy9hL2Jhc2U2NA==",              // base64 with +/=
            "token=a1b2c3d4e5f6a7b8",                        // hex
            "auth=550e8400-e29b-41d4-a716-446655440000",     // UUID
            "access_token=ya29.A0ARrdaM-abcDEF_123-456",      // OAuth-ish
        ] {
            assert!(!flags(c), "false positive on opaque token: {c}");
        }
    }

    #[test]
    fn non_session_cookie_is_ignored() {
        // adtech / telemetry cookies are NOT scanned even if odd.
        assert!(!flags("_ga=GA1.2.1234567890.1600000000"));
        assert!(!flags("_fbp=fb.1.1600000000.1234567890"));
        // even a quote in a non-session cookie is ignored (out of scope).
        assert!(!flags("preferences=theme'dark"));
    }

    #[test]
    fn no_cookie_header_is_clean() {
        let m = http::Method::GET;
        let u: http::Uri = "/".parse().unwrap();
        let h = http::HeaderMap::new();
        let b = BodyPeek::empty();
        let req = RequestView {
            method: &m, uri: &u, version: http::Version::HTTP_11,
            headers: &h, peer: "127.0.0.1:1".parse().unwrap(), tls: None, body: &b,
        };
        assert!(CookieInjectionDetector.inspect(&req).is_empty());
    }

    #[test]
    fn one_signal_per_request() {
        // two malicious session cookies → exactly one signal.
        let n = signals_for_cookie("sid=' OR 1=1--; token=' UNION SELECT 1--")
            .iter()
            .filter(|s| s.tag == "cookie_injection")
            .count();
        assert_eq!(n, 1);
    }

    #[test]
    fn value_is_injection_unit() {
        assert!(value_is_injection("' OR 1=1--"));
        assert!(value_is_injection(r#"{"$ne":null}"#));
        assert!(!value_is_injection("plainopaquetoken123"));
        assert!(!value_is_injection("base64+with/slashes=="));
    }
}
