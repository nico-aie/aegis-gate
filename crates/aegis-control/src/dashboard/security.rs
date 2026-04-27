//! Security-header set attached to every `/dashboard/**` response
//! (D-M1-T1.5).
//!
//! Single source of truth: every transport (today: aegis-proxy's
//! admin_router) imports [`SECURITY_HEADERS`] and applies the same
//! list. Spec lives in `docs/dashboard-enterprise/security.md`
//! §"Headers (full set on dashboard responses)".

#![allow(dead_code)]

/// Content Security Policy spelled out as a single string so the
/// header value is identical to the way operators paste it into
/// other tools.
///
/// Mirrors `docs/dashboard-enterprise/security.md` §"Content
/// Security Policy" verbatim. `'unsafe-inline'` for styles is the
/// Chart.js requirement documented there; everything else is tight.
pub const CSP: &str = concat!(
    "default-src 'self'; ",
    "script-src 'self'; ",
    "style-src 'self' 'unsafe-inline'; ",
    "img-src 'self' data:; ",
    "connect-src 'self'; ",
    "font-src 'self'; ",
    "object-src 'none'; ",
    "base-uri 'self'; ",
    "form-action 'self'; ",
    "frame-ancestors 'none'; ",
    "report-uri /api/csp/report",
);

/// Permissions-Policy spelled out per
/// `docs/dashboard-enterprise/security.md` §"Headers (full set …)".
pub const PERMISSIONS_POLICY: &str = "accelerometer=(), camera=(), \
    geolocation=(), gyroscope=(), magnetometer=(), microphone=(), \
    payment=(), usb=()";

/// Strict-Transport-Security — 2 years, includeSubDomains, preload.
/// Same value as `Cargo.toml` ↔ deploy templates.
pub const HSTS: &str = "max-age=63072000; includeSubDomains; preload";

/// The full set of security headers to attach to every dashboard
/// response. Order is significant only for diffing: applying the
/// headers in this order keeps any audit comparison stable.
pub const SECURITY_HEADERS: &[(&str, &str)] = &[
    ("Content-Security-Policy", CSP),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Permissions-Policy", PERMISSIONS_POLICY),
    ("Strict-Transport-Security", HSTS),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Embedder-Policy", "require-corp"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_set_size_matches_spec() {
        // 9 headers per docs/dashboard-enterprise/security.md.
        assert_eq!(SECURITY_HEADERS.len(), 9);
    }

    #[test]
    fn every_documented_header_is_present() {
        for name in [
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy",
            "Permissions-Policy",
            "Strict-Transport-Security",
            "Cross-Origin-Opener-Policy",
            "Cross-Origin-Embedder-Policy",
            "Cross-Origin-Resource-Policy",
        ] {
            assert!(
                SECURITY_HEADERS.iter().any(|(n, _)| *n == name),
                "missing security header {name}"
            );
        }
    }

    #[test]
    fn no_duplicate_header_names() {
        // Duplicates would shadow earlier values silently when applied.
        let mut seen: Vec<&str> = SECURITY_HEADERS.iter().map(|(n, _)| *n).collect();
        seen.sort_unstable();
        let len = seen.len();
        seen.dedup();
        assert_eq!(seen.len(), len, "duplicate security header name");
    }

    #[test]
    fn csp_locks_default_and_disables_framing() {
        assert!(CSP.contains("default-src 'self'"));
        assert!(CSP.contains("frame-ancestors 'none'"));
        assert!(CSP.contains("object-src 'none'"));
        // No CDN exception sneaks in.
        assert!(
            !CSP.contains("'unsafe-eval'"),
            "CSP must never permit 'unsafe-eval'"
        );
        // 'unsafe-inline' is a Chart.js requirement *only* for styles;
        // it must not leak into script-src.
        assert!(
            !CSP.contains("script-src 'self' 'unsafe-inline'"),
            "CSP must not allow inline scripts"
        );
    }

    #[test]
    fn nosniff_and_deny_match_spec() {
        let map: std::collections::HashMap<&str, &str> =
            SECURITY_HEADERS.iter().copied().collect();
        assert_eq!(map["X-Content-Type-Options"], "nosniff");
        assert_eq!(map["X-Frame-Options"], "DENY");
        assert_eq!(map["Referrer-Policy"], "no-referrer");
    }

    #[test]
    fn hsts_two_years_with_preload() {
        let map: std::collections::HashMap<&str, &str> =
            SECURITY_HEADERS.iter().copied().collect();
        let hsts = map["Strict-Transport-Security"];
        assert!(hsts.contains("max-age=63072000"), "expected 2 years");
        assert!(hsts.contains("includeSubDomains"));
        assert!(hsts.contains("preload"));
    }

    #[test]
    fn cross_origin_isolation_is_enabled() {
        let map: std::collections::HashMap<&str, &str> =
            SECURITY_HEADERS.iter().copied().collect();
        assert_eq!(map["Cross-Origin-Opener-Policy"], "same-origin");
        assert_eq!(map["Cross-Origin-Embedder-Policy"], "require-corp");
        assert_eq!(map["Cross-Origin-Resource-Policy"], "same-origin");
    }

    #[test]
    fn permissions_policy_disables_high_risk_apis() {
        let map: std::collections::HashMap<&str, &str> =
            SECURITY_HEADERS.iter().copied().collect();
        let pp = map["Permissions-Policy"];
        for api in [
            "accelerometer", "camera", "geolocation", "gyroscope",
            "magnetometer", "microphone", "payment", "usb",
        ] {
            assert!(
                pp.contains(&format!("{api}=()")),
                "Permissions-Policy missing disabled directive for {api}"
            );
        }
    }

    #[test]
    fn header_names_use_canonical_case() {
        // HTTP headers are case-insensitive, but operators / audit
        // tooling compare strings. Canonical Title-Case keeps logs
        // diff-friendly.
        for (name, _) in SECURITY_HEADERS {
            let first = name.chars().next().expect("non-empty header name");
            assert!(
                first.is_ascii_uppercase(),
                "header {name:?} should start uppercase"
            );
        }
    }
}
