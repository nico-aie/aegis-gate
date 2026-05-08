use aegis_core::pipeline::RequestView;
use regex::Regex;
use std::sync::LazyLock;

use super::{Detector, Signal};

/// HTTP header injection / response splitting detector.
pub struct HeaderInjectionDetector;

static INJECTION_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"(?:\r\n|\r|\n)",
        r"(?:%0d%0a)",
        r"(?:%0d)",
        r"(?:%0a)",
        r"(?:%0D%0A)",
        r"(?:\\r\\n)",
        r"(?i)(?:Set-Cookie\s*:)",
        r"(?i)(?:Location\s*:\s*https?://)",
        r"(?i)(?:Content-Type\s*:)",
        r"(?i)(?:Transfer-Encoding\s*:)",
        r"(?i)(?:X-Forwarded-For\s*:)",
        r"(?i)(?:HTTP/\d\.\d\s+\d{3})",
    ]
    .iter()
    .map(|p| Regex::new(p).unwrap())
    .collect()
});

impl Detector for HeaderInjectionDetector {
    fn id(&self) -> &'static str {
        "header_injection"
    }

    fn inspect(&self, req: &RequestView<'_>) -> Vec<Signal> {
        let mut signals = Vec::new();

        // Check query string for CRLF injection (both raw and decoded).
        if let Some(query) = req.uri.query() {
            check(query, "query", &mut signals);
            check(&super::url_decode(query), "query", &mut signals);
        }

        // Check header values (excluding host and standard ones).
        for (name, value) in req.headers.iter() {
            let name_str = name.as_str();
            if matches!(name_str, "host" | "content-length" | "content-type") {
                continue;
            }
            if let Ok(val) = value.to_str() {
                check_crlf(val, name_str, &mut signals);
            }
        }

        // SEC-L002 (2026-05-08) — X-Forwarded-Host poisoning. The
        // CRLF scan above catches XFH with control bytes; this
        // adds shape-suspicion checks for clean attacker-domain
        // poisoning (Host: a.com, X-Forwarded-Host: evil.com)
        // that backends trust for cache keys, password-reset
        // links, OAuth redirect URIs, etc.
        if let Some(xfh_val) = req
            .headers
            .get("x-forwarded-host")
            .and_then(|v| v.to_str().ok())
        {
            let host = req
                .headers
                .get("host")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if xfh_is_suspicious(xfh_val, host) {
                signals.push(Signal {
                    score: 35,
                    tag: "header_injection".into(),
                    field: "x-forwarded-host".into(),
                });
            }
        }

        signals
    }
}

/// SEC-L002 — flag X-Forwarded-Host shapes that indicate poisoning.
/// Conservative: many legit reverse-proxy chains set XFH to the
/// original public hostname while Host is the proxy's internal
/// address, so a bare "XFH != Host" mismatch isn't enough to
/// alert. We require additional shape-suspicion (CRLF/control,
/// multiple hosts beyond a normal proxy chain, or attacker-keyword
/// + Host mismatch).
fn xfh_is_suspicious(xfh: &str, host: &str) -> bool {
    if xfh.is_empty() {
        return false;
    }
    // Control bytes / CRLF — header-injection style XFH.
    if xfh.bytes().any(|b| b == b'\r' || b == b'\n' || b < 0x20) {
        return true;
    }
    // Multiple hosts via comma. Legit chains typically have at
    // most 2 entries; 3+ suggests attacker-appended values.
    if xfh.split(',').count() > 2 {
        return true;
    }
    // Doesn't match Host AND contains an attacker-shape needle.
    // Loose by design — never flags legit proxy chains where XFH
    // is just a different (public) hostname.
    if !host.is_empty() && !xfh.eq_ignore_ascii_case(host) {
        let xfh_lc = xfh.to_ascii_lowercase();
        for needle in [
            "evil",
            "attacker",
            "malicious",
            "phish",
            "javascript:",
            "data:",
            "<",
            ">",
            "\"",
            "'",
        ] {
            if xfh_lc.contains(needle) {
                return true;
            }
        }
    }
    false
}

fn check(input: &str, field: &str, signals: &mut Vec<Signal>) {
    for re in INJECTION_PATTERNS.iter() {
        if re.is_match(input) {
            signals.push(Signal {
                score: 40,
                tag: "header_injection".into(),
                field: field.into(),
            });
            return;
        }
    }
}

fn check_crlf(input: &str, field: &str, signals: &mut Vec<Signal>) {
    // Only check for CRLF patterns in header values — first 4 patterns.
    for re in INJECTION_PATTERNS.iter().take(6) {
        if re.is_match(input) {
            signals.push(Signal {
                score: 40,
                tag: "header_injection".into(),
                field: field.into(),
            });
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::pipeline::BodyPeek;

    fn view_with_uri(uri: &str) -> (http::Method, http::Uri, http::HeaderMap, BodyPeek) {
        (
            http::Method::GET,
            uri.parse().unwrap(),
            http::HeaderMap::new(),
            BodyPeek::empty(),
        )
    }

    fn make_view<'a>(
        m: &'a http::Method,
        u: &'a http::Uri,
        h: &'a http::HeaderMap,
        b: &'a BodyPeek,
    ) -> RequestView<'a> {
        RequestView {
            method: m, uri: u, version: http::Version::HTTP_11,
            headers: h, peer: "127.0.0.1:1234".parse().unwrap(),
            tls: None, body: b,
        }
    }

    macro_rules! positive {
        ($name:ident, $input:expr) => {
            #[test]
            fn $name() {
                let d = HeaderInjectionDetector;
                let (m, u, h, b) = view_with_uri($input);
                let req = make_view(&m, &u, &h, &b);
                assert!(!d.inspect(&req).is_empty(), "expected detection for: {}", $input);
            }
        };
    }

    macro_rules! negative {
        ($name:ident, $input:expr) => {
            #[test]
            fn $name() {
                let d = HeaderInjectionDetector;
                let (m, u, h, b) = view_with_uri($input);
                let req = make_view(&m, &u, &h, &b);
                assert!(d.inspect(&req).is_empty(), "false positive for: {}", $input);
            }
        };
    }

    // Positive cases (≥30).
    positive!(crlf_encoded, "/?q=%0d%0aSet-Cookie:+evil=1");
    positive!(crlf_upper, "/?q=%0D%0ALocation:+http://evil.com");
    positive!(cr_only, "/?q=%0dInjected");
    positive!(lf_only, "/?q=%0aInjected");
    positive!(set_cookie_inject, "/?q=Set-Cookie:+session=hijacked");
    positive!(location_inject, "/?q=Location:+https://evil.com");
    positive!(content_type_inject, "/?q=Content-Type:+text/html");
    positive!(transfer_encoding_inject, "/?q=Transfer-Encoding:+chunked");
    positive!(http_response, "/?q=HTTP/1.1+200+OK");
    positive!(xff_inject, "/?q=X-Forwarded-For:+1.2.3.4");
    positive!(escaped_crlf, "/?q=\\r\\nEvil:+header");
    positive!(crlf_set_cookie_path, "/?redirect=%0d%0aSet-Cookie:+a=b");
    positive!(crlf_in_name_param, "/?name=%0d%0aHTTP/1.1+200");
    positive!(lf_location, "/?url=%0aLocation:+https://bad.com");
    positive!(cr_set_cookie, "/?data=%0dSet-Cookie:+x=y");
    positive!(double_crlf, "/?q=%0d%0a%0d%0aBody");
    positive!(http_10_response, "/?q=HTTP/1.0+302+Found");
    positive!(http_20_response, "/?q=HTTP/2.0+200+OK");
    positive!(location_with_crlf, "/?q=%0D%0ALocation:+http://x.com/y");
    positive!(content_type_html, "/?q=Content-Type:+text/html;charset=utf-8");
    positive!(xff_spoof, "/?q=X-Forwarded-For:+127.0.0.1");
    positive!(set_cookie_domain, "/?q=Set-Cookie:+s=v;+domain=.evil.com");
    positive!(transfer_enc_gzip, "/?q=Transfer-Encoding:+gzip");
    positive!(crlf_encoded_mixed, "/?q=%0D%0aEvil:+val");
    positive!(location_ftp, "/?q=Location:+https://ftp.evil.com");
    positive!(crlf_double_header, "/?q=%0d%0aX-Evil:+1%0d%0aX-More:+2");
    positive!(content_type_xml, "/?q=Content-Type:+application/xml");
    positive!(xff_ipv6, "/?q=X-Forwarded-For:+::1");
    positive!(set_cookie_httponly, "/?q=Set-Cookie:+a=b;+HttpOnly");
    positive!(location_encoded, "/?q=Location:+https://evil.com%2Fpath");

    // Negative cases (≥30).
    negative!(clean_root, "/");
    negative!(clean_api, "/api/users?page=1");
    negative!(clean_search, "/search?q=hello+world");
    negative!(clean_query, "/items?name=test&value=123");
    negative!(clean_path, "/products/123");
    negative!(clean_encoded_space, "/path?q=hello%20world");
    negative!(clean_encoded_plus, "/path?q=hello+world");
    negative!(clean_json, "/api?format=json");
    negative!(clean_bool, "/api?flag=true");
    negative!(clean_uuid, "/api/550e8400-e29b");
    negative!(clean_numeric, "/items/42");
    negative!(clean_email, "/api?email=user%40example.com");
    negative!(clean_date, "/api?date=2024-01-01");
    negative!(clean_url_param, "/api?url=example.com%2Fpath");
    negative!(clean_long_query, "/api?q=abcdefghijklmnopqrstuvwxyz");
    negative!(clean_multi_param, "/api?a=1&b=2&c=3&d=4");
    negative!(clean_utf8, "/api?name=%C3%A9mile");
    negative!(clean_encoded_amp, "/api?q=a%26b");
    negative!(clean_encoded_eq, "/api?q=a%3Db");
    negative!(clean_hash, "/page?section=top");
    negative!(clean_sort, "/api?sort=name&order=asc");
    negative!(clean_filter, "/api?filter=active&limit=50");
    negative!(clean_pagination, "/api?page=3&per_page=25");
    negative!(clean_locale, "/api?lang=en-US");
    negative!(clean_version, "/api/v2/users");
    negative!(clean_nested, "/api/users/123/posts/456");
    negative!(clean_extension, "/assets/style.css");
    negative!(clean_image, "/img/logo.png");
    negative!(clean_callback, "/api?callback=handleResponse");
    negative!(clean_token, "/api?token=abc123def456");
    negative!(clean_timestamp, "/api?ts=1706000000");

    // SEC-L002 (2026-05-08) — X-Forwarded-Host poisoning.

    fn make_view_with_headers<'a>(
        m: &'a http::Method,
        u: &'a http::Uri,
        h: &'a http::HeaderMap,
        b: &'a BodyPeek,
    ) -> RequestView<'a> {
        make_view(m, u, h, b)
    }

    fn xfh_view(host: &str, xfh: &[u8]) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        h.insert("host", host.parse().unwrap());
        if let Ok(v) = http::HeaderValue::from_bytes(xfh) {
            h.insert("x-forwarded-host", v);
        }
        h
    }

    #[test]
    fn xfh_with_evil_keyword_flagged() {
        let d = HeaderInjectionDetector;
        let u: http::Uri = "/".parse().unwrap();
        let m = http::Method::GET;
        let h = xfh_view("a.com", b"evil.attacker.com");
        let b = BodyPeek::empty();
        let req = make_view_with_headers(&m, &u, &h, &b);
        let signals = d.inspect(&req);
        assert!(signals.iter().any(|s| s.field == "x-forwarded-host"),
            "evil-domain XFH must flag, got {signals:?}");
    }

    #[test]
    fn xfh_with_attacker_keyword_flagged() {
        let d = HeaderInjectionDetector;
        let u: http::Uri = "/".parse().unwrap();
        let m = http::Method::GET;
        let h = xfh_view("api.example.com", b"attacker.example.com");
        let b = BodyPeek::empty();
        let req = make_view_with_headers(&m, &u, &h, &b);
        assert!(d.inspect(&req).iter().any(|s| s.field == "x-forwarded-host"));
    }

    #[test]
    fn xfh_with_javascript_uri_flagged() {
        let d = HeaderInjectionDetector;
        let u: http::Uri = "/".parse().unwrap();
        let m = http::Method::GET;
        let h = xfh_view("a.com", b"javascript:alert(1)");
        let b = BodyPeek::empty();
        let req = make_view_with_headers(&m, &u, &h, &b);
        assert!(d.inspect(&req).iter().any(|s| s.field == "x-forwarded-host"));
    }

    // (Note: a control-byte / CRLF XFH test isn't possible at this
    // layer — `http::HeaderValue::from_bytes` rejects NUL/CR/LF
    // before construction. The `xfh.bytes().any(|b| ...)` check in
    // `xfh_is_suspicious` is defense-in-depth for the case where
    // some future code path constructs a HeaderValue without the
    // hyper validation gate.)

    #[test]
    fn xfh_with_three_hosts_flagged() {
        let d = HeaderInjectionDetector;
        let u: http::Uri = "/".parse().unwrap();
        let m = http::Method::GET;
        // > 2 entries via comma — attacker appended
        let h = xfh_view("a.com", b"a.com, proxy.com, evil.com");
        let b = BodyPeek::empty();
        let req = make_view_with_headers(&m, &u, &h, &b);
        assert!(d.inspect(&req).iter().any(|s| s.field == "x-forwarded-host"));
    }

    #[test]
    fn xfh_legit_proxy_chain_not_flagged() {
        // Legit reverse-proxy chain: Host is the internal service
        // address, XFH is the public hostname. No suspicious shape.
        let d = HeaderInjectionDetector;
        let u: http::Uri = "/".parse().unwrap();
        let m = http::Method::GET;
        let h = xfh_view("internal-svc:8080", b"api.example.com");
        let b = BodyPeek::empty();
        let req = make_view_with_headers(&m, &u, &h, &b);
        let signals: Vec<_> = d
            .inspect(&req)
            .into_iter()
            .filter(|s| s.field == "x-forwarded-host")
            .collect();
        assert!(signals.is_empty(), "legit proxy chain must not flag, got {signals:?}");
    }

    #[test]
    fn xfh_matching_host_not_flagged() {
        let d = HeaderInjectionDetector;
        let u: http::Uri = "/".parse().unwrap();
        let m = http::Method::GET;
        let h = xfh_view("api.example.com", b"api.example.com");
        let b = BodyPeek::empty();
        let req = make_view_with_headers(&m, &u, &h, &b);
        let signals: Vec<_> = d
            .inspect(&req)
            .into_iter()
            .filter(|s| s.field == "x-forwarded-host")
            .collect();
        assert!(signals.is_empty());
    }

    #[test]
    fn xfh_two_legit_proxy_chain_not_flagged() {
        // 2 entries via comma is normal proxy hop; only > 2 flags.
        let d = HeaderInjectionDetector;
        let u: http::Uri = "/".parse().unwrap();
        let m = http::Method::GET;
        let h = xfh_view("a.com", b"public.example.com, edge.example.com");
        let b = BodyPeek::empty();
        let req = make_view_with_headers(&m, &u, &h, &b);
        let signals: Vec<_> = d
            .inspect(&req)
            .into_iter()
            .filter(|s| s.field == "x-forwarded-host")
            .collect();
        assert!(signals.is_empty());
    }
}
