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

        signals
    }
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
}
