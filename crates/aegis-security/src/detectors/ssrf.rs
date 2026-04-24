use aegis_core::pipeline::RequestView;
use regex::Regex;
use std::sync::LazyLock;

use super::{Detector, Signal};

/// SSRF detector.
pub struct SsrfDetector;

static SSRF_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"(?i)(?:https?://(?:127\.0\.0\.1|localhost))",
        r"(?i)(?:https?://0\.0\.0\.0)",
        r"(?i)(?:https?://\[::1?\])",
        r"(?i)(?:https?://169\.254\.169\.254)",
        r"(?i)(?:https?://metadata\.google\.internal)",
        r"(?i)(?:https?://100\.100\.100\.200)",
        r"(?i)(?:https?://10\.\d{1,3}\.\d{1,3}\.\d{1,3})",
        r"(?i)(?:https?://172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})",
        r"(?i)(?:https?://192\.168\.\d{1,3}\.\d{1,3})",
        r"(?i)(?:file://)",
        r"(?i)(?:gopher://)",
        r"(?i)(?:dict://)",
        r"(?i)(?:ftp://(?:127|10|192\.168|172\.(?:1[6-9]|2\d|3[01])))",
        r"(?i)(?:https?://0x[0-9a-f]+)",
        r"(?i)(?:https?://\d{8,10})",
        r"(?i)(?:https?://0[0-7]+\.)",
    ]
    .iter()
    .map(|p| Regex::new(p).unwrap())
    .collect()
});

impl Detector for SsrfDetector {
    fn id(&self) -> &'static str {
        "ssrf"
    }

    fn inspect(&self, req: &RequestView<'_>) -> Vec<Signal> {
        let mut signals = Vec::new();

        // Check query params for URLs (URL-decoded).
        if let Some(query) = req.uri.query() {
            check_ssrf(&super::url_decode(query), "query", &mut signals);
        }

        let uri = super::url_decode(&req.uri.to_string());
        check_ssrf(&uri, "uri", &mut signals);

        let body = std::str::from_utf8(req.body.peek(8192)).unwrap_or("");
        if !body.is_empty() {
            check_ssrf(&super::url_decode(body), "body", &mut signals);
        }

        for name in &["referer", "x-original-url", "x-rewrite-url"] {
            if let Some(val) = req.headers.get(*name).and_then(|v| v.to_str().ok()) {
                check_ssrf(val, name, &mut signals);
            }
        }

        signals
    }
}

fn check_ssrf(input: &str, field: &str, signals: &mut Vec<Signal>) {
    for re in SSRF_PATTERNS.iter() {
        if re.is_match(input) {
            signals.push(Signal {
                score: 50,
                tag: "ssrf".into(),
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
                let d = SsrfDetector;
                let (m, u, h, b) = view_with_uri($input);
                let req = make_view(&m, &u, &h, &b);
                assert!(!d.inspect(&req).is_empty(), "expected SSRF for: {}", $input);
            }
        };
    }

    macro_rules! negative {
        ($name:ident, $input:expr) => {
            #[test]
            fn $name() {
                let d = SsrfDetector;
                let (m, u, h, b) = view_with_uri($input);
                let req = make_view(&m, &u, &h, &b);
                assert!(d.inspect(&req).is_empty(), "false positive for: {}", $input);
            }
        };
    }

    positive!(ssrf_localhost, "/proxy?url=http://localhost/admin");
    positive!(ssrf_127, "/proxy?url=http://127.0.0.1/secret");
    positive!(ssrf_metadata, "/proxy?url=http://169.254.169.254/latest/meta-data/");
    positive!(ssrf_google_meta, "/proxy?url=http://metadata.google.internal/");
    positive!(ssrf_ipv6_loop, "/proxy?url=http://[::1]/");
    positive!(ssrf_10_net, "/proxy?url=http://10.0.0.1/");
    positive!(ssrf_172, "/proxy?url=http://172.16.0.1/");
    positive!(ssrf_192, "/proxy?url=http://192.168.1.1/");
    positive!(ssrf_file, "/proxy?url=file:///etc/passwd");
    positive!(ssrf_gopher, "/proxy?url=gopher://evil/");
    positive!(ssrf_dict, "/proxy?url=dict://evil/");
    positive!(ssrf_zero, "/proxy?url=http://0.0.0.0/");
    positive!(ssrf_hex_ip, "/proxy?url=http://0x7f000001/");
    positive!(ssrf_decimal_ip, "/proxy?url=http://2130706433/");
    positive!(ssrf_octal, "/proxy?url=http://0177.0.0.1/");
    positive!(ssrf_https_localhost, "/proxy?url=https://localhost/");
    positive!(ssrf_https_127, "/proxy?url=https://127.0.0.1:8080/");
    positive!(ssrf_alibaba, "/proxy?url=http://100.100.100.200/");
    positive!(ssrf_10_deep, "/proxy?url=http://10.255.255.255/");
    positive!(ssrf_172_31, "/proxy?url=http://172.31.255.255/");
    positive!(ssrf_192_168, "/proxy?url=http://192.168.255.255/");
    positive!(ssrf_ftp_internal, "/proxy?url=ftp://10.0.0.1/");
    positive!(ssrf_ipv6_bracket, "/proxy?url=http://[::]/");
    positive!(ssrf_localhost_port, "/proxy?url=http://localhost:9200/");
    positive!(ssrf_file_win, "/proxy?url=file:///c:/windows/win.ini");
    positive!(ssrf_127_port, "/proxy?url=http://127.0.0.1:3306/");
    positive!(ssrf_meta_path, "/proxy?url=http://169.254.169.254/latest/api/token");
    positive!(ssrf_172_20, "/proxy?url=http://172.20.0.1/internal");
    positive!(ssrf_10_1, "/proxy?url=http://10.1.2.3/secret");
    positive!(ssrf_192_168_0, "/proxy?url=http://192.168.0.1/router");

    negative!(clean_root, "/");
    negative!(clean_api, "/api/users");
    negative!(clean_external, "/proxy?url=https://example.com/");
    negative!(clean_google, "/proxy?url=https://google.com/");
    negative!(clean_no_url, "/search?q=hello");
    negative!(clean_path, "/products/123");
    negative!(clean_version, "/v2/api");
    negative!(clean_static, "/static/main.js");
    negative!(clean_health, "/health");
    negative!(clean_query, "/items?page=1&sort=name");
    negative!(clean_cdn, "/proxy?url=https://cdn.example.com/image.jpg");
    negative!(clean_docs, "/proxy?url=https://docs.rust-lang.org/");
    negative!(clean_github, "/proxy?url=https://github.com/owner/repo");
    negative!(clean_blog, "/blog/post-1");
    negative!(clean_webhook, "/webhooks/handler");
    negative!(clean_numeric, "/items/42");
    negative!(clean_encoded, "/path?name=hello%20world");
    negative!(clean_json, "/api/data.json");
    negative!(clean_robots, "/robots.txt");
    negative!(clean_sitemap, "/sitemap.xml");
    negative!(clean_feed, "/feed.xml");
    negative!(clean_image, "/images/photo.jpg");
    negative!(clean_css, "/styles/main.css");
    negative!(clean_long_path, "/a/b/c/d/e/f/g/h");
    negative!(clean_uuid, "/api/550e8400-e29b-41d4-a716-446655440000");
    negative!(clean_download, "/download/file.zip");
    negative!(clean_manifest, "/manifest.json");
    negative!(clean_sw, "/sw.js");
    negative!(clean_favicon, "/favicon.ico");
    negative!(clean_mailto, "/contact?email=user@example.com");
    negative!(clean_auth, "/auth/callback");
}
