use aegis_core::pipeline::RequestView;
use regex::Regex;
use std::sync::LazyLock;

use super::{Detector, Signal};

/// Path traversal detector.
pub struct PathTraversalDetector;

static TRAVERSAL_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"(?:\.\.[\\/])",
        r"(?:%2e%2e[\\/])",
        r"(?:%2e%2e%2f)",
        r"(?:%252e%252e%252f)",
        r"(?:\.\.%2f)",
        r"(?:%2e%2e/)",
        r"(?:\.%2e/)",
        r"(?:%2e\./)",
        r"(?:/etc/(?:passwd|shadow|hosts|resolv\.conf))",
        r"(?:/proc/self/(?:environ|cmdline|fd))",
        r"(?:(?:c|d):[\\/])",
        r"(?:boot\.ini)",
        r"(?:win\.ini)",
        r"(?:\\\\[^\\]+\\)",
        r"(?:%00|\x00)",
        r"(?:%5c)",
    ]
    .iter()
    .map(|p| Regex::new(p).unwrap())
    .collect()
});

impl Detector for PathTraversalDetector {
    fn id(&self) -> &'static str {
        "path_traversal"
    }

    fn inspect(&self, req: &RequestView<'_>) -> Vec<Signal> {
        let mut signals = Vec::new();

        let raw_uri = req.uri.to_string();
        let decoded_uri = super::url_decode(&raw_uri);
        check(&raw_uri, "uri", &mut signals);
        check(&decoded_uri, "uri", &mut signals);

        let body = std::str::from_utf8(req.body.peek(8192)).unwrap_or("");
        if !body.is_empty() {
            let decoded_body = super::url_decode(body);
            check(body, "body", &mut signals);
            check(&decoded_body, "body", &mut signals);
        }

        signals
    }
}

fn check(input: &str, field: &str, signals: &mut Vec<Signal>) {
    for re in TRAVERSAL_PATTERNS.iter() {
        if re.is_match(input) {
            signals.push(Signal {
                score: 45,
                tag: "path_traversal".into(),
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
                let d = PathTraversalDetector;
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
                let d = PathTraversalDetector;
                let (m, u, h, b) = view_with_uri($input);
                let req = make_view(&m, &u, &h, &b);
                assert!(d.inspect(&req).is_empty(), "false positive for: {}", $input);
            }
        };
    }

    positive!(dotdot_slash, "/../../etc/passwd");
    positive!(dotdot_backslash, "/..\\..\\windows\\system32");
    positive!(encoded_dotdot, "/%2e%2e/%2e%2e/etc/passwd");
    positive!(double_encoded, "/%252e%252e%252f");
    positive!(etc_passwd, "/file?name=/etc/passwd");
    positive!(etc_shadow, "/file?name=/etc/shadow");
    positive!(proc_self, "/file?name=/proc/self/environ");
    positive!(windows_drive, "/file?name=c:\\windows\\system32");
    positive!(boot_ini, "/file?name=boot.ini");
    positive!(win_ini, "/file?name=win.ini");
    positive!(null_byte, "/file%00.jpg");
    positive!(unc_path, "/file?name=\\\\server\\share");
    positive!(mixed_dotdot, "/..%2f..%2fetc/passwd");
    positive!(dot_2e_slash, "/.%2e/etc/passwd");
    positive!(backslash_encoded, "/%5c..%5c..%5cwindows");
    positive!(etc_hosts, "/read?f=/etc/hosts");
    positive!(etc_resolv, "/read?f=/etc/resolv.conf");
    positive!(proc_cmdline, "/read?f=/proc/self/cmdline");
    positive!(proc_fd, "/read?f=/proc/self/fd/0");
    positive!(triple_dotdot, "/../../../etc/passwd");
    positive!(d_drive, "/file?name=d:\\data\\secrets");
    positive!(many_traversal, "/a/../b/../c/../../../etc/passwd");
    positive!(dotdot_query, "/path?file=../secret.txt");
    positive!(encoded_null, "/path?file=test%00.txt");
    positive!(mixed_encoding, "/%2e%2e/..%2f/etc/passwd");
    positive!(dotdot_fragment, "/path?f=../../hidden");
    positive!(windows_backslash, "/..\\system32\\config");
    positive!(multiple_dotdot, "/public/../../../../etc/shadow");
    positive!(encoded_backslash, "/%5cwindows%5csystem32");
    positive!(long_traversal, "/a/b/c/d/../../../../../etc/passwd");

    negative!(clean_root, "/");
    negative!(clean_api, "/api/users/123");
    negative!(clean_nested, "/a/b/c/d");
    negative!(clean_query, "/search?q=test");
    negative!(clean_file, "/files/report.pdf");
    negative!(clean_static, "/static/main.js");
    negative!(clean_dots_in_name, "/file.tar.gz");
    negative!(clean_version, "/v2/api");
    negative!(clean_uuid, "/api/550e8400-e29b");
    negative!(clean_encoded_space, "/path?name=hello%20world");
    negative!(clean_numeric, "/items/42");
    negative!(clean_health, "/health/ready");
    negative!(clean_metrics, "/metrics");
    negative!(clean_sitemap, "/sitemap.xml");
    negative!(clean_robots, "/robots.txt");
    negative!(clean_favicon, "/favicon.ico");
    negative!(clean_image, "/images/logo.png");
    negative!(clean_json, "/api/data.json");
    negative!(clean_xml, "/feed.xml");
    negative!(clean_blog, "/blog/2024/my-post");
    negative!(clean_auth, "/auth/login");
    negative!(clean_webhook, "/webhooks/handler");
    negative!(clean_locale, "/en-US/docs");
    negative!(clean_long, "/a/b/c/d/e/f/g/h/i/j");
    negative!(clean_dash, "/my-resource");
    negative!(clean_underscore, "/my_page");
    negative!(clean_page, "/page?num=1");
    negative!(clean_sort, "/list?sort=name");
    negative!(clean_filter, "/items?category=books");
    negative!(clean_download, "/download/file-v1.2.3.zip");
    negative!(clean_manifest, "/manifest.json");
}
