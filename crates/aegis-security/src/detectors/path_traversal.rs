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
        // 2026-05-22 (legit-dataset FP fix) — Windows drive root, but
        // anchored to a value boundary so the drive letter isn't the
        // tail of a normal word. The old `(?:c|d):[\\/]` matched `c:/`
        // / `d:/` ANYWHERE, false-positiving on ubiquitous strings like
        // `dynami(c:/)slot`, `ab(c:/)cdn`, `a(d:/)banner` (ad-tech).
        // Now the drive letter must follow start or a non-alphanumeric
        // (`=c:\`, `/c:/`, `=C:/boot.ini`), matching a real
        // `?file=c:\windows` traversal but not a mid-word coincidence.
        r"(?i)(?:^|[^a-z0-9])[cd]:[\\/]",
        r"(?:boot\.ini)",
        r"(?:win\.ini)",
        r"(?:\\\\[^\\]+\\)",
        r"(?:%00|\x00)",
        // 2026-05-24 (FP fix) — the old bare `(?:%5c)` matched an
        // encoded backslash ANYWHERE, false-positiving on the heap of
        // legit traffic that carries encoded backslashes in query
        // values (encoded URLs, JSON/analytics payloads, Windows paths
        // as DATA — e.g. opaque CDN/beacon paths with `?d=a%5cb`). It
        // was also lowercase-only, so it FP'd on legit `%5c` yet let a
        // real `%5C` attack slip past. Now the encoded backslash must
        // sit in a traversal context: adjacent to `..` or doubled
        // (encoded UNC `\\`). Real `..%5c..%5c` still fires — the
        // decode pass recovers `..\`, caught by the `\.\.[\\/]` rule
        // above; a lone `%5c` in a value no longer trips.
        r"(?i)(?:\.\.%5c|%5c\.\.|%5c%5c)",
        // GAP-002 (Run-5, 2026-05-09) — overlong UTF-8 encoding
        // for `.`, `/`, `\`. RFC 3629 forbids these (any code
        // point < 0x80 must be encoded in 1 byte), but legacy
        // parsers + some app servers decode them — used to
        // bypass naive prefix matching.
        //   %c0%ae = overlong U+002E (`.`)
        //   %c0%af = overlong U+002F (`/`)
        //   %c0%5c = overlong U+005C (`\`)
        //   %c1%9c = also overlong `\`
        r"(?i)(?:%c0%ae){2,}",
        r"(?i)%c0%af",
        r"(?i)%c0%5c|%c1%9c",
        // Docker socket path — unix-socket exposure attack
        // target. Distinct from Docker REST API recon (caught
        // by recon.rs via `/v\d+\.\d+/containers`); this catches
        // the FILESYSTEM path appearing in path-traversal or
        // SSRF param values (`?file=/var/run/docker.sock`).
        r"(?i)/var/run/docker\.sock\b",
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

        // S1 (2026-05-18) — replace single-pass `url_decode` with
        // the shared normaliser. Adds repeated URL-decode (catches
        // `%252e%252e`), HTML-entity decode (`&period;&period;/`),
        // and unicode-escape decode (`..`). The QC rules-binary
        // eval ranked traversal recall at 59 % under the old
        // pipeline; closing the decoder gap is the single biggest
        // win on that score.
        let raw_uri = req.uri.to_string();
        for variant in super::normalize_for_detection(&raw_uri) {
            check(&variant, "uri", &mut signals);
            if !signals.is_empty() {
                break;
            }
        }

        let body = std::str::from_utf8(req.body.peek(8192)).unwrap_or("");
        if !body.is_empty() && signals.is_empty() {
            for variant in super::normalize_for_detection(body) {
                check(&variant, "body", &mut signals);
                if !signals.is_empty() {
                    break;
                }
            }
        }

        signals
    }
}

fn check(input: &str, field: &str, signals: &mut Vec<Signal>) {
    for re in TRAVERSAL_PATTERNS.iter() {
        if re.is_match(input) {
            signals.push(Signal {
                score: super::scores::path_traversal::PATH_TRAVERSAL,
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
    // 2026-05-24 (FP fix) — was `/%5cwindows%5csystem32` (a lone
    // encoded backslash, the over-broad case). Now assert the real
    // attack forms: encoded UNC `\\server\share`, and the uppercase
    // `%5C` traversal that the old lowercase-only rule let through.
    positive!(encoded_backslash_unc, "/%5c%5cserver%5cshare");
    positive!(encoded_backslash_upper, "/%5C..%5C..%5Cwindows");
    // GAP-002 (Run-5) — overlong UTF-8 + Docker socket positives.
    positive!(overlong_utf8_slash,    "/?p=%c0%af..%c0%af..%c0%afetc%c0%afpasswd");
    positive!(overlong_utf8_dot,      "/?p=%c0%ae%c0%ae/etc");
    positive!(overlong_utf8_back,     "/?p=%c0%5cwindows");
    positive!(overlong_utf8_back_alt, "/?p=%c1%9cwindows");
    positive!(docker_socket,          "/file?p=/var/run/docker.sock");
    positive!(docker_socket_query,    "/api?fetch=/var/run/docker.sock&x=1");
    positive!(long_traversal, "/a/b/c/d/../../../../../etc/passwd");
    // S1 (2026-05-18) — decoder-evasion positives, closes the 59 %
    // traversal-recall gap surfaced by the ML rules-binary eval.
    // Each row is a payload that survived the single-pass
    // `url_decode` pre-fix and now trips after `normalize_for_detection`.
    positive!(double_url_encoded,        "/?p=%252e%252e%252fetc%252fpasswd");
    positive!(double_url_encoded_uri,    "/%252e%252e%252fetc%252fpasswd");
    positive!(triple_url_encoded,        "/?p=%25252e%25252e%25252fetc%25252fpasswd");
    positive!(html_entity_dot,           "/?p=&period;&period;/etc/passwd");
    positive!(html_entity_dot_synonym,   "/?p=&dot;&dot;&sol;etc&sol;passwd");
    // Numeric / hex entities — the literal `#` is the URL fragment
    // marker, so realistic attacker traffic URL-encodes it as `%23`.
    // After the first URL-decode pass we recover `&#46;&#46;/...`
    // and the entity decoder turns each `&#46;` into `.`.
    positive!(html_entity_numeric_dot,   "/?p=&%2346;&%2346;/etc/passwd");
    positive!(html_entity_hex_dot,       "/?p=&%23x2e;&%23x2e;/etc/passwd");
    positive!(unicode_escape_dotdot,     "/?p=\\u002e\\u002e/etc/passwd");
    positive!(hex_escape_dotdot,         "/?p=\\x2e\\x2e/etc/passwd");
    positive!(mixed_url_and_entity,      "/?p=%2e%2e&sol;etc&sol;passwd");

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
    // 2026-05-22 (legit-dataset FP fix) — `c:/` / `d:/` as the tail of
    // a normal word (NOT a Windows drive root) must NOT flag. These are
    // ubiquitous in ad-tech / tracking URLs.
    negative!(clean_dynamic_colon_slash, "/track?cb=dynamic:/slot");
    negative!(clean_word_abc_drive,      "/i?src=pic-abc:/cdn/x.png");
    negative!(clean_word_ad_drive,       "/sync?x=ad:/banner");
    negative!(clean_scheme_like,         "/r?cb=basic:/auth");
    negative!(clean_filter, "/items?category=books");
    negative!(clean_download, "/download/file-v1.2.3.zip");
    negative!(clean_manifest, "/manifest.json");
    // 2026-05-24 (FP fix) — a bare encoded backslash in a query/body
    // value is data, not traversal. These mirror the user-reported
    // false positive: opaque CDN/beacon paths whose query carried an
    // encoded `\`. Both cases must now pass clean.
    negative!(clean_encoded_backslash_value, "/track?d=a%5cb");
    negative!(clean_encoded_backslash_upper, "/img?u=a%5Cb");
    negative!(clean_beacon_encoded_bs, "/AGY0DmkM-xA2f00AEg/t9amcwJVb2mp3z?d=x%5cy");
}
