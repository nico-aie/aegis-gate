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
        // 2026-07 (FP fix) — the guard was `[^a-z0-9]` (any non-alnum),
        // which still allowed `_D:/` — an Oracle ATG Commerce form-handler
        // param (`?_dyncharset=…&_D:/atg/commerce/…`), a benign platform
        // idiom. Tightened to a real VALUE boundary (`=`, `&`, `?`, `/`,
        // `\`, quote, whitespace, start). A real `?file=c:\windows` /
        // `/c:/boot.ini` still fires; `_D:/`, `.d:/`, `-c:/` no longer do.
        r#"(?i)(?:^|[=&?/\\"'\s])[cd]:[\\/]"#,
        r"(?:boot\.ini)",
        r"(?:win\.ini)",
        // Literal UNC `\\host\share`. 2026-07 (FP fix) — the host segment must
        // START with an alphanumeric (a real UNC/SMB hostname), so the rule no
        // longer trips on JSON/JS-escaped backslashes in analytics/error beacons
        // (`https?:\\/\\/…`, `cookie":"\\"…\\"` — where `\\` is followed by `/`
        // or `"`, not a hostname). Real `\\server\share` still fires.
        r"(?:\\\\[a-zA-Z0-9][^\\]*\\)",
        r"(?:%00|\x00)",
        // 2026-05-24 (FP fix) — the old bare `(?:%5c)` matched an
        // encoded backslash ANYWHERE, false-positiving on the heap of
        // legit traffic that carries encoded backslashes in query
        // values (encoded URLs, JSON/analytics payloads, Windows paths
        // as DATA — e.g. opaque CDN/beacon paths with `?d=a%5cb`). It
        // was also lowercase-only, so it FP'd on legit `%5c` yet let a
        // real `%5C` attack slip past. Now the encoded backslash must
        // sit in a traversal context: adjacent to `..`. Real `..%5c..%5c`
        // still fires; a lone `%5c` in a value no longer trips.
        // 2026-07 (FP fix) — dropped the `%5c%5c` (encoded UNC) alternative:
        // it false-positived on analytics/error beacons carrying `\\` in
        // telemetry data (.NET namespaces / Windows stack-trace paths, e.g.
        // `name='Ms.Webi.OutgoingRequest'`). A real encoded UNC `%5c%5cserver%5c`
        // still fires — the decode pass recovers `\\server\`, caught by the
        // literal-UNC rule `\\\\[^\\]+\\` below.
        r"(?i)(?:\.\.%5c|%5c\.\.)",
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
        // 2026 LFI/RFI stream wrappers — `php://filter`, `data://`,
        // `expect://`, `phar://`, `zip://`, `glob://`. These schemes
        // never appear in legitimate request targets; their presence in
        // a path/param IS the attack (PHP wrapper LFI, base64 RFI, RCE
        // via expect). file/dict/gopher are left to the ssrf detector.
        r"(?i)\b(?:php|data|expect|phar|zip|glob)://",
        // Sensitive files reached WITHOUT a `../` prefix (absolute or
        // app-relative path). Distinctive targets — ~0 FP on real traffic.
        r"(?i)/\.ssh/(?:id_rsa|id_dsa|id_ecdsa|id_ed25519|authorized_keys)\b",
        r"(?i)(?:^|[/\\])\.env(?:[./\\]|$)",
        r"(?i)/web\.config\b|/WEB-INF/web\.xml\b",
        r"(?i)/etc/(?:nginx/nginx|apache2/apache2|httpd/httpd)\.conf\b",
        // Fullwidth solidus (U+FF0F) traversal evasion: `..／..／`.
        // Raw percent-encoded form + the decoded char (the normaliser
        // feeds a url-decoded variant where %ef%bc%8f becomes U+FF0F).
        r"(?i)\.\.%ef%bc%8f",
        "\\.\\.\u{ff0f}",
        // 2026-07 (junk-separator evasion) — a sensitive `/etc/` file reached
        // when the `/` before the filename is an ENCODED / non-slash separator
        // (overlong `%c0%af`, `%2f`→ already caught, `%3f`→`?`, `0x2f`, unicode
        // `%u2215`), so the plain `/etc/passwd` rule above misses it:
        //   `etc%c0%afpasswd`, `etc%3fshadow`, `etc0x2fgroup`.
        // Scoped to /etc/-only sensitive files (`passwd/shadow/group/gshadow`) at
        // a word boundary, with an ENCODED-only gap, so benign `etc`-containing
        // paths never trip. Measured 0 added FP on 40k Legitimate. The bulk of
        // this evasion family uses INVALID encoding (`%bg%qf`) with no real-world
        // value — deliberately NOT matched to keep FP at zero.
        r"(?i)\betc(?:%[0-9a-z]{2}|0x[0-9a-f]{2}|%u[0-9a-f]{4}){1,6}(?:passwd|shadow|group|gshadow)\b",
    ]
    .iter()
    .map(|p| Regex::new(p).unwrap())
    .collect()
});

// 2026-07 (junk-separator compound rule) — catches obfuscated traversal whose
// separator is an INVALID percent-encoding (`etc%bg%qfpasswd`, `..%bg%qf..boot.ini`)
// that survives url-decode, so neither the `/etc/passwd` (needs a real slash) nor
// the `%`-count features fire. Requires BOTH signals in the same normalised
// variant:
//   1. INVALID_PCT — a `%` + two chars where at least one is a non-hex letter
//      (`%bg`, `%qf`, `%zz`). Real clients never emit these; measured on 40k
//      Legitimate only 0.005% carry any (e.g. `50%off`), and none alongside a
//      sensitive target.
//   2. SENSITIVE_TARGET — a path-traversal target filename.
// Alone, INVALID_PCT is not enough (a stray `50%off` is benign); the AND with a
// sensitive target makes it 0-FP (measured 0/40291) while recovering the invalid-
// encoding evasion family that raw `%`-counting could only catch by risking FP.
static INVALID_PCT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"%(?:[0-9a-fA-F][g-zG-Z]|[g-zG-Z][0-9a-zA-Z])").unwrap());
// Sensitive-file targets. Bare `passwd`/`shadow` are NOT used (they occur in
// benign words — `box-shadow`, `text-shadow`; `password` doesn't contain `passwd`
// but `shadow` does appear). Instead they must sit in an `/etc/` slash context OR
// an `etc<junk-gap>file` context (the junk-separator attack), so `box-shadow`
// without a preceding `etc<gap>` never matches. The specific config/key filenames
// are attack-only strings on their own.
static SENSITIVE_TARGET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)boot\.ini|win\.ini|wp-config|web\.config|id_rsa|(?:^|[/\\.])\.env|/proc/self|/etc/(?:passwd|shadow|hosts|group|issue|gshadow)|etc(?:%[0-9a-zA-Z]{2}|[^a-z0-9]){1,6}(?:passwd|shadow|group|gshadow|hosts|issue)\b",
    )
    .unwrap()
});

impl Detector for PathTraversalDetector {
    fn id(&self) -> &'static str {
        "path_traversal"
    }

    fn inspect(&self, req: &RequestView<'_>) -> Vec<Signal> {
        let mut signals = Vec::new();

        // 2026-05-24 — path_traversal inspects the URL (path + query)
        // ONLY, never the request body. Traversal is a URL/path-layer
        // attack: the exploit is a request path that resolves to a file
        // on the server. A WAF can't tell a filesystem-path body field
        // from free text, so scanning bodies for `../` / `/etc/passwd`
        // false-positives on the large volume of legit content that
        // carries those strings as DATA — analytics/RUM beacons (Shopify
        // Monorail, Chromium UMA), AI prompts, chat messages, code
        // snippets, markdown, JSON configs. Body-delivered file paths
        // belong to app-layer validation (safe_path / resolve), where the
        // field's role is known; the body is still scanned by the
        // injection detectors (sqli, xss, command_injection, …) for THEIR
        // vectors.
        //
        // S1 (2026-05-18) — the shared normaliser still feeds `check`
        // repeated URL-decode (`%252e%252e`), HTML-entity decode
        // (`&period;&period;/`) and unicode-escape decode (`.`), so
        // encoded traversal in the query string still trips.
        let raw_uri = req.uri.to_string();
        for variant in super::normalize_for_detection(&raw_uri) {
            check(&variant, "uri", &mut signals);
            if !signals.is_empty() {
                break;
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
    // Compound: invalid percent-encoding (junk separator) AND a sensitive target.
    if INVALID_PCT.is_match(input) && SENSITIVE_TARGET.is_match(input) {
        signals.push(Signal {
            score: super::scores::path_traversal::PATH_TRAVERSAL,
            tag: "path_traversal".into(),
            field: field.into(),
        });
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

    // 2026 — LFI/RFI stream wrappers + absolute sensitive files + fullwidth.
    positive!(php_filter_wrapper,   "/load?f=php://filter/convert.base64-encode/resource=/app/.env");
    positive!(data_wrapper_b64,     "/x?p=data://text/plain;base64,PD9waHA");
    positive!(expect_wrapper,       "/x?cmd=expect://id");
    positive!(phar_wrapper,         "/x?f=phar://test.phar/x");
    positive!(ssh_key_abs,          "/download?f=/root/.ssh/id_rsa");
    positive!(env_file,             "/static/.env");
    positive!(web_config,           "/read?f=/web.config");
    positive!(webinf_xml,           "/read?f=/WEB-INF/web.xml");
    positive!(nginx_conf,           "/read?f=/etc/nginx/nginx.conf");
    positive!(fullwidth_slash_enc,  "/assets?p=..%ef%bc%8f..%ef%bc%8fetc/passwd");
    // 2026-07 (junk-separator) — /etc/ sensitive file via ENCODED non-slash gap.
    positive!(etc_overlong_passwd,  "/download?f=etc%c0%afpasswd");
    positive!(etc_qmark_shadow,     "/read?f=etc%3fshadow");
    positive!(etc_hex_group,        "/read?f=etc0x2fgroup");
    positive!(etc_unicode_passwd,   "/read?f=etc%u2215passwd");
    // 2026-07 (compound: invalid-% + sensitive target) — invalid-encoding junk sep.
    positive!(junk_sep_etc_passwd,  "/?p=..%bg%qf..%bg%qfetc%bg%qfpasswd");
    positive!(junk_sep_etc_shadow,  "/read?f=etc%zz%zzshadow");
    positive!(junk_sep_qmark_passwd,"/?p=%3F.%bg%qf%3F.%bg%qfetc%bg%qfpasswd");

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
    // 2026-07 (junk-separator rule FP guards) — the new etc-gap rule needs an
    // ENCODED gap AND an /etc/-specific file; these benign forms must stay clean.
    negative!(clean_fetch_passwordreset, "/fetch?redirect=passwordreset");   // "etc" in fetch, no encoded gap, passwd≠password
    negative!(clean_etc_readme,          "/docs/etc/readme.txt");            // etc but not a sensitive file
    negative!(clean_etc_eq_passwords,    "/config?etc=passwords");           // gap `=` not encoded, and passwords≠passwd\b
    negative!(clean_etcher_download,     "/apps/etcher-1.18.11.deb");        // "etc" inside "etcher", no gap+target
    // 2026-07 (FP fix) — drive-letter guard + encoded-UNC drop.
    negative!(clean_atg_form_handler,    "/checkout/includes/?_dyncharset=utf-8&_D:/atg/commerce/order/CartModifierFormHandler"); // ATG `_D:/` idiom
    negative!(clean_beacon_double_bs,    "/collect/t.gif?name=Ns%5c%5cClass"); // `\\` in telemetry data, no `..` / trailing `\`
    negative!(clean_beacon_js_escape,    "/collect/v1/t.gif?re=(https?:\\\\/\\\\/mem.gfx.ms)"); // JS-regex escape `\\/`, host isn't alnum
    // 2026-07 (compound rule FP guards) — invalid-% present but must NOT fire
    // without a sensitive target; and a target word without invalid-% context.
    negative!(clean_percent_off,         "/sale?discount=50%off&id=42");        // invalid-% `%of`, no target
    negative!(clean_invalid_pct_only,    "/track?a=%gg&b=%hh&id=1");            // invalid-% only, no target
    negative!(clean_box_shadow_pct,      "/theme?css=box-shadow%20effect&x=%zz"); // invalid-% + "shadow" but no /etc/ or etc-gap
    negative!(clean_password_reset_pct,  "/auth?type=password_reset&t=%zz");    // "password" ≠ "passwd", invalid-% present
    negative!(clean_etc_readme_pct,      "/docs?p=etc%bg%qfreadme.md");         // etc-gap but "readme" not sensitive

    // 2026-05-24 (FP fix) — body scanning skips the bare literal `../`.
    fn view_with_body(body: &str) -> (http::Method, http::Uri, http::HeaderMap, BodyPeek) {
        (
            http::Method::POST,
            "/beacon".parse().unwrap(),
            http::HeaderMap::new(),
            BodyPeek::new(body.as_bytes().to_vec(), Some(body.len() as u64), false),
        )
    }

    // 2026-05-24 — path_traversal is URL-only; the request body is NOT
    // scanned. Traversal-looking strings in a body (analytics/RUM URLs,
    // AI prompts, chat, code, JSON configs) are DATA, not attacks, and
    // must pass clean — app-layer validation owns body file-paths.
    #[test]
    fn body_relative_url_dotdot_is_clean() {
        let det = PathTraversalDetector;
        let (m, u, h, b) = view_with_body(
            r#"{"resource_timing":"https://cdn.shop.com/a/../b/app.js","page":"/x/../y"}"#,
        );
        let req = make_view(&m, &u, &h, &b);
        assert!(det.inspect(&req).is_empty(), "FP: ../ in analytics body");
    }

    #[test]
    fn body_etc_passwd_text_is_clean() {
        // e.g. an AI prompt / chat message about the file — body isn't
        // scanned, so this must NOT register as a traversal hit.
        let det = PathTraversalDetector;
        let (m, u, h, b) =
            view_with_body(r#"{"q":"what does ../../../../etc/passwd do on Linux?"}"#);
        let req = make_view(&m, &u, &h, &b);
        assert!(det.inspect(&req).is_empty(), "FP: traversal text in body");
    }

    #[test]
    fn body_encoded_dotdot_is_clean() {
        let det = PathTraversalDetector;
        let (m, u, h, b) = view_with_body("p=%2e%2e%2f%2e%2e%2fwindows");
        let req = make_view(&m, &u, &h, &b);
        assert!(det.inspect(&req).is_empty(), "FP: encoded ../ in body");
    }

    // URL-delivered traversal (path + query) is STILL caught — the real
    // attack surface is unaffected by dropping the body scan.
    #[test]
    fn uri_dotdot_detection_unchanged() {
        let det = PathTraversalDetector;
        let (m, u, h, b) = view_with_uri("/path?file=../secret.txt");
        let req = make_view(&m, &u, &h, &b);
        assert!(!det.inspect(&req).is_empty(), "lost URI ../ detection");
    }

    #[test]
    fn uri_encoded_etc_passwd_still_flagged() {
        let det = PathTraversalDetector;
        let (m, u, h, b) = view_with_uri("/?f=..%2F..%2F..%2F..%2Fetc%2Fpasswd");
        let req = make_view(&m, &u, &h, &b);
        assert!(!det.inspect(&req).is_empty(), "lost URL traversal detection");
    }
}
