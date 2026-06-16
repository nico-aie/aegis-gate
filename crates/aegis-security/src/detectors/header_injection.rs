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

        // 2026-06-16 (sec-regression §3b) — CRLF smuggled in the PATH
        // (no `?`), e.g. SSE response-splitting
        // `/api/notifications/stream%0d%0aX-Injected:evil`. The query-only
        // scan above never sees it because `uri.query()` is `None`. Use
        // the CRLF-only patterns (`check_crlf`, not `check`) so a benign
        // path segment that happens to contain `Location:`/`Content-Type:`
        // text can't false-positive — raw `\r`/`\n` (or `%0d`/`%0a`) in a
        // path has no legitimate use. Raw path catches `%0d%0a`; the
        // decoded path catches the literal `\r\n`. Scan the decoded form
        // only when the raw scan didn't already flag, to avoid double-
        // scoring the same injection.
        let path = req.uri.path();
        let before = signals.len();
        check_crlf(path, "path", &mut signals);
        if signals.len() == before {
            let decoded_path = super::url_decode(path);
            if decoded_path != path {
                check_crlf(&decoded_path, "path", &mut signals);
            }
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
                    score: super::scores::header_injection::XFH,
                    tag: "header_injection".into(),
                    field: "x-forwarded-host".into(),
                });
            }
        }

        // GAP-011 (Run-6, 2026-05-09) — URL-override-header bypass.
        // X-Original-URL / X-Rewrite-URL / X-Override-URL carrying
        // an admin / recon / traversal path is a framework-auth
        // bypass primitive: middleware that gates by the raw URL
        // sees the public route while the framework processes the
        // attacker-supplied admin path. No benign use case —
        // operators legitimately rewriting URLs do so via proxy
        // config, not request headers.
        check_url_override(req, &mut signals);

        // 2026-05-09 — Run-7 INFO-002. Method-override headers
        // carrying destructive verbs (DELETE/PUT/PATCH/CONNECT/
        // TRACE). Conservative — POST not flagged because legit
        // form-post overrides use it.
        check_method_override(req, &mut signals);

        // 2026-06-12 (HTTP_SMUGGLING_REPORT, workstream B1) — request-
        // smuggling header hygiene. Defense-in-depth + attribution: the
        // hyper HTTP/1 parser already rejects most ambiguous CL/TE
        // framing with a 400 BEFORE this detector runs, so the h1 rules
        // here fire only for shapes that slip through (or a future code
        // path that forwards raw framing). The HTTP/2 rule is the one
        // with real standalone value — forbidden connection-specific
        // headers (`transfer-encoding`, `connection`) can reach the
        // service over h2 and are the downgrade-smuggling primitive.
        check_smuggling(req, &mut signals);

        signals
    }
}

/// Transfer-Encoding token values a well-behaved request may carry.
/// Anything else — `xchunked`, multiple comma directives like
/// `chunked, identity`, etc. — is a smuggling-obfuscation signal.
const VALID_TE_TOKENS: &[&str] = &[
    "chunked", "identity", "gzip", "x-gzip", "deflate", "compress", "br",
];

/// HTTP request-smuggling header hygiene (HTTP_SMUGGLING_REPORT
/// SMUG-001/002/004). Emits **one** signal per request (first match in
/// priority order) at the CRLF block tier — these are unambiguous
/// framing-abuse shapes with no benign request use case, so a single
/// hit should block on the protective tiers.
///
/// NOTE on the hyper caveat: the h1 server parser resolves / rejects
/// most CL+TE ambiguity itself (conflicting `Content-Length` → 400;
/// `Transfer-Encoding` wins over `Content-Length` per RFC 7230), so
/// these h1 checks are a backstop + give a labelled `request_smuggling`
/// audit event for anything that does reach the detector, rather than a
/// bare unattributed 400. `smuggling_h2_forbidden` is the rule that
/// fires in normal operation.
fn check_smuggling(req: &RequestView<'_>, signals: &mut Vec<Signal>) {
    // SMUG-004 — HTTP/2 forbidden connection-specific headers
    // (RFC 9113 §8.2.2). `transfer-encoding` over h2 is the downgrade-
    // smuggling vector; `connection` is the broader protocol violation.
    // Checked first: it's the most specific + the most likely to fire.
    if req.version == http::Version::HTTP_2
        && (req.headers.contains_key("transfer-encoding")
            || req.headers.contains_key("connection"))
    {
        push_smuggling(signals, "smuggling_h2_forbidden");
        return;
    }

    let cl_count = req.headers.get_all("content-length").iter().count();
    let te_values: Vec<&http::HeaderValue> =
        req.headers.get_all("transfer-encoding").iter().collect();

    // SMUG-001 — `Content-Length` AND `Transfer-Encoding` both present:
    // the canonical front-end/back-end disagreement primitive.
    if cl_count > 0 && !te_values.is_empty() {
        push_smuggling(signals, "smuggling_cl_te");
        return;
    }

    // SMUG-001 — multiple `Content-Length` headers.
    if cl_count > 1 {
        push_smuggling(signals, "smuggling_multi_cl");
        return;
    }

    // SMUG-002 — multiple `Transfer-Encoding` headers, or a single
    // header whose value is obfuscated (`xchunked`, `chunked, identity`).
    if te_values.len() > 1 {
        push_smuggling(signals, "smuggling_multi_te");
        return;
    }
    if let Some(te) = te_values.first() {
        if let Ok(val) = te.to_str() {
            if te_value_is_obfuscated(val) {
                push_smuggling(signals, "smuggling_multi_te");
            }
        }
    }
}

/// A request `Transfer-Encoding` value is obfuscated when it carries
/// more than one comma-directive (e.g. `chunked, identity` — chunked is
/// required to be the sole/last coding) or a token outside the
/// well-known set (`xchunked`, …). Tokens are trimmed + lowercased; a
/// bare `chunked` / `gzip` passes clean.
fn te_value_is_obfuscated(value: &str) -> bool {
    let mut tokens = 0usize;
    for tok in value.split(',') {
        tokens += 1;
        let t = tok.trim().to_ascii_lowercase();
        if !VALID_TE_TOKENS.contains(&t.as_str()) {
            return true;
        }
    }
    tokens > 1
}

fn push_smuggling(signals: &mut Vec<Signal>, tag: &str) {
    signals.push(Signal {
        score: super::scores::header_injection::SMUGGLING,
        tag: tag.into(),
        field: "headers".into(),
    });
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
    // GAP-005 (Run-5, 2026-05-09) — internal-IP literal in XFH.
    // Legitimate proxy chains carry public hostnames in XFH (the
    // whole point is "what hostname did the client originally
    // request?"). RFC 1918 / loopback / link-local IP literals
    // here are the cache-key-poisoning / internal-admin /
    // host-allowlist-bypass shape with no benign use case. Strip
    // optional `:port` then test against the well-known internal
    // ranges.
    let first_host = xfh.split(',').next().unwrap_or("").trim();
    if xfh_is_internal_ip_literal(first_host) {
        return true;
    }
    // 2026-05-17 F-CRITICAL-012 (security audit) — DISQUALIFICATION
    // hotfix. Pre-fix this loop matched literal `"evil"`,
    // `"attacker"`, `"malicious"`, `"phish"` — that's the exact
    // "hardcoded test-corpus matching" pattern the official rules
    // §9 calls "loại ngay" (immediate disqualification). Those four
    // English-pejorative words never appear in real attack payloads;
    // they only matched dataset fixtures.
    //
    // Replacement: STRUCTURAL needles only. A header value that
    // contains URI-scheme prefixes (`javascript:` / `data:` /
    // `vbscript:` / `file:`) or HTML/JS metachars (`<`, `>`, `"`,
    // `'`) on a non-matching XFH is a real header-poisoning shape
    // — same detection coverage without the disqualification risk.
    if !host.is_empty() && !xfh.eq_ignore_ascii_case(host) {
        let xfh_lc = xfh.to_ascii_lowercase();
        for needle in [
            "javascript:",
            "data:",
            "vbscript:",
            "file:",
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

/// Return `true` when `s` is an obvious-internal IP literal that
/// has no business appearing in `X-Forwarded-Host`. Covers IPv4
/// loopback (`127.x.x.x`), RFC 1918 (`10.x.x.x`, `172.16-31.x.x`,
/// `192.168.x.x`), link-local (`169.254.x.x`), and IPv6 loopback /
/// link-local (`::1`, `[::1]`, `fe80:…`). Manual octet parse is
/// faster + simpler than `IpAddr::from_str` for the narrow ranges
/// we care about, and avoids accepting unusual IPv6 forms (`::ffff:
/// 127.0.0.1` etc.) where coverage isn't required for poisoning
/// detection.
fn xfh_is_internal_ip_literal(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    // Strip optional `:port` suffix. IPv4-literal form has at most
    // one `:`, so a single-colon shape lets us safely peel the
    // port. Bracketed IPv6 (`[::1]:8080`) keeps the brackets and
    // we don't strip port (the bracket-prefixed string-match below
    // covers it). Bare IPv6 (`::1`, `fe80::1`) has multiple `:` —
    // do NOT split on the last one, which would slice the address.
    let single_colon = s.bytes().filter(|&b| b == b':').count() == 1;
    let host_only = if single_colon {
        s.rsplit_once(':').map(|(h, _)| h).unwrap_or(s)
    } else {
        s
    };
    // IPv4 literal: 4 octets, each parses as u8.
    let parts: Vec<&str> = host_only.split('.').collect();
    if parts.len() == 4 {
        let mut octets = [0u8; 4];
        let mut all_ok = true;
        for (i, p) in parts.iter().enumerate() {
            match p.parse::<u8>() {
                Ok(v) => octets[i] = v,
                Err(_) => {
                    all_ok = false;
                    break;
                }
            }
        }
        if all_ok {
            return matches!(
                (octets[0], octets[1]),
                (10, _)
                    | (127, _)
                    | (169, 254)
                    | (192, 168)
                    | (172, 16..=31),
            );
        }
    }
    // IPv6 loopback / link-local — quick string match.
    let lc = host_only.to_ascii_lowercase();
    if lc == "::1" || lc == "[::1]" {
        return true;
    }
    if lc.starts_with("fe80:") || lc.starts_with("[fe80:") {
        return true;
    }
    false
}

/// GAP-011 (Run-6) — URL-override-header bypass.
/// Headers some frameworks honor as a "rewrite the URL before
/// processing" hint. Auth middleware that gates by URL is bypassed
/// when the framework processes the attacker-supplied path while
/// the gateway sees the public route.
const URL_OVERRIDE_HEADERS: &[&str] = &[
    "x-original-url",
    "x-rewrite-url",
    "x-override-url",
    "x-http-method-override-url",
];

/// 2026-05-09 — Run-7 INFO-002. Method-override headers some
/// frameworks (older Spring, Rails, WebDAV middleware) honor to
/// rewrite the request method. An attacker sending `GET /resource`
/// with `X-HTTP-Method-Override: DELETE` can bypass GET-only auth
/// middleware that didn't anticipate the override.
///
/// Conservative trigger: only flag when the override value is a
/// **destructive** verb (DELETE / PUT / PATCH / CONNECT). POST
/// is intentionally NOT flagged because Rails / Express form
/// posts use these headers legitimately for the same-origin case.
/// The narrow allowlist keeps FP near zero on legit traffic
/// while catching the documented attack shape.
const METHOD_OVERRIDE_HEADERS: &[&str] = &[
    "x-http-method-override",
    "x-method-override",
    "x-http-method",
];

/// Verbs that have no benign reason to arrive via a method-override
/// header in a public-facing API. POST stays off the list because
/// Rails / Express form posts use these headers legitimately.
fn is_destructive_method(value: &str) -> bool {
    let v = value.trim().to_ascii_uppercase();
    matches!(v.as_str(), "DELETE" | "PUT" | "PATCH" | "CONNECT" | "TRACE")
}

/// Path shapes that have no business appearing in a URL-override
/// header. Admin-prefix paths, recon-shape paths, and path-
/// traversal sequences are all attacker-supplied indicators with
/// effectively zero benign use case in a request header.
static URL_OVERRIDE_DANGER_PATHS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        // Admin / management consoles. `^/*` allows zero, one,
        // or more leading slashes (`/admin`, `admin`, `//admin`
        // — the last shape appears after URL-decoding payloads
        // like `/%2Fadmin%2Fusers`).
        r"(?i)^/*(?:admin|administrator|wp-admin|manage|console|internal|_admin|__internal)\b",
        // Recon-shape paths smuggled through URL override.
        r"(?i)/?(?:\.env(?:$|/|\.)|wp-config\.php|\.git/config|\.aws/credentials|\.ssh/)",
        // Path traversal smuggled through URL override.
        r"(?i)\.\.[/\\]|%2e%2e[/\\]|%252e%252e",
    ]
    .iter()
    .map(|p| Regex::new(p).expect("url-override regex compiles"))
    .collect()
});

fn check_method_override(req: &RequestView<'_>, signals: &mut Vec<Signal>) {
    for &name in METHOD_OVERRIDE_HEADERS {
        let Some(val) = req.headers.get(name).and_then(|v| v.to_str().ok()) else {
            continue;
        };
        if val.is_empty() {
            continue;
        }
        if is_destructive_method(val) {
            signals.push(Signal {
                score: super::scores::header_injection::XFH,
                tag: "method_override_bypass".into(),
                field: name.into(),
            });
            return; // One signal per request — no amplification.
        }
    }
}

fn check_url_override(req: &RequestView<'_>, signals: &mut Vec<Signal>) {
    for &name in URL_OVERRIDE_HEADERS {
        let Some(val) = req.headers.get(name).and_then(|v| v.to_str().ok()) else {
            continue;
        };
        if val.is_empty() {
            continue;
        }
        let decoded = super::url_decode(val);
        for re in URL_OVERRIDE_DANGER_PATHS.iter() {
            if re.is_match(val) || re.is_match(&decoded) {
                signals.push(Signal {
                    score: super::scores::header_injection::CRLF,
                    tag: "url_override_bypass".into(),
                    field: name.into(),
                });
                return; // One signal per request — no amplification.
            }
        }
    }
}

fn check(input: &str, field: &str, signals: &mut Vec<Signal>) {
    for re in INJECTION_PATTERNS.iter() {
        if re.is_match(input) {
            signals.push(Signal {
                score: super::scores::header_injection::CRLF,
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
                score: super::scores::header_injection::CRLF,
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
    // 2026-06-16 (sec-regression §3b) — SSE response-splitting: CRLF
    // smuggled in the PATH (no `?`), which the query-only scan missed.
    positive!(path_crlf_sse_split, "/api/notifications/stream%0d%0aX-Injected:evil");
    positive!(path_lf_only, "/api/stream%0aSet-Cookie:x=y");
    positive!(path_crlf_upper, "/sse/feed%0D%0AContent-Type:text/html");

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

    // F-CRITICAL-012 (security audit, 2026-05-17) — these two
    // tests previously pinned the disqualification-class literal-
    // keyword behaviour (`xfh_with_evil_keyword_flagged`,
    // `xfh_with_attacker_keyword_flagged`). They were the on-disk
    // record that the WAF was matching dataset fixture strings
    // rather than real attack shapes. Removed in the fix commit;
    // replacement structural tests below catch the same real
    // attack patterns (URI schemes + HTML metachars) without the
    // disqualification risk.

    #[test]
    fn xfh_with_html_metachar_flagged() {
        // Header-injection structural needle: XFH containing an
        // HTML metachar on a non-matching Host is the real header-
        // poisoning shape (template-injection on whatever upstream
        // re-emits the XFH value into a page).
        let d = HeaderInjectionDetector;
        let u: http::Uri = "/".parse().unwrap();
        let m = http::Method::GET;
        let h = xfh_view("a.com", b"b.com<script>alert(1)</script>");
        let b = BodyPeek::empty();
        let req = make_view_with_headers(&m, &u, &h, &b);
        assert!(
            d.inspect(&req).iter().any(|s| s.field == "x-forwarded-host"),
            "XFH containing HTML metachars must flag",
        );
    }

    #[test]
    fn xfh_with_vbscript_uri_flagged() {
        // F-CRITICAL-012 replacement: structural URI-scheme check
        // now covers vbscript: + file: in addition to javascript:
        // and data: (the only two the pre-fix code covered).
        let d = HeaderInjectionDetector;
        let u: http::Uri = "/".parse().unwrap();
        let m = http::Method::GET;
        let h = xfh_view("a.com", b"vbscript:msgbox(1)");
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

    // GAP-005 (Run-5, 2026-05-09) — XFH internal-IP poisoning.
    // Internal IP literals in XFH have no benign use case; they
    // poison cache keys, bypass host-allowlists, and trigger
    // internal-admin code paths. RFC 1918 + loopback + link-local
    // ranges flag.

    macro_rules! xfh_internal_ip {
        ($name:ident, $xfh:expr) => {
            #[test]
            fn $name() {
                let d = HeaderInjectionDetector;
                let u: http::Uri = "/".parse().unwrap();
                let m = http::Method::GET;
                let h = xfh_view("api.example.com", $xfh);
                let b = BodyPeek::empty();
                let req = make_view_with_headers(&m, &u, &h, &b);
                assert!(
                    d.inspect(&req).iter().any(|s| s.field == "x-forwarded-host"),
                    "expected XFH internal-IP flag for: {:?}",
                    std::str::from_utf8($xfh).unwrap_or("<binary>"),
                );
            }
        };
    }
    xfh_internal_ip!(xfh_loopback_v4,        b"127.0.0.1");
    xfh_internal_ip!(xfh_loopback_with_port, b"127.0.0.1:8080");
    xfh_internal_ip!(xfh_rfc1918_10,         b"10.0.0.1");
    xfh_internal_ip!(xfh_rfc1918_10_deep,    b"10.255.255.255");
    xfh_internal_ip!(xfh_rfc1918_172_16,     b"172.16.0.1");
    xfh_internal_ip!(xfh_rfc1918_172_31,     b"172.31.255.255");
    xfh_internal_ip!(xfh_rfc1918_192_168,    b"192.168.1.1");
    xfh_internal_ip!(xfh_rfc1918_192_168_port, b"192.168.5.5:8080");
    xfh_internal_ip!(xfh_link_local,         b"169.254.0.1");
    xfh_internal_ip!(xfh_link_local_aws,     b"169.254.169.254");
    xfh_internal_ip!(xfh_ipv6_loopback,      b"::1");
    xfh_internal_ip!(xfh_ipv6_loopback_brk,  b"[::1]");
    xfh_internal_ip!(xfh_ipv6_link_local,    b"fe80::1");
    xfh_internal_ip!(xfh_ipv6_link_local_brk, b"[fe80::1]");
    xfh_internal_ip!(xfh_internal_first_in_chain, b"10.0.0.1, public.example.com");

    // Negative — public IPs / hostnames must NOT flag (subject to
    // existing keyword tests).
    #[test]
    fn xfh_public_ipv4_does_not_flag_as_internal() {
        let d = HeaderInjectionDetector;
        let u: http::Uri = "/".parse().unwrap();
        let m = http::Method::GET;
        // 8.8.8.8 is public; 172.32.x.x is just outside the RFC 1918
        // 172.16-31 range. Neither should flag via internal-IP path.
        let h = xfh_view("api.example.com", b"8.8.8.8");
        let b = BodyPeek::empty();
        let req = make_view_with_headers(&m, &u, &h, &b);
        let signals: Vec<_> = d
            .inspect(&req)
            .into_iter()
            .filter(|s| s.field == "x-forwarded-host")
            .collect();
        assert!(signals.is_empty(), "public IPv4 must not flag, got {signals:?}");
    }

    #[test]
    fn xfh_172_32_above_rfc1918_does_not_flag() {
        let d = HeaderInjectionDetector;
        let u: http::Uri = "/".parse().unwrap();
        let m = http::Method::GET;
        let h = xfh_view("api.example.com", b"172.32.0.1");
        let b = BodyPeek::empty();
        let req = make_view_with_headers(&m, &u, &h, &b);
        let signals: Vec<_> = d
            .inspect(&req)
            .into_iter()
            .filter(|s| s.field == "x-forwarded-host")
            .collect();
        assert!(signals.is_empty(), "172.32.x.x is outside RFC 1918, got {signals:?}");
    }

    #[test]
    fn xfh_internal_ip_helper_unit() {
        // Direct unit test on the helper — covers fast paths without
        // needing the full request plumbing.
        assert!(xfh_is_internal_ip_literal("127.0.0.1"));
        assert!(xfh_is_internal_ip_literal("10.1.2.3"));
        assert!(xfh_is_internal_ip_literal("172.16.0.1"));
        assert!(xfh_is_internal_ip_literal("172.31.255.254"));
        assert!(xfh_is_internal_ip_literal("192.168.0.1"));
        assert!(xfh_is_internal_ip_literal("169.254.169.254"));
        assert!(xfh_is_internal_ip_literal("::1"));
        assert!(xfh_is_internal_ip_literal("[::1]"));
        assert!(xfh_is_internal_ip_literal("fe80::1"));
        // Negatives.
        assert!(!xfh_is_internal_ip_literal(""));
        assert!(!xfh_is_internal_ip_literal("api.example.com"));
        assert!(!xfh_is_internal_ip_literal("8.8.8.8"));
        assert!(!xfh_is_internal_ip_literal("172.32.0.1"));
        assert!(!xfh_is_internal_ip_literal("256.0.0.1"));
        assert!(!xfh_is_internal_ip_literal("not-an-ip"));
    }

    // GAP-011 (Run-6, 2026-05-09) — URL-override-header bypass.
    // X-Original-URL / X-Rewrite-URL carrying admin / recon /
    // traversal paths flag with sub-tag `url_override_bypass`.

    fn url_override_view(name: &'static str, val: &[u8]) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        h.insert("host", "api.example.com".parse().unwrap());
        if let Ok(v) = http::HeaderValue::from_bytes(val) {
            h.insert(name, v);
        }
        h
    }

    macro_rules! url_override_blocks {
        ($name:ident, $header:expr, $value:expr) => {
            #[test]
            fn $name() {
                let d = HeaderInjectionDetector;
                let u: http::Uri = "/".parse().unwrap();
                let m = http::Method::GET;
                let h = url_override_view($header, $value);
                let b = BodyPeek::empty();
                let req = make_view_with_headers(&m, &u, &h, &b);
                let signals = d.inspect(&req);
                assert!(
                    signals.iter().any(|s| s.tag == "url_override_bypass"),
                    "expected url_override_bypass for {} = {:?}, got {:?}",
                    $header,
                    std::str::from_utf8($value).unwrap_or("<binary>"),
                    signals,
                );
            }
        };
    }
    url_override_blocks!(uo_x_original_admin,         "x-original-url", b"/admin/users");
    url_override_blocks!(uo_x_original_administrator, "x-original-url", b"/administrator/index.php");
    url_override_blocks!(uo_x_original_wp_admin,      "x-original-url", b"/wp-admin/options.php");
    url_override_blocks!(uo_x_original_console,       "x-original-url", b"/console");
    url_override_blocks!(uo_x_original_internal,      "x-original-url", b"/__internal/health");
    url_override_blocks!(uo_x_rewrite_admin,          "x-rewrite-url", b"/admin");
    url_override_blocks!(uo_x_override_manage,        "x-override-url", b"/manage");
    url_override_blocks!(uo_x_method_override,        "x-http-method-override-url", b"/admin/db");
    url_override_blocks!(uo_x_original_env,           "x-original-url", b"/.env");
    url_override_blocks!(uo_x_original_wp_config,     "x-original-url", b"/wp-config.php");
    url_override_blocks!(uo_x_original_git,           "x-original-url", b"/.git/config");
    url_override_blocks!(uo_x_original_aws_creds,     "x-original-url", b"/.aws/credentials");
    url_override_blocks!(uo_x_original_traversal,     "x-original-url", b"/../../../etc/passwd");
    url_override_blocks!(uo_x_original_encoded,       "x-original-url", b"/%2Fadmin%2Fusers");
    url_override_blocks!(uo_x_original_double_enc,    "x-original-url", b"/%252e%252e/admin");

    // Score is the CRLF tier (40) — header heuristic.
    #[test]
    fn url_override_emits_header_tier_score() {
        let d = HeaderInjectionDetector;
        let u: http::Uri = "/".parse().unwrap();
        let m = http::Method::GET;
        let h = url_override_view("x-original-url", b"/admin/users");
        let b = BodyPeek::empty();
        let req = make_view_with_headers(&m, &u, &h, &b);
        let signal = d.inspect(&req)
            .into_iter()
            .find(|s| s.tag == "url_override_bypass")
            .expect("url_override_bypass signal");
        assert_eq!(signal.score, 70, "url_override_bypass should score 70 (header tier — CRLF)");
        assert_eq!(signal.field, "x-original-url");
    }

    // Negatives — must NOT fire on legitimate API paths.
    macro_rules! url_override_clean {
        ($name:ident, $header:expr, $value:expr) => {
            #[test]
            fn $name() {
                let d = HeaderInjectionDetector;
                let u: http::Uri = "/".parse().unwrap();
                let m = http::Method::GET;
                let h = url_override_view($header, $value);
                let b = BodyPeek::empty();
                let req = make_view_with_headers(&m, &u, &h, &b);
                let signals: Vec<_> = d
                    .inspect(&req)
                    .into_iter()
                    .filter(|s| s.tag == "url_override_bypass")
                    .collect();
                assert!(
                    signals.is_empty(),
                    "false positive url_override_bypass for {} = {:?}: {:?}",
                    $header,
                    std::str::from_utf8($value).unwrap_or("<binary>"),
                    signals,
                );
            }
        };
    }
    url_override_clean!(uo_clean_api_users,    "x-original-url", b"/api/users");
    url_override_clean!(uo_clean_products,     "x-original-url", b"/products/123");
    url_override_clean!(uo_clean_static,       "x-rewrite-url", b"/static/main.js");
    url_override_clean!(uo_clean_health,       "x-original-url", b"/health");
    url_override_clean!(uo_clean_metrics,      "x-original-url", b"/metrics");
    url_override_clean!(uo_clean_sub_admin,    "x-original-url", b"/api/v1/users-admin-list"); // contains "admin" but not as path prefix

    #[test]
    fn url_override_absent_header_does_not_flag() {
        let d = HeaderInjectionDetector;
        let u: http::Uri = "/".parse().unwrap();
        let m = http::Method::GET;
        let mut h = http::HeaderMap::new();
        h.insert("host", "api.example.com".parse().unwrap());
        let b = BodyPeek::empty();
        let req = make_view_with_headers(&m, &u, &h, &b);
        assert!(
            !d.inspect(&req).iter().any(|s| s.tag == "url_override_bypass"),
            "no header → no signal",
        );
    }

    // 2026-05-09 — Run-7 INFO-002. Method-override headers
    // carrying destructive verbs (DELETE/PUT/PATCH/CONNECT/TRACE)
    // fire the method_override_bypass sub-tag at score 35.
    // Conservative — POST stays unflagged because Rails / Express
    // form posts use these headers legitimately.

    fn method_override_view(name: &'static str, val: &[u8]) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        h.insert("host", "api.example.com".parse().unwrap());
        if let Ok(v) = http::HeaderValue::from_bytes(val) {
            h.insert(name, v);
        }
        h
    }

    macro_rules! method_override_blocks {
        ($name:ident, $header:expr, $value:expr) => {
            #[test]
            fn $name() {
                let d = HeaderInjectionDetector;
                let u: http::Uri = "/".parse().unwrap();
                let m = http::Method::GET;
                let h = method_override_view($header, $value);
                let b = BodyPeek::empty();
                let req = make_view_with_headers(&m, &u, &h, &b);
                let signals = d.inspect(&req);
                assert!(
                    signals.iter().any(|s| s.tag == "method_override_bypass"),
                    "expected method_override_bypass for {} = {:?}, got {:?}",
                    $header,
                    std::str::from_utf8($value).unwrap_or("<binary>"),
                    signals,
                );
            }
        };
    }
    method_override_blocks!(mo_x_http_method_override_delete,  "x-http-method-override", b"DELETE");
    method_override_blocks!(mo_x_http_method_override_put,     "x-http-method-override", b"PUT");
    method_override_blocks!(mo_x_http_method_override_patch,   "x-http-method-override", b"PATCH");
    method_override_blocks!(mo_x_http_method_override_connect, "x-http-method-override", b"CONNECT");
    method_override_blocks!(mo_x_http_method_override_trace,   "x-http-method-override", b"TRACE");
    method_override_blocks!(mo_x_method_override_delete,       "x-method-override", b"DELETE");
    method_override_blocks!(mo_x_http_method_delete,           "x-http-method", b"DELETE");
    method_override_blocks!(mo_lowercase_delete,               "x-http-method-override", b"delete");
    method_override_blocks!(mo_with_whitespace,                "x-http-method-override", b"  DELETE  ");

    macro_rules! method_override_clean {
        ($name:ident, $header:expr, $value:expr) => {
            #[test]
            fn $name() {
                let d = HeaderInjectionDetector;
                let u: http::Uri = "/".parse().unwrap();
                let m = http::Method::GET;
                let h = method_override_view($header, $value);
                let b = BodyPeek::empty();
                let req = make_view_with_headers(&m, &u, &h, &b);
                let signals: Vec<_> = d
                    .inspect(&req)
                    .into_iter()
                    .filter(|s| s.tag == "method_override_bypass")
                    .collect();
                assert!(
                    signals.is_empty(),
                    "false positive method_override_bypass for {} = {:?}: {:?}",
                    $header,
                    std::str::from_utf8($value).unwrap_or("<binary>"),
                    signals,
                );
            }
        };
    }
    // POST is intentionally NOT flagged — Rails / Express use it
    // for legit form-post overrides. GET / HEAD / OPTIONS are safe
    // verbs. Empty / missing headers stay green.
    method_override_clean!(mo_clean_post,    "x-http-method-override", b"POST");
    method_override_clean!(mo_clean_get,     "x-http-method-override", b"GET");
    method_override_clean!(mo_clean_head,    "x-http-method-override", b"HEAD");
    method_override_clean!(mo_clean_options, "x-http-method-override", b"OPTIONS");

    // Score check.
    #[test]
    fn method_override_emits_header_tier_score() {
        let d = HeaderInjectionDetector;
        let u: http::Uri = "/".parse().unwrap();
        let m = http::Method::GET;
        let h = method_override_view("x-http-method-override", b"DELETE");
        let b = BodyPeek::empty();
        let req = make_view_with_headers(&m, &u, &h, &b);
        let signal = d.inspect(&req)
            .into_iter()
            .find(|s| s.tag == "method_override_bypass")
            .expect("method_override_bypass signal");
        assert_eq!(signal.score, 50, "method_override_bypass should score 50 (header tier — XFH)");
    }

    // 2026-06-12 (HTTP_SMUGGLING_REPORT, workstream B1) — request-
    // smuggling header hygiene. These unit tests bypass hyper and feed
    // the detector the framing shape directly, so they pin the detector
    // LOGIC; whether hyper delivers a given shape to the detector at
    // runtime is a separate (environment) question — see the QC doc.

    fn smuggling_signals(h: http::HeaderMap, version: http::Version) -> Vec<Signal> {
        let d = HeaderInjectionDetector;
        let m = http::Method::POST;
        let u: http::Uri = "/".parse().unwrap();
        let b = BodyPeek::empty();
        let req = RequestView {
            method: &m,
            uri: &u,
            version,
            headers: &h,
            peer: "127.0.0.1:1234".parse().unwrap(),
            tls: None,
            body: &b,
        };
        d.inspect(&req)
    }

    fn has(signals: &[Signal], tag: &str) -> bool {
        signals.iter().any(|s| s.tag == tag)
    }

    #[test]
    fn smuggling_cl_te_flags() {
        let mut h = http::HeaderMap::new();
        h.insert("content-length", "4".parse().unwrap());
        h.insert("transfer-encoding", "chunked".parse().unwrap());
        assert!(has(&smuggling_signals(h, http::Version::HTTP_11), "smuggling_cl_te"));
    }

    #[test]
    fn smuggling_multi_cl_flags() {
        let mut h = http::HeaderMap::new();
        h.append("content-length", "5".parse().unwrap());
        h.append("content-length", "6".parse().unwrap());
        assert!(has(&smuggling_signals(h, http::Version::HTTP_11), "smuggling_multi_cl"));
    }

    #[test]
    fn smuggling_multi_te_header_flags() {
        let mut h = http::HeaderMap::new();
        h.append("transfer-encoding", "chunked".parse().unwrap());
        h.append("transfer-encoding", "identity".parse().unwrap());
        assert!(has(&smuggling_signals(h, http::Version::HTTP_11), "smuggling_multi_te"));
    }

    #[test]
    fn smuggling_obfuscated_te_value_flags() {
        let mut h = http::HeaderMap::new();
        h.insert("transfer-encoding", "xchunked".parse().unwrap());
        assert!(has(&smuggling_signals(h, http::Version::HTTP_11), "smuggling_multi_te"));
    }

    #[test]
    fn smuggling_multi_directive_te_flags() {
        let mut h = http::HeaderMap::new();
        h.insert("transfer-encoding", "chunked, identity".parse().unwrap());
        assert!(has(&smuggling_signals(h, http::Version::HTTP_11), "smuggling_multi_te"));
    }

    #[test]
    fn smuggling_h2_transfer_encoding_flags() {
        let mut h = http::HeaderMap::new();
        h.insert("transfer-encoding", "chunked".parse().unwrap());
        assert!(has(&smuggling_signals(h, http::Version::HTTP_2), "smuggling_h2_forbidden"));
    }

    #[test]
    fn smuggling_h2_connection_flags() {
        let mut h = http::HeaderMap::new();
        h.insert("connection", "keep-alive".parse().unwrap());
        assert!(has(&smuggling_signals(h, http::Version::HTTP_2), "smuggling_h2_forbidden"));
    }

    #[test]
    fn smuggling_emits_block_tier_score() {
        let mut h = http::HeaderMap::new();
        h.insert("content-length", "4".parse().unwrap());
        h.insert("transfer-encoding", "chunked".parse().unwrap());
        let s = smuggling_signals(h, http::Version::HTTP_11);
        let sig = s.iter().find(|s| s.tag.starts_with("smuggling_")).expect("signal");
        assert_eq!(sig.score, 70, "smuggling is block tier (70)");
    }

    #[test]
    fn smuggling_one_signal_per_request() {
        // CL+TE and a duplicate TE both present — must emit exactly ONE
        // smuggling signal (no risk amplification).
        let mut h = http::HeaderMap::new();
        h.insert("content-length", "4".parse().unwrap());
        h.append("transfer-encoding", "chunked".parse().unwrap());
        h.append("transfer-encoding", "x".parse().unwrap());
        let n = smuggling_signals(h, http::Version::HTTP_11)
            .iter()
            .filter(|s| s.tag.starts_with("smuggling_"))
            .count();
        assert_eq!(n, 1, "at most one smuggling signal per request");
    }

    // Negatives — legitimate framing must not flag.

    #[test]
    fn smuggling_single_cl_clean() {
        let mut h = http::HeaderMap::new();
        h.insert("content-length", "42".parse().unwrap());
        assert!(!has(&smuggling_signals(h, http::Version::HTTP_11), "smuggling_cl_te"));
    }

    #[test]
    fn smuggling_single_chunked_te_clean() {
        let mut h = http::HeaderMap::new();
        h.insert("transfer-encoding", "chunked".parse().unwrap());
        let s = smuggling_signals(h, http::Version::HTTP_11);
        assert!(!s.iter().any(|s| s.tag.starts_with("smuggling_")), "got {s:?}");
    }

    #[test]
    fn smuggling_single_gzip_te_clean() {
        let mut h = http::HeaderMap::new();
        h.insert("transfer-encoding", "gzip".parse().unwrap());
        let s = smuggling_signals(h, http::Version::HTTP_11);
        assert!(!s.iter().any(|s| s.tag.starts_with("smuggling_")), "got {s:?}");
    }

    #[test]
    fn smuggling_h1_connection_clean() {
        // `Connection` is legitimate on HTTP/1.1 — only forbidden on h2.
        let mut h = http::HeaderMap::new();
        h.insert("connection", "keep-alive".parse().unwrap());
        let s = smuggling_signals(h, http::Version::HTTP_11);
        assert!(!s.iter().any(|s| s.tag.starts_with("smuggling_")), "got {s:?}");
    }

    #[test]
    fn smuggling_te_obfuscation_unit() {
        assert!(!te_value_is_obfuscated("chunked"));
        assert!(!te_value_is_obfuscated("gzip"));
        assert!(!te_value_is_obfuscated("CHUNKED"));
        assert!(te_value_is_obfuscated("xchunked"));
        assert!(te_value_is_obfuscated("chunked, identity"));
        // OWS around a token is trimmed → a trailing-space "chunked "
        // is treated as clean (hyper would have normalised it anyway).
        assert!(!te_value_is_obfuscated("chunked "));
    }
}
