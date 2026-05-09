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
        r"(?i)javascript\s*:",
        r"(?i)vbscript\s*:",
        r"(?i)on(?:load|error|click|mouse|focus|blur|submit|change|key|drag|touch|animat|transitionend)\s*=",
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
        r"(?i)\\u00[0-9a-f]{2}",
        r#"(?i)<meta\s+[^>]*http-equiv\s*=\s*['"]?refresh"#,
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

        // GAP-012 (Run-6, 2026-05-09) — three-stage decode chain:
        // raw → URL-decoded → HTML-entity-decoded. The named-entity
        // bypass (`&lt;script&gt;`) doesn't match the existing
        // `&#NN;` numeric-entity pattern; entity-decoding the value
        // before pattern match closes that gap.
        let raw_uri = req.uri.to_string();
        let url_decoded_uri = super::url_decode(&raw_uri);
        let entity_decoded_uri = super::html_entity_decode(&url_decoded_uri);
        check_xss(&url_decoded_uri, "uri", &mut signals);
        if entity_decoded_uri != url_decoded_uri {
            check_xss(&entity_decoded_uri, "uri", &mut signals);
        }

        let body = std::str::from_utf8(req.body.peek(8192)).unwrap_or("");
        if !body.is_empty() {
            let url_decoded_body = super::url_decode(body);
            let entity_decoded_body = super::html_entity_decode(&url_decoded_body);
            check_xss(&url_decoded_body, "body", &mut signals);
            if entity_decoded_body != url_decoded_body {
                check_xss(&entity_decoded_body, "body", &mut signals);
            }
        }

        for name in &["cookie", "referer", "user-agent"] {
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
    positive!(xss_javascript_proto, "/?q=javascript:void(0)");
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
    positive!(xss_unicode_escape, "/?q=\\u0041");
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
}
