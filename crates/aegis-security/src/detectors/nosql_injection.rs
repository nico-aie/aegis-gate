//! NoSQL injection detector (MongoDB-flavored operator
//! injection).
//!
//! 2026-05-08 (Run-5 GAP-007) — closes the gap that AI alone was
//! covering pre-fix. Detects MongoDB operator injection in two
//! surfaces: query-string (`?username[$ne]=invalid`) and JSON
//! request bodies (`{"$where": "function(){return true}"}`).
//!
//! ## Why a dedicated detector
//!
//! sqli patterns target SQL syntax (UNION, SELECT, OR 1=1,
//! comment markers). NoSQL operator injection has a completely
//! different syntax — bracketed operator names in query strings
//! and `$`-prefixed keys in JSON bodies. Folding these into sqli
//! would break the cohesion of the sqli pattern set; splitting
//! keeps both detectors' patterns coherent and makes
//! `set_profile { policies: ["nosql_injection"], mode: "log_only" }`
//! a single-target operator knob.
//!
//! ## Detection logic
//!
//! The MongoDB query-operator vocabulary is **closed** and
//! **documented** — `$ne`, `$gt`, `$where`, etc. The detector
//! matches **only** documented operator names; bare `$` in URL
//! values (e.g. `?cost=$10` for currency, `?id=$1` for Postgres
//! parameter placeholders) doesn't match because the pattern
//! requires `[$<word>]` brackets or `"$<word>":` JSON-key shape.
//!
//! Why not parse the JSON body to find `$`-prefixed keys?
//! Parsing every JSON body would add real cost on every request
//! (regex is faster). The string-match `"$<op>":` pattern is
//! cheap and equivalent for valid JSON; for malformed JSON,
//! neither approach is reliable. We accept the regex cost.
//!
//! Score 50 — high-confidence injection tier (same as sqli, xss,
//! ssrf, cmdi). NoSQL operator injection is auth-bypass /
//! data-exfil class. Pattern is so specific (closed operator
//! vocabulary) that legit Postgres `$1` placeholders, currency
//! strings, and template variables never match.

use aegis_core::pipeline::RequestView;
use regex::Regex;
use std::sync::LazyLock;

use super::{Detector, Signal};

pub struct NoSqlInjectionDetector;

static NOSQL_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        // Query string: `param[$ne]=foo`, `param[$where]=...`.
        // The `[$<op>]` shape only appears in NoSQL operator
        // injection — legit URL params don't wrap operator names
        // in brackets. Operator allowlist is the documented
        // MongoDB query-operator vocabulary.
        r"(?i)\[\$(?:ne|gt|gte|lt|lte|in|nin|eq|regex|where|or|and|not|nor|exists|type|elemMatch|all|size|expr|jsonSchema|mod|geoIntersects|geoWithin|near|nearSphere|text|search|comment)\]",

        // JSON body: `"$ne":`, `"$where":`. Conservative — leading
        // double-quote + closing double-quote-colon shape is the
        // canonical JSON key form. Legit fields whose VALUE
        // contains `$` (currency, template strings) don't match
        // because the `$` is in the value, not the key position.
        r#"(?i)"\$(?:ne|gt|gte|lt|lte|in|nin|eq|regex|where|or|and|not|nor|exists|type|elemMatch|all|size|expr|jsonSchema|mod|geoIntersects|geoWithin|near|nearSphere|text|search|comment)"\s*:"#,

        // CouchDB / Mongo `$where` JS evaluation. Already matched
        // by the two patterns above when serialized correctly,
        // but this third pattern catches `db.find({$where: ...})`-
        // shaped legacy serializers that omit the quote.
        r"(?i)\$where\s*:\s*function\s*\(",
    ]
    .iter()
    .map(|p| Regex::new(p).expect("nosql regex compiles"))
    .collect()
});

impl Detector for NoSqlInjectionDetector {
    fn id(&self) -> &'static str {
        "nosql_injection"
    }

    fn inspect(&self, req: &RequestView<'_>) -> Vec<Signal> {
        let mut signals = Vec::new();

        // URI surface — both raw and url-decoded.
        let raw_uri = req.uri.to_string();
        let decoded_uri = super::url_decode(&raw_uri);
        check(&raw_uri, "uri", &mut signals);
        check(&decoded_uri, "uri", &mut signals);

        // Body — first 8 KiB, decoded.
        let body = std::str::from_utf8(req.body.peek(8192)).unwrap_or("");
        if !body.is_empty() {
            let decoded_body = super::url_decode(body);
            check(body, "body", &mut signals);
            check(&decoded_body, "body", &mut signals);
        }

        // Cookie values — NoSQL operators smuggled via session/other
        // cookies (`Cookie: sid={"$gt":""}`). The operator vocabulary is so
        // specific (`[$ne]` brackets / `"$where":` JSON-key shape) that a
        // normal opaque session token (`sid=F1X3IwA8…`) never matches, so
        // scanning the cookie here is safe FP-wise — unlike the broad
        // sqli/nosqli-in-cookie scan that lives behind the default-OFF
        // CookieInjection class.
        if signals.is_empty() {
            if let Some(cookie) = req.headers.get("cookie").and_then(|v| v.to_str().ok()) {
                check(cookie, "cookie", &mut signals);
                if signals.is_empty() {
                    check(&super::url_decode(cookie), "cookie", &mut signals);
                }
            }
        }

        signals
    }
}

fn check(input: &str, field: &str, signals: &mut Vec<Signal>) {
    for re in NOSQL_PATTERNS.iter() {
        if re.is_match(input) {
            signals.push(Signal {
                score: super::scores::nosql_injection::NOSQL_INJECTION,
                tag: "nosql_injection".into(),
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
                let d = NoSqlInjectionDetector;
                let (m, u, h, b) = view_with_uri($input);
                let req = make_view(&m, &u, &h, &b);
                assert!(
                    !d.inspect(&req).is_empty(),
                    "expected detection for: {}",
                    $input,
                );
            }
        };
    }

    macro_rules! negative {
        ($name:ident, $input:expr) => {
            #[test]
            fn $name() {
                let d = NoSqlInjectionDetector;
                let (m, u, h, b) = view_with_uri($input);
                let req = make_view(&m, &u, &h, &b);
                assert!(
                    d.inspect(&req).is_empty(),
                    "false positive for: {}",
                    $input,
                );
            }
        };
    }

    // --- QA Run-5 reproductions ---
    positive!(nosql_qs_ne,                "/api/users?username[$ne]=invalid");
    positive!(nosql_qs_gt,                "/api/users?id[$gt]=0");

    // --- Query-string operator variants ---
    positive!(nosql_qs_regex,             "/?q[$regex]=.*");
    positive!(nosql_qs_where,             "/?q[$where]=1");
    positive!(nosql_qs_in,                "/?ids[$in]=1,2,3");
    positive!(nosql_qs_exists,            "/?f[$exists]=true");
    positive!(nosql_qs_url_encoded,       "/?q%5B%24ne%5D=invalid");

    // Body-side JSON keys — `"$ne":`, `"$where":`, etc.
    // (URI must be valid; payload lives in query for these tests.
    //  Body-surface tests would need a body-injection harness.)
    positive!(nosql_body_via_query_ne,    "/api?q={%22%24ne%22%3A%22x%22}");
    positive!(nosql_body_via_query_where,
        "/api?q={%22%24where%22%3A%22function(){return%201}%22}");

    // `$where: function(){...}` legacy serializer shape.
    positive!(nosql_where_function,
        "/?q=%7B%24where%3A%20function()%20%7B%20return%20true%20%7D%7D");

    // --- Negatives — common FP traps ---

    // Postgres `$1` parameter placeholder — legit pattern in
    // generated SQL strings that some apps reflect into URLs.
    negative!(clean_pg_placeholder,       "/api?q=$1");
    negative!(clean_pg_placeholder_2,     "/api?q=SELECT%20%24%241");

    // Currency strings.
    negative!(clean_currency,             "/api?cost=$10.50");
    negative!(clean_currency_eu,          "/api?cost=%E2%82%AC10");

    // Template-style `$` in value (not key).
    negative!(clean_template_value,       "/api?msg=hello+%24user");

    // Bare `$ne` outside brackets/quotes — appears in some
    // log strings / config files.
    negative!(clean_bare_ne,              "/api?msg=value+ne+something");

    // Field whose VALUE contains a `$`-string — value-side `$`
    // doesn't match the key-side pattern.
    negative!(clean_dollar_in_value,
        "/api?q={%22item%22%3A%22%24cost%22}");      // {"item":"$cost"}

    // Single-underscore `_id` (valid Mongo doc ID, not an operator).
    negative!(clean_underscore_id,        "/api?q={%22_id%22%3A%22abc%22}");

    // Plain queries.
    negative!(clean_root,                 "/");
    negative!(clean_simple_query,         "/api?q=hello");
    negative!(clean_array_param,          "/api?items[]=a&items[]=b");  // PHP array param, no $
    negative!(clean_legitimate_dollar,    "/api?price=10dollars");

    // --- Cookie surface (2026 — NoSQL operator smuggled via cookie) ---
    fn view_with_cookie(cookie: &str) -> (http::Method, http::Uri, http::HeaderMap, BodyPeek) {
        let mut h = http::HeaderMap::new();
        h.insert("cookie", cookie.parse().unwrap());
        (http::Method::GET, "/api/transactions".parse().unwrap(), h, BodyPeek::empty())
    }

    #[test]
    fn nosql_in_cookie_gt() {
        let d = NoSqlInjectionDetector;
        let (m, u, h, b) = view_with_cookie(r#"sid={"$gt":""}"#);
        let req = make_view(&m, &u, &h, &b);
        assert!(!d.inspect(&req).is_empty(), "NoSQL operator in cookie must fire");
    }

    #[test]
    fn nosql_in_cookie_where() {
        let d = NoSqlInjectionDetector;
        let (m, u, h, b) = view_with_cookie(r#"pref={"$where":"1"}; sid=abc"#);
        let req = make_view(&m, &u, &h, &b);
        assert!(!d.inspect(&req).is_empty(), "NoSQL $where in cookie must fire");
    }

    #[test]
    fn clean_opaque_session_cookie_no_fp() {
        let d = NoSqlInjectionDetector;
        let (m, u, h, b) = view_with_cookie("sid=F1X3IwA81DkwXf5iryzMmdCp3gB7mGPt; theme=dark");
        let req = make_view(&m, &u, &h, &b);
        assert!(d.inspect(&req).is_empty(), "opaque session cookie must not FP");
    }
}
