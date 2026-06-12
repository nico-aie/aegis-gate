//! JWT attack-shape detector (Phase A1).
//!
//! 2026-06-12 — response to `plans/issues/JWT_ATTACK_REPORT.md`. The
//! WAF previously did **not** decode JWTs carried in `Cookie` /
//! `Authorization` headers, so every alg-confusion / key-injection /
//! kid-traversal payload sailed through (the report measured ~0%
//! effective detection on 600 samples).
//!
//! This detector closes the **structural** gap: it Base64URL-decodes
//! the token *header* (JWT part 0) and flags malicious shapes. It is
//! the JWT analogue of the sqli / xss detectors — it pattern-matches an
//! attack shape in attacker-controlled input.
//!
//! ## Deliberately NOT in scope (see the plan)
//! This detector **never verifies the signature**, never handles a
//! secret/key, and makes no authenticity decision. Signature and
//! business-auth validation belong in the router/gateway, not the WAF
//! (`plans/future/jwt-and-smuggling-detection.md`,
//! `project_waf_vs_gateway_boundary` memory). Consequently the two
//! report techniques that *require* a key — weak-secret brute force
//! (the token has a valid signature) and RS256→HS256 confusion (needs
//! the app's expected alg + public key) — are out of scope by design.
//!
//! ## Phase A1 rules (all no-config, structural blocks, score 80)
//! - `jwt_alg_none`     — `alg` is `none`/`null`/empty, any case.
//! - `jwt_x5c_inline`   — header embeds inline key material (`x5c`/`jwk`).
//! - `jwt_kid_injection`— `kid` carries traversal / SQLi / URL scheme.
//!
//! `jku`/`x5u` external-host, time-claim forgery, and the role-claim
//! heuristic land in Phase A2/A3 (they need config and/or `log_only`).

use aegis_core::pipeline::RequestView;
use base64::Engine as _;
use serde_json::Value;

use super::{scores, Detector, Signal};

/// Cap on JWT-shaped tokens decoded per request. A request carries one
/// session token in practice; the cap bounds CPU against a header
/// stuffed with many fake tokens.
const MAX_TOKENS_PER_REQUEST: usize = 2;

/// Reject absurdly long encoded header parts before decoding. A real
/// JWT header is tens of bytes; even an `x5c`-bearing one is a few KB.
const MAX_ENCODED_HEADER_BYTES: usize = 16 * 1024;

/// Window for "forged" time claims — 10 years in seconds. An `exp`
/// further out than this, or an `iat` older than this, is not a clock-
/// skew artifact; it's a hand-edited token.
const TEN_YEARS_SECS: u64 = 315_360_000;

/// JWT attack-shape detector. Holds the `jku`/`x5u` host allowlist;
/// otherwise stateless.
pub struct JwtInspectionDetector {
    /// Hosts a `jku` / `x5u` URL may reference. Empty = strict mode
    /// (any external key-set URL flags). Entries are literal hostnames
    /// or `*.example.com` globs.
    jku_allowed_domains: Vec<String>,
}

impl JwtInspectionDetector {
    pub fn new(jku_allowed_domains: Vec<String>) -> Self {
        Self { jku_allowed_domains }
    }
}

impl Detector for JwtInspectionDetector {
    fn id(&self) -> &'static str {
        "jwt_inspection"
    }

    fn inspect(&self, req: &RequestView<'_>) -> Vec<Signal> {
        let mut signals = Vec::new();
        let mut budget = MAX_TOKENS_PER_REQUEST;
        let now = unix_now();

        // Authorization: Bearer <jwt> (also accept a bare JWT value).
        if budget > 0 {
            if let Some(val) = req
                .headers
                .get(http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
            {
                if let Some(tok) = bearer_token(val) {
                    if is_jwt_shaped(tok) {
                        self.inspect_token(tok, now, &mut signals);
                        budget -= 1;
                    }
                }
            }
        }

        // Cookie: name=<jwt>; … — scan every cookie value, not just a
        // hardcoded `sid` (the corpus's name): matching on the JWT
        // SHAPE rather than the cookie name avoids fixture-coupling.
        if budget > 0 {
            if let Some(cookie) = req
                .headers
                .get(http::header::COOKIE)
                .and_then(|v| v.to_str().ok())
            {
                for pair in cookie.split(';') {
                    if budget == 0 {
                        break;
                    }
                    let value = pair
                        .trim()
                        .split_once('=')
                        .map(|(_, v)| v)
                        .unwrap_or("")
                        .trim();
                    if is_jwt_shaped(value) {
                        self.inspect_token(value, now, &mut signals);
                        budget -= 1;
                    }
                }
            }
        }

        signals
    }
}

/// Strip an optional `Bearer ` (case-insensitive) prefix. Returns the
/// raw token; a value with no scheme prefix is returned as-is so a
/// bare-JWT `Authorization` value is still inspected.
fn bearer_token(value: &str) -> Option<&str> {
    let v = value.trim();
    if v.len() >= 7 && v[..7].eq_ignore_ascii_case("bearer ") {
        Some(v[7..].trim())
    } else if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

/// `header.payload.signature` shape with a base64url alphabet. Header
/// and payload must be non-empty; the signature MAY be empty (the
/// `alg:none` case ends in a trailing dot).
fn is_jwt_shaped(s: &str) -> bool {
    let mut parts = s.split('.');
    let (Some(h), Some(p), Some(sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    !h.is_empty()
        && !p.is_empty()
        && h.bytes().all(is_b64url)
        && p.bytes().all(is_b64url)
        && sig.bytes().all(is_b64url)
}

fn is_b64url(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

impl JwtInspectionDetector {
    /// Decode + inspect a single JWT-shaped token. Silent on any
    /// decode/parse failure — a token we can't read is not our signal
    /// to raise (the gateway will reject a malformed token on its own).
    fn inspect_token(&self, token: &str, now: u64, signals: &mut Vec<Signal>) {
        let mut parts = token.split('.');
        let header_part = parts.next().unwrap_or("");
        let payload_part = parts.next().unwrap_or("");
        if header_part.len() > MAX_ENCODED_HEADER_BYTES {
            return;
        }
        let Some(header) = decode_json_object(header_part) else {
            return;
        };

        // RULE jwt_alg_none — `alg` none/null/empty, case-insensitive.
        if let Some(alg) = header.get("alg").and_then(|v| v.as_str()) {
            let a = alg.trim().to_ascii_lowercase();
            if a == "none" || a == "null" || a.is_empty() {
                signals.push(Signal {
                    score: scores::jwt_inspection::ALG_NONE,
                    tag: "jwt_alg_none".into(),
                    field: "jwt:alg".into(),
                });
            }
        }

        // RULE jwt_x5c_inline — inline key material (`x5c` cert chain
        // or `jwk`). Presence of the key alone is the signal;
        // production tokens fetch keys from a server-side JWKS.
        if header.contains_key("x5c") || header.contains_key("jwk") {
            signals.push(Signal {
                score: scores::jwt_inspection::KEY_INJECTION,
                tag: "jwt_x5c_inline".into(),
                field: "jwt:x5c".into(),
            });
        }

        // RULE jwt_kid_injection — traversal / SQLi / URL scheme in `kid`.
        if let Some(kid) = header.get("kid").and_then(|v| v.as_str()) {
            if kid_is_malicious(kid) {
                signals.push(Signal {
                    score: scores::jwt_inspection::KID_INJECTION,
                    tag: "jwt_kid_injection".into(),
                    field: "jwt:kid".into(),
                });
            }
        }

        // RULE jwt_jku_external — `jku` / `x5u` key-set URL pointing at
        // a host outside the allowlist (empty allowlist = any external
        // URL). SSRF + attacker-controlled-JWKS signature bypass.
        for field in ["jku", "x5u"] {
            if let Some(url) = header.get(field).and_then(|v| v.as_str()) {
                if !self.jku_host_allowed(url) {
                    signals.push(Signal {
                        score: scores::jwt_inspection::JKU_EXTERNAL,
                        tag: "jwt_jku_external".into(),
                        field: format!("jwt:{field}"),
                    });
                }
            }
        }

        // RULE jwt_time_forged — hand-edited time claims in the payload.
        if let Some(payload) = decode_json_object(payload_part) {
            if time_claims_forged(&payload, now) {
                signals.push(Signal {
                    score: scores::jwt_inspection::TIME_FORGED,
                    tag: "jwt_time_forged".into(),
                    field: "jwt:exp".into(),
                });
            }
        }
    }

    /// True when a `jku`/`x5u` URL's host is on the allowlist. An
    /// unparseable URL (no host) is treated as NOT allowed — a token
    /// whose key-set URL we can't even read is not one to trust.
    fn jku_host_allowed(&self, url: &str) -> bool {
        let Some(host) = url_host(url) else {
            return false;
        };
        self.jku_allowed_domains
            .iter()
            .any(|entry| domain_matches(entry, &host))
    }
}

/// Base64URL-decode (no padding) and parse a JWT part as a JSON object.
/// Returns `None` for any non-object or undecodable input.
fn decode_json_object(part: &str) -> Option<serde_json::Map<String, Value>> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(part)
        .ok()?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    match value {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

/// True when a `kid` carries a non-benign shape: path traversal, an
/// absolute system path, a URL/file scheme, or SQL metacharacters.
///
/// Conservative by construction — a normal `kid` is an opaque key id
/// (UUID, `2024-09-key`, `keys/active`). A single `/` is fine; only
/// `../`, absolute system roots, schemes, and SQL metachars flag, so a
/// path-style key id does not false-positive.
fn kid_is_malicious(kid: &str) -> bool {
    // Path traversal.
    if kid.contains("../") || kid.contains("..\\") {
        return true;
    }
    let lc = kid.to_ascii_lowercase();
    // Absolute system paths — known-content files used to forge an
    // empty / predictable HMAC key (`/dev/null`, `/etc/passwd`, …).
    for root in ["/etc/", "/dev/", "/proc/", "/sys/"] {
        if lc.starts_with(root) {
            return true;
        }
    }
    // Remote key fetch (SSRF / RFI) via URL or file scheme.
    for scheme in ["http://", "https://", "file://"] {
        if lc.starts_with(scheme) {
            return true;
        }
    }
    // SQL injection into a key-lookup query. Metacharacters first…
    if kid.contains('\'') || kid.contains('"') || kid.contains(';') || kid.contains("--") {
        return true;
    }
    // …then space-delimited keywords (require surrounding spaces so a
    // legit `kid` like `selection-key` / `android-2024` stays green).
    for kw in [" or ", " and ", " union", "union ", " select", "select "] {
        if lc.contains(kw) {
            return true;
        }
    }
    false
}

/// Extract the lowercased host from a URL string. Returns `None` when
/// there's no `scheme://host` shape. Strips an optional `userinfo@`
/// prefix and a trailing `:port` / path / query / fragment.
fn url_host(url: &str) -> Option<String> {
    let after_scheme = url.split("://").nth(1)?;
    // authority ends at the first '/', '?', or '#'.
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    // drop userinfo (`user:pass@host`).
    let hostport = authority.rsplit('@').next().unwrap_or(authority);
    // drop `:port` — but not inside a bracketed IPv6 literal.
    let host = if let Some(stripped) = hostport.strip_prefix('[') {
        stripped.split(']').next().unwrap_or(stripped)
    } else {
        hostport.split(':').next().unwrap_or(hostport)
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// Allowlist match: `entry` is a literal host (`auth.example.com`) or a
/// `*.example.com` glob (matches any sub-domain, not the bare apex).
/// `host` is already lowercased.
fn domain_matches(entry: &str, host: &str) -> bool {
    let entry = entry.trim().to_ascii_lowercase();
    if let Some(suffix) = entry.strip_prefix("*.") {
        host.ends_with(&format!(".{suffix}"))
    } else {
        host == entry
    }
}

/// Forged-time-claim heuristic over the decoded payload. Flags an
/// `exp` more than 10 years out, an `iat` more than 10 years old, or
/// the classic `iat==0 && nbf==0` epoch-forged pair.
fn time_claims_forged(payload: &serde_json::Map<String, Value>, now: u64) -> bool {
    let exp = payload.get("exp").and_then(Value::as_u64);
    let iat = payload.get("iat").and_then(Value::as_u64);
    let nbf = payload.get("nbf").and_then(Value::as_u64);

    if let Some(exp) = exp {
        if exp > now.saturating_add(TEN_YEARS_SECS) {
            return true;
        }
    }
    if let Some(iat) = iat {
        if iat < now.saturating_sub(TEN_YEARS_SECS) {
            return true;
        }
    }
    // Both issued-at AND not-before pinned to the Unix epoch — no real
    // issuer does this; it's a hand-zeroed forgery.
    matches!((iat, nbf), (Some(0), Some(0)))
}

/// Current Unix time in seconds. Falls back to 0 if the clock is set
/// before the epoch (the `exp`/`iat` windows degrade gracefully).
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::pipeline::BodyPeek;

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

    /// Encode a JWT with the given header JSON and a fixed dummy
    /// payload + signature.
    fn tok(header_json: &str) -> String {
        tok2(header_json, r#"{"user":"a"}"#)
    }

    /// Encode a JWT with explicit header + payload JSON.
    fn tok2(header_json: &str, payload_json: &str) -> String {
        let enc = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s);
        format!("{}.{}.sig", enc(header_json), enc(payload_json))
    }

    /// Run the detector (strict, empty allowlist) with the token in a
    /// `Cookie: sid=`.
    fn signals_for_cookie(token: &str) -> Vec<Signal> {
        signals_for_cookie_with(token, vec![])
    }

    /// Run the detector with an explicit `jku` allowlist.
    fn signals_for_cookie_with(token: &str, allowlist: Vec<String>) -> Vec<Signal> {
        let mut h = http::HeaderMap::new();
        h.insert("cookie", format!("sid={token}").parse().unwrap());
        let m = http::Method::GET;
        let u: http::Uri = "/".parse().unwrap();
        let b = BodyPeek::empty();
        let req = make_view(&m, &u, &h, &b);
        JwtInspectionDetector::new(allowlist).inspect(&req)
    }

    fn has_tag(signals: &[Signal], tag: &str) -> bool {
        signals.iter().any(|s| s.tag == tag)
    }

    // ---- jwt_alg_none -----------------------------------------------

    macro_rules! alg_none_positive {
        ($name:ident, $alg:expr) => {
            #[test]
            fn $name() {
                let t = tok(&format!(r#"{{"alg":"{}","typ":"JWT"}}"#, $alg));
                assert!(
                    has_tag(&signals_for_cookie(&t), "jwt_alg_none"),
                    "expected jwt_alg_none for alg={:?}",
                    $alg,
                );
            }
        };
    }
    alg_none_positive!(alg_none_lower, "none");
    alg_none_positive!(alg_none_title, "None");
    alg_none_positive!(alg_none_upper, "NONE");
    alg_none_positive!(alg_none_mixed, "nOnE");
    alg_none_positive!(alg_none_alt, "NoNe");
    alg_none_positive!(alg_none_trailing, "nonE");
    alg_none_positive!(alg_none_null, "null");
    alg_none_positive!(alg_none_padded, " none ");

    #[test]
    fn alg_empty_string_flags() {
        let t = tok(r#"{"alg":"","typ":"JWT"}"#);
        assert!(has_tag(&signals_for_cookie(&t), "jwt_alg_none"));
    }

    #[test]
    fn alg_none_real_corpus_header() {
        // The report's ID=2 header decodes to {"alg":"none","typ":"JWT"}.
        let t = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.";
        assert!(has_tag(&signals_for_cookie(t), "jwt_alg_none"));
    }

    // ---- jwt_x5c_inline ---------------------------------------------

    #[test]
    fn x5c_present_flags() {
        let t = tok(r#"{"alg":"RS256","typ":"JWT","x5c":["MIICIjANBg=="]}"#);
        assert!(has_tag(&signals_for_cookie(&t), "jwt_x5c_inline"));
    }

    #[test]
    fn jwk_inline_flags() {
        let t = tok(r#"{"alg":"RS256","typ":"JWT","jwk":{"kty":"RSA","n":"x","e":"AQAB"}}"#);
        assert!(has_tag(&signals_for_cookie(&t), "jwt_x5c_inline"));
    }

    // ---- jwt_kid_injection ------------------------------------------

    macro_rules! kid_positive {
        ($name:ident, $kid:expr) => {
            #[test]
            fn $name() {
                let t = tok(&format!(r#"{{"alg":"HS256","kid":"{}"}}"#, $kid));
                assert!(
                    has_tag(&signals_for_cookie(&t), "jwt_kid_injection"),
                    "expected jwt_kid_injection for kid={:?}",
                    $kid,
                );
            }
        };
    }
    kid_positive!(kid_dev_null, "/dev/null");
    kid_positive!(kid_traversal, "../../dev/null");
    kid_positive!(kid_etc_passwd, "/etc/passwd");
    kid_positive!(kid_proc, "/proc/self/environ");
    kid_positive!(kid_sql_quote, "key' OR '1'='1");
    kid_positive!(kid_sql_drop, "k'; DROP TABLE signing_keys; --");
    kid_positive!(kid_union, "key UNION SELECT secret");
    kid_positive!(kid_http_scheme, "http://attacker.com/evil.key");
    kid_positive!(kid_file_scheme, "file:///etc/passwd");
    kid_positive!(kid_backslash_traversal, r"..\\..\\windows");

    // ---- negatives: legitimate tokens must stay green ---------------

    macro_rules! clean_header {
        ($name:ident, $json:expr) => {
            #[test]
            fn $name() {
                let t = tok($json);
                let s = signals_for_cookie(&t);
                assert!(s.is_empty(), "false positive for header {}: {:?}", $json, s);
            }
        };
    }
    clean_header!(clean_hs256, r#"{"alg":"HS256","typ":"JWT"}"#);
    clean_header!(clean_rs256, r#"{"alg":"RS256","typ":"JWT"}"#);
    clean_header!(clean_es256, r#"{"alg":"ES256","typ":"JWT"}"#);
    clean_header!(clean_hs512, r#"{"alg":"HS512","typ":"JWT"}"#);
    clean_header!(clean_kid_uuid, r#"{"alg":"RS256","kid":"550e8400-e29b-41d4-a716"}"#);
    clean_header!(clean_kid_dated, r#"{"alg":"RS256","kid":"2024-09-signing-key"}"#);
    clean_header!(clean_kid_pathish, r#"{"alg":"RS256","kid":"keys/active"}"#);
    clean_header!(clean_kid_selection, r#"{"alg":"HS256","kid":"selection-key-7"}"#);
    clean_header!(clean_kid_android, r#"{"alg":"HS256","kid":"android-prod-2024"}"#);
    clean_header!(clean_no_kid, r#"{"alg":"RS256","typ":"JWT"}"#);

    #[test]
    fn non_jwt_cookie_is_ignored() {
        let mut h = http::HeaderMap::new();
        h.insert("cookie", "sid=abc123sessionid; theme=dark".parse().unwrap());
        let m = http::Method::GET;
        let u: http::Uri = "/".parse().unwrap();
        let b = BodyPeek::empty();
        let req = make_view(&m, &u, &h, &b);
        assert!(JwtInspectionDetector::new(vec![]).inspect(&req).is_empty());
    }

    #[test]
    fn no_cookie_no_auth_is_clean() {
        let h = http::HeaderMap::new();
        let m = http::Method::GET;
        let u: http::Uri = "/".parse().unwrap();
        let b = BodyPeek::empty();
        let req = make_view(&m, &u, &h, &b);
        assert!(JwtInspectionDetector::new(vec![]).inspect(&req).is_empty());
    }

    #[test]
    fn malformed_base64_header_is_ignored() {
        // Shape-valid (three dot-separated b64url segments) but the
        // header doesn't decode to JSON — silent, no signal.
        let s = signals_for_cookie("not-valid-b64url-but-shaped.payload.sig");
        // `inspect_token` runs but decode fails → no signal.
        assert!(s.is_empty());
    }

    #[test]
    fn two_part_token_is_not_jwt_shaped() {
        assert!(!is_jwt_shaped("header.payload"));
    }

    #[test]
    fn empty_signature_is_jwt_shaped() {
        // alg:none tokens end in a trailing dot — sig segment empty.
        assert!(is_jwt_shaped("aGVhZGVy.cGF5bG9hZA."));
    }

    // ---- transport variants -----------------------------------------

    #[test]
    fn alg_none_via_authorization_bearer() {
        let t = tok(r#"{"alg":"none","typ":"JWT"}"#);
        let mut h = http::HeaderMap::new();
        h.insert("authorization", format!("Bearer {t}").parse().unwrap());
        let m = http::Method::GET;
        let u: http::Uri = "/".parse().unwrap();
        let b = BodyPeek::empty();
        let req = make_view(&m, &u, &h, &b);
        assert!(has_tag(&JwtInspectionDetector::new(vec![]).inspect(&req), "jwt_alg_none"));
    }

    #[test]
    fn bearer_prefix_is_case_insensitive() {
        let t = tok(r#"{"alg":"none"}"#);
        let mut h = http::HeaderMap::new();
        h.insert("authorization", format!("bEaReR {t}").parse().unwrap());
        let m = http::Method::GET;
        let u: http::Uri = "/".parse().unwrap();
        let b = BodyPeek::empty();
        let req = make_view(&m, &u, &h, &b);
        assert!(has_tag(&JwtInspectionDetector::new(vec![]).inspect(&req), "jwt_alg_none"));
    }

    #[test]
    fn basic_auth_is_ignored() {
        let mut h = http::HeaderMap::new();
        h.insert("authorization", "Basic dXNlcjpwYXNz".parse().unwrap());
        let m = http::Method::GET;
        let u: http::Uri = "/".parse().unwrap();
        let b = BodyPeek::empty();
        let req = make_view(&m, &u, &h, &b);
        assert!(JwtInspectionDetector::new(vec![]).inspect(&req).is_empty());
    }

    // ---- scoring -----------------------------------------------------

    #[test]
    fn signals_emit_structural_block_score() {
        let t = tok(r#"{"alg":"none","x5c":["x"],"kid":"/dev/null"}"#);
        let s = signals_for_cookie(&t);
        assert_eq!(s.len(), 3, "all three A1 rules fire, got {s:?}");
        assert!(s.iter().all(|sig| sig.score == 80), "structural block tier = 80");
    }

    #[test]
    fn id_is_stable() {
        assert_eq!(JwtInspectionDetector::new(vec![]).id(), "jwt_inspection");
    }

    // ---- unit: kid_is_malicious -------------------------------------

    #[test]
    fn kid_helper_unit() {
        assert!(kid_is_malicious("/dev/null"));
        assert!(kid_is_malicious("../../etc/passwd"));
        assert!(kid_is_malicious("http://evil/key"));
        assert!(kid_is_malicious("k' OR 1=1"));
        assert!(!kid_is_malicious("550e8400-e29b"));
        assert!(!kid_is_malicious("keys/active"));
        assert!(!kid_is_malicious("android-2024"));
        assert!(!kid_is_malicious("selection"));
        assert!(!kid_is_malicious(""));
    }

    // ---- Phase A2: jwt_jku_external ---------------------------------

    #[test]
    fn jku_external_strict_flags_any_url() {
        // Empty allowlist (strict) → any jku host flags.
        let t = tok(r#"{"alg":"RS256","jku":"https://attacker.evil.com/jwks.json"}"#);
        assert!(has_tag(&signals_for_cookie(&t), "jwt_jku_external"));
    }

    #[test]
    fn x5u_external_strict_flags() {
        let t = tok(r#"{"alg":"RS256","x5u":"https://attacker.evil.com/chain.pem"}"#);
        assert!(has_tag(&signals_for_cookie(&t), "jwt_jku_external"));
    }

    #[test]
    fn jku_real_corpus_header() {
        // Report ID=3 header decodes with jku=https://attacker.evil.com/jwks.json.
        let t = concat!(
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImprdSI6Imh0dHBzOi8vYXR0YWNrZXIu",
            "ZXZpbC5jb20vandrcy5qc29uIn0.eyJ1c2VyIjoiYWRtaW4ifQ.fakersasig"
        );
        assert!(has_tag(&signals_for_cookie(t), "jwt_jku_external"));
    }

    #[test]
    fn jku_on_allowlist_is_clean() {
        let t = tok(r#"{"alg":"RS256","jku":"https://auth.example.com/jwks.json"}"#);
        let s = signals_for_cookie_with(&t, vec!["auth.example.com".into()]);
        assert!(!has_tag(&s, "jwt_jku_external"), "allowlisted host must not flag: {s:?}");
    }

    #[test]
    fn jku_wildcard_allowlist_matches_subdomain() {
        let t = tok(r#"{"alg":"RS256","jku":"https://keys.auth.example.com/jwks.json"}"#);
        let s = signals_for_cookie_with(&t, vec!["*.example.com".into()]);
        assert!(!has_tag(&s, "jwt_jku_external"));
    }

    #[test]
    fn jku_off_allowlist_flags_even_with_allowlist_set() {
        let t = tok(r#"{"alg":"RS256","jku":"https://evil.com/jwks.json"}"#);
        let s = signals_for_cookie_with(&t, vec!["auth.example.com".into()]);
        assert!(has_tag(&s, "jwt_jku_external"));
    }

    #[test]
    fn jku_with_userinfo_and_port_extracts_host() {
        // userinfo + port must not fool the host extraction.
        let t = tok(r#"{"alg":"RS256","jku":"https://auth.example.com@evil.com:8443/jwks"}"#);
        let s = signals_for_cookie_with(&t, vec!["auth.example.com".into()]);
        // Real host is evil.com (after `@`), which is NOT allowlisted.
        assert!(has_tag(&s, "jwt_jku_external"), "host after userinfo is evil.com: {s:?}");
    }

    #[test]
    fn no_jku_no_signal() {
        let t = tok(r#"{"alg":"RS256","typ":"JWT"}"#);
        assert!(!has_tag(&signals_for_cookie(&t), "jwt_jku_external"));
    }

    #[test]
    fn url_host_unit() {
        assert_eq!(url_host("https://a.com/x").as_deref(), Some("a.com"));
        assert_eq!(url_host("https://A.COM:443/x").as_deref(), Some("a.com"));
        assert_eq!(url_host("https://u:p@host.com/x").as_deref(), Some("host.com"));
        assert_eq!(url_host("https://[::1]:8443/x").as_deref(), Some("::1"));
        assert_eq!(url_host("not-a-url"), None);
    }

    // ---- Phase A2: jwt_time_forged ----------------------------------

    #[test]
    fn time_far_future_exp_flags() {
        // exp in year 2286.
        let t = tok2(r#"{"alg":"HS256"}"#, r#"{"role":"admin","exp":9999999999}"#);
        assert!(has_tag(&signals_for_cookie(&t), "jwt_time_forged"));
    }

    #[test]
    fn time_epoch_iat_nbf_flags() {
        let t = tok2(r#"{"alg":"HS256"}"#, r#"{"user":"alice","iat":0,"nbf":0}"#);
        assert!(has_tag(&signals_for_cookie(&t), "jwt_time_forged"));
    }

    #[test]
    fn time_real_corpus_header() {
        // Report ID=26 payload: role:admin, exp:9999999999, iat:0, nbf:0.
        let t = concat!(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.",
            "eyJ1c2VyIjoiYWxpY2UiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjk5OTk5OTk5OTksImlhdCI6MCwibmJmIjowfQ.",
            "invalidsignature"
        );
        assert!(has_tag(&signals_for_cookie(t), "jwt_time_forged"));
    }

    #[test]
    fn time_sane_token_is_clean() {
        // exp ~1 year out, iat ~now — a normal token must stay green.
        let now = unix_now();
        let payload = format!(r#"{{"user":"a","iat":{},"exp":{}}}"#, now - 60, now + 3600);
        let t = tok2(r#"{"alg":"HS256"}"#, &payload);
        assert!(!has_tag(&signals_for_cookie(&t), "jwt_time_forged"));
    }

    #[test]
    fn time_no_claims_is_clean() {
        let t = tok2(r#"{"alg":"HS256"}"#, r#"{"user":"a"}"#);
        assert!(!has_tag(&signals_for_cookie(&t), "jwt_time_forged"));
    }

    #[test]
    fn time_claims_forged_unit() {
        let now = 1_700_000_000u64;
        let forged_exp =
            serde_json::from_str::<serde_json::Map<String, Value>>(r#"{"exp":9999999999}"#).unwrap();
        assert!(time_claims_forged(&forged_exp, now));
        let epoch =
            serde_json::from_str::<serde_json::Map<String, Value>>(r#"{"iat":0,"nbf":0}"#).unwrap();
        assert!(time_claims_forged(&epoch, now));
        let sane = serde_json::from_str::<serde_json::Map<String, Value>>(
            r#"{"iat":1699999940,"exp":1700003600}"#,
        )
        .unwrap();
        assert!(!time_claims_forged(&sane, now));
    }

    #[test]
    fn domain_matches_unit() {
        assert!(domain_matches("a.com", "a.com"));
        assert!(domain_matches("A.com", "a.com"));
        assert!(domain_matches("*.example.com", "x.example.com"));
        assert!(domain_matches("*.example.com", "a.b.example.com"));
        assert!(!domain_matches("*.example.com", "example.com"));
        assert!(!domain_matches("a.com", "b.com"));
    }
}
