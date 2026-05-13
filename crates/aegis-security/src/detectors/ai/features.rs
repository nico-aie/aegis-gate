//! AI-T2 — 27-feature extractor for the ONNX binary classifier.
//!
//! The trained model was fed feature vectors of length
//! [`NUM_FEATURES`] during training.  Inference must produce the
//! SAME 27 floats in the SAME order — any drift here corrupts
//! the model's input distribution and its predictions become
//! garbage.
//!
//! ## Input format
//!
//! Accepts both shapes the training pipeline emits:
//!
//! - **Single-line** (legacy): `"METHOD /url body"`
//! - **Multi-line** (current): `"METHOD /url body\nHeader: value\n…"`
//!   where header values (User-Agent, Cookie, Referer, …) are
//!   appended to the request line on subsequent lines.
//!
//! The first line is parsed as `METHOD URL BODY` (BODY = anything
//! after the second space).  All remaining lines are joined and
//! contribute their text to the "full" string the count- and
//! regex-features run against — so a `User-Agent: sqlmap/1.7`
//! header trips `scanner_count` exactly the way it did during
//! training.
//!
//! ## Feature layout
//!
//! | idx | name                  | source                    | scale  |
//! |-----|-----------------------|---------------------------|--------|
//! |  0  | request_len           | total bytes (incl. hdrs)  | raw    |
//! |  1  | method_id             | GET=0 POST=1 …            | id     |
//! |  2  | path_len              | URL up to `?`             | raw    |
//! |  3  | query_len             | URL after `?`             | raw    |
//! |  4  | body_len              | request body              | raw    |
//! |  5  | num_params            | `&`-separated count       | raw    |
//! |  6  | entropy               | Shannon over chars        | bits   |
//! |  7  | digit_ratio           | digits / total chars      | 0..1   |
//! |  8  | upper_ratio           | uppercase / total chars   | 0..1   |
//! |  9  | special_char_count    | `'"<>;=%&+`               | raw    |
//! | 10  | single_quote_count    | `'`                       | raw    |
//! | 11  | double_quote_count    | `"`                       | raw    |
//! | 12  | angle_bracket_count   | `<` and `>`               | raw    |
//! | 13  | semicolon_count       | `;`                       | raw    |
//! | 14  | pct_encoded_count     | `%XX` matches (raw)       | raw    |
//! | 15  | sql_keyword_count     | sql verbs (decoded)       | raw    |
//! | 16  | xss_pattern_count     | xss markers (decoded)     | raw    |
//! | 17  | path_traversal_count  | `../` (decoded)           | raw    |
//! | 18  | cmd_injection_count   | shell sep (decoded)       | raw    |
//! | 19  | scanner_count         | sqlmap/nikto/… (decoded)  | raw    |
//! | 20  | ssrf_count            | metadata IPs (decoded)    | raw    |
//! | 21  | php_pattern_count     | `.php` / eval(  (decoded) | raw    |
//! | 22  | null_byte_count       | `%00` / `\\x00` (raw)     | raw    |
//! | 23  | hex_encode_count      | `0xDEADBEEF` (raw)        | raw    |
//! | 24  | crlf_inject_count     | `%0a` `\\r\\n` (raw)      | raw    |
//! | 25  | double_encode_count   | `%25XX` (raw)             | raw    |
//! | 26  | ssti_count            | `{{...}}` `${...}` `<%=` (decoded) | raw |
//!
//! Counts marked **(raw)** are computed from the un-decoded
//! request bytes — `pct_encoded_count` would be self-defeating
//! after a decode pass.  Counts marked **(decoded)** run on the
//! `%XX`-decoded string so payloads that hide behind encoding
//! still trigger.
//!
//! ## Method ID map
//!
//! GET=0 · POST=1 · PUT=2 · DELETE=3 · PATCH=4 · HEAD=5 ·
//! OPTIONS=6 · everything else=7. Match the training pipeline
//! verbatim.

use std::sync::LazyLock as Lazy;

use regex::Regex;

/// Length of one feature vector. The model's input shape is
/// `[batch, NUM_FEATURES]`.
pub const NUM_FEATURES: usize = 27;

/// Static names — useful for debugging / logging the top-3
/// contributors when `cfg.ai.explain` is on (future work).
#[allow(dead_code)]
pub const FEATURE_NAMES: [&str; NUM_FEATURES] = [
    "request_len",
    "method_id",
    "path_len",
    "query_len",
    "body_len",
    "num_params",
    "entropy",
    "digit_ratio",
    "upper_ratio",
    "special_char_count",
    "single_quote_count",
    "double_quote_count",
    "angle_bracket_count",
    "semicolon_count",
    "pct_encoded_count",
    "sql_keyword_count",
    "xss_pattern_count",
    "path_traversal_count",
    "cmd_injection_count",
    "scanner_count",
    "ssrf_count",
    "php_pattern_count",
    "null_byte_count",
    "hex_encode_count",
    "crlf_inject_count",
    "double_encode_count",
    "ssti_count",
];

// ─── Regex patterns — case-insensitive, compiled once ────────

static SQL_KEYWORDS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)\b(select|union|insert|update|delete|drop|create|alter|exec|execute|where|from|having|order|group|join|table|database|schema|char|nchar|varchar|cast|convert|declare|waitfor|xp_|sp_|0x)\b",
    )
    .expect("sql keyword regex compiles")
});

static XSS_MARKERS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(<script|javascript:|vbscript:|onload=|onerror=|onclick=|onfocus=|alert\(|confirm\(|prompt\(|document\.cookie|document\.write|eval\(|<iframe|<img\s|<svg|srcdoc=)",
    )
    .expect("xss marker regex compiles")
});

static SCANNER_UA: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(nikto|sqlmap|nmap|masscan|acunetix|nessus|openvas|dirbuster|gobuster|wfuzz|w3af|commix)",
    )
    .expect("scanner UA regex compiles")
});

static PCT_ENCODED: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"%[0-9a-fA-F]{2}").expect("pct regex"));

static CMD_INJECTION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[;|]|\|\||&&|\$\(|`[^`]*`").expect("cmd regex"));

static SSRF_TARGETS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(?:127\.0\.0\.1|localhost|169\.254\.|0\.0\.0\.0|::1|file://|dict://|gopher://|ftp://)",
    )
    .expect("ssrf regex compiles")
});

static PHP_MARKERS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(?:\.php|eval\(|base64_decode\(|system\(|passthru\(|shell_exec\(|phpinfo\(|\$_(?:GET|POST|REQUEST|FILES)\[)",
    )
    .expect("php marker regex compiles")
});

static NULL_BYTE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"%00|\\x00|\\u0000").expect("null byte regex"));

static HEX_LITERAL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"0x[0-9a-fA-F]{4,}").expect("hex literal regex"));

static CRLF_INJ: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"%0[aAdD]|\\r\\n|\r\n").expect("crlf regex"));

static DOUBLE_PCT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"%25[0-9a-fA-F]{2}").expect("double-encoded pct regex"));

static SSTI_MARKERS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?is)(\{\{.*?\}\})|(\$\{[^}]{1,200}\})|(#\{[^}]{1,200}\})|(<%=.*?%>)|(\?\s*new\s*\()|(__(class|mro|subclasses|globals|builtins|import)__)|(freemarker\.template|velocity\.tools)|(\{\s*\d+\s*\*\s*\d+\s*\})",
    )
    .expect("ssti marker regex compiles")
});

// ─── Helpers ─────────────────────────────────────────────────

#[inline]
fn method_id(method: &str) -> f32 {
    // Uppercase compare — methods are case-sensitive by RFC but
    // many tools / clients send lowercase, and the training set
    // normalised before the lookup.
    let upper = method.trim();
    if upper.eq_ignore_ascii_case("GET")     { 0.0 }
    else if upper.eq_ignore_ascii_case("POST")    { 1.0 }
    else if upper.eq_ignore_ascii_case("PUT")     { 2.0 }
    else if upper.eq_ignore_ascii_case("DELETE")  { 3.0 }
    else if upper.eq_ignore_ascii_case("PATCH")   { 4.0 }
    else if upper.eq_ignore_ascii_case("HEAD")    { 5.0 }
    else if upper.eq_ignore_ascii_case("OPTIONS") { 6.0 }
    else                                          { 7.0 }
}

/// Decode `%XX` percent-encoding.  Non-hex sequences pass
/// through unchanged.  Lossy (treats output as bytes-as-chars)
/// to match the training pipeline's behaviour exactly.
fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h * 16 + l) as u8 as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// Shannon entropy over chars (bits).  Empty → 0.
fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    // Char-frequency bucket — chars > 0xFF map to 255 to bound
    // memory; matches the training pipeline's clamp.
    let mut counts = [0u32; 256];
    let mut n = 0u32;
    for c in s.chars() {
        let idx = (c as u32).min(255) as usize;
        counts[idx] += 1;
        n += 1;
    }
    let total = n as f32;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = (c as f32) / total;
            -p * p.log2()
        })
        .sum()
}

// ─── Public extractor ────────────────────────────────────────

/// Extract a 27-feature vector from a single HTTP request
/// rendered as either:
///
/// - `"METHOD /path?query body"` (single-line, legacy)
/// - `"METHOD /path?query body\nHeader: value\n…"` (multi-line,
///   matches the training pipeline)
///
/// See the module-level docs for the exact feature layout.
///
/// Allocation budget: one [`String`] for headers joined into one
/// line, one for the URL-decoded full request, and one for its
/// lowercase variant.  All bounded by request size; well below
/// the 5 ms budget the model needs.
pub fn extract_features(request: &str) -> [f32; NUM_FEATURES] {
    // Split first line from headers (if any).
    let (first_line, headers_text): (&str, String) = match request.find('\n') {
        Some(nl) => (
            &request[..nl],
            request[nl + 1..].replace('\n', " "),
        ),
        None => (request, String::new()),
    };

    // Three-piece split: METHOD / URL / BODY.  Missing parts
    // default to GET / "/" / "".
    let mut parts = first_line.splitn(3, ' ');
    let method = parts.next().unwrap_or("GET");
    let url = parts.next().unwrap_or("/");
    let body = parts.next().unwrap_or("");

    // URL → (path, query).
    let (path, query) = match url.find('?') {
        Some(pos) => (&url[..pos], &url[pos + 1..]),
        None => (url, ""),
    };

    // "Full" string used for most counts: URL + body + header
    // values when present.  Matches training shape — regex
    // patterns scan User-Agent, Cookie, Referer, etc.
    let full = {
        let mut s = url.to_string();
        if !body.is_empty() {
            s.push(' ');
            s.push_str(body);
        }
        if !headers_text.is_empty() {
            s.push(' ');
            s.push_str(&headers_text);
        }
        s
    };
    let full_dec = url_decode(&full);
    let full_dec_lower = full_dec.to_ascii_lowercase();

    // Total chars; clamp to 1 to keep ratios well-defined.
    let total_chars = full.chars().count().max(1) as f32;

    // Param count — one per `&` plus one for non-empty.  Query
    // and body params count; header values don't.
    let num_params = {
        let q = if query.is_empty() {
            0
        } else {
            query.matches('&').count() + 1
        };
        let b = if body.is_empty() {
            0
        } else {
            body.matches('&').count() + 1
        };
        (q + b) as f32
    };

    let digit_count = full.chars().filter(|c| c.is_ascii_digit()).count() as f32;
    let upper_count = full.chars().filter(|c| c.is_ascii_uppercase()).count() as f32;
    let special_count = full
        .chars()
        .filter(|c| matches!(c, '\'' | '"' | '<' | '>' | ';' | '=' | '%' | '&' | '+'))
        .count() as f32;

    // Path-traversal count uses the decoded-lower string so
    // `..%2F..` still trips.
    let path_traversal_count = full_dec_lower.matches("../").count() as f32;
    let single_quote_count = full.matches('\'').count() as f32;
    let double_quote_count = full.matches('"').count() as f32;
    let angle_bracket_count =
        (full.matches('<').count() + full.matches('>').count()) as f32;
    let semicolon_count = full.matches(';').count() as f32;

    [
        request.len() as f32,                                // 0  request_len (incl. headers)
        method_id(method),                                   // 1  method_id
        path.len() as f32,                                   // 2  path_len
        query.len() as f32,                                  // 3  query_len
        body.len() as f32,                                   // 4  body_len (first line only)
        num_params,                                          // 5  num_params (query + body)
        shannon_entropy(&full),                              // 6  entropy
        digit_count / total_chars,                           // 7  digit_ratio
        upper_count / total_chars,                           // 8  upper_ratio
        special_count,                                       // 9  special_char_count
        single_quote_count,                                  // 10 single_quote_count
        double_quote_count,                                  // 11 double_quote_count
        angle_bracket_count,                                 // 12 angle_bracket_count
        semicolon_count,                                     // 13 semicolon_count
        PCT_ENCODED.find_iter(&full).count() as f32,         // 14 pct_encoded_count    (raw)
        SQL_KEYWORDS.find_iter(&full_dec).count() as f32,    // 15 sql_keyword_count    (decoded)
        XSS_MARKERS.find_iter(&full_dec).count() as f32,     // 16 xss_pattern_count    (decoded)
        path_traversal_count,                                // 17 path_traversal_count
        CMD_INJECTION.find_iter(&full_dec).count() as f32,   // 18 cmd_injection_count  (decoded)
        SCANNER_UA.find_iter(&full_dec).count() as f32,      // 19 scanner_count        (decoded)
        SSRF_TARGETS.find_iter(&full_dec).count() as f32,    // 20 ssrf_count           (decoded)
        PHP_MARKERS.find_iter(&full_dec).count() as f32,     // 21 php_pattern_count    (decoded)
        NULL_BYTE.find_iter(&full).count() as f32,           // 22 null_byte_count      (raw)
        HEX_LITERAL.find_iter(&full).count() as f32,         // 23 hex_encode_count     (raw)
        CRLF_INJ.find_iter(&full).count() as f32,            // 24 crlf_inject_count    (raw)
        DOUBLE_PCT.find_iter(&full).count() as f32,          // 25 double_encode_count  (raw)
        SSTI_MARKERS.find_iter(&full_dec).count() as f32,    // 26 ssti_count           (decoded)
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(a: f32, b: f32) -> bool {
        (a - b).abs() < 1e-3
    }

    #[test]
    fn vector_is_exactly_27_features() {
        let v = extract_features("GET / HTTP/1.1");
        assert_eq!(v.len(), NUM_FEATURES);
        assert_eq!(FEATURE_NAMES.len(), NUM_FEATURES);
    }

    #[test]
    fn method_id_matches_training_map() {
        assert_eq!(method_id("GET"), 0.0);
        assert_eq!(method_id("POST"), 1.0);
        assert_eq!(method_id("PUT"), 2.0);
        assert_eq!(method_id("DELETE"), 3.0);
        assert_eq!(method_id("PATCH"), 4.0);
        assert_eq!(method_id("HEAD"), 5.0);
        assert_eq!(method_id("OPTIONS"), 6.0);
        assert_eq!(method_id("OBSCURE"), 7.0);
        assert_eq!(method_id("get"), 0.0, "case-insensitive");
    }

    #[test]
    fn url_decode_handles_pct() {
        assert_eq!(url_decode("a%20b"), "a b");
        assert_eq!(url_decode("a%2fb"), "a/b");
        assert_eq!(url_decode("%2E%2E"), "..");
        // Non-hex passthrough.
        assert_eq!(url_decode("100%"), "100%");
        assert_eq!(url_decode("%zz"), "%zz");
    }

    #[test]
    fn entropy_matches_intuition() {
        assert_eq!(shannon_entropy(""), 0.0);
        // All same → entropy 0
        assert!(approx_eq(shannon_entropy("aaaa"), 0.0));
        // Two equally-distributed chars → 1 bit
        assert!(approx_eq(shannon_entropy("ab"), 1.0));
    }

    #[test]
    fn clean_get_root_has_low_attack_signals() {
        let v = extract_features("GET / HTTP/1.1");
        // No SQL / XSS / ptrav / cmd / scanner / SSRF / PHP /
        // null bytes / hex / crlf / double-encode / ssti markers.
        assert_eq!(v[15], 0.0, "sql_keyword_count");
        assert_eq!(v[16], 0.0, "xss_pattern_count");
        assert_eq!(v[17], 0.0, "path_traversal_count");
        assert_eq!(v[18], 0.0, "cmd_injection_count");
        assert_eq!(v[19], 0.0, "scanner_count");
        assert_eq!(v[20], 0.0, "ssrf_count");
        assert_eq!(v[26], 0.0, "ssti_count");
    }

    #[test]
    fn sqli_payload_lights_up_sql_count() {
        let v = extract_features("GET /search?q=' UNION SELECT password FROM users--");
        assert!(v[15] >= 3.0, "sql_keyword_count should hit union+select+from, got {}", v[15]);
        assert!(v[10] >= 1.0, "single_quote_count");
    }

    #[test]
    fn xss_payload_lights_up_xss_count() {
        let v = extract_features("GET /?q=<script>alert(1)</script>");
        assert!(v[16] >= 2.0, "xss markers (<script + alert), got {}", v[16]);
        assert!(v[12] >= 2.0, "angle_bracket_count");
    }

    #[test]
    fn path_traversal_lights_up_after_decoding() {
        // Encoded form must decode + still trip the counter.
        let v = extract_features("GET /files?p=..%2F..%2Fetc%2Fpasswd");
        assert!(v[17] >= 1.0, "path_traversal_count after decode, got {}", v[17]);
        // Three %XX sequences in the input → pct_encoded_count = 3.
        assert!(v[14] >= 3.0, "pct_encoded_count, got {}", v[14]);
    }

    #[test]
    fn ssrf_payload_lights_up_ssrf_count() {
        let v = extract_features("GET /fetch?url=http://169.254.169.254/latest/meta-data/");
        assert!(v[20] >= 1.0, "ssrf_count, got {}", v[20]);
    }

    #[test]
    fn scanner_ua_in_body_lights_scanner_count() {
        let v = extract_features("GET / sqlmap/1.5.7");
        assert!(v[19] >= 1.0, "scanner_count, got {}", v[19]);
    }

    #[test]
    fn scanner_ua_in_header_lights_scanner_count() {
        // Multi-line: header on second line still trips the
        // scanner regex because the extractor folds headers
        // into the `full` string.
        let v = extract_features("GET /admin\nUser-Agent: sqlmap/1.7");
        assert!(v[19] >= 1.0, "scanner_count via header, got {}", v[19]);
    }

    #[test]
    fn double_encode_lights_up() {
        // %2527 = double-encoded single quote.
        let v = extract_features("GET /?q=%2527OR%25201%253D1");
        assert!(v[25] >= 3.0, "double_encode_count, got {}", v[25]);
    }

    #[test]
    fn crlf_injection_lights_up() {
        // Both raw + decoded forms.
        let v = extract_features("GET /?h=%0d%0aSet-Cookie:%20evil=1");
        assert!(v[24] >= 1.0, "crlf_inject_count via %0a, got {}", v[24]);
    }

    #[test]
    fn null_byte_lights_up() {
        let v = extract_features("GET /file.txt%00.png");
        assert!(v[22] >= 1.0, "null_byte_count, got {}", v[22]);
    }

    #[test]
    fn cmd_injection_lights_up() {
        let v = extract_features("GET /ping?host=8.8.8.8;cat /etc/passwd");
        assert!(v[18] >= 1.0, "cmd_injection_count, got {}", v[18]);
    }

    #[test]
    fn ssti_lights_up_on_jinja_arithmetic() {
        let v = extract_features("GET /search?q={{7*7}}");
        assert!(v[26] >= 1.0, "ssti_count for {{...}}, got {}", v[26]);
    }

    #[test]
    fn ssti_lights_up_on_spel() {
        let v = extract_features("GET /?q=${T(java.lang.Runtime).getRuntime().exec('id')}");
        assert!(v[26] >= 1.0, "ssti_count for ${{...}}, got {}", v[26]);
    }

    #[test]
    fn ratios_are_bounded_zero_to_one() {
        let v = extract_features("GET /AAAAAAAA HTTP/1.1");
        assert!(v[7] >= 0.0 && v[7] <= 1.0, "digit_ratio bounds: {}", v[7]);
        assert!(v[8] >= 0.0 && v[8] <= 1.0, "upper_ratio bounds: {}", v[8]);
    }

    #[test]
    fn empty_request_does_not_panic() {
        // Some pathological cases that should still produce a vector.
        let _ = extract_features("");
        let _ = extract_features("GET");
        let _ = extract_features("GET ");
        let _ = extract_features("GET / ");
        let _ = extract_features("? ");
    }

    #[test]
    fn no_nan_or_inf_in_output() {
        let inputs = [
            "GET / HTTP/1.1",
            "POST /login user=admin&pass=test",
            "GET /?q=' UNION SELECT *",
            "GET /<script>alert(1)</script>",
            "GET /%00",
            "GET /a/b/c",
            "GET /\nUser-Agent: sqlmap/1.7",
            "",
        ];
        for s in inputs {
            let v = extract_features(s);
            for (i, x) in v.iter().enumerate() {
                assert!(x.is_finite(), "feature {} is non-finite for {:?}", i, s);
            }
        }
    }
}
