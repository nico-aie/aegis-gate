//! 27-feature extractor — ported verbatim from `aegis-security/src/detectors/ai/features.rs`.
//!
//! The serving server must produce the SAME feature vector as the WAF so that
//! the ONNX model sees identical input distributions during inference.
//!
//! Input format (same as WAF `AiDetector::build_request_string`):
//!   "METHOD /path?query body\nUser-Agent: …\nCookie: …\nReferer: …"
//!
//! Feature layout — index order MUST NOT change without retraining the model:
//!   0  request_len           6  entropy            12 angle_bracket_count  18 cmd_injection_count  24 crlf_inject_count
//!   1  method_id             7  digit_ratio         13 semicolon_count      19 scanner_count         25 double_encode_count
//!   2  path_len              8  upper_ratio          14 pct_encoded_count    20 ssrf_count            26 ssti_count
//!   3  query_len             9  special_char_count   15 sql_keyword_count    21 php_pattern_count
//!   4  body_len             10  single_quote_count   16 xss_pattern_count    22 null_byte_count
//!   5  num_params           11  double_quote_count   17 path_traversal_count 23 hex_encode_count

use std::sync::LazyLock as Lazy;
use regex::Regex;

pub const NUM_FEATURES: usize = 27;

const MAX_URL_BYTES:  usize = 4_096;
const MAX_BODY_BYTES: usize = 8_192;

// ── Regexes (compiled once) ──────────────────────────────────────────────────

static SQL_KEYWORDS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(select|union|insert|update|delete|drop|create|alter|exec|execute|where|from|having|order|group|join|table|database|schema|char|nchar|varchar|cast|convert|declare|waitfor|xp_|sp_|0x)\b")
        .expect("sql regex")
});
// Context gate for sql_keyword_count (#15) — mirrors features.py `_SQL_CTX`. A lone
// SQL keyword in prose scores 0; the count is kept only when SQL *syntax* co-occurs.
static SQL_CTX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)union\s+(?:all\s+)?select|\bselect\b[^a-zA-Z]*?(?:\*|@@|count\s*\(|distinct\b|top\s+\d|[\w`\[\]]+\s*,)|\bselect\s+(?:version|substring|substr|concat|char|count|current_user|current_database|current_setting|session_user|user|database|group_concat|load_file)\b|@@\w+|\bfrom\s+(?:information_schema|mysql\.|pg_|sys\.|sysobjects)|\binsert\s+into\b|\bdelete\s+from\b|\bupdate\b[^;]{0,80}?\bset\b|\bdrop\s+(?:table|database|schema)\b|\balter\s+table\b|\bcreate\s+(?:table|database)\b|\b(?:order|group)\s+by\s+\d|\bhaving\s+\d|\binto\s+(?:outfile|dumpfile)\b|\bwaitfor\s+delay\b|\b(?:information_schema|load_file|extractvalue|updatexml|benchmark|sleep|pg_sleep)\s*\(|\b(?:xp_|sp_)\w+|(?:--|\#)\s*$|/\*.*?\*/|;\s*(?:select|insert|update|delete|drop|union|create|alter)\b|['"]\s*(?:or|and)\s|\b(?:or|and)\b\s*['"\d][^=<>]{0,12}?[=<>]\s*['"\d\w(]"#,
    )
    .expect("sql context regex compiles")
});
static XSS_MARKERS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(<script|javascript:|vbscript:|onload=|onerror=|onclick=|onfocus=|alert\(|confirm\(|prompt\(|document\.cookie|document\.write|eval\(|<iframe|<img\s|<svg|srcdoc=)")
        .expect("xss regex")
});
static SCANNER_UA: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(nikto|sqlmap|nmap|masscan|acunetix|nessus|openvas|dirbuster|gobuster|wfuzz|w3af|commix)")
        .expect("scanner regex")
});
static PCT_ENCODED: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"%[0-9a-fA-F]{2}").expect("pct regex"));
// Mirrors features.py _CMD: pipe, &&, $(, backtick-pair, shellshock "() {".
// (Bare `;` is NOT a cmd signal here — too common in benign cookies/matrix params.)
static CMD_INJECTION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\||&&|\$\(|`[^`]*`|\(\s*\)\s*\{").expect("cmd regex"));
// Word-boundaries on numeric IPs so `0.0.0.0` no longer matches inside Chrome
// version strings (Chrome/120.0.0.0). Mirrors features.py _SSRF.
static SSRF_TARGETS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:\b127\.0\.0\.1\b|localhost|\b169\.254\.|\b0\.0\.0\.0\b|::1|file://|dict://|gopher://|ftp://)")
        .expect("ssrf regex")
});
/// True if `s` looks like raw binary (beacon/protobuf) not text. Mirrors
/// features.py `_is_binary`: short strings text; else < 75% printable.
fn is_binary_body(s: &str) -> bool {
    let total = s.chars().count();
    if total < 16 { return false; }
    let printable = s.chars()
        .filter(|&c| (' '..='~').contains(&c) || matches!(c, '\t' | '\n' | '\r'))
        .count();
    (printable as f32) / (total as f32) < 0.75
}
// Bare `.php` removed (benign FP driver); mirrors features.py _PHP.
static PHP_MARKERS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:php://|<\?php|eval\(|base64_decode\(|system\(|passthru\(|shell_exec\(|phpinfo\(|\$_(?:GET|POST|REQUEST|FILES)\[)")
        .expect("php regex")
});
/// Count only percent-encodings decoding to an injection-relevant byte (control
/// <0x20 or `<>'"`;|\$`). Mirrors features.py `_dangerous_pct_count`.
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
static NULL_BYTE:   Lazy<Regex> = Lazy::new(|| Regex::new(r"%00|\\x00|\\u0000").expect("null byte regex"));
static HEX_LITERAL: Lazy<Regex> = Lazy::new(|| Regex::new(r"0x[0-9a-fA-F]{4,}").expect("hex regex"));
static CRLF_INJ:    Lazy<Regex> = Lazy::new(|| Regex::new(r"%0[aAdD]|\\r\\n|\r\n").expect("crlf regex"));
static DOUBLE_PCT:  Lazy<Regex> = Lazy::new(|| Regex::new(r"%25[0-9a-fA-F]{2}").expect("double pct regex"));
static SSTI_MARKERS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?is)(\{\{.*?\}\})|(\$\{[^}]{1,200}\})|(#\{[^}]{1,200}\})|(<%=.*?%>)|(@\([^)]{1,200}\))|(\?\s*new\s*\()|(__(class|mro|subclasses|globals|builtins|import)__)|(freemarker\.template|velocity\.tools)|(\{\s*\d+\s*\*\s*\d+\s*\})")
        .expect("ssti regex")
});

// ── Helpers ──────────────────────────────────────────────────────────────────

#[inline]
fn truncate_bytes(s: &str, max: usize) -> &str {
    if s.len() <= max { return s; }
    let mut idx = max;
    while !s.is_char_boundary(idx) { idx -= 1; }
    &s[..idx]
}

#[inline]
fn method_id(m: &str) -> f32 {
    if      m.eq_ignore_ascii_case("GET")     { 0.0 }
    else if m.eq_ignore_ascii_case("POST")    { 1.0 }
    else if m.eq_ignore_ascii_case("PUT")     { 2.0 }
    else if m.eq_ignore_ascii_case("DELETE")  { 3.0 }
    else if m.eq_ignore_ascii_case("PATCH")   { 4.0 }
    else if m.eq_ignore_ascii_case("HEAD")    { 5.0 }
    else if m.eq_ignore_ascii_case("OPTIONS") { 6.0 }
    else                                      { 7.0 }
}

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

fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() { return 0.0; }
    let mut counts = [0u32; 256];
    let mut n = 0u32;
    for c in s.chars() {
        counts[(c as u32).min(255) as usize] += 1;
        n += 1;
    }
    let total = n as f32;
    counts.iter().filter(|&&c| c > 0).map(|&c| {
        let p = (c as f32) / total;
        -p * p.log2()
    }).sum()
}

// ── Public extractor ────────────────────────────────────────────────────────

/// Extract a 27-element feature vector from an HTTP request string.
///
/// Accepts both single-line (`"METHOD /url body"`) and multi-line
/// (`"METHOD /url body\nUser-Agent: …\n…"`) formats.
pub fn extract_features(request: &str) -> [f32; NUM_FEATURES] {
    let (first_line, headers_text): (&str, String) = match request.find('\n') {
        Some(nl) => (&request[..nl], request[nl + 1..].replace('\n', " ")),
        None     => (request, String::new()),
    };

    let mut parts = first_line.splitn(3, ' ');
    let method = parts.next().unwrap_or("GET");
    let url    = truncate_bytes(parts.next().unwrap_or("/"), MAX_URL_BYTES);
    let body   = truncate_bytes(parts.next().unwrap_or(""), MAX_BODY_BYTES);

    let (path, query) = match url.find('?') {
        Some(pos) => (&url[..pos], &url[pos + 1..]),
        None      => (url, ""),
    };

    // Binary body (beacon/protobuf) → excluded from text scans; length features
    // (body_len #4, request_len #0) still use the real body. Mirrors features.py.
    let body_feat: &str = if is_binary_body(body) { "" } else { body };

    let full = {
        let mut s = url.to_string();
        if !body_feat.is_empty()    { s.push(' '); s.push_str(body_feat); }
        if !headers_text.is_empty() { s.push(' '); s.push_str(&headers_text); }
        s
    };
    let full_dec       = url_decode(&full);
    let full_dec_lower = full_dec.to_ascii_lowercase();

    let total_chars  = full.chars().count().max(1) as f32;
    let digit_count  = full.chars().filter(|c| c.is_ascii_digit()).count() as f32;
    let upper_count  = full.chars().filter(|c| c.is_ascii_uppercase()).count() as f32;
    let special_count = full.chars()
        .filter(|c| matches!(c, '\'' | '"' | '<' | '>' | ';'))  // injection chars only (= % & + are benign URL syntax)
        .count() as f32;
    let path_traversal_count = full_dec_lower.matches("../").count() as f32;

    let num_params = {
        let q = if query.is_empty() { 0 } else { query.matches('&').count() + 1 };
        let b = if body_feat.is_empty()  { 0 } else { body_feat.matches('&').count()  + 1 };
        (q + b) as f32
    };

    [
        request.len() as f32,                                // 0  request_len
        method_id(method),                                   // 1  method_id
        path.len() as f32,                                   // 2  path_len
        query.len() as f32,                                  // 3  query_len
        body.len() as f32,                                   // 4  body_len
        num_params,                                          // 5  num_params
        shannon_entropy(&full),                              // 6  entropy
        digit_count / total_chars,                           // 7  digit_ratio
        upper_count / total_chars,                           // 8  upper_ratio
        special_count,                                       // 9  special_char_count
        full.matches('\'').count() as f32,                   // 10 single_quote_count
        full.matches('"').count() as f32,                    // 11 double_quote_count
        (full.matches('<').count() + full.matches('>').count()) as f32, // 12 angle_bracket_count
        full.matches(';').count() as f32,                    // 13 semicolon_count
        dangerous_pct_count(&full) as f32,                   // 14 pct_encoded_count  (injection-relevant only)
        SQL_KEYWORDS.find_iter(&full_dec).count() as f32,    // 15 sql_keyword_count       (decoded)
        XSS_MARKERS.find_iter(&full_dec).count() as f32,     // 16 xss_pattern_count       (decoded)
        path_traversal_count,                                // 17 path_traversal_count    (decoded)
        CMD_INJECTION.find_iter(&full_dec).count() as f32,   // 18 cmd_injection_count     (decoded)
        SCANNER_UA.find_iter(&full_dec).count() as f32,      // 19 scanner_count           (decoded)
        SSRF_TARGETS.find_iter(&full_dec).count() as f32,    // 20 ssrf_count              (decoded)
        PHP_MARKERS.find_iter(&full_dec).count() as f32,     // 21 php_pattern_count       (decoded)
        NULL_BYTE.find_iter(&full).count() as f32,           // 22 null_byte_count         (raw)
        HEX_LITERAL.find_iter(&full).count() as f32,         // 23 hex_encode_count        (raw)
        CRLF_INJ.find_iter(&full).count() as f32,            // 24 crlf_inject_count       (raw)
        DOUBLE_PCT.find_iter(&full).count() as f32,          // 25 double_encode_count     (raw)
        SSTI_MARKERS.find_iter(&full_dec).count() as f32,    // 26 ssti_count              (decoded)
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_length_is_27() {
        assert_eq!(extract_features("GET /").len(), NUM_FEATURES);
    }

    #[test]
    fn clean_request_has_zero_attack_signals() {
        let v = extract_features("GET /api/users?id=42");
        assert_eq!(v[15], 0.0, "sql");
        assert_eq!(v[16], 0.0, "xss");
        assert_eq!(v[17], 0.0, "traversal");
    }

    #[test]
    fn sqli_payload_fires_sql_count() {
        let v = extract_features("GET /search?q=' UNION SELECT password FROM users--");
        assert!(v[15] >= 3.0, "sql_keyword_count={}", v[15]);
    }

    #[test]
    fn scanner_ua_in_header_fires() {
        let v = extract_features("GET /admin\nUser-Agent: sqlmap/1.7");
        assert!(v[19] >= 1.0, "scanner_count={}", v[19]);
    }

    #[test]
    fn no_nan_or_inf() {
        for s in ["", "GET /", "POST /login user=a&pass=b", "GET /?q=' UNION SELECT *"] {
            for (i, x) in extract_features(s).iter().enumerate() {
                assert!(x.is_finite(), "feature[{}] is non-finite for {:?}", i, s);
            }
        }
    }
}
