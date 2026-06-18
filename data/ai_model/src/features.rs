/// WAF feature extraction — exact port of ml_waf/features.py.
/// 29 dense float32 features per HTTP request string.
///
/// Input format (multi-line):
///   Line 0:  "METHOD /url [body]"
///   Lines 1+: "Header: value"   (User-Agent, Cookie, Referer, etc.)
///
/// Old single-line format "METHOD /url body" is still accepted.
use once_cell::sync::Lazy;
use regex::Regex;

pub const NUM_FEATURES: usize = 29;

/// Mirror build_clean_dataset.py truncation limits so live inference matches training.
const MAX_URL_BYTES: usize = 4_096;
const MAX_BODY_BYTES: usize = 8_192;

/// Truncate `s` to at most `max_bytes`, respecting UTF-8 char boundaries.
fn truncate(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut idx = max_bytes;
    while !s.is_char_boundary(idx) {
        idx -= 1;
    }
    &s[..idx]
}

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

static SQL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(select|union|insert|update|delete|drop|create|alter|exec|execute|where|from|having|order|group|join|table|database|schema|char|nchar|varchar|cast|convert|declare|waitfor|xp_|sp_|0x)\b").unwrap()
});

// Context gate for sql_keyword_count (parity with ml_waf/features.py `_SQL_CTX`).
static SQL_CTX_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?is)union\s+(?:all\s+)?select|\bselect\b[^a-zA-Z]*?(?:\*|@@|count\s*\(|distinct\b|top\s+\d|[\w`\[\]]+\s*,)|\bselect\s+(?:version|substring|substr|concat|char|count|current_user|current_database|current_setting|session_user|user|database|group_concat|load_file)\b|@@\w+|\bfrom\s+(?:information_schema|mysql\.|pg_|sys\.|sysobjects)|\binsert\s+into\b|\bdelete\s+from\b|\bupdate\b[^;]{0,80}?\bset\b|\bdrop\s+(?:table|database|schema)\b|\balter\s+table\b|\bcreate\s+(?:table|database)\b|\b(?:order|group)\s+by\s+\d|\bhaving\s+\d|\binto\s+(?:outfile|dumpfile)\b|\bwaitfor\s+delay\b|\b(?:information_schema|load_file|extractvalue|updatexml|benchmark|sleep|pg_sleep)\s*\(|\b(?:xp_|sp_)\w+|(?:--|\#)\s*$|/\*.*?\*/|;\s*(?:select|insert|update|delete|drop|union|create|alter)\b|['"]\s*(?:or|and)\s|\b(?:or|and)\b\s*['"\d][^=<>]{0,12}?[=<>]\s*['"\d\w(]"#).unwrap()
});

static XSS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(<script|javascript:|vbscript:|onload=|onerror=|onclick=|onfocus=|alert\(|confirm\(|prompt\(|document\.cookie|document\.write|eval\(|<iframe|<img\s|<svg|srcdoc=)").unwrap()
});

static SCANNER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(nikto|sqlmap|nmap|masscan|acunetix|nessus|openvas|dirbuster|gobuster|wfuzz|w3af|commix)").unwrap()
});

static PCT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"%[0-9a-fA-F]{2}").unwrap());

static CMD_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\||&&|\$\(|`[^`]*`").unwrap());

static SSRF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:127\.0\.0\.1|localhost|169\.254\.|0\.0\.0\.0|::1|file://|dict://|gopher://|ftp://)").unwrap()
});

static PHP_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:\.php|eval\(|base64_decode\(|system\(|passthru\(|shell_exec\(|phpinfo\(|\$_(?:GET|POST|REQUEST|FILES)\[)").unwrap()
});

static NULL_BYTE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"%00|\\x00|\\u0000").unwrap());

static HEX_ENCODE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"0x[0-9a-fA-F]{4,}").unwrap());

static CRLF_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"%0[aAdD]|\\r\\n|\r\n").unwrap());

static DBL_ENC_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"%25[0-9a-fA-F]{2}").unwrap());

static SSTI_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?is)(\{\{.*?\}\})|(\$\{[^}]{1,200}\})|(#\{[^}]{1,200}\})|(<%=.*?%>)|(\?\s*new\s*\()|(__(class|mro|subclasses|globals|builtins|import)__)|(freemarker\.template|velocity\.tools)|(\{\s*\d+\s*\*\s*\d+\s*\})"
    ).unwrap()
});

fn method_id(method: &str) -> f32 {
    match method.to_ascii_uppercase().as_str() {
        "GET"     => 0.0,
        "POST"    => 1.0,
        "PUT"     => 2.0,
        "DELETE"  => 3.0,
        "PATCH"   => 4.0,
        "HEAD"    => 5.0,
        "OPTIONS" => 6.0,
        _         => 7.0,
    }
}

/// Decode %XX percent-encoding — mirrors Python's `urllib.parse.unquote`.
///
/// Collects decoded bytes first, then interprets them as UTF-8 (with lossy
/// fallback for invalid sequences).  The old byte-by-byte char-push approach
/// produced Latin-1 characters for multi-byte UTF-8 sequences:
///   %E4%B8%AD → 'ä' + '¸' + soft-hyphen  (wrong)
/// vs Python:
///   %E4%B8%AD → '中'                       (correct)
///
/// For pure ASCII inputs (the common WAF case) both approaches are identical.
fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut raw: Vec<u8> = Vec::with_capacity(s.len());
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
    // Interpret as UTF-8; replace invalid sequences (same as Python's errors='replace').
    String::from_utf8_lossy(&raw).into_owned()
}

/// Shannon entropy — mirrors Python's `_entropy()` exactly.
///
/// Uses a HashMap keyed by char so every Unicode code point gets its own
/// bucket.  The old fixed-array approach (256 slots) silently merged all
/// chars with code point > 255 into a single bucket, underestimating
/// entropy for non-ASCII payloads.
fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts: std::collections::HashMap<char, u32> = std::collections::HashMap::new();
    let mut n = 0u32;
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
        n += 1;
    }
    let n = n as f32;
    counts
        .values()
        .map(|&c| {
            let p = c as f32 / n;
            -p * p.log2()
        })
        .sum()
}

/// Extract 29 WAF features from a raw HTTP request string.
///
/// Accepts both formats:
///   Single-line : "METHOD /url body"
///   Multi-line  : "METHOD /url body\nUser-Agent: ...\nCookie: ..."
pub fn extract_features(request: &str) -> [f32; NUM_FEATURES] {
    // Split into the request line and optional header lines.
    let (first_line, headers_text): (&str, String) = match request.find('\n') {
        Some(nl) => (&request[..nl], request[nl + 1..].replace('\n', " ")),
        None     => (request, String::new()),
    };

    let mut parts = first_line.splitn(3, ' ');
    let method = parts.next().unwrap_or("GET");
    let url    = truncate(parts.next().unwrap_or("/"), MAX_URL_BYTES);
    let body   = truncate(parts.next().unwrap_or(""), MAX_BODY_BYTES);

    let (path, query) = match url.find('?') {
        Some(pos) => (&url[..pos], &url[pos + 1..]),
        None      => (url, ""),
    };

    // `full` includes url + body + header values so every regex pattern
    // also scans User-Agent, Cookie, Referer, etc. — mirrors Python logic.
    // Separate full strings:
    // - full_for_chars: URL + body only (for character counts, no header noise)
    // - full_for_patterns: URL + body + headers (for regex-based attack detection in all fields)
    let full_for_chars = {
        let mut s = url.to_string();
        if !body.is_empty() { s.push(' '); s.push_str(body); }
        s
    };

    let full_for_patterns = {
        let mut s = url.to_string();
        if !body.is_empty()         { s.push(' '); s.push_str(body); }
        if !headers_text.is_empty() { s.push(' '); s.push_str(&headers_text); }
        s
    };

    let full_dec_for_patterns = url_decode(&full_for_patterns);
    let n = full_for_chars.chars().count().max(1) as f32;

    // num_params counts query-string and body params, not header values.
    let num_params =
        (if query.is_empty() { 0 } else { query.matches('&').count() + 1 })
        + (if body.is_empty()  { 0 } else { body.matches('&').count() + 1 });

    let digit_count  = full_for_chars.chars().filter(|c| c.is_ascii_digit()).count() as f32;
    let upper_count  = full_for_chars.chars().filter(|c| c.is_ascii_uppercase()).count() as f32;
    let special_count = full_for_chars
        .chars()
        .filter(|c| matches!(c, '\'' | '"' | '<' | '>' | ';' | '=' | '%' | '&' | '+'))
        .count() as f32;

    // "../" is already lowercase — no need to lowercase full_dec before matching.
    let path_traversal = full_dec_for_patterns.matches("../").count() as f32;

    [
        // Python len() counts Unicode *characters*; Rust str::len() counts UTF-8
        // *bytes*.  Use chars().count() so the values match for non-ASCII input.
        request.chars().count() as f32,                                    // 0  total length in chars
        method_id(method),                                                 // 1
        path.chars().count() as f32,                                       // 2
        query.chars().count() as f32,                                      // 3
        body.chars().count() as f32,                                       // 4  body length in chars
        num_params as f32,                                                 // 5  query + body params
        shannon_entropy(&full_for_chars),                                  // 6
        digit_count / n,                                                   // 7
        upper_count / n,                                                   // 8
        special_count,                                                     // 9
        full_for_chars.matches('\'').count() as f32,                       // 10
        full_for_chars.matches('"').count() as f32,                        // 11
        (full_for_chars.matches('<').count() + full_for_chars.matches('>').count()) as f32,    // 12
        full_for_chars.matches(';').count() as f32,                        // 13
        PCT_RE.find_iter(&full_for_chars).count() as f32,                  // 14 raw
        if SQL_CTX_RE.is_match(&full_dec_for_patterns) {                   // 15 decoded, context-gated
            SQL_RE.find_iter(&full_dec_for_patterns).count() as f32
        } else {
            0.0
        },
        XSS_RE.find_iter(&full_dec_for_patterns).count() as f32,           // 16 decoded
        path_traversal,                                                    // 17 decoded
        CMD_RE.find_iter(&full_dec_for_patterns).count() as f32,           // 18 decoded
        SCANNER_RE.find_iter(&full_dec_for_patterns).count() as f32,       // 19 decoded
        SSRF_RE.find_iter(&full_dec_for_patterns).count() as f32,          // 20 decoded
        PHP_RE.find_iter(&full_dec_for_patterns).count() as f32,           // 21 decoded
        NULL_BYTE_RE.find_iter(&full_for_patterns).count() as f32,          // 22 raw — %00 vanishes after url_decode, must scan raw string
        HEX_ENCODE_RE.find_iter(&full_for_chars).count() as f32,           // 23 raw
        CRLF_RE.find_iter(&full_for_chars).count() as f32,                 // 24 raw
        DBL_ENC_RE.find_iter(&full_for_chars).count() as f32,              // 25 raw
        SSTI_RE.find_iter(&full_dec_for_patterns).count() as f32,          // 26 decoded
        request.matches('\n').count() as f32,                              // 27 header_count
        shannon_entropy(&headers_text),                                    // 28 header_entropy
    ]
}
