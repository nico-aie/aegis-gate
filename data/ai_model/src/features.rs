/// WAF feature extraction — exact port of ml_waf/features.py.
/// 26 dense float32 features per HTTP request string.
use once_cell::sync::Lazy;
use regex::Regex;

pub const NUM_FEATURES: usize = 26;

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
];

static SQL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(select|union|insert|update|delete|drop|create|alter|exec|execute|where|from|having|order|group|join|table|database|schema|char|nchar|varchar|cast|convert|declare|waitfor|xp_|sp_|0x)\b").unwrap()
});

static XSS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(<script|javascript:|vbscript:|onload=|onerror=|onclick=|onfocus=|alert\(|confirm\(|prompt\(|document\.cookie|document\.write|eval\(|<iframe|<img\s|<svg|srcdoc=)").unwrap()
});

static SCANNER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(nikto|sqlmap|nmap|masscan|acunetix|nessus|openvas|dirbuster|gobuster|wfuzz|w3af|commix)").unwrap()
});

static PCT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"%[0-9a-fA-F]{2}").unwrap());

static CMD_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[;|]|\|\||&&|\$\(|`[^`]*`").unwrap());

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

fn method_id(method: &str) -> f32 {
    match method.to_ascii_uppercase().as_str() {
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

/// Decode %XX percent-encoding. Non-hex sequences are kept as-is.
fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
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

/// Shannon entropy — uses chars to match Python's behaviour.
fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    let mut n = 0u32;
    for c in s.chars() {
        counts[(c as u32).min(255) as usize] += 1;
        n += 1;
    }
    let n = n as f32;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f32 / n;
            -p * p.log2()
        })
        .sum()
}

/// Extract 26 WAF features from a raw HTTP request string.
pub fn extract_features(request: &str) -> [f32; NUM_FEATURES] {
    let mut parts = request.splitn(3, ' ');
    let method = parts.next().unwrap_or("GET");
    let url = parts.next().unwrap_or("/");
    let body = parts.next().unwrap_or("");

    let (path, query) = if let Some(pos) = url.find('?') {
        (&url[..pos], &url[pos + 1..])
    } else {
        (url, "")
    };

    let full: String = if body.is_empty() {
        url.to_string()
    } else {
        format!("{} {}", url, body)
    };

    // Decoded version — catches payloads hidden behind percent-encoding
    let full_dec = url_decode(&full);

    let n = full.chars().count().max(1) as f32;

    let num_params = (if query.is_empty() {
        0
    } else {
        query.matches('&').count() + 1
    }) + (if body.is_empty() {
        0
    } else {
        body.matches('&').count() + 1
    });

    let digit_count = full.chars().filter(|c| c.is_ascii_digit()).count() as f32;
    let upper_count = full.chars().filter(|c| c.is_ascii_uppercase()).count() as f32;
    let special_count = full
        .chars()
        .filter(|c| matches!(c, '\'' | '"' | '<' | '>' | ';' | '=' | '%' | '&' | '+'))
        .count() as f32;

    let full_dec_lower = full_dec.to_lowercase();
    let path_traversal = full_dec_lower.matches("../").count() as f32;

    [
        request.len() as f32,                                  // 0  request_len
        method_id(method),                                     // 1  method_id
        path.len() as f32,                                     // 2  path_len
        query.len() as f32,                                    // 3  query_len
        body.len() as f32,                                     // 4  body_len
        num_params as f32,                                     // 5  num_params
        shannon_entropy(&full),                                // 6  entropy
        digit_count / n,                                       // 7  digit_ratio
        upper_count / n,                                       // 8  upper_ratio
        special_count,                                         // 9  special_char_count
        full.matches('\'').count() as f32,                     // 10 single_quote_count
        full.matches('"').count() as f32,                      // 11 double_quote_count
        (full.matches('<').count() + full.matches('>').count()) as f32, // 12 angle_bracket_count
        full.matches(';').count() as f32,                      // 13 semicolon_count
        PCT_RE.find_iter(&full).count() as f32,                // 14 pct_encoded_count    (raw)
        SQL_RE.find_iter(&full_dec).count() as f32,            // 15 sql_keyword_count    (decoded)
        XSS_RE.find_iter(&full_dec).count() as f32,            // 16 xss_pattern_count    (decoded)
        path_traversal,                                        // 17 path_traversal_count (decoded)
        CMD_RE.find_iter(&full_dec).count() as f32,            // 18 cmd_injection_count  (decoded)
        SCANNER_RE.find_iter(&full_dec).count() as f32,        // 19 scanner_count        (decoded)
        SSRF_RE.find_iter(&full_dec).count() as f32,           // 20 ssrf_count           (decoded)
        PHP_RE.find_iter(&full_dec).count() as f32,            // 21 php_pattern_count    (decoded)
        NULL_BYTE_RE.find_iter(&full).count() as f32,          // 22 null_byte_count      (raw)
        HEX_ENCODE_RE.find_iter(&full).count() as f32,         // 23 hex_encode_count     (raw)
        CRLF_RE.find_iter(&full).count() as f32,               // 24 crlf_inject_count    (raw)
        DBL_ENC_RE.find_iter(&full).count() as f32,            // 25 double_encode_count  (raw)
    ]
}
