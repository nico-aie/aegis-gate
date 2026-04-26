use regex::Regex;
use std::sync::LazyLock;

/// Headers to strip from responses.
const STRIP_HEADERS: &[&str] = &["server", "x-powered-by"];

/// Security headers to inject.
pub struct SecurityHeaders {
    pub x_content_type_options: &'static str,
    pub x_frame_options: &'static str,
    pub hsts: &'static str,
    pub referrer_policy: &'static str,
    pub permissions_policy: &'static str,
    pub csp: Option<String>,
}

impl Default for SecurityHeaders {
    fn default() -> Self {
        Self {
            x_content_type_options: "nosniff",
            x_frame_options: "DENY",
            hsts: "max-age=63072000; includeSubDomains; preload",
            referrer_policy: "strict-origin-when-cross-origin",
            permissions_policy: "camera=(), microphone=(), geolocation=()",
            csp: None,
        }
    }
}

/// Apply security header injection to a response header map.
pub fn inject_security_headers(headers: &mut http::HeaderMap, config: &SecurityHeaders) {
    // Strip dangerous headers.
    for name in STRIP_HEADERS {
        headers.remove(*name);
    }

    // Inject security headers.
    headers.insert("x-content-type-options", config.x_content_type_options.parse().unwrap());
    headers.insert("x-frame-options", config.x_frame_options.parse().unwrap());
    headers.insert("strict-transport-security", config.hsts.parse().unwrap());
    headers.insert("referrer-policy", config.referrer_policy.parse().unwrap());
    headers.insert("permissions-policy", config.permissions_policy.parse().unwrap());
    if let Some(csp) = &config.csp {
        headers.insert("content-security-policy", csp.parse().unwrap());
    }
}

// Stack trace patterns for various languages.
static STACK_TRACE_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"(?m)^\s*at\s+[\w.$<>]+\s+\([\w.]+:\d+:\d+\)", // Node.js
        r"(?m)^\s*at\s+[\w.$]+\([\w./]+\.java:\d+\)",       // JVM
        r#"(?m)^\s*File\s+"[^"]+",\s+line\s+\d+"#,       // Python
        r"(?m)^\s+\d+:\s+0x[0-9a-f]+\s+-\s+",              // Rust
        r"(?m)^\s*#\d+\s+[\w./]+\.php\(\d+\)",              // PHP
        r"(?m)^\s*at\s+[\w.]+\s+in\s+[\w/.:]+:line\s+\d+", // .NET
        r"(?m)^\s*[\w./]+\.rb:\d+:in\s+`",                  // Rails/Ruby
        r"(?m)goroutine\s+\d+\s+\[",                        // Go
        r"(?m)^\s*[\w./]+\.go:\d+\s+",                      // Go files
        r"(?m)Traceback\s+\(most recent call last\)",        // Python traceback header
    ]
    .iter()
    .map(|p| Regex::new(p).unwrap())
    .collect()
});

// Internal IP patterns (RFC 1918, link-local, loopback).
static INTERNAL_IP_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3})\b"
    ).unwrap()
});

/// Scrub stack traces from a text chunk.
pub fn scrub_stack_traces(text: &str) -> String {
    let mut result = text.to_string();
    for re in STACK_TRACE_PATTERNS.iter() {
        result = re.replace_all(&result, "[REDACTED]").to_string();
    }
    result
}

/// Mask internal IP addresses in text.
pub fn mask_internal_ips(text: &str) -> String {
    INTERNAL_IP_PATTERN.replace_all(text, "[INTERNAL]").to_string()
}

/// Process a response body chunk through all filters.
pub fn filter_chunk(chunk: &[u8]) -> Vec<u8> {
    match std::str::from_utf8(chunk) {
        Ok(text) => {
            let scrubbed = scrub_stack_traces(text);
            let masked = mask_internal_ips(&scrubbed);
            masked.into_bytes()
        }
        Err(_) => chunk.to_vec(), // Binary data: pass through.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Header tests.
    #[test]
    fn strips_server_header() {
        let mut headers = http::HeaderMap::new();
        headers.insert("server", "nginx/1.25".parse().unwrap());
        headers.insert("content-type", "text/html".parse().unwrap());
        inject_security_headers(&mut headers, &SecurityHeaders::default());
        assert!(!headers.contains_key("server"));
        assert!(headers.contains_key("content-type"));
    }

    #[test]
    fn strips_x_powered_by() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-powered-by", "Express".parse().unwrap());
        inject_security_headers(&mut headers, &SecurityHeaders::default());
        assert!(!headers.contains_key("x-powered-by"));
    }

    #[test]
    fn injects_security_headers() {
        let mut headers = http::HeaderMap::new();
        inject_security_headers(&mut headers, &SecurityHeaders::default());
        assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
        assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
        assert!(headers.contains_key("strict-transport-security"));
        assert!(headers.contains_key("referrer-policy"));
        assert!(headers.contains_key("permissions-policy"));
    }

    #[test]
    fn injects_csp_when_configured() {
        let mut headers = http::HeaderMap::new();
        let config = SecurityHeaders {
            csp: Some("default-src 'self'".into()),
            ..SecurityHeaders::default()
        };
        inject_security_headers(&mut headers, &config);
        assert_eq!(headers.get("content-security-policy").unwrap(), "default-src 'self'");
    }

    #[test]
    fn no_csp_when_none() {
        let mut headers = http::HeaderMap::new();
        inject_security_headers(&mut headers, &SecurityHeaders::default());
        assert!(!headers.contains_key("content-security-policy"));
    }

    // Stack trace scrubbing tests.
    #[test]
    fn scrub_nodejs_trace() {
        let text = "Error: something\n    at Object.<anonymous> (app.js:10:15)\n    at Module._compile (internal:5:3)";
        let scrubbed = scrub_stack_traces(text);
        assert!(!scrubbed.contains("app.js:10:15"));
    }

    #[test]
    fn scrub_python_trace() {
        let text = "Traceback (most recent call last)\n  File \"/app/views.py\", line 42\n    return render()";
        let scrubbed = scrub_stack_traces(text);
        assert!(!scrubbed.contains("/app/views.py"));
    }

    #[test]
    fn scrub_java_trace() {
        let text = "    at com.example.App.main(App.java:25)\n    at java.base/Thread.run(Thread.java:833)";
        let scrubbed = scrub_stack_traces(text);
        assert!(!scrubbed.contains("App.java:25"));
    }

    #[test]
    fn scrub_go_trace() {
        let text = "goroutine 1 [running]:\nmain.handler()";
        let scrubbed = scrub_stack_traces(text);
        assert!(!scrubbed.contains("goroutine 1"));
    }

    #[test]
    fn normal_text_unchanged() {
        let text = "Hello, this is a normal response body with no stack traces.";
        assert_eq!(scrub_stack_traces(text), text);
    }

    // Internal IP masking tests.
    #[test]
    fn mask_rfc1918_10() {
        let text = "Connected to 10.0.1.5 on port 8080";
        let masked = mask_internal_ips(text);
        assert!(!masked.contains("10.0.1.5"));
        assert!(masked.contains("[INTERNAL]"));
    }

    #[test]
    fn mask_rfc1918_172() {
        let text = "Server at 172.16.0.1";
        let masked = mask_internal_ips(text);
        assert!(!masked.contains("172.16.0.1"));
    }

    #[test]
    fn mask_rfc1918_192() {
        let text = "Backend: 192.168.1.100";
        let masked = mask_internal_ips(text);
        assert!(!masked.contains("192.168.1.100"));
    }

    #[test]
    fn mask_loopback() {
        let text = "Listening on 127.0.0.1:3000";
        let masked = mask_internal_ips(text);
        assert!(!masked.contains("127.0.0.1"));
    }

    #[test]
    fn mask_link_local() {
        let text = "IP: 169.254.1.1";
        let masked = mask_internal_ips(text);
        assert!(!masked.contains("169.254.1.1"));
    }

    #[test]
    fn public_ip_untouched() {
        let text = "Server: 8.8.8.8";
        assert_eq!(mask_internal_ips(text), text);
    }

    // filter_chunk tests.
    #[test]
    fn filter_chunk_scrubs_and_masks() {
        let text = "Error at 10.0.0.1\n    at Object.<anonymous> (app.js:10:15)";
        let filtered = filter_chunk(text.as_bytes());
        let result = String::from_utf8(filtered).unwrap();
        assert!(!result.contains("10.0.0.1"));
        assert!(!result.contains("app.js:10:15"));
    }

    #[test]
    fn filter_chunk_binary_passthrough() {
        let binary = vec![0xFF, 0xFE, 0x00, 0x01];
        let filtered = filter_chunk(&binary);
        assert_eq!(filtered, binary);
    }

    #[test]
    fn filter_chunk_clean_text_unchanged() {
        let text = "OK";
        let filtered = filter_chunk(text.as_bytes());
        assert_eq!(filtered, text.as_bytes());
    }
}
