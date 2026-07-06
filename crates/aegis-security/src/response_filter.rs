use regex::Regex;
use std::sync::LazyLock;

/// 2026-05-18 F-CRITICAL-013 (security audit, Phase F §5.7 sub-fix
/// 1+3): outbound response header strip-list. Pre-fix this only
/// covered `server` + `x-powered-by`; backend frameworks routinely
/// leak version banners and debug context that §5.7 explicitly
/// requires the WAF to scrub.
///
/// Exact matches catch the well-known stable header names.
const STRIP_HEADERS_EXACT: &[&str] = &[
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-runtime",
    "x-version",
    "x-generator",
    "x-php-version",
    "x-rails-env",
];

/// Prefix matches catch families of debug / internal headers that
/// frameworks emit with caller-specific suffixes (`X-Debug-User`,
/// `X-Internal-Latency`, `X-Trace-Id`, etc.). §5.7 mandates that
/// PII / debug context never crosses the WAF to the client.
const STRIP_HEADERS_PREFIX: &[&str] = &[
    "x-debug",
    "x-internal",
    "x-trace",
];

/// Test whether a response header name should be stripped before
/// the WAF emits the response to the client. Case-insensitive —
/// HTTP/2 lowercases header names so a single lowercase match
/// covers the wire, but production responses from upstream HTTP/1.1
/// often carry mixed-case names that the strip needs to handle too.
pub fn should_strip_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    STRIP_HEADERS_EXACT.iter().any(|h| *h == lower)
        || STRIP_HEADERS_PREFIX.iter().any(|p| lower.starts_with(p))
}

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
    // 2026-05-18 F-CRITICAL-013 §5.7 — strip the wider class via
    // the unified `should_strip_header` predicate (exact + prefix).
    // Headers we strip get collected first because `retain` would
    // need a mutable + immutable borrow otherwise.
    let to_remove: Vec<http::HeaderName> = headers
        .keys()
        .filter(|k| should_strip_header(k.as_str()))
        .cloned()
        .collect();
    for name in to_remove {
        headers.remove(&name);
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

/// 2026-05-18 F-CRITICAL-013 §5.7 sub-fix (IPv6 internal-IP).
/// Covers:
///
/// - `::1` — IPv6 loopback
/// - `fc00::/7` — Unique Local Addresses (matches `fc..` / `fd..`)
/// - `fe80::/10` — link-local (`fe80::` through `febf::`)
/// - `::ffff:<ipv4>` — IPv4-mapped IPv6
///
/// `\b` alone is unreliable for IPv6 because `:` is a non-word
/// character — `\b` fires at every `hex→:` and `:→hex` boundary,
/// so a public address like `2001:db8::1` would match the `::1`
/// suffix unintentionally. Each branch instead uses explicit
/// char-class anchors `(?:^|[^0-9a-fA-F:])` ... `(?:$|[^0-9a-fA-F])`
/// to require the IPv6 token be its own atom in the surrounding
/// text. The leading anchor is captured into named group `lead`
/// so `replace_all` can preserve it.
static INTERNAL_IPV6_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        // Leading anchor only — the `lead` capture distinguishes
        // bare `::1` from the `::1` tail of a longer public address
        // like `2001:db8::1`. We deliberately do NOT anchor the
        // trailing side because legitimate contexts (`::1:9999`
        // for port, `fc00:abcd:1234:5678::42` for the rest of a
        // ULA) place hex/colon directly after our pattern. Greedy
        // hex/colon consumption inside the address branches
        // (`[0-9a-f:]+`) handles the ULA / link-local "rest of
        // address" naturally.
        r"(?ix)
            (?P<lead> ^ | [^0-9a-fA-F:] )
            (?:
                ::1
                | [f][cd][0-9a-f]{2} : [0-9a-f:]+
                | fe[89ab][0-9a-f]   : [0-9a-f:]+
                | ::ffff: \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}
            )
        "
    ).unwrap()
});

/// EG-2 T4 (2026-07-05) — detection oracle over the SAME
/// [`struct@STACK_TRACE_PATTERNS`] the scrubber rewrites. The error-leak
/// detector (`detectors::egress_leak`) reuses this so the "observe" and the
/// "redact" halves can never drift to different pattern sets: one is the
/// twin of the other (design §3 — "count/audit what these scrub instead of
/// silently rewriting").
pub fn has_stack_trace(text: &str) -> bool {
    STACK_TRACE_PATTERNS.iter().any(|re| re.is_match(text))
}

/// EG-2 T4 — detection oracle over the internal-IP patterns
/// [`mask_internal_ips`] rewrites (IPv4 RFC-1918/loopback/link-local + the
/// IPv6 ULA/link-local/loopback/mapped set). True when the text contains any
/// internal address.
pub fn has_internal_ip(text: &str) -> bool {
    INTERNAL_IP_PATTERN.is_match(text) || INTERNAL_IPV6_PATTERN.is_match(text)
}

/// Scrub stack traces from a text chunk.
pub fn scrub_stack_traces(text: &str) -> String {
    let mut result = text.to_string();
    for re in STACK_TRACE_PATTERNS.iter() {
        result = re.replace_all(&result, "[REDACTED]").to_string();
    }
    result
}

/// Mask internal IP addresses in text. 2026-05-18 F-CRITICAL-013
/// §5.7: also masks IPv6 internal addresses (`::1`, `fc00::/7`,
/// `fe80::/10`, IPv4-mapped IPv6 `::ffff:10.0.0.1`). Pre-fix only
/// IPv4 RFC 1918 + link-local + loopback were caught; backend
/// errors from IPv6-only deployments leaked unmasked.
pub fn mask_internal_ips(text: &str) -> String {
    let v4 = INTERNAL_IP_PATTERN.replace_all(text, "[INTERNAL]");
    // IPv6 regex captures the leading anchor (start of text or
    // non-hex-non-colon char) so the surrounding context is
    // preserved across the replacement.
    INTERNAL_IPV6_PATTERN
        .replace_all(&v4, "${lead}[INTERNAL]")
        .to_string()
}

/// Infra connection-string DSNs (`redis://…`, `postgres://user:pass@…`).
/// Masked whole — the scheme + creds + host are all internal-disclosure.
static INFRA_DSN_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:rediss?|mongodb(?:\+srv)?|postgres(?:ql)?|mysql|amqps?)://[^\s"'<>]+"#)
        .unwrap()
});

/// Internal service-discovery hostnames: any FQDN carrying an `internal` or
/// `svc` label (`db.internal.novabet.local`, `x.svc.cluster.local`). The
/// interior `.internal.`/`.svc.` label is the signature — it does not occur
/// in public FQDNs, so `api.example.com` and the bare-`.local` filename
/// `app.local.js` are not matched.
static INTERNAL_HOST_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:internal|svc)(?:\.[a-z0-9-]+)*\b").unwrap()
});

/// Bare `*.cluster.local` (K8s) without an `svc` label.
static CLUSTER_LOCAL_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.cluster\.local\b").unwrap()
});

/// RF-3 (2026-07-06 S-Tester) — mask internal service-discovery hostnames
/// and infra connection-string DSNs, the sibling of [`mask_internal_ips`]
/// (which only masks IP literals). The `SUSPICIOUS_200` leaks disclosed
/// `db.internal.novabet.local` / `redis.internal.novabet.local:6379` which
/// no rung touched. Scoped to `internal`/`svc` labels + `.cluster.local` +
/// infra DSN schemes — all non-publicly-routable, so FP≈0. Public FQDNs
/// (`api.example.com`) and bare-`.local` mDNS filenames (`app.local.js`) are
/// intentionally NOT matched.
pub fn mask_internal_hostnames(text: &str) -> String {
    let a = INFRA_DSN_PATTERN.replace_all(text, "[INTERNAL]");
    let b = INTERNAL_HOST_PATTERN.replace_all(&a, "[INTERNAL]");
    CLUSTER_LOCAL_PATTERN.replace_all(&b, "[INTERNAL]").to_string()
}

/// 2026-05-18 F-CRITICAL-013 §5.7 sub-fix (JSON field masking).
/// Recursively replaces values of fields whose names match
/// `field_names` (case-insensitive) with `replacement`. Pure
/// function over `serde_json::Value`; no I/O, no allocation
/// beyond the replacement string.
///
/// Pipeline integration (wiring `on_response_complete` to call
/// this on JSON bodies) is a follow-up — this helper is the
/// load-bearing piece. Operators tuning `cfg.dlp.field_mask`
/// will see real effect once the wire-up lands.
///
/// Why field-aware, not regex: regex over arbitrary text can't
/// reliably distinguish a card number value from a card-number-
/// shaped string inside a stack trace. Field-aware masking only
/// touches the values of explicitly listed JSON keys — zero
/// false-positives on natural-language bodies.
pub fn mask_json_fields(
    body: &mut serde_json::Value,
    field_names: &[String],
    replacement: &str,
) {
    match body {
        serde_json::Value::Object(map) => {
            let names_lower: Vec<String> = field_names
                .iter()
                .map(|s| s.to_ascii_lowercase())
                .collect();
            for (k, v) in map.iter_mut() {
                if names_lower
                    .iter()
                    .any(|n| n == k.to_ascii_lowercase().as_str())
                {
                    *v = serde_json::Value::String(replacement.to_string());
                } else {
                    mask_json_fields(v, field_names, replacement);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr.iter_mut() {
                mask_json_fields(v, field_names, replacement);
            }
        }
        _ => {}
    }
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

    // RF-3 (2026-07-06 S-Tester) — internal-hostname masking.
    #[test]
    fn rf3_masks_internal_service_hostnames() {
        for host in [
            "db.internal.novabet.local",
            "redis.internal.novabet.local",
            "kubernetes.default.svc.cluster.local",
        ] {
            let out = mask_internal_hostnames(&format!("connect to {host} now"));
            assert!(!out.contains(host), "internal host leaked: {out}");
            assert!(out.contains("[INTERNAL]"), "no mask marker: {out}");
        }
    }

    #[test]
    fn rf3_masks_host_with_port_preserving_port() {
        let out = mask_internal_hostnames("redis.internal.novabet.local:6379");
        assert!(!out.contains("redis.internal.novabet.local"), "host leaked: {out}");
    }

    #[test]
    fn rf3_masks_infra_dsn() {
        let out = mask_internal_hostnames("redis://cache.internal.svc:6379/0");
        assert!(out.contains("[INTERNAL]"), "infra DSN must mask: {out}");
    }

    #[test]
    fn rf3_public_hostname_untouched() {
        // Public FQDNs and bare-`.local` filenames must pass through.
        for s in ["GET https://api.example.com/v1", "load /static/app.local.js"] {
            assert_eq!(mask_internal_hostnames(s), s, "public host masked: {s}");
        }
    }

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

    /// 2026-05-18 F-CRITICAL-013 §5.7: the extended exact strip
    /// list catches version banners no §5.7-compliant WAF should
    /// forward to clients.
    #[test]
    fn strips_extended_version_banners() {
        let mut headers = http::HeaderMap::new();
        for h in [
            "x-aspnet-version",
            "x-aspnetmvc-version",
            "x-runtime",
            "x-version",
            "x-generator",
            "x-php-version",
            "x-rails-env",
        ] {
            headers.insert(
                http::HeaderName::from_bytes(h.as_bytes()).unwrap(),
                "leak".parse().unwrap(),
            );
        }
        inject_security_headers(&mut headers, &SecurityHeaders::default());
        for h in [
            "x-aspnet-version",
            "x-aspnetmvc-version",
            "x-runtime",
            "x-version",
            "x-generator",
            "x-php-version",
            "x-rails-env",
        ] {
            assert!(!headers.contains_key(h), "{h} must be stripped");
        }
    }

    /// 2026-05-18 F-CRITICAL-013 §5.7: prefix scanner catches
    /// caller-specific debug / internal / trace headers
    /// frameworks routinely emit.
    #[test]
    fn strips_debug_internal_trace_prefixes() {
        let mut headers = http::HeaderMap::new();
        for h in [
            "x-debug-user",
            "x-debug",
            "x-internal-latency",
            "x-internal",
            "x-trace-id",
            "x-trace",
        ] {
            headers.insert(
                http::HeaderName::from_bytes(h.as_bytes()).unwrap(),
                "leak".parse().unwrap(),
            );
        }
        inject_security_headers(&mut headers, &SecurityHeaders::default());
        for h in [
            "x-debug-user",
            "x-debug",
            "x-internal-latency",
            "x-internal",
            "x-trace-id",
            "x-trace",
        ] {
            assert!(!headers.contains_key(h), "{h} must be stripped");
        }
    }

    /// Negative: legitimate response headers are NOT stripped.
    /// Specifically `content-type`, `etag`, `cache-control`,
    /// `x-request-id` (custom but non-debug) must pass through.
    #[test]
    fn does_not_strip_legitimate_headers() {
        let mut headers = http::HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        headers.insert("etag", "\"abc123\"".parse().unwrap());
        headers.insert("cache-control", "max-age=3600".parse().unwrap());
        headers.insert("x-request-id", "uuid-here".parse().unwrap());
        inject_security_headers(&mut headers, &SecurityHeaders::default());
        assert!(headers.contains_key("content-type"));
        assert!(headers.contains_key("etag"));
        assert!(headers.contains_key("cache-control"));
        assert!(headers.contains_key("x-request-id"));
    }

    /// `should_strip_header` is case-insensitive — HTTP/2 emits
    /// lowercase but HTTP/1.1 upstream responses don't necessarily.
    #[test]
    fn should_strip_is_case_insensitive() {
        assert!(should_strip_header("Server"));
        assert!(should_strip_header("X-POWERED-BY"));
        assert!(should_strip_header("X-Debug-User"));
        assert!(!should_strip_header("Content-Type"));
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

    // ---- 2026-05-18 F-CRITICAL-013 §5.7 ---------------------------------

    /// IPv6 loopback (`::1`) masked.
    #[test]
    fn masks_ipv6_loopback() {
        let text = "upstream unreachable: ::1:9999";
        let m = mask_internal_ips(text);
        assert!(!m.contains("::1"), "got {m}");
        assert!(m.contains("[INTERNAL]"));
    }

    /// Unique Local Address `fc00::/7` masked.
    #[test]
    fn masks_ipv6_ula() {
        let text = "trying upstream fc00:abcd:1234:5678::42 …";
        let m = mask_internal_ips(text);
        assert!(!m.contains("fc00:abcd"), "got {m}");
        assert!(m.contains("[INTERNAL]"));
    }

    /// Link-local `fe80::/10` masked.
    #[test]
    fn masks_ipv6_link_local() {
        let text = "neighbor fe80::1234:abcd advertised";
        let m = mask_internal_ips(text);
        assert!(!m.contains("fe80::1234"), "got {m}");
    }

    /// IPv4-mapped IPv6 (`::ffff:10.0.0.1`) masked — covers the
    /// `[::ffff:<v4>]` SSRF / leak shape.
    #[test]
    fn masks_ipv4_mapped_ipv6() {
        let text = "rerouting to ::ffff:10.0.0.5 backend";
        let m = mask_internal_ips(text);
        assert!(!m.contains("::ffff:10.0.0.5"), "got {m}");
    }

    /// Public IPv6 addresses are NOT masked (negative test).
    #[test]
    fn does_not_mask_public_ipv6() {
        let text = "ipv6 host 2001:db8::1 listening";
        let m = mask_internal_ips(text);
        assert!(m.contains("2001:db8::1"), "public IPv6 should not be masked: {m}");
    }

    /// JSON field mask replaces values for configured field names.
    #[test]
    fn json_field_mask_replaces_listed_fields() {
        let mut body = serde_json::json!({
            "user": "alice",
            "card_number": "4242424242424242",
            "bank_account": "12345-67890",
            "balance": 100,
        });
        let fields = vec!["card_number".to_string(), "bank_account".to_string()];
        mask_json_fields(&mut body, &fields, "***");
        assert_eq!(body["card_number"], serde_json::Value::String("***".into()));
        assert_eq!(body["bank_account"], serde_json::Value::String("***".into()));
        assert_eq!(body["user"], serde_json::Value::String("alice".into()));
        assert_eq!(body["balance"], serde_json::json!(100));
    }

    /// JSON field mask is case-insensitive on field names.
    #[test]
    fn json_field_mask_is_case_insensitive() {
        let mut body = serde_json::json!({"Card_Number": "4242"});
        mask_json_fields(&mut body, &["card_number".into()], "***");
        assert_eq!(body["Card_Number"], serde_json::Value::String("***".into()));
    }

    /// JSON field mask recurses into nested objects + arrays.
    #[test]
    fn json_field_mask_recurses() {
        let mut body = serde_json::json!({
            "users": [
                {"name": "alice", "ssn": "111-22-3333"},
                {"name": "bob",   "ssn": "444-55-6666"},
            ],
            "meta": {
                "owner": {"ssn": "999-00-1111"},
            },
        });
        mask_json_fields(&mut body, &["ssn".into()], "***");
        assert_eq!(body["users"][0]["ssn"], serde_json::Value::String("***".into()));
        assert_eq!(body["users"][1]["ssn"], serde_json::Value::String("***".into()));
        assert_eq!(body["meta"]["owner"]["ssn"], serde_json::Value::String("***".into()));
        assert_eq!(body["users"][0]["name"], serde_json::Value::String("alice".into()));
    }

    /// Empty field-names list is a no-op.
    #[test]
    fn json_field_mask_empty_list_no_op() {
        let original = serde_json::json!({"card_number": "4242", "user": "alice"});
        let mut body = original.clone();
        mask_json_fields(&mut body, &[], "***");
        assert_eq!(body, original);
    }
}
