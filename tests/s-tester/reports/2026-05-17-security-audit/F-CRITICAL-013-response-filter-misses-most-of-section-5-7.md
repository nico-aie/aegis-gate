---
id: 2026-05-17-response-filter-misses-most-of-5-7
date: 2026-05-17T00:00Z
severity: CRITICAL
area: security · response filtering · outbound protection
component: crates/aegis-security/src/response_filter.rs · crates/aegis-security/src/pipeline.rs (on_response_*)
interop_contract: official rules §5.7 Response Filtering & Outbound Protection (BẮT BUỘC)
status: open
test_mode: source-review (spot-verified: STRIP_HEADERS = ["server", "x-powered-by"])
---

# F-CRITICAL-013 · `response_filter.rs` only strips 2 headers — misses every major §5.7 outbound-protection requirement

## Summary

§5.7 lists FOUR outbound-protection requirements as mandatory:

| Req | Status |
|---|---|
| Block response containing stack trace / internal IP / API key / verbose error (5xx > size cap) | ⚠️ Partial — scrub only, never blocks |
| Mask/redact sensitive JSON fields by configurable list (card_number, bank_account) | ❌ Missing — DLP regex scan, not field-aware |
| Detect + block PII leak in response HEADERS (X-Debug, X-Internal-*) | ❌ Missing — only `server` + `x-powered-by` stripped |
| Configurable 5xx body-size cap | ❌ Missing |

Spot-verified at [response_filter.rs:5](aegis-gate/crates/aegis-security/src/response_filter.rs#L5):

```rust
const STRIP_HEADERS: &[&str] = &["server", "x-powered-by"];
```

That's it. `X-Debug`, `X-Debug-*`, `X-Internal-*`, `X-AspNet-Version`,
`X-Generator`, `X-Runtime`, `X-Php-Version`, etc. — all of which
backend frameworks routinely leak — are passed through to the client.

Body-side scanning at
[response_filter.rs:75-86](aegis-gate/crates/aegis-security/src/response_filter.rs#L75-L86)
detects stack traces and internal IPs but only REDACTS (replaces
patterns inline); it never short-circuits the response with a 502
"upstream leaked sensitive data" decision, as the spec requires
("**Block** response chứa stack trace…").

## Impact

- **§5.7 violation across all four sub-requirements.** Every grader
  that probes §5.7 will deduct.
- **Security Effectiveness rubric (40/120)** — §5.7 is "BẮT BUỘC".
- **Real-world exposure** — backend frameworks (Django DEBUG=True,
  Spring Boot stack traces, Rails error pages) routinely leak the
  exact information §5.7 enumerates. The WAF's outbound protection
  is the last line of defense.
- **Operator-facing UX** — operators tuning `card_number` /
  `bank_account` field masks via `cfg.dlp.field_list` see no effect
  because the current DLP path is text-regex-based, not JSON-field-
  based.

## Suggested fix

Four additive changes.

### 1. Expand `STRIP_HEADERS` + add prefix scanner

```diff
-const STRIP_HEADERS: &[&str] = &["server", "x-powered-by"];
+const STRIP_HEADERS_EXACT: &[&str] = &[
+    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
+    "x-runtime", "x-version", "x-generator", "x-php-version", "x-rails-env",
+];
+const STRIP_HEADERS_PREFIX: &[&str] = &[
+    "x-debug",
+    "x-internal",
+    "x-trace",
+];
+
+fn should_strip_header(name: &str) -> bool {
+    let lower = name.to_ascii_lowercase();
+    STRIP_HEADERS_EXACT.contains(&lower.as_str())
+        || STRIP_HEADERS_PREFIX.iter().any(|p| lower.starts_with(p))
+}
```

Update `inject_security_headers` (the existing scrub call site):

```diff
-for name in STRIP_HEADERS {
-    headers.remove(*name);
-}
+headers.retain(|name, _| !should_strip_header(name.as_str()));
```

### 2. Add 5xx body-size cap + verbose-error block

```rust
// pipeline.rs::on_response_start
if status.is_server_error() {
    if let Some(content_length) = headers.get(CONTENT_LENGTH)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
    {
        if content_length > cfg.response_filter.max_5xx_body_bytes {
            return Verdict::ReplaceWith {
                status: 502,
                body: br#"{"error":"upstream response too large"}"#.to_vec(),
                rule_id: "response_filter.verbose_5xx_blocked",
            };
        }
    }
}
```

Default `max_5xx_body_bytes` ~ 4 KiB. Operator-tunable.

### 3. Field-aware JSON masking

```rust
// dlp/mod.rs
pub struct FieldMask {
    pub field_names: Vec<String>,            // ["card_number", "bank_account", "ssn"]
    pub replacement: String,                  // "***"
}

pub fn mask_json_fields(body: &mut serde_json::Value, mask: &FieldMask) {
    match body {
        serde_json::Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if mask.field_names.iter().any(|f| f.eq_ignore_ascii_case(k)) {
                    *v = serde_json::Value::String(mask.replacement.clone());
                } else {
                    mask_json_fields(v, mask);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr.iter_mut() { mask_json_fields(v, mask); }
        }
        _ => {}
    }
}
```

Pipeline integration:

```rust
// on_response_complete:
if let Ok(mut json) = serde_json::from_slice::<serde_json::Value>(&body) {
    mask_json_fields(&mut json, &cfg.dlp.field_mask);
    let new_body = serde_json::to_vec(&json)?;
    // ... rewrite body ...
}
```

Operator config:

```yaml
dlp:
  field_mask:
    field_names: [card_number, bank_account, ssn, social_security_number, email]
    replacement: "***"
```

### 4. Block (not just scrub) on stack-trace / internal-IP / API-key detection

Combine the existing detectors with a `Verdict::Replace { ..., status: 502 }` instead of inline redact. The current "redact only" mode is acceptable as a TOGGLE (`cfg.response_filter.mode: scrub | block`), but the default should be `block` per the spec's "Block response chứa stack trace" wording.

Add IPv6 to the internal-IP regex (currently IPv4-only per
F-HIGH-response-filter-dlp): `::1`, `fc00::/7`, `fe80::/10`.

## Verification

```sh
HOST="http://127.0.0.1:8080"

# Stack-trace leak from upstream:
# (configure upstream to return a 500 with a Python traceback in body)
curl -sk "$HOST/upstream-with-500" -i | head -50
# Expect: 502 with generic body; X-WAF-Rule-Id: response_filter.stack_trace_blocked.

# Header leak:
# (configure upstream to set X-Debug-User: alice in response)
curl -sk "$HOST/x-debug-leak" -i | grep -i '^x-debug'
# Expect: no x-debug header in response.

# JSON field mask:
curl -sk "$HOST/api/user/1" | jq .card_number
# Expect: "***" (not the actual card_number from upstream).
```

Regression cases in `tests/security/response_filter/`:
- Stack trace leak (Python, Java, .NET, Rust formats)
- Internal IPv4 + IPv6 leak
- AWS API-key leak
- X-Debug-User header leak
- card_number JSON field mask

## Severity rationale

CRITICAL. §5.7 is "BẮT BUỘC" with four enumerated sub-requirements
all of which are either missing or half-implemented. Security
Effectiveness rubric (40/120) takes a measurable hit. Fix is
~100 LoC of mostly mechanical work.
