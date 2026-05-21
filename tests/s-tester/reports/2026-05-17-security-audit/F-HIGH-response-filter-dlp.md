---
id: 2026-05-17-high-response-filter-dlp-bundle
date: 2026-05-17T00:00Z
severity: HIGH
area: security · response filter · DLP · content inspection
component: crates/aegis-security/src/{response_filter.rs, dlp/*.rs, content/mod.rs}
interop_contract: official rules §5.7 (Response Filtering & Outbound Protection)
status: open
test_mode: source-review
---

# F-HIGH-response-filter-dlp bundle — 5 issues complementary to F-CRITICAL-013

These items don't rise to CRITICAL individually but each is a §5.7
gap.

---

## RD-01 · `dlp/fpe.rs` is a STUB: "XORs with key bytes mod 10"

**Component:** [dlp/fpe.rs:52, 74-89](../../../../crates/aegis-security/src/dlp/fpe.rs#L52)

File header line 1: *"Format-Preserving Encryption stub (AES-FF1).
In production, use a proper FF1 crate."*

Implementation: `XOR each digit with key byte mod 10. Symmetric.`

This is NOT AES-FF1. It's not even XOR-mod-10 securely — repeated
ciphertexts under the same key reveal everything via known-plaintext.

The README advertises "format-preserving encryption (AES-FF1)" as
part of DLP. If a grader probes PCI/PII masking effectiveness, this
fails.

**Fix:** use the `fpe` crate (pure-Rust FF1 implementation by RustCrypto):

```toml
[workspace.dependencies]
fpe = "0.6"
```

```rust
use fpe::ff1::{FF1, FlexibleNumeralString};

pub fn encrypt(&self, plaintext: &str) -> Option<(String, u32)> {
    let ff = FF1::<aes::Aes256>::new(&self.key.key, 10).ok()?;
    let digits: Vec<u16> = plaintext.bytes().filter(|b| b.is_ascii_digit())
        .map(|b| (b - b'0') as u16).collect();
    let encrypted = ff.encrypt(&[], &FlexibleNumeralString::from(digits)).ok()?;
    let out: String = encrypted.iter().map(|d| ((*d as u8) + b'0') as char).collect();
    Some((out, self.key.version))
}
```

Document the dep choice (license, crate freshness).

---

## RD-02 · Internal-IP regex covers IPv4 only; misses IPv6 `::1`, `fc00::/7`, `fe80::/10`

**Component:** [response_filter.rs:68-72](../../../../crates/aegis-security/src/response_filter.rs#L68-L72)

The current regex matches IPv4 RFC1918 / 169.254 / 127.0.0.0/8. §5.7's
"internal IP" framing is family-agnostic. Modern backends frequently
expose IPv6 ULA / link-local addresses in error responses (Kubernetes
service mesh, dual-stack networks).

**Fix:** add IPv6 patterns:

```rust
const IPV6_INTERNAL_PATTERNS: &[&str] = &[
    r"\b::1\b",                              // loopback
    r"\b[fF][cdCD][0-9a-fA-F]{2}:",         // fc00::/7 ULA
    r"\b[fF][eE]8[0-9a-fA-F]:",             // fe80::/10 link-local
    r"\b[fF][fF][0-9a-fA-F]{2}:",           // ff00::/8 multicast
];
```

---

## RD-03 · DLP has no field-aware JSON masking — `card_number` field config silently ignored

**Component:** [dlp/mod.rs:153-159](../../../../crates/aegis-security/src/dlp/mod.rs#L153-L159)

§5.7 specifies "Mask/redact sensitive fields trong response JSON
(configurable field list: card_number, bank_account, ...)". Current
DLP does substring/regex matching on the whole response text — it
masks anything that LOOKS like a card number, not anything whose
JSON KEY is `card_number`.

Difference matters: a legitimate response with `{"product_id": "4111111111111111"}` (16 digits but not a card) gets masked
(false positive), while `{"card_number": "abcd1234"}` (operator's
opaque token format) doesn't (false negative).

**Fix:** see F-CRITICAL-013's "field-aware JSON masking" section.
Two-step DLP: (1) regex scan for known PII shapes (current behavior),
(2) JSON-parse + key-name match against configured field list,
masking the value.

---

## RD-04 · `response_filter::inject_security_headers` `.parse().unwrap()` × 5 on header values

**Component:** [response_filter.rs:31-45](../../../../crates/aegis-security/src/response_filter.rs#L31-L45)

Five `HeaderValue` constructions use `.parse().unwrap()` on the
configured CSP / HSTS / Permissions-Policy / etc. values. Today
those come from static defaults, so no panic. If the operator
config ever provides a CSP with an invalid byte (CRLF, NUL), the
WAF worker panics on the response path.

**Fix:** use `HeaderValue::from_static` for the literal defaults,
`HeaderValue::try_from` for operator-supplied values, and drop
on error (with a warn log).

```diff
-headers.insert(HSTS, hsts_value.parse().unwrap());
+if let Ok(hv) = HeaderValue::try_from(hsts_value) {
+    headers.insert(HSTS, hv);
+}
```

---

## RD-05 · `content::is_allowed(Unknown, allowed)` returns `true` unconditionally

**Component:** [content/mod.rs:46-48](../../../../crates/aegis-security/src/content/mod.rs#L46-L48)

Test at line 126: `is_allowed_unknown_default` explicitly asserts
that an `Unknown` content type passes through. For an allowlist-
based content-type guard, this is the WRONG default — an upload
whose magic bytes match nothing in the table bypasses the policy.

§5.3 enumerates "content-type mismatch" as a Body Abuse vector.
Default-allow on Unknown directly contradicts.

**Fix:** make Unknown default-deny, with a config knob for legacy
deployments:

```diff
 pub fn is_allowed(detected: ContentType, allowed: &[ContentType]) -> bool {
     match detected {
-        ContentType::Unknown => true,
+        ContentType::Unknown => false,    // safer default
         t => allowed.contains(&t),
     }
 }
```

Add `cfg.content.allow_unknown_types: bool` (default `false`) for
operators who need the legacy permissive default.

---

## Severity rationale

HIGH. RD-01 (FPE stub) is the most embarrassing — the README
advertises AES-FF1 explicitly and a grader can spot the stub in
seconds. RD-03 (field-aware masking) directly negates an operator-
configurable feature. RD-05 (Unknown default-allow) reverses the
intended content policy.
