# Response Filtering (v2)

> **v1 → v2:** response filtering now shares a pipeline with the
> enterprise **DLP** subsystem ([`dlp.md`](./dlp.md)), supports
> **format-preserving encryption (FPE)** tokenization for regulated
> fields, validates responses against **OpenAPI / GraphQL** schemas
> ([`api-security.md`](./api-security.md)), and can route suspicious
> payloads to an **ICAP** antivirus ([`content-scanning.md`](./content-scanning.md)).

## Purpose

Attackers learn from responses as much as from requests. Verbose errors
leak schemas; a 500 with a stack trace reveals framework versions; a
chatty JSON endpoint exposes PII. Response filtering is the **outbound
half** of the WAF — scrubbing, masking, and verifying backend responses
before they reach the client.

## What gets filtered

### Stack traces

Framework-specific patterns (Python, JVM, Node, Rust, PHP, .NET, Rails,
Go). On match, the body is replaced with a configurable generic page and
the event is audit-logged `high` severity.

### Internal IP addresses

RFC 1918, link-local, loopback, ULA / link-local IPv6 → `[REDACTED]`
(or a configurable fake public range).

### DLP redaction

Two modes, both powered by [`dlp.md`](./dlp.md):

- **Field-name match** — case-insensitive against a configurable allowlist
  (`password`, `ssn`, `credit_card`, `api_key`, `private_key`, …). Uses a
  streaming JSON tokenizer — no full parse.
- **Value-pattern match** — credit cards (with Luhn validation), SSN,
  JWTs (`eyJ...`), cloud key prefixes (`AKIA`, `sk_`, `pk_`, `ghp_`,
  `xoxb-`), IBANs, email addresses (optional)

Matches are replaced with one of:

- `[REDACTED]`
- A deterministic token via **FPE** (format-preserving encryption) so
  shape is preserved for downstream systems that need to pass it through
  without seeing the cleartext
- A masked form (`****-****-****-1234`)

### OpenAPI / GraphQL response validation

When a route has an attached OpenAPI or GraphQL schema, responses are
validated against it. Violations can:

- **Block** (replace body with a generic error) — default for PCI routes
- **Redact** (strip offending fields)
- **Warn** (log + forward) — default for discovery mode

See [`api-security.md`](./api-security.md).

### ICAP content scan (optional)

For file-download and user-generated-content responses, the filter can
send the body to an ICAP server (ClamAV, commercial AV) before release.
Latency budget is enforced; on timeout, the `failure_mode` decides.

### Information-leak headers

Stripped by default: `Server`, `X-Powered-By`, `X-AspNet-Version`,
`X-AspNetMvc-Version`, `X-Runtime`, `X-Generator`, `X-Drupal-Cache`.

### Security header injection

Added to all responses unless already present:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: ...`
- `Content-Security-Policy: ...` (if configured)

## Streaming strategy

Response filtering works on streaming bodies via a frame processor:

1. Content-type gate — only text/*, application/json, application/xml,
   application/*+json inspected; binary passes through
2. Per-frame: scan patterns, redact/tokenize in-place, forward
3. A trailing N-byte buffer catches patterns that span frame boundaries
4. `max_scan_bytes` hard cap (default 1 MiB); beyond it, pass-through
   after first chunk is scrubbed

Caching stores the **post-filter** form, so filters run once per distinct
response, not once per cache hit.

## Block pages

Custom HTML for block / challenge / 503, including:

- Friendly message (configurable per tier)
- Request ID for user-to-support correlation
- Optional challenge-retry link
- No backend info, no stack, no version strings

Per-status / per-tier / per-route templates.

## Configuration

```yaml
response_filtering:
  enabled: true
  strip_headers: [Server, X-Powered-By, X-AspNet-Version]
  add_security_headers:
    enabled: true
    hsts_max_age: 31536000
    csp: "default-src 'self'"
  stack_trace_removal:
    enabled: true
    replacement: "An internal error occurred. Request ID: {request_id}"
  internal_ip_masking:
    enabled: true
    replacement: "[REDACTED]"
  dlp:
    enabled: true
    fields: [password, ssn, credit_card, api_key]
    value_patterns: [credit_card, ssn, jwt, cloud_key]
    mode: fpe           # redact | mask | fpe
    fpe_key: "${secret:vault:kv/data/waf#fpe_key}"
  openapi_validation:
    enabled: true
    mode: redact
  icap:
    enabled: false
    endpoint: "icap://clamav.internal:1344/reqmod"
    timeout_ms: 200
  max_scan_bytes: 1048576
```

## Implementation

- `src/response/filter.rs` — streaming frame orchestrator
- `src/response/redactor.rs` — stack-trace + IP masking
- `src/response/dlp.rs` — DLP bridge
- `src/response/schema_check.rs` — OpenAPI/GraphQL validation
- `src/response/icap.rs` — ICAP client
- `src/response/block_page.rs` — templated block pages

## Performance notes

- Streaming tokenizer avoids full-body allocation for gigabyte responses
- Aho-corasick for the fixed DLP field/pattern set — O(n) over the body
- FPE via AES-FF1; per-value cost is microseconds for ≤19-char inputs
- Content-type gate means binary traffic pays ~zero
