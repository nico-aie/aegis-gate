# Request Body Abuse

## Purpose

Detect malformed, oversized, or abusive request bodies that aim to exhaust resources or exploit parser bugs. Body abuse is an attack on the WAF and backend's **parsing infrastructure** rather than on the application logic.

## Attack patterns

### Oversized body

A body far larger than the endpoint expects. Used for DoS (fill memory, burn CPU on parsing), slowloris-style attacks (send body over many minutes), or upload abuse.

### Content-Type mismatch

A body that doesn't match its declared content type. Example: `Content-Type: application/json` with body `<?xml version="1.0"?><...`. Intended to bypass content-type-specific validation or exploit multi-parser vulnerabilities.

### Zip bombs / decompression bombs

A small compressed body that expands to massive size. The WAF enforces max **decompressed** body size.

### JSON depth bomb

Deeply nested JSON (`[[[[[[[[[...]]]]]]]]`) that triggers O(depth) stack usage in parsers. The WAF enforces a max nesting depth.

### XML entity expansion (Billion Laughs)

Nested entity definitions that expand exponentially when parsed. Example:

```xml
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  ...
]>
```

The WAF blocks XML with DOCTYPE / external entities by default.

### Multipart abuse

- Thousands of tiny parts (file upload DoS)
- Parts with oversized names or headers
- Malformed boundary markers
- Missing `Content-Disposition`

### Null bytes

Null bytes (`\x00`) in contexts that shouldn't contain them (URL-encoded form data, text fields). Used for truncation attacks and file extension bypass.

### Encoding mismatch

A body declared as UTF-8 containing invalid UTF-8 sequences. Used to bypass encoding-aware validators.

## Limits

Configurable ceilings:

| Limit | Default |
|---|---|
| Max body size | 10 MB |
| Max body size after decompression | 50 MB |
| Max body scan size (for detection) | 64 KB |
| Max JSON nesting depth | 32 |
| Max JSON object keys | 1000 |
| Max multipart parts | 100 |
| Max header name length | 256 |
| Max header value length | 8192 |
| Max total header size | 64 KB |

Exceeding any limit → reject with 413 (Payload Too Large) or 400 (Bad Request).

## Per-tier overrides

Different routes have different needs. An upload endpoint on HIGH tier might allow 100 MB; a login endpoint on CRITICAL should allow only a few KB.

```yaml
tiers:
  - name: critical
    body_limits:
      max_body_bytes: 16384
      max_json_depth: 8
  - name: high
    body_limits:
      max_body_bytes: 10485760
  - name: medium
    body_limits:
      max_body_bytes: 1048576      # static uploads are unusual
```

## Implementation

- `src/detection/body_abuse.rs` — size enforcement, JSON depth checker, XML DOCTYPE rejection, multipart validation

## Detection pipeline

Body abuse checks run **before** content scanning (SQLi, XSS). This is critical: a malicious JSON depth bomb must be rejected **without** being fully parsed.

The checks are streaming where possible:

- Body size is checked incrementally as bytes arrive; the request is killed as soon as the limit is exceeded
- JSON depth is tracked with a counter during a shallow tokenizer pass, not via full parsing
- XML is rejected outright if a DOCTYPE declaration is found in the first 1 KB

## Actions

- Limit exceeded: reject with 413, increment risk, audit log
- DOCTYPE / external entity detected: reject with 400, risk +40
- Suspicious multipart: reject with 400

## Design notes

- Body abuse defense is the **first line** against parser DoS — it must never be bypassed by any later stage
- Streaming enforcement means an attacker can't waste an unbounded amount of memory by sending a slowly-growing body
- Detection runs on the inbound body before it's forwarded to the backend, so the backend never sees abusive payloads
