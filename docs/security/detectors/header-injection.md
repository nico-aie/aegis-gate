# HTTP Header Injection

> **Status:** Implemented — `aegis-security/src/detectors/header_injection.rs`.
>
> See [`../../../plans/plan.md`](../../../plans/plan.md#1-doc-by-doc-implementation-status) for the full matrix.

## Purpose

Detect CRLF injection attacks — attempts to inject newlines into headers, which can lead to header smuggling, cache poisoning, response splitting, and cookie injection.

## Attack pattern

An attacker passes a value containing `\r\n` (CRLF) into a parameter that ends up reflected in an HTTP response header. The injected CRLF terminates the current header and lets the attacker inject new headers or even a new response.

Example payload in a `redirect` parameter:

```
http://example.com/?redirect=foo%0d%0aSet-Cookie:%20session=attacker
```

If the backend reflects this into a `Location:` header, the resulting response contains an attacker-controlled `Set-Cookie`.

## Patterns

The detector scans for these byte sequences in request inputs that could end up in response headers:

- `\r\n` (raw CRLF)
- `%0d%0a`, `%0D%0A`, `%0d%0A`, `%0D%0a`
- `\u000d\u000a`
- `%0a` alone (some servers treat LF as line terminator)
- `%0d` alone
- `\n` in header-destined contexts

## Surfaces

- All query parameters (most common injection point for `Location:` headers)
- Request headers **whose values are reflected back by the backend** (e.g., `Referer` ends up in logs; a crafted `Host` header can end up in generated URLs)
- Cookie values
- Request body fields that end up in redirects

The detector doesn't know what the backend does with which field, so it scans broadly and relies on scoring to avoid false positives.

## Incoming-header sanity checks

Separate from CRLF detection, the WAF also validates incoming headers:

- Header names must match `[!-9;-~]+` (RFC 7230 tchar set)
- Header values must not contain raw CTL characters (`\x00`-`\x1f` except `\t`)
- `Host` header must be present and parseable
- `Content-Length` must be a positive integer
- No duplicate `Content-Length` or mixed `Content-Length` + `Transfer-Encoding` (smuggling defense)

Malformed headers are rejected with 400 immediately.

## X-Forwarded-Host poisoning

Added 2026-05-08 (SEC-L002). The detector inspects the **value** of the
`X-Forwarded-Host` (XFH) request header for shape-suspicious patterns
that backends would treat as the public hostname for cache keys, OAuth
redirect URIs, password-reset email links, etc.

The check is conservative — many legit reverse-proxy chains set XFH to
the public hostname while `Host` is the proxy's internal address, so a
bare "XFH ≠ Host" mismatch isn't enough to alert. The detector flags
when the XFH carries:

| Shape | Example | Why suspicious |
|---|---|---|
| Attacker-keyword + Host mismatch | `Host: a.com`, `XFH: evil.attacker.com` | Classic poisoning probe |
| `javascript:` / `data:` URI | `XFH: javascript:alert(1)` | XSS pivot via cache-bound link |
| Quoting / angle-bracket chars | `XFH: <script>` | HTML-context injection |
| Three or more comma-separated hosts | `XFH: a.com, proxy.com, evil.com` | Attacker appended a host to a legitimate proxy chain |
| Control bytes (NUL/CR/LF) | (defense-in-depth — hyper rejects upstream) | Header smuggling |
| **Internal-IP literal** (added 2026-05-09 GAP-005) | `XFH: 127.0.0.1`, `XFH: 10.0.0.1`, `XFH: 169.254.169.254`, `XFH: ::1`, `XFH: fe80::1` | Cache-key poisoning / internal-admin code-path bypass / host-allowlist evasion. Legit proxy chains carry **public hostnames** in XFH; an RFC 1918 / loopback / link-local IP literal here has no benign use case. |

Score: `35` (slightly below CRLF since the heuristic is broader).
Field tag: `x-forwarded-host` so the audit log + dashboard can
distinguish XFH poisoning from query-CRLF.

#### Internal-IP literal — what specifically flags

The `xfh_is_internal_ip_literal` helper (added GAP-005) checks the **first** comma-segment of the XFH value (after stripping an optional `:port`) against:

| Range | Examples |
|---|---|
| IPv4 loopback (`127.0.0.0/8`) | `127.0.0.1`, `127.55.0.1` |
| IPv4 RFC 1918 (`10.0.0.0/8`, `172.16-31.0.0/12`, `192.168.0.0/16`) | `10.0.0.1`, `172.20.5.5:8080`, `192.168.1.1` |
| IPv4 link-local (`169.254.0.0/16`) | `169.254.169.254` (cloud metadata) |
| IPv6 loopback | `::1`, `[::1]` |
| IPv6 link-local | `fe80::1`, `[fe80::1]` |

Public addresses like `8.8.8.8` or just-outside-RFC1918 addresses like `172.32.0.1` do **not** flag — the helper is a narrow internal-range check, not a generic IP-literal flag (legitimate origin servers may have IP-literal hostnames in some setups).

**Why not also block "arbitrary domain mismatch":** many legit proxy chains do exactly that (`Host: internal-svc:8080`, `XFH: api.example.com`). Bare mismatch is too broad without an operator allowlist. Internal-IP-literal-in-XFH is the narrow shape with no legitimate use case, so it's safe to flag without operator config.

## HTTP request smuggling defense

Request smuggling exploits discrepancies in how the WAF and backend parse `Content-Length` vs `Transfer-Encoding`. The WAF enforces:

- Reject requests with **both** `Content-Length` and `Transfer-Encoding`
- Reject `Transfer-Encoding: chunked` with unusual casing or whitespace (`Transfer-Encoding:  chunked `, `Transfer-Encoding: xchunked`, etc.)
- Reject conflicting `Content-Length` values in multiple headers
- Enforce strict parsing: the first `Content-Length` wins, subsequent ones are errors

## Configuration

```yaml
detection:
  header_injection:
    enabled: true
    risk_increment: 50
    reject_malformed_headers: true
    reject_smuggling: true
```

## Actions

- CRLF in a parameter: +50 risk, almost always blocked (CRLF in form inputs has no legitimate use)
- Malformed header: reject with 400, no backend contact
- Smuggling-shaped request: reject with 400, audit log flagged as smuggling attempt

## Implementation

- `src/detection/header_injection.rs`
- Header validation is also done at the proxy core level before the pipeline runs

## Design notes

- Smuggling defense is at the **proxy core**, not just the detection module, because it's a structural parsing concern
- Any smuggling-shaped request is blocked outright — there's no legitimate reason to send one
