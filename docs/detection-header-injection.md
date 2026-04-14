# HTTP Header Injection

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
