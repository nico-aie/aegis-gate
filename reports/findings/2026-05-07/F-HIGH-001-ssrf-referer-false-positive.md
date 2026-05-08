# F-HIGH-001 · SSRF detector false-positive on Referer header

**Severity:** HIGH  
**Component:** `crates/aegis-security/src/detectors/ssrf.rs`  
**Found:** 2026-05-07  

---

## Summary

The SSRF detector scans the `Referer` request header for loopback/private IP URL patterns. Browsers automatically set `Referer: http://127.0.0.1:8080/` for sub-resource requests (favicon, XHR, JS fetch) when the page origin is `127.0.0.1:8080`. This causes any request made from a page hosted on the WAF's own address to be blocked as SSRF.

## Observed behaviour

```
# Browser on http://127.0.0.1:8080/ making sub-requests:
GET /favicon.ico
  Referer: http://127.0.0.1:8080/
  → 403  detector: ssrf

# Without Referer header (referrerPolicy: no-referrer):
GET /favicon.ico
  (no Referer)
  → 403  detector: ai   (separate AI FP — see F-CRITICAL-002)

# But for paths NOT blocked by AI:
GET /
  Referer: http://127.0.0.1:8080/
  → 403  detector: ssrf

GET /
  (no Referer)
  → 200  ✓
```

Confirmed in `waf_audit.log`:
```json
{"path":"/favicon.ico","action":"block","rule_id":"ssrf","..."}
{"path":"/","action":"block","rule_id":"ssrf","..."}
{"path":"/__waf_control/capabilities","action":"block","rule_id":"ssrf","..."}
```

## Root cause

`crates/aegis-security/src/detectors/ssrf.rs` scans these headers:
```rust
let scan_headers = ["referer", "x-original-url", "x-rewrite-url"];
```

The SSRF pattern:
```rust
r"(?i)(?:https?://(?:127\.0\.0\.1|localhost))",
```

This matches `Referer: http://127.0.0.1:8080/` — a legitimate browser-set header indicating the page's own origin.

The `Referer` header conveys the **page the user is currently on**, not an SSRF target. An attacker would not need to forge a Referer header to exploit SSRF — they would use query parameters, POST body, or other injection points. `Referer` is already scanned in the path/query surface if it contains a URL-like value.

## Impact

- Any page hosted on a loopback or private-range address that makes sub-requests through the WAF will have all those sub-requests blocked.
- Affects dev/staging environments running on localhost and internal deployments on RFC 1918 addresses.
- All `/__waf_control/*` control calls from a browser on the same host are blocked.

## Recommended fix

Remove `"referer"` from the SSRF header scan list in `ssrf.rs`:

```rust
// Before:
let scan_headers = ["referer", "x-original-url", "x-rewrite-url"];

// After:
let scan_headers = ["x-original-url", "x-rewrite-url"];
```

`x-original-url` and `x-rewrite-url` are legitimate SSRF vectors (they instruct reverse proxies to rewrite the request URL). `Referer` is not.

Update unit test to add a negative case with a loopback Referer:
```rust
negative!(clean_with_loopback_referer, "/api/data", headers: {"Referer": "http://127.0.0.1:8080/"});
```
