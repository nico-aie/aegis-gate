---
id: 2026-05-17-cors-preflight-panic-on-hostile-origin
date: 2026-05-17T00:00Z
severity: CRITICAL
area: data-plane · transforms
component: crates/aegis-proxy/src/transform/cors.rs (handle_preflight, apply_cors_headers)
interop_contract: Round 1 stability ("không bị crash/panic khi xử lý traffic")
status: open
test_mode: source-review
---

# F-CRITICAL-009 · CORS preflight handler `unwrap()`s `HeaderValue::from_str(&client_origin)` — a crafted `Origin:` byte panics the worker on the hot path

## Summary

`transform/cors.rs` reads the client-supplied `Origin` request header
and reuses it as the value of the response `Access-Control-Allow-Origin`
header. The construction uses `HeaderValue::from_str(...).unwrap()`.
`HeaderValue::from_str` rejects any byte outside the printable ASCII
range (`0x20..=0x7E`) plus tab.

`HeaderName::from_str` (called earlier to extract `Origin` via
`req.headers().get(ORIGIN).and_then(|h| h.to_str().ok())`) accepts
some bytes that `HeaderValue::from_str` then rejects — notably
`0x7F` DEL, which is `ascii_graphic() == false` so `to_str` accepts
but `from_str` rejects.

A single crafted request like:

```
OPTIONS / HTTP/1.1
Host: target.example.com
Origin: http://attacker.test/<0x7F>
Access-Control-Request-Method: GET
```

panics the tokio worker, which propagates to the hyper service
future and terminates the connection. Repeated attacks across
connections poison every worker thread.

Round 1's pass/fail criterion explicitly requires *"không bị
crash/panic khi xử lý một lượng traffic hợp lệ liên tục"* — and the
data plane DOES NOT recover gracefully from this panic in a way the
contract considers acceptable.

## Observed code path

`crates/aegis-proxy/src/transform/cors.rs:57-138` (paraphrased):

```rust
let origin = req
    .headers()
    .get(ORIGIN)
    .and_then(|h| h.to_str().ok())          // 0x7F passes here
    .unwrap_or("")
    .to_string();

// ... allow-origin policy check ...
let allow_origin = if cfg.allows(&origin) { origin } else { "null".into() };

// PREFLIGHT response builder:
let mut resp = Response::builder()
    .status(204)
    .header(ACCESS_CONTROL_ALLOW_ORIGIN, &allow_origin);   // ← rejects 0x7F

let resp = resp.body(Full::new(Bytes::new())).unwrap();    // ← panics here
```

A second site at `cors.rs:138` does the same in `apply_cors_headers`:

```rust
headers.insert(
    ACCESS_CONTROL_ALLOW_ORIGIN,
    HeaderValue::from_str(&allow_origin).unwrap(),  // ← panics on 0x7F
);
```

A third site at `cors.rs:88-91` echoes the client-controlled
`Access-Control-Request-Headers` value verbatim into the response —
same panic vector with a different trigger header.

## Repro

```sh
# Send an OPTIONS with a DEL (0x7F) byte in Origin:
printf 'OPTIONS / HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: http://x\x7f\r\nAccess-Control-Request-Method: GET\r\nConnection: close\r\n\r\n' \
    | ncat 127.0.0.1 8080

# WAF logs (stderr) show a panic with backtrace.
# tokio runtime handles it but the connection is killed; under
# repeated abuse, throughput visibly degrades.
```

## Impact

- **Round 1 stability pass/fail** — explicit criterion. Single
  crafted OPTIONS request → panic. Easily reachable from the
  benchmark traffic mix or any browser-facing route.
- **DoS amplification** — many connections in parallel each
  panicking one tokio task at a time can starve the runtime if
  CORS is exercised heavily.
- **Information leak** — Rust panic messages typically include a
  file:line. If the WAF's logging policy includes panic
  backtraces, the attacker can confirm the panic and gather code
  structure.

## Suggested fix

Replace every `HeaderValue::from_str(...).unwrap()` on
client-derived input with a safe defaulting path:

```diff
-let mut resp = Response::builder()
-    .status(204)
-    .header(ACCESS_CONTROL_ALLOW_ORIGIN, &allow_origin);
-let resp = resp.body(Full::new(Bytes::new())).unwrap();
+let allow_origin_hv = HeaderValue::from_str(&allow_origin)
+    .unwrap_or_else(|_| HeaderValue::from_static("null"));
+let resp = Response::builder()
+    .status(204)
+    .header(ACCESS_CONTROL_ALLOW_ORIGIN, allow_origin_hv)
+    .body(Full::new(Bytes::new()))
+    .expect("static body never fails Response::builder");   // expect ok on static body
```

Apply the same pattern to:
- `apply_cors_headers` at cors.rs:138 (use `headers.insert(...HV)`
  inside an `if let Ok(hv) = ...`).
- The `Access-Control-Request-Headers` echo at cors.rs:88-91.

**Better fix** — validate `Origin` once at the entry point of the
CORS module. If `from_str` would reject, treat the request as
having no Origin (drop the request from CORS processing) and let
the rest of the pipeline handle it normally. This prevents the
class of bugs from creeping back.

```rust
fn parse_origin(req: &Request<Incoming>) -> Option<HeaderValue> {
    let raw = req.headers().get(ORIGIN)?;
    let s = raw.to_str().ok()?;
    HeaderValue::from_str(s).ok()    // single chokepoint; no later .unwrap()
}
```

## Verification

After the fix, repeat the repro:

```sh
printf 'OPTIONS / HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: http://x\x7f\r\nAccess-Control-Request-Method: GET\r\nConnection: close\r\n\r\n' \
    | ncat 127.0.0.1 8080
# Expect: 204 with Access-Control-Allow-Origin: null (or omitted).
# WAF stays up; no panic in stderr.
```

Add a regression case in `tests/security/` exercising the byte
range `0x00..=0xFF` in the Origin header and asserting no panic.

## Severity rationale

CRITICAL because the bug is a one-byte payload, attacker-controlled,
hits the Round-1 pass/fail crash criterion directly, and is in a
public-facing path (any browser-exposed CORS route). The fix is
3 lines plus a defensive entry-point validator.
