---
id: 2026-05-17-upstream-body-unbounded-buffer
date: 2026-05-17T00:00Z
severity: HIGH
area: data-plane · upstream forwarding
component: crates/aegis-proxy/src/upstream/forward.rs (resp.into_body().collect())
interop_contract: Round 3 stability / "không bị crash dưới áp lực", Round 1 "duy trì trạng thái hoạt động ổn định"
status: open
test_mode: source-review
---

# F-HIGH-003 · Upstream response body buffered fully into memory with no size cap — OOM risk

## Summary

The forward path reads the entire upstream response body into memory
via `resp.into_body().collect().await` with no `Limited<_>` wrapper
and no per-response size cap. A malicious or runaway upstream that
returns a multi-GB response will consume RAM proportional to the
response size, per concurrent request, before the WAF can ship a
single byte to the client.

Round 1's stability criterion (*"không bị crash/panic khi xử lý một
lượng traffic hợp lệ liên tục"*) and Round 3's resilience criterion
both penalize WAFs that OOM under load. A 4 GB upstream response
across 8 concurrent requests will allocate 32 GB transiently —
typical CI / staging hosts will OOM-kill the process before the
benchmark phase ends.

## Observed code path

`crates/aegis-proxy/src/upstream/forward.rs:~511-516` (paraphrased):

```rust
let (parts, body) = resp.into_parts();
let bytes = body
    .collect()        // ← buffers EVERYTHING into RAM
    .await
    .map_err(|_| ...)?
    .to_bytes();
let resp = Response::from_parts(parts, Full::new(bytes));
```

This is a `http_body_util::BodyExt::collect()` call with no
preceding `Limited::new(body, MAX)` wrap.

The pattern is repeated on the response-stamping path
(`data_plane.rs:1438-1503`) where the body is *re-collected*
even though `forward()` already returned `Full<Bytes>`, doubling
the transient memory footprint. That second issue is HIGH-grade
but separate (allocator churn rather than OOM); listed in the
F-MEDIUM bundle as `M-04`.

## Repro

```sh
# 1. Start an upstream that returns a large body:
python3 -c "
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.end_headers()
        # 2 GB body
        chunk = b'x' * (1024 * 1024)
        for _ in range(2048):
            self.wfile.write(chunk)
HTTPServer(('127.0.0.1', 9999), H).serve_forever()
" &

# 2. Point a route in config/dev.yaml at it (or use the mock
#    upstream Makefile target).

# 3. Send a few concurrent requests:
for i in 1 2 3 4 5 6 7 8; do
    curl -sk http://127.0.0.1:8080/ -o /dev/null &
done; wait

# 4. Watch RSS:
ps -o pid,rss,command -C waf
# RSS climbs to >16 GB and the OOM killer may fire.
```

## Impact

- A single misbehaving upstream can OOM the WAF, taking down ALL
  protected applications (not just the misbehaving one) — violates
  blast-radius isolation.
- Round 3 *"Graceful degradation"* and *"khả năng duy trì
  observability và behavior nhất quán trong điều kiện tải cao"*
  scoring drops to zero on this scenario.
- Under attack, a malicious upstream is unlikely, but a
  legitimate upstream serving a large file (video stream,
  database backup download) hits the same buffer.

## Suggested fix

Wrap the upstream body in `http_body_util::Limited` with a
config-driven cap, and stream the body to the client instead of
collecting it whenever possible:

```diff
-let (parts, body) = resp.into_parts();
-let bytes = body
-    .collect()
-    .await
-    .map_err(|_| ...)?
-    .to_bytes();
-let resp = Response::from_parts(parts, Full::new(bytes));
+use http_body_util::{BodyExt, Limited};
+
+let (parts, body) = resp.into_parts();
+let limit = cfg.runtime.max_upstream_response_bytes
+    .unwrap_or(64 * 1024 * 1024); // 64 MiB default
+let limited = Limited::new(body, limit);
+let bytes = limited
+    .collect()
+    .await
+    .map_err(|e| ForwardError::UpstreamBodyOverflow(e.to_string()))?
+    .to_bytes();
+let resp = Response::from_parts(parts, Full::new(bytes));
```

When the limit is exceeded, return `502 Bad Gateway` with
`X-WAF-Action: timeout` or `circuit_breaker` (per §3 — upstream
degradation maps to `circuit_breaker`).

**Follow-up (out of scope for this finding):** the longer-term
fix is to *stream* the upstream response through to the client
without buffering at all (use `StreamBody`), so the per-request
memory is bounded by tokio's mpsc backpressure. This requires
threading streaming bodies through the response stamping path,
which is a larger refactor.

## Verification

Repeat the 2 GB-upstream repro; with the cap in place the WAF
should return 502 quickly without RSS growth beyond the limit
plus per-connection overhead.

A regression case belongs in `tests/protocols/`:

```sh
# Upstream returns 200 MB; WAF configured with 64 MB cap.
# Expect 502 + audit action: circuit_breaker (or similar).
```

## Severity rationale

HIGH. Exploitable but requires a hostile or misconfigured upstream;
not exploitable by an unauthenticated WAN attacker directly. CRITICAL
would be reserved for unauthenticated-attacker DoS.
