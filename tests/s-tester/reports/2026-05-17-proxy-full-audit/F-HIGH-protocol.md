---
id: 2026-05-17-high-protocol-bundle
date: 2026-05-17T00:00Z
severity: HIGH
area: data-plane · protocol handlers
component: crates/aegis-proxy/src/proto/{h2.rs,ws_forward.rs}, src/tcp_tunnel.rs, src/proxy.rs, src/listener/http3.rs
interop_contract: Round 1 reverse-proxy + stability · Round 2 false positives · CVE-2023-44487 mitigation
status: open
test_mode: source-review
---

# F-HIGH-protocol bundle — 6 issues in protocol handlers (H2/H3/WS/CONNECT)

Each mini-finding is small enough to bundle. All affect either
contract clauses or Round-1/2 scoring; none individually warrants
CRITICAL.

---

## P-01 · H2 rapid-reset detector window never advances — CVE-2023-44487 mitigation non-functional after first window

**Component:** [proto/h2.rs:47-58](aegis-gate/crates/aegis-proxy/src/proto/h2.rs#L47-L58)

`ResetTracker::record_reset` initializes `window_start` once at
construction and never advances it. The intended logic ("reset the
counter when a window elapses") fires on every call after the first
window passes (`if elapsed >= self.window`), so the count is reset
to 1 on every call — limit effectively becomes "1024 per call"
which is "no limit".

With `max_resets_per_window=1024`, an attacker who waits >30 s after
connection open gets unlimited `RST_STREAM` frames. The
CVE-2023-44487 mitigation is non-functional in steady state.

The TODO comment at lines 51-52 acknowledges the gap.

**Fix:** advance `window_start` when the elapsed-window branch
fires:

```diff
 if elapsed >= self.window {
+    self.window_start = now;
     self.count = 1;
 }
```

---

## P-02 · WS upstream `read_response_head` has no read deadline → slowloris on upstream side

**Component:** [proto/ws_forward.rs:129-155](aegis-gate/crates/aegis-proxy/src/proto/ws_forward.rs#L129-L155)

The function takes a `connect_timeout` parameter that gates the TCP
connect, but the subsequent header-read loop (`stream.read_buf`) has
no timeout. A malicious upstream that drips 1 byte / N seconds holds
the proxy task hung for up to the 16 KiB `MAX_HEAD_BYTES` — easily
hours per connection.

**Fix:** wrap the read loop in `tokio::time::timeout`:

```diff
-while !found_terminator {
-    let n = stream.read_buf(&mut buf).await?;
+let deadline = std::time::Instant::now() + read_timeout;
+while !found_terminator {
+    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
+    if remaining.is_zero() { return Err(...); }
+    let n = tokio::time::timeout(remaining, stream.read_buf(&mut buf)).await??;
     ...
 }
```

---

## P-03 · CONNECT tunnel has no idle timeout on `copy_bidirectional`

**Component:** [tcp_tunnel.rs:425](aegis-gate/crates/aegis-proxy/src/tcp_tunnel.rs#L425)

`tokio::io::copy_bidirectional` runs until both halves close. A
CONNECT tunnel to a slow-drip destination (`1 byte/hour`) sits
forever. Combined with the per-IP cap of 16 simultaneous CONNECT
tunnels, a single attacker can permanently consume all 16 slots
with trickle traffic.

**Fix:** wrap each side in an idle-timer wrapper that returns
`UnexpectedEof` if no bytes flow for N seconds, OR use the
`copy_bidirectional` variant that takes a deadline.

```rust
// Sketch:
use tokio::io::{AsyncReadExt, AsyncWriteExt};
let mut idle_deadline = std::time::Instant::now() + idle_timeout;
loop {
    tokio::select! {
        n = client.read(&mut buf) => { ... reset deadline ... }
        n = upstream.read(&mut buf) => { ... reset deadline ... }
        _ = tokio::time::sleep_until(idle_deadline.into()) => break,
    }
}
```

---

## P-04 · H2 / H3 Host fallback to literal `"localhost"` masks routing failures

**Component:** [proxy.rs:221-225](aegis-gate/crates/aegis-proxy/src/proxy.rs#L221-L225)

For HTTP/2 + HTTP/3 requests, the canonical host lives in the URI
`:authority` pseudo-header, not in a `Host:` header. The proxy reads
`req.headers().get(HOST)` only, defaulting to literal `"localhost"`
when absent. Any H2/H3 request without `Host:` (legitimate per RFC)
silently routes to the default/catch-all route.

For routes that require an exact host match, this means the WAF
delivers traffic to the wrong upstream (or 404s).

**Fix:** prefer `req.uri().host()` when present:

```diff
-let host = req
-    .headers()
-    .get(HOST)
-    .and_then(|h| h.to_str().ok())
-    .unwrap_or("localhost");
+let host = req
+    .uri()
+    .host()
+    .or_else(|| req.headers().get(HOST).and_then(|h| h.to_str().ok()))
+    .unwrap_or("localhost");
```

---

## P-05 · H3 request body buffered unbounded into `BytesMut`

**Component:** [listener/http3.rs:241-256](aegis-gate/crates/aegis-proxy/src/listener/http3.rs#L241-L256)

The h3 `recv_data` loop calls `body.extend_from_slice(chunk.chunk())`
with no size cap. Quinn's per-stream `stream_receive_window` defaults
to ~1.25 MiB but the application drains and re-grows `BytesMut` until
the stream finishes. A client that opens a stream and keeps sending
DATA frames OOMs the proxy.

**Fix:** track a running total, return 413 once the configured
`max_request_body_bytes` (see F-CRITICAL-004 from previous audit)
is exceeded. Mirror the fix here regardless of whether F-CRITICAL-001
is also landed (since the H3 path may be remediated independently).

---

## P-06 · QUIC transport limits mostly unset

**Component:** [listener/http3.rs:140-155](aegis-gate/crates/aegis-proxy/src/listener/http3.rs#L140-L155)

Only `max_concurrent_bidi_streams` + `max_idle_timeout` are set on
the `quinn::TransportConfig`. NOT set:

- `max_concurrent_uni_streams` (h3 control streams use unidirectional)
- `stream_receive_window` (per-stream flow control)
- `receive_window` (per-connection flow control)
- `datagram_receive_buffer_size`

Quinn defaults are large (≥1 MiB per stream, 12.5 MiB per
connection). Under DDoS / sustained high-concurrency traffic, the
per-connection memory amplification is significant.

**Fix:** clamp explicitly:

```rust
transport
    .max_concurrent_bidi_streams(VarInt::from_u32(100u32).into())
    .max_concurrent_uni_streams(VarInt::from_u32(10u32).into())
    .stream_receive_window(VarInt::from_u32(256 * 1024).into())   // 256 KiB
    .receive_window(VarInt::from_u32(4 * 1024 * 1024).into())     // 4 MiB
    .max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
```

Values from operator config; defaults above are reasonable
benchmark defaults.

---

## Severity rationale

HIGH. Each item is either a CVE-class issue (P-01) or a
DoS/correctness vector. None alone warrants CRITICAL because either
- the exploit requires sustained / specialized traffic (P-02, P-03,
  P-05), OR
- the impact is degraded performance rather than total bypass
  (P-04, P-06).

Bundled to keep the report tractable. Each fix is independent and
small.
