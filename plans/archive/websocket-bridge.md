# WS-T — WebSocket Upgrade Bridge

> **Status:** design-only, ready to implement. Track ID prefix
> `WS-T<n>`. Closes the silent-WebSocket-broken gap surfaced by
> the operator audit on 2026-05-03 — `proto/ws.rs` has the
> bridge primitive but it was never wired into the data-plane
> request handler, so production WS traffic fails after the
> initial handshake.

## 0 · One-line summary

Detect `Upgrade: websocket` requests in the data-plane handler,
run them through the existing detector chain, then bridge the
client + upstream sockets via `copy_bidirectional` after the
upstream returns 101 — same primitive TCP-T uses for CONNECT,
just triggered by header detection instead of method.

## 1 · Why this matters

`proto/ws.rs::bridge_upgrade` exists with a real WebSocket echo
test — but the data-plane forwarder uses hyper's pooled HTTP
client which doesn't honor upgrades. The 101 response goes
through but the bridge never runs. WS clients see "connected"
in their dev tools, then no frames flow.

## 2 · Why not the existing `forward.rs` path

Three reasons hyper's pooled HTTP client doesn't fit:

1. **Upgrade-eats-the-pool.** A successful 101 takes the TCP
   socket out of the HTTP keep-alive cycle forever. Hyper's
   pooled client is built around reusing connections; the
   upgrade case violates that contract.
2. **`hyper::upgrade::on()` on the client side requires owning
   the request struct**, but our forwarder splits parts/body
   early to thread through the detector pipeline.
3. **The WebSocket spec requires byte-for-byte preservation**
   of `Sec-WebSocket-Key` / `Sec-WebSocket-Accept` /
   `Sec-WebSocket-Protocol` / `Sec-WebSocket-Version`
   negotiation. Re-serializing through hyper's request builder
   risks header reordering that some implementations care about.

## 3 · Architecture

```
client ──GET /ws + Upgrade: websocket──► WAF ──TCP──► upstream
                                          │
                                          ├─ detectors run on the upgrade request
                                          │  (host policy, IP rate-limit, mTLS,
                                          │   custom detector for WS-specific
                                          │   abuse patterns — out of v1)
                                          │
                                          ├─ raw TCP connect to upstream member
                                          ├─ write original request bytes
                                          ├─ read response bytes
                                          │
                                          ▼
                                       101 ──► return to client unchanged
                                          │
                                          ├─ extract OnUpgrade from parts
                                          ├─ await both upgrades complete
                                          │
                                          └─ tokio::spawn(copy_bidirectional)
```

The bridge IS `proto/ws.rs::bridge_upgrade` — already tested
with a real WS echo backend.

## 4 · Trigger (admission)

A request enters the WS path when ALL of:

1. `is_websocket_upgrade(&req)` returns true (header check
   covering `Upgrade: websocket` + `Connection: Upgrade`,
   case-insensitive, multi-value `Connection` aware).
2. The resolved route's pool scheme is `http` / `https` /
   `auto` (NOT `tcp` — that's the CONNECT path; not `grpc` /
   `h2c` — those don't speak HTTP/1.1 upgrade).
3. All standard detectors pass (rate limit, host policy,
   tier admission, mTLS).

Anything else: existing forward path runs. Notably, **GET to a
`scheme: tcp` route with `Upgrade: websocket`** returns 502
`non_connect_to_tcp_route` (today's TCP-T behaviour) — operators
either pick the right scheme or use CONNECT.

## 5 · Slice breakdown

| Slice | Scope | Estimate |
|---|---|---|
| **WS-T1** | Detection + early-stage observability. Wire `is_websocket_upgrade()` into `forward_allow_to_upstream`; when detected, log + emit a `websocket_detected` metric + return a 502 with `x-waf-rule-id: websocket_not_yet_implemented`. Honest stub that surfaces the gap in dashboards. | ~1h |
| **WS-T2** | Raw-TCP forwarder for upgrade requests. New `proto/ws_forward.rs` that takes the original `parts` + body bytes + upstream socket addr, re-serializes the request, opens TCP, writes, reads response. Returns the response shape so the handler can decide if it's 101. | ~3h |
| **WS-T3** | Bridge wiring. On 101 from upstream: extract `OnUpgrade` from client parts (same trick as TCP-T3), spawn `bridge_upgrade(upgraded, upstream_addr)` (already exists), return 101 to client. On non-101: pass response through. | ~2h |
| **WS-T4** | Audit shape. `websocket_open` / `websocket_close` events with byte counters + duration + close reason. Same shape as TCP-T's tunnel events; bytes counted via `copy_bidirectional` return. | ~1h |
| **WS-T5** | Integration tests. Spin up a real WS echo backend (test util already exists at `proto/ws.rs::websocket_echo_through_tunnel`); drive the WAF; assert request frames + response frames round-trip. Plus a deny-path test (detector blocks WS). | ~2h |
| **WS-T6** | Dashboard surface. `protocol: "ws" \| "wss"` indicator on Live Feed entries. `aegis_websocket_open_total` + `aegis_websocket_active` Prometheus metrics. ~1h. | ~1h |

Total: ~10h. Strict order T1 → T5; T6 independent.

## 6 · Performance

WebSocket is the cheap case among long-lived flows:

- After the handshake, the WAF doesn't inspect frames — it's
  pure `copy_bidirectional`. No per-frame CPU cost.
- One spawned task per active WS (same as CONNECT). Memory
  footprint dominated by the per-direction buffer (default
  ~8 KB each = 16 KB / connection).
- 5 ms timeout doesn't apply — WebSocket is long-lived. We
  rely on the kernel's TCP keepalive (default 2h on Linux,
  configurable).
- No batch — single-request inference doesn't apply because
  there's no inference. The bridge is sync-friendly bytes.

## 7 · Out of scope (deferred to WS-T7+)

- **Per-frame inspection** (DPI on WebSocket frames). Real
  WAFs sometimes do this; we explicitly don't in v1 because
  it requires de-framing the WebSocket protocol and risks
  false-positives on binary frames.
- **WS over HTTP/2** (extended CONNECT, RFC 8441). Same
  reasoning as TCP-T — h1 covers the operator population.
- **WS auto-rate-limit** per connection. Future track.
- **wss:// support to upstream**. Today's bridge is plain TCP;
  TLS-to-upstream for WS would need a separate connector.

## 8 · Operator footguns (designed-out)

- **WS to a `scheme: tcp` route**: returns 502
  `non_connect_to_tcp_route` (existing TCP-T behaviour).
- **WS to a `scheme: grpc` / `h2c` route**: 502
  `websocket_not_supported_on_h2_routes` — h2 doesn't speak
  HTTP/1.1 upgrade.
- **Detectors block during handshake**: standard 403; client
  sees the WebSocket connection fail, just like any blocked
  HTTP request.

## 9 · Done-when

- `cargo test -p aegis-proxy ws` passes with WS-T tests.
- Real WS client (browser dev tools / wscat) → WAF → echo
  backend round-trips frames cleanly.
- Boot log shows `data-plane: WebSocket upgrade support live`
  when at least one route resolves to a non-tcp scheme.
- `docs/data-plane/reverse-proxy.md` § "WebSocket" gains a
  section explaining the bridge architecture.
