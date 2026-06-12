# WebSocket inspection

Aegis-Gate inspects WebSocket traffic in **two phases**:

1. **Handshake (always on).** The `GET … Upgrade: websocket` request runs
   through the full security pipeline — detectors, per-IP risk, operator
   rules, the mTLS identity gate — exactly like any other HTTP request.
   Admission gates whether the tunnel is created at all. A handshake that
   trips a detector or a blocked IP never becomes a socket.

2. **Frame message inspection (opt-in, `ws_inspect`).** Once the tunnel is
   established, the WAF can additionally inspect **text** messages flowing
   **client → upstream**, reassembling them across fragments and running
   them through the body detectors (XSS / SQLi / body_abuse) before
   forwarding. This is the layer that catches hostile user content sent
   *over* an already-established socket (chat, collaborative editors,
   GraphQL-over-WS) — the case a plain L4 tunnel can't see.

Without `ws_inspect`, an established WebSocket is a byte tunnel: only the
handshake was inspected. With it on, the tunnel becomes message-aware for
client text.

## Enabling it

Per route, default off:

```yaml
routes:
  - id: chat
    path: /ws
    upstream: chat-pool
    ws_inspect:
      enabled: true
      mode: log_only        # log_only (default) | enforce
      max_message_bytes: 4194304   # 0 ⇒ 4 MiB default
```

- **`mode: log_only`** (the recommended first step) — a message that
  crosses the block threshold is **forwarded**, but a
  `websocket_frame_block` audit event fires (`mode: log_only`) and the
  `aegis_websocket_frame_block_total{route,tag}` counter increments. Tune
  the detector mask / tier threshold against real traffic before
  enforcing.
- **`mode: enforce`** — the offending message is **dropped** and the
  socket is closed with WS Close `1008` (policy violation).

The verdict reuses the per-request scoring model: the summed detector
score for the reassembled message is compared against the route tier's
per-request threshold — the same logic as the HTTP detector-block path.

## What is and isn't inspected (v1)

| | Inspected |
|---|---|
| **Text frames (`0x1`), client → upstream** | ✅ reassembled across continuation frames, then scanned |
| Binary frames (`0x2`) | ❌ pass through verbatim (binary needs schema-aware decoders) |
| Control frames (close / ping / pong) | ❌ pass through verbatim |
| **upstream → client** (responses) | ❌ always zero-copy in v1 |

Fragmentation is **not** an evasion vector: a payload split across frames
(`AT` + `TACK`) is reassembled to its `FIN` and inspected as one message,
so the detector sees the whole logical payload.

## Caveats

- **Compression (`permessage-deflate`).** When `ws_inspect` is on, the WAF
  **strips the `Sec-WebSocket-Extensions` offer from the forwarded
  handshake**, so the negotiated connection is uncompressed and therefore
  decodable. As defence-in-depth, if a compressed frame still arrives
  (RSV1 set), the bridge **fails closed** (WS Close `1002`) rather than
  forward an un-inspected compressed message. Inflate-then-inspect (with a
  zip-bomb bound) is a future enhancement.
- **Oversize messages are skipped, not blocked.** A reassembled text
  message larger than `max_message_bytes` is **forwarded without
  inspection** (memory stays bounded — buffering stops at the cap and the
  rest streams through), and `messages_skipped_oversize` is recorded. This
  favours availability for legitimately large messages; the trade-off is
  that an attacker can pad a payload past the cap to evade, so the skip is
  metered — keep the cap high enough for real traffic but low enough that
  padding is conspicuous. (A single *frame* over 1 MiB is still a
  protocol-level close.)
- **Direction.** Only client → upstream text is inspected in v1. Response
  (upstream → client) scanning is a separate, larger track.
- **Forwarding preserves masking.** Frames are re-emitted to the upstream
  with their original client masking (not unmasked), because real WS
  servers reject unmasked client frames.

## Off-by-default guarantee

With `ws_inspect` absent or `enabled: false`, the bridge is the exact
zero-copy `copy_bidirectional` tunnel that shipped before this feature —
no frame parser, no reassembly buffer, no added allocation or latency.
Existing WebSocket routes are byte-for-byte unchanged.

## Observability

- **Audit:** `websocket_frame_block` (`AuditClass::Access`) carries
  `client_ip`, `route_id`, `rule_id` (top detector tag), `risk_score`
  (summed), `mode` (`enforce` / `log_only`), and `fields.matched_field` /
  `fields.message_bytes`. Additive to the existing `websocket_open` /
  `websocket_close` shape (`schema_version` unchanged).
- **Metrics:** `aegis_websocket_frame_block_total{route,tag}` alongside
  the existing `aegis_websocket_open_total` / `_close_total` /
  `aegis_websocket_active`.

Design + phase history:
[`plans/archive/websocket-message-inspection.md`](../../plans/archive/websocket-message-inspection.md).
