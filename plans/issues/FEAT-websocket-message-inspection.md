# FEAT — WebSocket message-level inspection (text frames)

> **Type:** FEAT (feature track) · **Status:** Designed — not started · **Branch:** `develop`
> **Track ID prefix:** `WS-MSG<n>`
> **Design doc:** [`../future/websocket-message-inspection.md`](../future/websocket-message-inspection.md) (decisions + justification live there)
> **Roadmap slot:** [`../future/world-class-waf-roadmap.md`](../future/world-class-waf-roadmap.md) — protocol-coverage gap.
> **Builds on (shipped):** WS-T WebSocket bridge ([`../archive/websocket-bridge.md`](../archive/websocket-bridge.md)) — which scoped frame-level abuse detection *out of v1*; this is the follow-up.

**Goal (one line):** today the WAF inspects only the WebSocket *handshake* and then byte-tunnels
every frame via `copy_bidirectional` (`data_plane.rs:1894`). This adds an opt-in frame-parsing
bridge that, for **text frames (opcode `0x1`) client → upstream**, reassembles the message payload
and runs it through the existing body-oriented detectors (XSS / SQLi / body_abuse) before
forwarding — blocking or closing the socket on a verdict. Binary / control frames stay zero-copy.

**Off by default.** Gated per-route behind `ws_inspect` (default `off`). With it off, the bridge
runs the exact `copy_bidirectional` path that ships today — no frame parser, no reassembly buffer,
no added allocation or latency. Existing WS traffic is byte-for-byte unchanged. (Design §0.)

---

## Scope (v1 — design §2)

| Dimension | v1 | Out of v1 |
|---|---|---|
| Opcode | text `0x1` only; `0x0` continuation reassembled into text | binary `0x2`, control `0x8/0x9/0xA` pass through verbatim |
| Direction | client → upstream only | upstream → client response scanning (v2) |
| Fragmentation | reassemble to `FIN`, bounded cap | — |
| Compression | `permessage-deflate` → strip extension on handshake (fail-closed if present) | inflate + zip-bomb bound (v2) |
| Detectors | reuse body-class (XSS/SQLi/body_abuse) via mask | frame-specific detector types (v2) |
| Verdict | `block` (Close `1008`) / `log_only`, honours route/global mode | per-frame rate limiting, GraphQL-over-WS op parsing |

---

## Phase checklist

- [ ] **WS-MSG1 — codec.** `crates/aegis-proxy/src/proto/ws_codec.rs`: bounded RFC 6455 frame reader/writer + unit tests (header parse at 7/16/64-bit length classes, mask/unmask, RSV1 reject, oversize → close code). Pure, no I/O.
  - **Gate:** codec round-trips `tokio-tungstenite`-produced frames.
- [ ] **WS-MSG2 — inspecting bridge.** Replace `copy_bidirectional` (`data_plane.rs:1894`) with a `tokio::select!` two-half bridge **behind `ws_inspect.enabled`**; off-path stays the literal current code. Reassembly + bounded buffers.
  - **Gate:** binary/control passthrough byte-identical to today; text reassembly correct across fragments.
- [ ] **WS-MSG3 — detector hook.** Thread captured request context + detector/mask handles into the task; build synthetic `RequestView` (same trick as operator-rule path `data_plane.rs:1621`); wire `run_all_filtered`; threshold + verdict.
  - **Gate:** known XSS/SQLi payload in a text frame is blocked; benign chat text passes.
- [ ] **WS-MSG4 — verdict I/O + audit + metrics.** WS Close `1008` on block; `log_only` forward+audit path; `websocket_frame_block` audit event (additive to existing WS shape); `aegis_websocket_frame_block_total{route,tag}` counter.
  - **Gate:** enforce closes the socket; log_only forwards + audits.
- [ ] **WS-MSG5 — config + config-plane.** `ws_inspect` on `RouteConfig`; thread into the Redis `config:waf:doc` schema (not just boot YAML — or it goes stale on dashboard save); deflate strip-on-handshake; boot/handshake validation; dashboard surface.
  - **Gate:** dashboard toggle takes effect on the next WS connection.
- [ ] **WS-MSG6 — docs.** `docs/security/websocket.md` (new): two-phase model, what's inspected, deflate caveat, direction caveat. Update the architecture answer that motivated this plan.

---

## Decisions to lock before WS-MSG1 (design §11 — recommended defaults, confirm in review)

| # | Decision | Recommended default | Locked? |
|---|---|---|---|
| 1 | Forward text frames re-framed **unmasked** vs preserve original masking | Unmasked, with masked fallback if a backend rejects | [ ] |
| 2 | On `ws_inspect` + client offers `permessage-deflate` | **Strip** the extension from the forwarded handshake (vs reject upgrade) | [ ] |
| 3 | Codec source: vetted crate (`fastwebsockets` / `tokio-tungstenite` decode) vs ~200-line hand-rolled bounded reader | Decide after §0 research weighs dependency surface | [ ] |
| 4 | Default mode on first enable | `log_only` (operators tune mask/threshold before `enforce`) | [ ] |
| 5 | Direction | v1 client→upstream only (response scanning deferred to v2) | [ ] |

---

## Files to touch (anticipated — design §4–§7)

- **new** `crates/aegis-proxy/src/proto/ws_codec.rs` — bounded RFC 6455 reader/writer + unit tests; constants `MAX_FRAME_PAYLOAD` (~1 MiB → close `1009`), `MAX_MESSAGE_BYTES` (~4 MiB → close `1009`).
- `crates/aegis-proxy/src/proto/mod.rs` — register module.
- `crates/aegis-proxy/src/data_plane.rs` (~1869–1894) — replace `copy_bidirectional` with the gated two-half bridge; thread captured `parts` (method/uri/headers) + `Arc` detector/mask handles into the bridge task.
- `crates/aegis-core/src/config.rs` — `ws_inspect` block on `RouteConfig`; config-plane `config:waf:doc` schema threading; boot/handshake validation.
- `crates/aegis-control/src/metrics/websocket.rs` — `aegis_websocket_frame_block_total{route,tag}`.
- Audit projection — `websocket_frame_block` event (`AuditClass::Access`, additive `fields`, `schema_version` unchanged).
- Dashboard — `ws_inspect` route toggle surface.
- Docs: `docs/security/websocket.md` (new); architecture doc update.
- Tests: `ws_codec.rs` unit tests; integration via `tokio-tungstenite` through the WAF to a WS echo backend (extend `proto/ws.rs:98` `websocket_echo_through_tunnel`).

---

## Acceptance gates (merge bar — design §9–§10)

- [ ] Off by default proven: `ws_inspect` off → literal current `copy_bidirectional` path; every existing WS-T test (`data_plane.rs:3792+`, `proto/ws*.rs`) passes unchanged.
- [ ] Binary frame round-trips byte-identical with `ws_inspect` on; benign text passes.
- [ ] Text frame carrying `<script>` / `' OR 1=1--` blocked → client gets Close `1008`.
- [ ] Fragmented text reassembled and inspected as one message (no fragmentation evasion).
- [ ] `log_only` forwards the malicious frame **and** emits `websocket_frame_block` (`action: would_block`).
- [ ] Oversize frame/message → close `1009`; invalid UTF-8 in text → close `1007`; non-masked client frame → close `1002`.
- [ ] `permessage-deflate` stripped from forwarded handshake when inspection on (connection uncompressed).
- [ ] Throughput regression benchmarked: inspected vs passthrough route (WS-MSG2 gate).

---

## Out of scope (design §2)

Binary-frame inspection; response (upstream→client) scanning; `permessage-deflate` inflate;
per-frame rate limiting; GraphQL-over-WS operation parsing; HTTP/2 extended-CONNECT WS
(already unsupported, `data_plane.rs:1789`).
