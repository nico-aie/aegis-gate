# FEAT — WebSocket message-level inspection (text frames)

> **Type:** FEAT (feature track) · **Status:** ✅ WS-MSG1–6 shipped — ready for PR · **Branch:** `feat/websocket-message-inspection`
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

- [x] **WS-MSG1 — codec** (`ab61bb3`). `proto/ws_codec.rs`: bounded RFC 6455 header parse (7/16/64 length classes), mask/unmask, RSV/opcode/control validation, bounds, `encode_unmasked`/`encode_close`, `WsCodecError → close_code`. Pure, no I/O. 14 units incl. RFC §5.7 canonical vectors.
- [x] **WS-MSG2 — inspecting bridge** (`c92fffb`). `proto/ws_inspect.rs`: single-task `tokio::select!` bridge gated on `ws_inspect.enabled`; off-path = literal `copy_bidirectional`. Reassembly + bounded buffers; binary/control verbatim; forwarding **preserves masking** (tungstenite rejects unmasked → overrides §4.1). **Oversize policy changed per operator steer: skip+forward (metered), not close `1009`.** 6 bridge units + e2e tungstenite round-trip (text+binary) with inspection on.
- [x] **WS-MSG3 — detector hook** (`c9fe6de`). `run_bridge` gains an `inspect` hook; data_plane builds a synthetic `RequestView` (handshake ctx + stamped `text/plain` Content-Type so body detectors engage), runs `run_all_filtered` over the route-tier mask, sums scores vs the tier threshold. Detectors live on `ProxyContext` (`ws_detectors`/`ws_detector_mask`). e2e: real detector chain blocks an SQLi text frame; benign passes; fragmented `AT`+`TACK` blocked after reassembly.
- [x] **WS-MSG4 — verdict I/O + audit + metrics** (`7a111a8`). `websocket_frame_block` audit (rule_id=top tag, risk_score=sum, mode=enforce|log_only, fields.matched_field/message_bytes); `aegis_websocket_frame_block_total{route,tag}`. enforce → Close `1008`; log_only → forward + audit. e2e log_only test asserts forward **and** audit.
- [x] **WS-MSG5 — config + config-plane** (`cdca081`). `ws_inspect` on `RouteConfig` (boot YAML) + `RouteConfigPatch` (dashboard/API round-trip; `WsInspectConfig` now `Serialize`); deflate strip-on-handshake (`forward_websocket_upgrade`); RSV1 fail-close (`CompressionUnsupported` → 1002). _React dashboard control = frontend follow-up._
- [x] **WS-MSG6 — docs.** `docs/security/websocket.md` (new): two-phase model, what's inspected, deflate + oversize + direction caveats, off-by-default guarantee, observability.

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

- [x] Off by default proven: `ws_inspect` off → literal current `copy_bidirectional` path; every existing WS-T test passes unchanged.
- [x] Binary frame round-trips byte-identical with `ws_inspect` on; benign text passes. *(e2e + bridge units)*
- [x] Text frame carrying `' OR 1=1--` blocked → client gets Close `1008`. *(e2e with real detectors)*
- [x] Fragmented text reassembled and inspected as one message (no fragmentation evasion). *(`AT`+`TACK` block test)*
- [x] `log_only` forwards the malicious frame **and** emits `websocket_frame_block`. *(e2e — `mode: log_only`)*
- [x] Single frame over `MAX_FRAME_PAYLOAD` → close; **oversize reassembled message → skip+forward (metered), NOT `1009`** (operator steer); non-masked client frame → close `1002`; compressed (RSV1) → close `1002`. _UTF-8 validity (`1007`) not enforced in v1 — detectors operate on raw bytes; noted as a follow-up._
- [x] `permessage-deflate` stripped from forwarded handshake when inspection on (connection uncompressed). *(ws_forward test)*
- [ ] Throughput regression benchmarked: inspected vs passthrough route. *(deferred — micro-bench not yet run; off-by-default keeps the default path zero-cost)*

---

## Out of scope (design §2)

Binary-frame inspection; response (upstream→client) scanning; `permessage-deflate` inflate;
per-frame rate limiting; GraphQL-over-WS operation parsing; HTTP/2 extended-CONNECT WS
(already unsupported, `data_plane.rs:1789`).
