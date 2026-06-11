# WS-MSG — WebSocket message-level inspection (text frames)

> **Status (2026-06-11): ✅ Shipped (WS-MSG1–6).** Branch: `feat/websocket-message-inspection`.
> Tracker: [`../issues/FEAT-websocket-message-inspection.md`](../issues/FEAT-websocket-message-inspection.md).
> Two decisions changed from this design during implementation:
> (1) forwarding **preserves the original client masking** (not unmasked, §4.1) —
> required because `tokio-tungstenite`-class servers reject unmasked client frames;
> (2) an **oversize reassembled message is skipped + forwarded (metered), not closed
> `1009`** (operator steer) — favours availability for large legit messages. See
> `docs/security/websocket.md` for the shipped behaviour.
> Track ID prefix `WS-MSG<n>`. Implementation tracker:
> [`../issues/FEAT-websocket-message-inspection.md`](../issues/FEAT-websocket-message-inspection.md)
> (phase checklist + acceptance gates). This doc holds the design rationale.
>
> **Goal (one line):** today the WAF inspects only the WebSocket *handshake*
> (the `GET … Upgrade: websocket` request) and then byte-tunnels every frame via
> `copy_bidirectional`. This plan adds an **opt-in frame-parsing bridge** that, for
> **text frames (opcode `0x1`)** flowing **client → upstream**, reassembles the
> message payload and runs it through the existing body-oriented detectors
> (XSS / SQLi / body_abuse) before forwarding — blocking or closing the socket on a
> verdict. Binary / control frames stay zero-copy passthrough.
>
> **Why now:** the WebSocket bridge (WS-T, shipped — see
> [`../archive/websocket-bridge.md`](../archive/websocket-bridge.md)) explicitly
> scoped frame-level abuse detection *out of v1*. That leaves an established
> WS socket as an uninspected L4 tunnel — a real bypass for any backend that
> takes user content over WS (chat, collaborative editors, GraphQL-over-WS).
> This is the natural follow-up track and slots into the world-class roadmap as a
> protocol-coverage gap.

---

## 0. Off by default — existing WS traffic stays byte-for-byte unchanged

Frame inspection is gated behind a per-route opt-in (`ws_inspect`, default `off`).
With it off, the bridge runs the **exact** `copy_bidirectional` path that ships
today (`data_plane.rs:1894`) — no frame parser, no reassembly buffer, no added
allocation or latency on the hot path. Existing deployments are completely
unaffected. This mirrors the opt-in gating used by
[`proxy-protocol.md`](./proxy-protocol.md) §0 and cluster mode.

The decision is deliberate: frame parsing on a high-throughput WS stream is not
free, and most WS traffic (binary protocols, market-data fan-out) has no
text-content attack surface. Operators turn it on for the routes that carry
user-authored text into a backend.

---

## 1. What exists today (verified against code 2026-06-11)

- **Handshake inspection (shipped):** the `GET` upgrade request goes through the
  full detector chain in `handle_data_request_inner` — body buffered
  (`data_plane.rs:685`), detectors run (`:796`), per-IP risk gate, operator rules
  (`:1613`), mTLS gate (`:1565`). Admission gates the *creation* of the tunnel.
- **The bridge (shipped, WS-T):** `forward_allow_to_upstream` detects the upgrade
  (`data_plane.rs:1735` via `proto/ws::is_websocket_upgrade`), picks a healthy
  member, calls `proto/ws_forward::forward_websocket_upgrade` to do the raw 101
  handshake, then on `101` spawns a task that runs
  **`tokio::io::copy_bidirectional(&mut client_io, &mut upstream)`**
  (`data_plane.rs:1894`). This is the single line frame inspection replaces.
- **No frame parsing anywhere.** `proto/ws.rs` / `proto/ws_forward.rs` deal only
  with the HTTP head; the post-101 byte stream is never decoded. There is **no
  RFC 6455 frame codec in the tree** — it must be added (or pulled in).
- **Detector contract:** `Detector::inspect(&self, req: &RequestView<'_>) -> Vec<Signal>`
  (`detectors/mod.rs:358`); `Signal { score, tag, field }` (`:36`). Body-shape
  detectors read `view.body` (a `BodyPeek`). The operator-rule evaluator already
  rebuilds a synthetic `RequestView` from buffered bytes
  (`data_plane.rs:1621-1634`) — **the same trick frame inspection reuses.**
- **WS metrics + audit (shipped, WS-T4/T6):** `record_open` / `record_close`
  (`data_plane.rs:1865`, `:1946`); `websocket_open` / `websocket_close` audit
  events (`:1952`, `:1901`) carrying `client_ip`, `route_id`, byte counts.
  **Frame-block audit events extend this existing shape.**

---

## 2. Scope — text frames, one direction, v1

| Dimension | v1 decision | Rationale |
|---|---|---|
| **Opcode** | Only **text `0x1`** inspected. `0x0` continuation reassembled *into* a text message; `0x2` binary, `0x8/0x9/0xA` (close/ping/pong) pass through verbatim. | Text is where the body detectors (XSS/SQLi) have signal. Binary needs schema-aware decoders — out of scope. |
| **Direction** | **client → upstream only.** upstream → client stays zero-copy. | The threat is hostile client content reaching the backend. Response scanning is a separate, larger track. |
| **Fragmentation** | Reassemble fragmented text messages (`0x1` + `0x0…` with `FIN`) up to a **bounded cap** before inspecting. | A detector needs the whole logical message; an attacker can't split a payload across frames to evade. The cap stops unbounded buffering. |
| **Compression** | If `permessage-deflate` was negotiated in the handshake → **fail closed** in v1 (refuse `ws_inspect` + deflate, log at boot/handshake). | Inspecting compressed frames needs an inflate step with its own zip-bomb bound; defer to v2. |
| **Detectors** | Reuse the **body-class** detectors (XSS, SQLi, body_abuse) via the mask. No new detector types in v1. | DRY — the message payload is "a body". Frame-specific detectors are a v2 extension point. |
| **Verdict actions** | `block` (drop frame + close with WS Close `1008`/policy) or `log_only` (emit audit, forward frame) — honors the route/global mode. | Symmetric with the existing enforce-vs-log_only model (see memory: X-WAF-Action vs Mode). |

**Explicitly out of v1:** binary-frame inspection, response (upstream→client)
scanning, `permessage-deflate` inflate, per-frame rate limiting, GraphQL-over-WS
operation parsing, HTTP/2 extended-CONNECT WS (already unsupported, `data_plane.rs:1789`).

---

## 3. Architecture — replace `copy_bidirectional` with an inspecting bridge

```
                    ┌──────────────── inspecting WS bridge (ws_inspect = on) ───────────────┐
 client             │                                                                       │   upstream
   │  text frame    │  proto/ws_codec        reassembly buf         detector run            │
   │═══════════════▶│──▶ parse frame ──▶ opcode 0x1/0x0? ──▶ append to msg buf              │
   │                │       │ FIN?                              │ (bounded cap)              │
   │                │       │  no ──────────────────────────────┘                           │
   │                │       │  yes                                                           │
   │                │       ▼                                                                │
   │                │   synth RequestView{ body = msg bytes } ─▶ run_all_filtered            │
   │                │       │                                      │                         │
   │                │       │  score < threshold (allow) ──────────┼──▶ re-emit frame ──────▶│
   │   WS Close ◀───│───────┘  score ≥ threshold (block) ─────────┘   (forward bytes)       │
   │   1008         │             • audit websocket_frame_block                              │
   │                │             • close both sockets                                       │
   │                │                                                                        │
   │  binary/ctrl ══│═══════════════ passthrough (no parse, copied verbatim) ═══════════════▶│
   └────────────────┴────────────────────────────────────────────────────────────────────────┘
   upstream → client : always zero-copy passthrough in v1
```

The hot path is no longer `copy_bidirectional`. Instead the bridge task splits
into two halves:

- **upstream → client:** `tokio::io::copy` (verbatim, unchanged semantics).
- **client → upstream:** a frame loop that decodes RFC 6455 frames off the client
  socket, passes binary/control frames straight through, and for text messages
  buffers → inspects → forwards-or-blocks.

Both halves run under `tokio::select!`; either side closing or an inspection
block tears down the pair (same lifecycle the current bridge has).

---

## 4. The frame codec (`proto/ws_codec.rs` — new)

A minimal, **bounded** RFC 6455 reader/writer. We do **not** need a full
WebSocket implementation (no handshake — that already happened; no masking key
generation — the client masks, we preserve). Required surface:

- Parse a frame header: `FIN`, `RSV1-3`, `opcode`, `MASK`, payload length
  (7 / 7+16 / 7+64), masking key.
- **Reject `RSV1` set** when `ws_inspect` is on (that's `permessage-deflate` →
  fail-closed per §2).
- Unmask the payload (client→server frames are always masked; a non-masked
  client frame is a protocol error → close `1002`).
- Re-emit a frame to the upstream **preserving the original masking** byte-for-byte
  when forwarding unchanged is cheapest — OR re-frame unmasked and let the upstream
  read it (decision §4.1).
- **Bounds (constants, no magic numbers):**
  - `MAX_FRAME_PAYLOAD` — single-frame cap (e.g. 1 MiB); over → close `1009`.
  - `MAX_MESSAGE_BYTES` — reassembled-message cap across fragments (e.g. 4 MiB);
    over → close `1009`. Mirrors the `MAX_HEAD_BYTES` discipline in
    `ws_forward.rs:61`.

> **Decision §4.1 (recommended, confirm in review):** forward text frames
> **re-framed unmasked** to the upstream. Rationale: the WAF is the server-side
> peer of the client; RFC 6455 says client→server frames are masked but
> server-internal forwarding to a trusted backend over the existing TCP socket
> doesn't require it, and re-masking adds cost. Confirm the backends in the fleet
> accept unmasked inbound (most server libraries do; some strict ones may not — if
> so, fall back to preserve-original-masking).

**Build vs. pull a crate:** evaluate `tokio-tungstenite` / `fastwebsockets` for
the codec in the research step (workflow §0). The existing test already depends on
`tokio-tungstenite` as a dev-dependency (`proto/ws.rs:101`). Prefer a vetted codec
over hand-rolling frame parsing **if** it exposes a header-level decode without
forcing us to own the whole connection lifecycle; otherwise a ~200-line bounded
reader is acceptable and keeps the dependency surface small. Decide in review.

---

## 5. Inspection hook — reuse body detectors via a synthetic `RequestView`

Per reassembled text message, build a `RequestView` the same way the live
operator-rule path does (`data_plane.rs:1621`):

```rust
let body_peek = aegis_core::pipeline::BodyPeek::new(
    msg_bytes.clone(),            // the reassembled text payload
    Some(msg_bytes.len() as u64),
    false,
);
let view = aegis_core::pipeline::RequestView {
    method: &ws_pseudo_method,    // synthetic; e.g. keep original GET
    uri: &original_uri,           // the upgrade request's URI (route scoping)
    version: original_version,
    headers: &original_headers,   // handshake headers (host, auth, etc.)
    peer: SocketAddr::new(peer_ip, 0),
    tls: None,
    body: &body_peek,
};
let signals = aegis_security::detectors::run_all_filtered(
    detectors, mask_for_ws_tier, &view,
);
```

- The detector **mask** is the per-route/tier mask, so an operator can scope which
  classes apply to WS text (`run_all_filtered`, `detectors/mod.rs:376`).
- Verdict = sum of `signal.score` vs the configured threshold (reuse the existing
  per-request scoring model — see memory: request-score-vs-cumulative; we use the
  **per-request SUM**, this is not the cumulative IP-risk feed).
- **Operator rules** can also run against the synthetic view (`rules::evaluate`,
  `data_plane.rs:1636`) so a `Block` rule scoped to the route applies to frames too
  — optional v1.1, note as extension point.

The handshake captured `parts` (method/uri/headers) must be **moved into the bridge
task** so the synthetic view has them. Today only `on_upgrade`, `leftover`,
`upstream_socket`, metrics, and `peer_ip` cross into the task (`data_plane.rs:1869`)
— this plan threads `Arc`-shared detector handles + the captured request context in.

---

## 6. Verdict handling

| Verdict | Action | Audit |
|---|---|---|
| **allow** (`score < threshold`) | forward the frame to upstream unchanged | none (or sampled debug) |
| **block** + mode `enforce` | drop the frame, send WS Close `1008` (policy violation) to the client, tear down the pair | `websocket_frame_block` event: `client_ip`, `route_id`, top `tag`, `score`, `field`, frame ordinal |
| **block** + mode `log_only` | forward the frame, emit the audit event with `mode: log_only` | same event, `action: would_block` |

Audit events extend the existing WS audit shape (`data_plane.rs:1901`) — same
`AuditClass::Access`, add `action: "websocket_frame_block"`, `rule_id` = detector
tag, `risk_score` = summed score, `fields.frame_ordinal` / `fields.matched_field`.
This keeps the Live Feed and metrics consumers working without a schema bump
(`schema_version: 1` unchanged; new fields are additive in the `fields` blob).

A new counter `aegis_websocket_frame_block_total{route,tag}` sits alongside the
existing `aegis_websocket_active` / `_close_total` (metrics/websocket.rs).

---

## 7. Config surface

Per-route, default off:

```yaml
routes:
  - id: chat
    upstream: chat-pool
    ws_inspect:
      enabled: true            # default false → today's zero-copy bridge
      mode: enforce            # enforce | log_only  (default log_only on first enable)
      max_message_bytes: 4194304
      # detector classes default to the route's existing tier mask;
      # operators narrow with the standard PUT /api/detectors surface
```

- Boot validation: `ws_inspect.enabled && permessage-deflate negotiable` is **not**
  a boot error (deflate is negotiated per-connection) — instead it's a
  **per-handshake** fail-closed: if the client offers `permessage-deflate` and the
  route has `ws_inspect.enabled`, the WAF **strips the extension offer from the
  forwarded handshake** so the negotiated connection is uncompressed and inspectable
  (decision §7.1 — recommended; the alternative is rejecting the upgrade, which is
  more disruptive).
- Mirror the config-plane rule: mutations validate against the Redis
  `config:waf:doc`, not the boot YAML (see memory: config-plane-doc-vs-file) — the
  `ws_inspect` block must be threaded into the doc schema, not just the file, or it
  goes stale on dashboard save.

---

## 8. Implementation phases (track IDs)

- **WS-MSG1 — codec.** `proto/ws_codec.rs`: bounded RFC 6455 frame reader/writer +
  unit tests (header parse at each length class, mask/unmask, RSV1 reject, oversize
  → close code). Pure, no I/O. *Gate: codec round-trips tungstenite-produced frames.*
- **WS-MSG2 — inspecting bridge.** Replace `copy_bidirectional` (`data_plane.rs:1894`)
  with the `tokio::select!` two-half bridge **behind `ws_inspect.enabled`**; off-path
  stays the literal current code. Reassembly + bounded buffers. *Gate: binary/control
  passthrough byte-identical to today; text reassembly correct across fragments.*
- **WS-MSG3 — detector hook.** Thread captured request context + detector/mask
  handles into the task; build synthetic `RequestView`; wire `run_all_filtered`;
  threshold + verdict. *Gate: a known XSS/SQLi payload in a text frame is blocked;
  benign chat text passes.*
- **WS-MSG4 — verdict I/O + audit + metrics.** WS Close `1008` on block, `log_only`
  path, `websocket_frame_block` audit, `aegis_websocket_frame_block_total`.
  *Gate: enforce closes the socket; log_only forwards + audits.*
- **WS-MSG5 — config + config-plane.** `ws_inspect` on `RouteConfig`, doc-schema
  threading, deflate strip-on-handshake, boot/handshake validation, dashboard
  surface. *Gate: toggle in dashboard takes effect on the next WS connection.*
- **WS-MSG6 — docs.** `docs/security/websocket.md` (new): the two-phase model,
  what's inspected, the deflate caveat, the direction caveat. Update the
  architecture answer that motivated this plan.

---

## 9. Risks & mitigations

| Risk | Mitigation |
|---|---|
| **Throughput regression on inspected routes** | Off by default; bounded buffers; only text reassembled; binary/control never parsed. Benchmark inspected vs. passthrough in WS-MSG2 gate. |
| **Evasion by fragmentation** | Reassemble to `FIN` before inspecting; cap at `MAX_MESSAGE_BYTES` then force a verdict (fail-closed: oversize → close `1009`). |
| **Evasion by `permessage-deflate`** | Strip the extension from the forwarded handshake when `ws_inspect` on → connection is uncompressed (§7.1). |
| **Backend rejects unmasked forwarded frames** | Decision §4.1 fallback: preserve original masking byte-for-byte. Validate against fleet backends in WS-MSG2. |
| **UTF-8 split across fragments** | Inspect on the reassembled message (full payload), not per-frame, so multi-byte chars are never split at the detector boundary. Invalid UTF-8 in a text message → close `1007` (protocol requires valid UTF-8). |
| **Detector built for HTTP bodies misfires on chat text** | `log_only` is the default on first enable; operators tune the mask/threshold before flipping to `enforce`. |
| **Half-duplex teardown races** | `tokio::select!` with explicit shutdown of both sockets, matching the current bridge's single-task lifecycle + `record_close`. |

---

## 10. Test plan

- **Unit (codec, WS-MSG1):** frame header parse at 7/16/64-bit lengths; unmask
  correctness; RSV1 reject; oversize frame/message → correct close code; continuation
  reassembly.
- **Integration (bridge, WS-MSG2/3):** real `tokio-tungstenite` client through the
  WAF to a WS echo backend (extend `proto/ws.rs:98` `websocket_echo_through_tunnel`):
  - binary frame round-trips byte-identical with `ws_inspect` on;
  - benign text passes;
  - text frame carrying `<script>` / `' OR 1=1--` is blocked, client gets Close `1008`;
  - fragmented text reassembled and inspected as one message;
  - `log_only` forwards the malicious frame **and** emits `websocket_frame_block`.
- **Config (WS-MSG5):** dashboard toggle reflected on next connection; deflate offer
  stripped when inspection on; off-by-default leaves the passthrough path.
- **Regression:** every existing WS-T test (`data_plane.rs:3792+`, `proto/ws*.rs`)
  passes unchanged with `ws_inspect` defaulted off.

---

## 11. Decisions to confirm in review

1. **§4.1** Forward text frames re-framed **unmasked** (vs. preserve original
   masking). *Recommended: unmasked, with masked fallback if a backend rejects.*
2. **§7.1** On `ws_inspect` + client offers `permessage-deflate`: **strip the
   extension** from the forwarded handshake (vs. reject the upgrade).
   *Recommended: strip.*
3. **Codec source:** vetted crate (`fastwebsockets`/`tokio-tungstenite` decode) vs.
   ~200-line bounded hand-rolled reader. *Recommended: decide after the §0 research
   step weighs the dependency surface.*
4. **Default mode on first enable:** `log_only` (recommended) vs. `enforce`.
5. **Direction:** v1 client→upstream only (recommended) vs. also scan
   upstream→client responses (larger, defer to v2).
