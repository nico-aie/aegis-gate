# gRPC-aware proxying — stream bodies, preserve trailers, wire `proto/grpc.rs` (future plan)

> **Status:** Drafted 2026-06-23. Not started. Slotted into the
> [world-class roadmap](./world-class-waf-roadmap.md) → *Operational /
> correctness backlog* (it corrects the roadmap's §1 overstatement that gRPC
> "already works").
>
> **Committed near-term scope = P1 only** (force the streaming path for gRPC +
> preserve trailers) — a standalone **S** correctness win that fixes unary +
> server-streaming + `grpc-status` and makes `tests/protocols/05-grpc.sh` real,
> with **no request-side change**. **P2 (stream the request body) and P3–P6 are
> deferred** larger work — P2 in particular is `Full<Bytes>` client-type surgery
> (§5.1). "Works like Envoy" (all four RPC shapes) needs P1 **+** P2; if only the
> trailer bug matters, P1 ships alone.
>
> Builds on the **shipped SSE streaming** response path
> (`plans/archive/sse-streaming-support.md`) and the h2 listener/upstream work
> already in tree. Carries the same "streamed ⇒ header-only inspection" security
> tradeoff the SSE work accepted on the response side — extended to the request
> side for gRPC only, and only when P2 lands. Related:
> [[project_hyper_normalizes_framing]], [[feedback_challenge_band_diagnostics]].

## Goal

Proxy gRPC correctly end-to-end:

- **Unary, server-streaming, client-streaming, bidirectional** all work.
- **`grpc-status` / `grpc-message` trailers survive** to the client (the gRPC
  status channel — without it every call looks like an internal error).
- gRPC traffic is **detected automatically** (`application/grpc*`) and routed to
  a streaming path, instead of relying on an operator hand-editing
  `streaming.content_types`.
- The existing buffered + fully-inspected path is **unchanged for non-gRPC
  traffic**. Only gRPC requests opt out of request-body buffering.

Non-goals for the core (deep protobuf inspection, method-level policy,
stream-level LB) are phased as later, optional tiers — see §6.

---

## 1. What already ships (verified in tree, 2026-06-23)

- **Inbound h2 over TLS works.** `accept.rs:2284-2301` serves h1/h2 via
  `hyper_util::server::conn::auto::Builder` on TLS connections; ALPN advertises
  `h2` (`run.rs:1198`, `listener/tls_policy.rs:66,146`). **h2c (cleartext h2) is
  deliberately not served** — the plaintext listener is h1-only
  (`accept.rs:2277-2279`).
- **Outbound h2 works, but only for explicit pools.** `build_client`
  (`upstream/forward.rs:228-329`) advertises h2 to the backend only for
  `scheme: grpc` or `h2c` pools (`forward.rs:268-271`) and sets `http2_only(true)`
  (`forward.rs:325-327`). `UpstreamScheme::Grpc` = HTTPS + ALPN-h2-only;
  `H2c` = cleartext prior-knowledge h2 (`aegis-core/src/config.rs:2608-2662`).
- **Response streaming infra exists** (from the SSE work). `forward()` returns
  `Response<DataBody>` + a `ResponseMode` (`forward.rs:418-433`);
  `stream_through` (`upstream/streaming.rs:241-256`) wraps the upstream
  `Incoming` body as `IdleTimeoutBody → EndOnError → PermitBody → boxed_unsync`
  into `DataBody = UnsyncBoxBody<Bytes, Infallible>` (`body.rs:22`). These
  wrappers forward `poll_frame` generically, so **trailer frames already pass
  through the streaming path**.
- **`proto/grpc.rs` is built but dead.** `is_grpc()` (detects
  `application/grpc*`) and a trailer-preserving `StreamingBody` are `pub`
  (`proto/mod.rs:6 pub mod grpc;`) with a full e2e unit test
  (`grpc_trailers_preserved_through_proxy`, `proto/grpc.rs:90-239`) — but **zero
  production callers** outside their own tests.
- **A gRPC smoke test already exists**: `tests/protocols/05-grpc.sh` asserts h2
  ALPN, that `application/grpc` is not rejected, and that `grpc-status` trailers
  are not stripped. This plan is what makes that test meaningful end-to-end.

## 2. The actual bugs (corrected, ranked)

The earlier "fix `EndOnError`" framing was imprecise. The real defects:

1. **CRITICAL — gRPC responses are classified `Buffered`, which drops trailers.**
   `classify_response_mode` (`streaming.rs:51-60`) matches the response
   `content-type` essence against `streaming.content_types`, whose default is
   `["text/event-stream"]` only (`config.rs:342-344`). `application/grpc` does
   not match → `Buffered` → the response hits `Limited::new(...).collect()`
   (`forward.rs:654-689`), which **discards HTTP/2 trailer frames**, losing
   `grpc-status`/`grpc-message`. This breaks *every* gRPC call, including unary.
   **This is the single highest-impact fix and unblocks unary + server-streaming
   on its own**, because the streaming path already forwards trailers.

2. **CRITICAL — the request body is fully buffered, capped, and deadline-bound.**
   `data_plane.rs:971-973` does
   `timeout(read_timeout, Limited::new(body, max_body_bytes).collect())`, then
   `forward()` takes `body: Bytes` and builds `Full::new(body)`
   (`forward.rs:529`) against a `PooledClient = Client<…, Full<Bytes>>`
   (`forward.rs:205-208`). Consequences: **client-streaming and bidi gRPC
   deadlock** (the backend never sees the first message until the client closes
   the request stream — but in bidi the client is waiting on server messages
   first), and any long-lived request stream is killed by `read_timeout` /
   `max_body_bytes`.

3. **HIGH — no automatic detection.** Even with (1) fixed via the allowlist,
   gRPC only streams if an operator manually adds `application/grpc` to
   `streaming.content_types`. `is_grpc()` exists but is never called. We want
   gRPC detected automatically on both request and response.

**Re: `EndOnError` (correction).** `EndOnError` (`streaming.rs:83-124`,
`Error = Infallible`) folds a genuine *transport* error from the upstream
`Incoming` body into a clean end-of-stream. For gRPC this is mostly fine:
gRPC **application** errors are delivered as a `grpc-status` *trailer on an
HTTP-200 response*, not as a transport error, so they ride the normal
trailer-forwarding path. `EndOnError` only triggers on an actual upstream
RST/IO error mid-stream — a real failure where there are no trailers to lose
anyway. So this is a **known edge-case limitation to document**, not a core bug
(see §5.3). The core fixes are (1) and (2).

## 3. Design

### 3.1 Force the streaming path for gRPC (fixes CRITICAL #1)
Make the response classifier treat gRPC as streaming regardless of the
allowlist. Two options:

- **(a) Allowlist default.** Add `application/grpc` to
  `default_streaming_content_types` (`config.rs:342-344`). Simple, but the
  essence match (`media_type_essence`) lowercases and strips params, so
  `application/grpc+proto` essence is `application/grpc+proto` — would **not**
  match a bare `application/grpc` entry. Needs a prefix match, not exact.
- **(b) `is_grpc`-forced streaming (preferred).** In the classifier call site
  (`forward.rs:561-568`), if the response `content-type` starts with
  `application/grpc`, force `ResponseMode::Streaming`. Reuse the `proto::grpc`
  prefix check so `application/grpc`, `application/grpc+proto`,
  `application/grpc-web` all match. This is the first production wiring of
  `proto/grpc.rs`.

Go with **(b)**, and keep `streaming.content_types` as the general SSE/other
mechanism. gRPC detection must not depend on operator config.

> **Correctness guard:** for gRPC, `on_exhaustion` must **reject (503)**, never
> `Buffer` — the `Buffer` degrade path (`forward.rs:631`,`654-689`) re-buffers
> and drops trailers. Either force-reject for gRPC, or document that
> `on_exhaustion: buffer` is unsafe with gRPC. See §5.2.

### 3.2 Stream the request body for gRPC (fixes CRITICAL #2)
The hard part. The upstream client is hardwired to `Full<Bytes>`.

- **Introduce a request-body enum** `ReqBody` implementing `hyper::body::Body`
  (`Data = Bytes`), e.g. `Buffered(Full<Bytes>)` | `Streaming(<boxed incoming>)`.
  Change `PooledClient`'s body generic from `Full<Bytes>` to `ReqBody`
  (`forward.rs:205-208`) so one pool serves both shapes. The existing buffered
  path wraps bytes as `ReqBody::Buffered`; the gRPC path passes
  `ReqBody::Streaming`.
- **Thread the raw `Incoming` through, gated on `is_grpc`.** In `data_plane.rs`
  the request body is consumed at `:936/971-973`. For a request where
  `is_grpc(&req)` is true *and* the matched pool is h2-capable
  (`scheme: grpc|h2c`), **skip the buffer/collect** and hand the raw `Incoming`
  (boxed) to `forward()` instead of `body_bytes: Bytes`. `forward()`'s signature
  (`forward.rs:418-433`) gains a body parameter that is `Bytes`-or-stream
  (an enum, or two entry points). All three allow-path call sites must pass it:
  `data_plane.rs:2846-2856`, the under-threshold/log-only path `:1525-1536`, and
  `:2031-2037`.
- **Full-duplex falls out of hyper.** Once neither side is pre-collected, the
  h2 client multiplexes request and response frames concurrently, so bidi works
  — provided the data plane does not `await` the whole request before reading
  the response (it won't, because we stop collecting).

### 3.3 Preserve trailers end-to-end (verify, don't assume)
The wrapper stack already forwards `poll_frame` frames generically, so trailers
*should* survive. Make it load-bearing with explicit tests rather than trust:

- Confirm `IdleTimeoutBody` (`upstream/idle_timeout.rs`), `EndOnError`,
  `PermitBody`, and `MeteredStreamBody` each forward `Frame::trailers` (not just
  data). `MeteredStreamBody` only counts `frame.data_ref()` bytes
  (`streaming.rs:199-203`) — confirm it still *returns* trailer frames untouched.
- Confirm the data-plane response path for `ResponseMode::Streaming` does **not**
  re-collect or strip trailers, and that the inbound h2 server
  (`serve_connection_with_upgrades`) emits trailer frames on the wire.
- The `Trailer:` *announce header* is hop-by-hop and stripped
  (`forward.rs:58,593`) — that is correct and unrelated to trailer *frames*.

### 3.4 Wire `is_grpc()` as the detection seam
`proto::grpc::is_grpc` becomes the single detection point, called on:
- the inbound request → choose streaming request path (§3.2) + skip request-body
  inspection (header-only, like SSE responses);
- the upstream response `content-type` → force streaming response (§3.1).

Decide whether to reuse `proto::grpc::StreamingBody` (its `Error = hyper::Error`,
so it needs `EndOnError`-style folding to box into `DataBody`'s `Infallible`) or
to route the upstream `Incoming` straight through the existing `stream_through`
(which already does the folding). **Prefer `stream_through`** for the response
(less new code); `StreamingBody` may be the cleaner fit for the *request* body
boxing. Confirm during implementation.

## 4. Security tradeoff (must be explicit)
Streaming a gRPC **request** body bypasses request-body inspection: the
SSRF/XSS/body-abuse detectors run on the buffered `BodyPeek`
(`data_plane.rs:1004-1008,1159-1164`) and the GraphQL guard
(`data_plane.rs:1118`) all require the full buffered body. A streamed gRPC
request is therefore **header-only inspected**, exactly as streamed responses
already are (documented at `data_plane.rs:315-323`).

Mitigation / scoping:
- Only requests that are **both** `is_grpc` **and** bound for an h2 pool take the
  streaming request path. All other traffic is unchanged (buffered + fully
  inspected).
- gRPC payloads are length-delimited protobuf — opaque to the current text
  detectors anyway, so little inspection value is lost today. Deep protobuf
  inspection is a separate, later tier (§6, P6).
- Keep an optional **size cap** even on the streamed gRPC path (a max in-flight /
  max-message bound) so streaming is not an unbounded-body bypass.

## 5. Open decisions / risks
1. **Client-type surgery (the big one).** Changing `PooledClient`'s body generic
   to `ReqBody` (§3.2) ripples through `build_client`, the connection pool, and
   every `forward()` call site. Highest-risk change; land it behind a flag and
   prove non-gRPC traffic is byte-for-byte unchanged.
2. **`on_exhaustion: buffer` is unsafe for gRPC** — it re-buffers and drops
   trailers (§3.1 guard). Force-reject for gRPC or document loudly.
3. **`EndOnError` edge case.** A mid-stream upstream *transport* error becomes a
   clean truncated EOS with no `grpc-status`; the gRPC client surfaces it as
   `UNAVAILABLE`/`INTERNAL`. Acceptable (it *is* a transport failure), but record
   it as a known limitation; a later refinement could synthesize a
   `grpc-status: 14` trailer on truncation.
4. **Long-lived streams vs timeouts/permits.** Server-streaming/bidi can be
   long-lived. `idle_timeout` default 300s resets per frame (fine for chatty
   streams) but a quiet bidi stream >300s idle is killed; `max_duration` default
   `None` (no cap) is right for gRPC. Each live stream holds one
   `streaming.max_concurrent` permit (default 256) for its whole lifetime —
   gRPC-heavy deployments need this raised. Tuning, not a blocker.
5. **h2c inbound** stays unsupported (`accept.rs:2277-2279`). gRPC clients must
   use TLS. Optional later phase (§6, P5) if a cleartext mesh sidecar needs it.
6. **Cancellation accounting.** A client-cancelled long stream must not be
   miscounted as an upstream failure by the circuit breaker / passive-health
   work ([[project_health_signals_reported_not_gating]]). Reuse the inflight RAII
   guard semantics.

## 6. Phasing (priorities mirror the requested tiering)

Near-term commitment is **P1 only**; P2 onward are deferred (see Status). Effort:
**S** ≤ ~3 d, **M** ~1–2 wk, **L** ~3 wk+ (roadmap convention).

- **P1 — CRITICAL · ✅ SHIPPED 2026-06-27 · S: gRPC responses stream + trailers preserved.**
  §3.1 (`proto::grpc::content_type_is_grpc` forces `ResponseMode::Streaming` in
  `classify_response_mode` AND in `forward()`'s mode pick — independent of
  `streaming.enabled`) + the §3.1 guard (gRPC under permit exhaustion **rejects
  503**, never `Buffer`-degrades, which would drop trailers) + §3.3 (verified the
  wrapper stack — incl. the `MeteredStreamBody` byte-counter — forwards trailer
  frames, with tests). **Unblocks unary + server-streaming + `grpc-status` with
  no request-side change.** Tests: classify-forces-streaming unit; trailer
  survival end-to-end through `forward()` (h2c mock backend); `meter()` trailer
  preservation; 503-on-exhaustion. `tests/protocols/05-grpc.sh` is now meaningful
  end-to-end (run against a live instance). **P2 (stream the request body) onward
  remain deferred.**
- **P2 — CRITICAL · DEFERRED · M: stream the request body.** §3.2 (`ReqBody`
  enum, thread `Incoming`, three call sites; `Full<Bytes>` client-type surgery,
  §5.1). **Unblocks client-streaming + bidirectional.** Behind a flag; prove
  non-gRPC unchanged. **P1 + P2 = "works like Envoy."**
- **P3 — CRITICAL · DEFERRED · S: wire `proto/grpc.rs` into production.** Falls
  out of P1+P2 (the `is_grpc` seam, §3.4); retire the dead-code status; add the
  size-cap guard on the streamed request path (§4).
- **P4 — HIGH · DEFERRED · M: method-aware policy/routing.** Parse the `:path`
  (`/package.Service/Method`) for per-method allow/deny + rate limits. No
  protobuf decode needed — just the path. Slots into the existing rule engine.
- **P5 — MEDIUM · DEFERRED · M: stream-level load balancing & h2c inbound
  (optional).** Per-stream LB picks (not per-connection), so multiplexed gRPC
  streams spread across members; optional h2c listener for cleartext mesh.
- **P6 — ADVANCED · DEFERRED · L: protobuf decoding + gRPC-aware WAF rules +
  gRPC health.** Length-delimited protobuf framing parse, optional schema-aware
  field inspection, and gRPC health-check probing
  (`grpc.health.v1.Health/Check`) as a pool health mode.

**Minimum "works like Envoy" = P1 + P2** (all four RPC shapes + correct
`grpc-status`). P3 makes it first-class rather than a special case. If only the
trailer bug is in scope, **P1 ships alone** and is the recommended start.

## 7. Tests
- **(P1)** Rust e2e: h2 mock backend emits `grpc-status`/`grpc-message` trailers
  on HTTP 200 → proxied response preserves them (generalize
  `proto/grpc.rs:90-239` into the live `forward()` path, not just `StreamingBody`).
  Unit: `is_grpc`-forced `Streaming` for `application/grpc`, `+proto`, `-web`.
- **(P1)** Trailer-survival unit test through the full
  `IdleTimeoutBody→EndOnError→PermitBody→MeteredStreamBody` stack.
- **(P2)** Client-streaming: client sends N delimited messages over time →
  backend receives all N before responding (no deadlock, no `read_timeout` kill).
  Bidi: interleaved request/response frames both flow (full-duplex).
- **(P2)** Regression: non-gRPC POST is still buffered, size-capped, and
  body-inspected (detectors fire) — byte-for-byte unchanged.
- **(P1/P2)** `on_exhaustion: buffer` + gRPC → rejected (not silently
  trailer-dropping).
- **Integration:** make `tests/protocols/05-grpc.sh` green end-to-end (real
  `grpcurl` unary + server-streaming).

## 8. Out of scope
- Deep protobuf field inspection / schema registry (P6 only sketches framing).
- gRPC-Web translation (HTTP/1.1 ↔ gRPC bridging).
- h2c inbound unless P5 is taken.
- Changing the active vs passive upstream health model
  ([[project_health_signals_reported_not_gating]]) — gRPC health-check probing in
  P6 reuses whatever lands there.
