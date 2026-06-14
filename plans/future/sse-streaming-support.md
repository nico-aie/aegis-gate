# SSE / streaming response support — data-plane stream-through (future plan)

> **Status (2026-06-14): SHIPPED on branch `feat/sse-streaming`.** Phases
> 1–7 + decision-5 semaphore are implemented and tested; §11 pre-code
> verification was completed first (results in §11a). Docs:
> [`../../docs/data-plane/sse-streaming.md`](../../docs/data-plane/sse-streaming.md).
> Only deferred item is Option C (incremental chunk-by-chunk body
> inspection, §9) — intentionally future.
>
> _Original status: PLANNED, not started. Plan reviewed (~8.5/10) and
> revised against feedback; §11 verification was mandatory before Phase 1._

## Goal

Let the WAF proxy `text/event-stream` (Server-Sent Events) responses from an
upstream to end-user clients with **incremental flush** (events delivered as
they arrive), **no premature cutoff**, and **no buffer-until-cap**. Normal
(non-streaming) responses keep today's behaviour: buffered, size-capped,
response-body-inspected.

WebSocket (`proto/ws_forward.rs`) and gRPC paths are out of scope and untouched.

---

## 1. Root cause (confirmed in code)

`upstream::forward::forward()` (`crates/aegis-proxy/src/upstream/forward.rs:565`)
buffers the **entire** upstream response body before emitting anything:

```rust
let body_bytes = tokio::time::timeout(
    read_deadline,                                    // cfg.response_body_read_timeout (default 30s)
    http_body_util::Limited::new(resp.into_body(), max_response).collect(),  // default 10 MiB cap
).await …;
*filtered.body_mut() = Full::new(body_bytes);         // re-emitted as one buffered Full<Bytes>
```

The whole data-plane chain is typed `Full<Bytes>`:

```
service_fn (accept.rs)
  └─ handle_data_request  (data_plane.rs:78)  → (Response<Full<Bytes>>, DecisionTag)
       └─ forward_allow_to_upstream (data_plane.rs)
            └─ forward()  (forward.rs:418)     → Result<Response<Full<Bytes>>, ForwardError>
```

For SSE this means: no incremental flush; the open-ended stream hits the 30 s
`response_body_read_timeout` → `ForwardError::Timeout` → v2.3 §3 `timeout`
decision. The client gets a truncated/error response, never a live stream.

The streaming primitives already exist in-repo: `admin_sse` uses
`UnsyncBoxBody<Bytes, Infallible>` + `StreamBody` for the dashboard Live Feed —
but only on the **admin** listener. The production **data** path is fully
buffered. (`proto/grpc.rs::StreamingBody` is a test fixture, not a production
path.)

---

## 2. Design

Make the data-plane response body a single **streamable** type and branch in
`forward()` on the upstream response media type: SSE streams through; everything
else buffers as today.

### Confirmed decisions (from review)

1. **Unified body type:** `type DataBody = UnsyncBoxBody<Bytes, Infallible>`.
   Matches the in-repo `admin_sse` precedent → low cognitive load. The
   per-response box alloc is noise vs network latency in a proxy. (Rejected: a
   `DataBody { Full | Stream }` enum — avoids boxing the buffered path but forces
   every middleware/builder to be generic + adds `match` arms everywhere; the
   micro-optimisation is meaningless here.)

2. **Streaming trigger — proper media-type parse, not `starts_with`.** SSE is
   sent as `Content-Type: text/event-stream` *and* `text/event-stream;
   charset=utf-8`. Parse the media type: split on `;`, trim, ASCII-lowercase the
   `type/subtype`, compare `type == "text" && subtype == "event-stream"`. (No
   `mime` crate in the workspace — manual parse, no new dependency.) Driven by a
   config allowlist so it's extensible later (NDJSON, gRPC-web). `Transfer-
   Encoding: chunked` is **logged** for forensics but is **not** a streaming
   trigger.

2a. **Classify ONCE — `ResponseMode` is a property of the response, not
    re-derived per phase.** This is the rule that prevents drift: the media-type
    decision in (2) happens exactly once, in `forward()`, and is carried forward
    as a value. Re-parsing `Content-Type` in the filter-bypass / audit / metrics
    sites is forbidden — one of them would eventually disagree (a missed
    `;charset` parse, a new allowlisted type added in one place only).

    ```rust
    pub enum ResponseMode { Buffered, Streaming }
    ```

    **Carrier (source of truth): the `DecisionTag`.** `forward()` returns the
    `ResponseMode` explicitly (compiler-enforced — can't be forgotten);
    `handle_data_request` folds it onto the `DecisionTag` (`decision.response_mode`).
    Every consumer — Phase 3 filter/cache bypass, Phase 5 audit, Phase 7 metrics,
    header stamping — reads `decision.response_mode`, never `Content-Type` again.
    The audit fields (`streamed` / `response_inspection_skipped`, decision 3)
    then come straight off the tag for free.

    Rationale for the tag over `response.extensions()`: `http::Extensions` is
    **dropped on every `Response::builder()` rebuild** — and responses are rebuilt
    in `forward.rs:586` (`replay_response_status_and_headers`) and in the
    `data_plane.rs` filter Rewrite/Abort paths — so an extension would have to be
    re-inserted after each rebuild or be silently lost, reintroducing the drift
    we're killing. The `DecisionTag` already travels alongside the response to
    every consumer and is already audited, so it's the natural single home; Rust
    also forces callers to handle the returned value. `response.extensions_mut()
    .insert(ResponseMode::Streaming)` is acceptable as an **optional self-
    describing mirror** for future response-only middleware, but is **not** the
    source of truth.

3. **Security posture — explicit, documented policy (not an accident).**
   Streamed responses are **header-inspected only**; the response *body* is not
   inspected (response-filter `OutboundAction`, response-side detectors, and the
   size cap are all bypassed). Request-side + response-header inspection still
   run in full. Enabled-by-default for `text/event-stream` with a config
   kill-switch (`streaming.enabled`). Audit every streamed response with an
   explicit:

   ```
   response_inspection_skipped: true
   reason: "streaming"
   streamed: true
   ```

   so the security team reads the log and immediately understands *why* the body
   wasn't inspected. (Future Option C — incremental chunk-by-chunk inspection —
   is noted in §9; out of scope here because current detectors may need the
   whole body to decide.)

4. **Timeout model — idle timeout on RAW BYTES, not SSE semantics.** Replace the
   whole-body read deadline (which kills any live stream) with an **inactivity**
   timeout: reset the timer on every `Frame::data(..)` the upstream produces —
   **not** on parsed SSE events. SSE servers send heartbeats as comments
   (`:keepalive\n\n`) or `event: ping` every 15–30 s; those are data frames and
   must reset the idle timer. Resetting only on parsed events would kill healthy
   streams. Default idle ≈ 5 min; optional absolute `max_duration` (default off).

### New decision (from review — highest architectural risk)

5. **Connection-pool exhaustion — explicit max-concurrent-streams cap.** The
   upstream client is `hyper_util::client::legacy::Client`
   (`forward.rs:316`). Its `pool_max_idle_per_host` / `pool_idle_timeout` bound
   **idle** connections only — an active SSE stream holds a checked-out upstream
   connection for the stream's entire lifetime (minutes/hours), which the pool
   does **not** cap. N concurrent SSE clients ⇒ N pinned upstream connections,
   unbounded. Add a WAF-level **semaphore** (`streaming.max_concurrent`, default
   e.g. 256): on exhaustion, fall back to **buffered** handling (which will then
   hit the read timeout and 504) or return `503` — TBD in Phase 3. The idle
   timeout (decision 4) is the backstop that releases hung upstream connections.

---

## 3. Phase 1 — Unified streamable body type

**Realistic, not trivial.** ~40–60 compile errors expected; 191 `Full`
references live in `aegis-proxy/src` (many in tests). The compiler drives this,
but it touches error builders, helpers, `stamp_interop_response`, and tests.

Strategy — **outside-in**, alias + helper first:

- **Step A:** `pub type DataBody = UnsyncBoxBody<Bytes, Infallible>;` (+ re-use
  `admin_sse::into_boxed` or a local `fn boxed(Response<Full<Bytes>>) ->
  Response<DataBody>` = `resp.map(|b| b.boxed())`).
- **Step B:** migrate the boundary first — `service_fn` (`accept.rs`) →
  `handle_data_request` return type → `forward_allow_to_upstream` → `forward()`.
- **Step C:** wrap every inline block/error/response-filter-abort builder (e.g.
  `data_plane.rs:2433`, the §2 `Full::new(Bytes::from(..))` block sites) via the
  helper. Generalise `stamp_interop_response` (`admin_dispatch.rs:1237`,
  currently `Response<Full<Bytes>>`) over the body type or add a `DataBody`
  overload.
- **Gate:** no behaviour change yet — `cargo build` green + full test suite
  passes before Phase 2.

Per [`../archive/`] convention and the rustfmt-whole-crate hazard: **hand-match
style**, do not `cargo fmt` whole files.

## 4. Phase 2 — Classify + streaming branch in `forward()` (the single classifier)

- After upstream response headers arrive, **classify exactly once** via the
  media-type parser (decision 2) against the config allowlist →
  `ResponseMode::{Buffered, Streaming}` (decision 2a). This is the *only* place
  `Content-Type` is consulted for the streaming decision.
- **Streaming:** filter hop-by-hop / `Connection`-listed headers on the headers
  only (reuse the existing loop at `forward.rs:589-612`); wrap
  `resp.into_body()` in a pass-through `StreamBody` with
  `BodyExt::map_err(|_| unreachable Infallible)` and an **idle-timeout wrapper**
  (decision 4) that polls the inner body and races each `poll_frame` against a
  reset-on-data timer; return without `collect()`.
- **Buffered:** unchanged (the current `Limited::collect()` path).
- **Carry the mode out explicitly:** `forward()` returns `(Response<DataBody>,
  ResponseMode)` (or a small `ForwardOutcome` struct). `forward_allow_to_upstream`
  / `handle_data_request` fold it onto the `DecisionTag` (`decision.response_mode`)
  — the single source of truth every later phase reads. Optionally also stamp
  `response.extensions_mut().insert(mode)` as a self-describing mirror (not
  authoritative).
- Ensure the read-timeout → `timeout` decision mapping is **not** applied when
  `mode == Streaming`.

## 5. Phase 3 — Response-filter / cache bypass (driven by `response_mode`, explicit)

The response-filter pipeline + response cache `store` run in `data_plane.rs`
(~`2415-2465`) on the **buffered** `body_bytes` (`OutboundAction::{PassThrough,
Rewrite, Abort}` + `cache_pending.store(..)`). A streamed body can't be re-read.

Branch on the **already-classified** mode — never re-parse `Content-Type` here
(decision 2a) and never let middleware fail silently:

```rust
match decision.response_mode {
    ResponseMode::Streaming => { /* header-inspected only:
        skip the OutboundAction pipeline + cache store entirely */ }
    ResponseMode::Buffered  => { /* current path: filter + maybe store */ }
}
```

`store()` already refuses non-200 / `no-store` / oversize, but an open-ended
stream must be excluded up front by `response_mode`, not by accident.

## 6. Phase 4 — Config (`aegis-core/config.rs` → `ConnectionPoolConfig`/forward cfg)

```yaml
streaming:
  enabled: true                       # kill-switch (decision 3)
  content_types: ["text/event-stream"]# allowlist (decision 2)
  idle_timeout: 300s                  # raw-byte inactivity (decision 4)
  max_duration: null                  # optional absolute cap
  max_concurrent: 256                 # semaphore (decision 5)
  on_exhaustion: buffer | reject_503  # TBD default
```

Defaults, validation, and threading into `forward()`.

## 7. Phase 5 — Observability / audit

- Audit fields derived from `decision.response_mode` (decision 2a) — **not** a
  re-parse: `streamed`, `response_inspection_skipped`, `reason` (decision 3).
  Confirm v2.3 §5 response headers stamp correctly — they're stamped at header
  time (pre-body), so streaming is fine.
- Metrics:
  - `responses_streamed_total` (counter)
  - `active_streams` (gauge)
  - `stream_duration_seconds` (histogram) — spot leaks / runaways
  - `stream_bytes_sent` (histogram) — spot leaks / unbounded streams

## 8. Phase 6 — Tests

- **Unit:** media-type classifier (`text/event-stream`,
  `text/event-stream;charset=utf-8`, negatives); hop-by-hop header filtering on
  the stream path; idle-timeout wrapper resets on a raw data frame.
- **Integration:**
  - **Slow-SSE regression (the proof the 30 s bug is gone):** mock upstream emits
    `data: 1` at t=0, `data: 2` at t=40 s, `data: 3` at t=80 s with
    `idle_timeout=5m` → all three arrive, stream stays open well past 30 s.
  - Heartbeat-only stream (`:keepalive` every 20 s) keeps the stream alive.
  - Idle-timeout fires when the upstream goes silent past the deadline.
  - **Non-SSE regression:** a normal JSON response is still buffered, size-
    capped, and body-inspected (response-filter still runs).
  - `max_concurrent` cap enforced (N+1th stream buffers/503s per config).
- **n-tester:** add `SSE-01` to `tests/n-tester/preprod-feature-plan`.

## 9. Phase 7 — Docs / dashboard

- Document the header-inspected-only posture + config + the
  `response_inspection_skipped` audit semantics.
- Optional Live Feed marker for streamed responses.
- Future note: **Option C — incremental inspection** (`chunk → inspect →
  forward`) is the ideal end state but is deliberately deferred; many detectors
  currently need the whole body to decide.

---

## 10. Risks

| Sev | Risk | Mitigation |
|---|---|---|
| HIGH | **Connection-pool exhaustion** — legacy `Client` pool bounds *idle* not *active*; live streams pin upstream conns. | `streaming.max_concurrent` semaphore + idle timeout; audit `ConnectionPoolConfig` (`keep_alive`, `max_idle_per_host`, `idle_timeout`) interaction. |
| HIGH | **Security:** response-body inspection bypassed for streams. | Request + header inspection still run; explicit config gate; explicit audit (`response_inspection_skipped`); documented policy. |
| HIGH | **Phase 1 blast radius** (~40–60 errors, 191 `Full` sites). | Outside-in migration; alias+helper; compiler-guided; build/test gate before Phase 2. |
| MED | **Response-filter / cache** silently breaking on a stream. | Explicit `is_streaming()` bypass branch (Phase 3), not implicit failure. |
| MED | **Timeout wrapper** killing healthy heartbeat streams. | Idle timer resets on raw `Frame::data`, never on parsed SSE events. |
| MED | h1 (chunked) vs h2 SSE flush semantics. | Test both transports. |
| LOW | `stamp_interop_response` generalisation; clippy/rustfmt noise. | Hand-match style; generic-over-body or overload. |

## 11a. Pre-code verification — RESULTS (2026-06-14, branch `feat/sse-streaming`)

Verified every §11 claim against current code before any Phase-1 work.
All claims hold; the feature is **greenfield** (no existing streaming
decision in the data path).

- **§11.1 response-filter / cache consumers** — confirmed. The buffered
  `body_bytes` is consumed in `data_plane.rs` ~2248–2420: the
  `OutboundAction::{PassThrough,Rewrite,Abort}` pipeline (~2413) and the
  `cache_pending.store(..)` path (~2248–2277). Both must sit behind the
  `ResponseMode::Streaming` bypass branch (Phase 3).
- **§11.2 connection-pool exhaustion** — confirmed. Upstream client is
  `hyper_util::client::legacy::Client` (`forward.rs:316`) built with
  `pool_max_idle_per_host` + `pool_idle_timeout` — bounds **idle** conns
  only. An active stream pins a checked-out conn for its lifetime →
  unbounded under N concurrent streams. `streaming.max_concurrent`
  semaphore (decision 5) is required, with the idle timeout as backstop.
- **§11.3 idle-timeout body wrapper** — no in-repo precedent (`admin_sse`
  has `StreamBody` but no idle timer). Built first as a standalone,
  TDD'd primitive: `upstream/idle_timeout.rs` (`IdleTimeoutBody<B>`),
  decoupled from the `Full`→`DataBody` migration. Resets the deadline on
  every inner frame; ends the stream (`Poll::Ready(None)`) on silence.
- **§11.4 `Full<Bytes>` footprint** — 190 refs in `aegis-proxy/src`
  (plan said 191 — accurate). Top data-plane sites: `data_plane.rs` (41),
  `responses.rs` (12), `proxy.rs` (11), `cors.rs` (8), `forward.rs` (8).
  The high-count admin files (`admin_mutate.rs` 52, `admin_dispatch.rs`
  15, `admin_login/get` 11 each) are the **admin plane** — out of scope;
  migration is the data path only. `admin_sse::into_boxed` already
  provides the `Response<Full<Bytes>> -> Response<UnsyncBoxBody<..>>`
  helper Phase 1 needs.
- **§11.5 classify-once carrier** — confirmed greenfield: no
  `event-stream`/`Content-Type` streaming decision exists in `forward.rs`
  or `data_plane.rs` today (the `forward.rs:16` doc comment notes
  streaming is future). `forward()` will be the sole classifier, so the
  decision 2a "classify once, ride the DecisionTag" rule starts clean.

**Phase-1 gate: SATISFIED.** Buffering site (`forward.rs:567` collect,
`:614` re-emit), `handle_data_request` → `Response<Full<Bytes>>`
(`data_plane.rs:110`), and `forward_allow_to_upstream` (`:1501`) all
confirmed. Next: land the idle-timeout primitive, then the outside-in
body migration.

## 11. Pre-code verification checklist (do FIRST — highest production-bug odds)

- [ ] **`response_filter` interaction** — map every site that consumes the
      buffered body (`data_plane.rs` ~2400-2470: `OutboundAction`, `cache.store`)
      and confirm the streaming bypass covers all of them.
- [ ] **Connection-pool exhaustion** — confirm `hyper_util` legacy `Client`
      behaviour with a never-completing body: does the conn stay checked out?
      does `pool_idle_timeout` apply? Decide the `max_concurrent` default + the
      exhaustion fallback.
- [ ] **Timeout-wrapper implementation** — prototype the idle-timeout `Body`
      wrapper; verify it resets on raw data frames and fires on silence; verify
      it cancels cleanly (no leaked task) when the client disconnects.
- [ ] **Every `Response<Full<Bytes>>` assumption** — enumerate before migrating:
      `handle_data_request`, `forward`, `forward_allow_to_upstream`,
      `stamp_interop_response`, error/block builders, helpers, trait bounds,
      tests.
- [ ] **`ResponseMode` carrier (classify-once, decision 2a)** — confirm
      `forward()` is the *only* site that consults `Content-Type` for the
      streaming decision; that the mode rides the `DecisionTag` to the
      filter-bypass, audit, and metrics sites; and grep that no later phase
      re-parses `Content-Type` to re-derive "is streaming".

## 12. Complexity

**Medium-High**, ~13–20 h (revised up from 11–18 h after the pool-cap +
explicit-bypass + richer-timeout additions). Phase 1 is the bulk; the
verification checklist (§11) front-loads the production-risk areas.
