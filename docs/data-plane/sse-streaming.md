# SSE / streaming responses (stream-through)

> **Status:** Implemented — `aegis-proxy/src/upstream/streaming.rs`,
> `upstream/idle_timeout.rs`, `upstream/forward.rs`, `data_plane.rs`;
> config in `aegis-core/src/config.rs` (`StreamingConfig`).
>
> Plan + decisions: [`../../plans/archive/sse-streaming-support.md`](../../plans/archive/sse-streaming-support.md).

## Purpose

Proxy `text/event-stream` (Server-Sent Events) — and any other
operator-allowlisted media type — to clients **incrementally**: events
are flushed as they arrive, the stream stays open indefinitely, and there
is no buffer-until-cap. Normal (non-streaming) responses are unchanged:
buffered, size-capped, and response-body-inspected.

Before this, the data plane buffered the **entire** upstream body before
emitting anything (`forward()` → `Limited::collect()`), so an open-ended
SSE stream hit the 30 s `response_body_read_timeout` and the client got a
truncated/error response instead of a live stream.

WebSocket (`proto/ws_forward.rs`) and gRPC paths are separate and
unaffected.

## How a response is classified

Classification happens **exactly once**, in `forward()`, the moment the
upstream response headers arrive. The response `Content-Type` is matched
against the `streaming.content_types` allowlist by **media-type essence**
— the `type/subtype` only, parameters and whitespace stripped, compared
case-insensitively — so both of these stream:

```
Content-Type: text/event-stream
Content-Type: text/event-stream; charset=utf-8
```

while `text/event-streamx`, `text/html`, a missing `Content-Type`, or an
empty allowlist all **buffer**. The result is a `ResponseMode`
(`Buffered | Streaming`) returned alongside the response; every later
stage reads that carried value and **never re-parses `Content-Type`**, so
the decision can't drift between layers.

## Security posture — header-inspected only

A streamed response is **header-inspected only**:

- Request-side inspection (detector chain, rules, risk gate) runs in full,
  as always.
- Response **headers** are inspected and hop-by-hop / `Connection`-listed
  headers are stripped, as always.
- The response **body is not buffered or inspected**: the response-filter
  pipeline (`OutboundAction`) **and** the response cache are bypassed for
  streamed responses (a stream can't be re-read or cached). The bypass is
  keyed on the carried `ResponseMode`, not re-derived.

This is a deliberate, documented trade-off (incremental chunk-by-chunk
inspection is a future option — see below). Every streamed response is
audited with explicit fields so the reason is never silent:

```jsonc
{
  "streamed": true,
  "response_inspection_skipped": true,
  "reason": "streaming"
}
```

(emitted on the listener audit event; derived from `DecisionTag.streamed`).

## Idle (inactivity) timeout — not a whole-body deadline

The buffered whole-body read deadline would kill any long-lived stream, so
streamed responses instead use an **inactivity** timeout
(`streaming.idle_timeout`, default 5 min): the deadline **resets on every
frame** the upstream produces. SSE heartbeats — comment frames
(`:keepalive\n\n`) or `event: ping` every 15–30 s — are data frames and
keep the stream alive. Only true silence past the deadline ends the stream
(gracefully, releasing the pinned upstream connection). An inner body
error is folded into a clean end-of-stream (logged for forensics).

## Concurrency cap

Each live stream pins an upstream connection for its **entire lifetime**,
which the hyper client pool (which bounds *idle* connections only) does
**not** cap — so N concurrent streams pin N connections, unbounded.
`streaming.max_concurrent` (default 256) is a WAF-level semaphore: a
permit is acquired before committing to stream and rides the response
body, releasing on stream end / error / client disconnect.

On exhaustion, `streaming.on_exhaustion` decides:

| value | behaviour |
|---|---|
| `reject` (default) | shed the new stream with `503` and drop the upstream response, releasing its connection immediately |
| `buffer` | handle it as a normal buffered response (subject to the buffered read deadline + size cap) |

## Configuration

```yaml
streaming:
  enabled: true                          # kill-switch; false ⇒ always buffer
  content_types: ["text/event-stream"]   # allowlist (media-type essence, case-insensitive)
  idle_timeout: 300s                      # inactivity timeout (resets on every frame)
  max_duration: null                      # optional absolute lifetime cap (none by default)
  max_concurrent: 256                     # live-stream semaphore (pinned-connection bound)
  on_exhaustion: reject                   # reject (503) | buffer
```

All fields default as shown; an absent `streaming:` block yields exactly
these defaults (enabled for `text/event-stream`).

## Metrics

| Metric | Type | Meaning |
|---|---|---|
| `aegis_responses_streamed_total` | counter | responses streamed (vs buffered) |
| `aegis_active_streams` | gauge | currently-live streams (watch vs `max_concurrent`) |
| `aegis_stream_duration_seconds` | histogram | per-stream lifetime |
| `aegis_stream_bytes_sent` | histogram | bytes delivered per stream |

The gauge and histograms are driven by a metrics guard that rides each
streamed body and records on drop, so a leaked/runaway stream shows up as
a stuck `aegis_active_streams` and a long-tail duration.

## Future — incremental inspection (Option C, deferred)

The ideal end state is chunk-by-chunk response inspection
(`chunk → inspect → forward`) so streamed bodies aren't a blind spot. It's
deliberately deferred: several current detectors need the whole body to
decide. Until then, streamed responses remain header-inspected only, with
the explicit audit trail above.
