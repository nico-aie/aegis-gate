# Page — Live Feed

> Real-time stream of audit events with filtering. The richer
> successor to the current single-screen event tail.

## Route

`GET /dashboard/live`

## Data sources

| Widget | Source |
|--------|--------|
| Event stream | SSE from `/dashboard/sse` (existing) |
| Event detail drawer | `GET /api/audit/{request_id}` (new) |
| Filter dropdowns | `GET /api/filters` (new — returns the active set of tiers, classes, actions, routes) |

## Layout

```
┌────────────────────────────────────────────────────────────────┐
│ Live Feed                                            [Pause]   │
│ Real-time decisions arriving over SSE                          │
├────────────────────────────────────────────────────────────────┤
│ Filter:  [Tier▾] [Class▾] [Decision▾] [Route▾] [search…]      │
├────────────────────────────────────────────────────────────────┤
│ TS    │ Class    │ Action │ Reason         │ Route   │ IP     │
│ ───── │ ──────── │ ────── │ ────────────── │ ─────── │ ────── │
│ … rows ↓                                                       │
└────────────────────────────────────────────────────────────────┘
```

- Header has a Pause toggle that stops the SSE handler from
  appending. Buffer continues filling up to 500 events server-side;
  a "23 new events" banner appears when paused.
- Filter strip: each dropdown is a multi-select chip group.
  The text search filters by `request_id`, `client_ip`, or `reason`
  via client-side string match (no server round-trip).
- Table virtualizes after 200 rows; oldest scrolls out at 1000.

## Row anatomy

```
16:40:30.413  detection  block   sqli signature 042   /api/login   1.2.3.4
              ^pill      ^pill   ^body                ^link        ^IP link
```

- Class pill colour from
  [`../theme.md`](../theme.md): `detection`=err,
  `admin`=warn, `system`=info, `access`=ok.
- Action pill: `block`/`challenge`/`allow`/`audit`.
- Click row → opens right-side drawer with the full
  `AuditEvent` JSON, plus a "Copy as cURL" of the original request
  if the event includes the captured request line.
- Right-click row (or kebab) → "Block this IP", "Whitelist this
  IP", "Open in Attack Events".

## Drawer

- 480px wide overlay on the right.
- Sections: Summary (action + reason + risk score), Network
  (client IP, ASN, geo, JA4 fingerprint, XFF chain), Request
  (method, host, path, headers — secrets redacted), Detection
  (rule id, signature, evidence excerpt), Audit (request_id,
  chain hash prev → next, sink delivery status).
- Footer: actions matching the row kebab menu.

## Connection management

- `/dashboard/sse` reconnects with exponential backoff (1s, 2s,
  5s, 10s, capped) on close. Status pill in the page header
  shows `Connected` (ok) / `Reconnecting…` (warn) / `Offline` (err).
- Server keeps a per-session ring buffer (last 500 events) so a
  reconnect can replay missed events. New endpoint
  `GET /api/audit/since?cursor=<seq>` returns the gap.

## Filter logic

Client-side filters apply to the rolling window. Server-side
filters propagate as SSE event-stream selectors via query
parameters: `/dashboard/sse?class=detection&action=block`. The
server applies the same predicate before pushing.

## Performance

- Each SSE message is < 1KB. At 1000 ev/s the bandwidth is ~1MB/s
  per dashboard tab — acceptable.
- Row append is batched at 60Hz (one `requestAnimationFrame` per
  paint) to avoid layout-thrash on bursty traffic.
- Virtualization: only the visible viewport rows are in the DOM
  (use a small in-house windowing helper, no library).

## Edge cases

- SSE disabled by network policy → fallback to long-poll on
  `/api/audit/since` (1s interval). Auto-detected when SSE close
  fires within 100ms three times in a row.
- Clock skew: timestamps are server-side; the client never adds
  `Date.now()`.
