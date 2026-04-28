# M2 — Live Feed

> **Status.** seed
>
> **Effort.** ~4 days
>
> **Depends on.** M0 (foundations + chrome) + M1 only for
> the visual reference (Live Feed inherits Overview's bar).
>
> **Why this milestone is second.** SSE + filter chips +
> drawer flow is the hardest interaction model in the
> dashboard. De-risk it here so M3 (Attack Events) and M4
> (Audit Log) can copy from a known-good pattern.

## Inputs

- Design contract: [`docs/control-plane/enterprise/pages/live-feed.md`](../../../docs/control-plane/enterprise/pages/live-feed.md)
- API endpoints used:
  - `GET /dashboard/sse` — Server-Sent Events stream
  - `GET /api/audit/since?cursor=N&limit=200` — reconnect
    backfill
  - `GET /api/filters` — populates the filter-chip
    autocomplete with currently-seen classes / actors /
    routes
- Components reused from M0: `table` (in streaming mode),
  `drawer`, `badge`, `skeleton`, `toast`
- New components introduced: **`filter-chip-bar`** — a
  composable chip bar with type-ahead autocomplete that
  feeds the table's filter predicate. Adds one component;
  reusable on M3 + M4.

## User goals

1. **Watch.** See requests stream past in real time, with
   the most recent at the top, without reflowing the visible
   rows when new ones arrive.
2. **Pin and inspect.** Click any row → drawer slides in
   with the full event JSON, hash-chain status, and a
   "show in audit page" deep link. The stream pauses while
   the drawer is open.
3. **Filter without losing state.** Add `class:detection
   actor:203.0.113.7` chips → the visible stream filters in
   place, the SSE channel keeps running, removing chips
   restores the unfiltered view instantly (no refetch).

## Scope

### In

- SSE auto-reconnect with `Last-Event-ID` style cursor
  using `/api/audit/since`. Status pill ("connected" /
  "reconnecting" / "disconnected") is the existing one in
  the M0 status bar — Live Feed reads it, doesn't own it.
- Filter chip bar above the table. Three chip types:
  `class:`, `actor:`, `route:`. Multiple chips compose with
  AND.
- Streaming table:
  - Sticky header with column sort hints (sort applies to
    the *current visible buffer*, not the underlying SSE
    order — make this explicit with a "sorted view —
    streaming paused below" affordance).
  - Virtual rows once buffer exceeds 500.
  - Keyboard nav: ↑↓ select row, Enter opens drawer,
    `f` focuses chip bar, `p` pauses/resumes the stream.
- Drawer for the selected row: full event JSON pretty-
  printed (`diff` component reused for nested-object
  display), chain hash, "view in /audit" deep link.
- Pause / resume stream button. When paused, new events
  count in a badge ("**12 new** since pause"). Click =
  flush + resume.
- Stale-data state: when the SSE channel is disconnected
  and the backfill cursor is more than `?cursor` 60 s
  behind, surface a banner *above* the table: "Stream
  reconnecting; events from <ts> may be missing — last
  cursor at <N>". Operator can dismiss; banner re-appears
  if the gap widens.

### Out

- Saved-filter presets (defer to M3 — Attack Events has the
  same filter bar; presets land there once we know which
  ones operators actually use).
- Multi-select on rows (defer to M4 — Audit Log is where
  bulk operations make sense, e.g. CSV export).
- Cross-column free-text search (Cmd+K is the project's
  global search affordance — Live Feed doesn't get one).

## Acceptance

- Stream sustains 200 events/s without reflowing the
  visible viewport (only the buffer at the top extends).
- Reconnect after a 5 s network blip restores the cursor
  position with zero visible "jump" — the only signal is
  the status pill briefly flipping.
- Drawer opens in < 100 ms, traps focus, ESC closes.
- Filter chip change re-renders only the table body; the
  chip bar and drawer keep state.
- Page module < 32 KB raw. The new `filter-chip-bar`
  component < 8 KB raw.
- Both themes pass screenshot review at 1280 / 1440 / 1920
  with the drawer open and ≥3 chips active.
- Playwright spec under `tests/e2e/dashboard/live-feed.spec.ts`:
  open page → wait for SSE → add filter chip → click row →
  drawer opens → verify chain hash present.

## Layout sketch

```
┌─────────────────────────────────────────────────────────────────┐
│  Live Feed             [class:detection ✕] [actor:1.2.3.4 ✕] +  │
├─────────────────────────────────────────────────────────────────┤
│ ts            class      action  actor          rule    score   │
│ 14:02:11.421  detection  block   203.0.113.7    sqli-1   95  →  │
│ 14:02:11.401  detection  block   203.0.113.7    sqli-1   95  →  │
│ 14:02:10.987  admin      update  admin          —         —  →  │
│ …                                                                │
├─────────────────────────────────────────────────────────────────┤
│  ▶ pause     stream connected     buffered: 1842    cursor: 42k │
└─────────────────────────────────────────────────────────────────┘
                                      ┌──────────────────────────┐
                                      │  Event detail            │
                                      │  ts:    14:02:11.421Z    │
                                      │  class: detection        │
                                      │  reason: blocked by      │
                                      │     detectors: sqli (95) │
                                      │  fields: { … }           │
                                      │  chain: 9f4c…  ✓ verify  │
                                      │                          │
                                      │  → Open in Audit Log     │
                                      └──────────────────────────┘
```

## Open questions

- **Buffer cap.** What's the max in-memory buffer before
  oldest rows get dropped? Default proposal: 5 000. Above
  that, "older events available — open Audit Log" affordance.
- **Sort while streaming.** The brief should resolve
  whether sorting auto-pauses the stream. Default: yes,
  sort = pause; toolbar shows "sorted — paused".
- **Drawer ↔ URL.** Deep-linking via `?event=<seq>` so a
  link can open the drawer pre-filled. Confirm with the
  audit page (M4) so they share the URL grammar.

## Out-of-scope drift log

(Empty until work begins.)
