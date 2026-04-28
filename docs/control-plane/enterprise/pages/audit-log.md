# Page — Audit Log

> Searchable view of the audit hash chain with verification status.
> Backed by `/api/audit*` (already implemented for v1) plus a few
> small read-only additions.

## Route

`GET /dashboard/audit`

## Data sources

| Widget | Source | Notes |
|--------|--------|-------|
| Filter strip | `GET /api/filters` | Returns class/actor/action sets |
| Result table | `GET /api/audit?since=&until=&class=&actor=&q=&limit=&cursor=` | Cursor pagination |
| Chain status pill | `GET /api/audit/verify?from=&to=` | Cached 30s |
| Detail drawer | `GET /api/audit/{request_id}` | Same as Live Feed |
| Witness status | `GET /api/audit/witness` | Last witness sig timestamp + lag |

## Layout

```
┌──────────────────────────────────────────────────────────────┐
│ Audit Log         Chain: [VERIFIED]  Witness: 12s ago        │
├──────────────────────────────────────────────────────────────┤
│ [time range] [class▾] [actor▾] [search…]    [Verify] [Export]│
├──────────────────────────────────────────────────────────────┤
│ TS · Class · Actor · Action · Target · Reason · Hash         │
│ … rows ↓                                                     │
└──────────────────────────────────────────────────────────────┘
```

- Chain pill: green `VERIFIED`, red `BROKEN at line N` with link
  to the offending event.
- Witness pill: green if `lag < witness_alert_threshold`
  (configurable), amber otherwise.
- `Verify` button: triggers a fresh chain walk via
  `/api/audit/verify` and updates the pill.
- `Export`: streams NDJSON of the current filtered set.

## Filter strip

- Time range: presets (1h, 24h, 7d, 30d) + custom range picker.
- Class multi-select: `Detection`, `Admin`, `System`, `Access`.
- Actor multi-select: known actors (`admin`, `system`,
  `gitops`, etc.).
- Search box: matches `request_id`, `client_ip`, `target` (case-
  insensitive substring on the server side).

## Result table

- Columns: TS · Class · Actor · Action · Target · Reason · Hash.
- Hash column shows the first 12 chars of the chain hash with a
  copy-to-clipboard hover button. Click expands to the full 64
  chars in a popover.
- Row click opens detail drawer (same as Live Feed).
- Cursor pagination: 100 rows per page, `Load more` button.

## Detail drawer

- Includes "Chain context": the previous and next event hashes
  with status pills, so the operator can see continuity at a
  glance.
- "Sink delivery" sub-section enumerates each configured SIEM
  sink and whether this event was acknowledged. Source:
  `GET /api/audit/{id}/sinks`.

## Erasure (GDPR)

- A small "GDPR" tab in the page exposes the existing
  `POST /api/gdpr/erase` flow with a confirm modal that requires
  the operator to type the `subject_id` to enable the button.
- After erasure, the row is replaced by an `[erased]` placeholder
  with `erased_at` timestamp.

## Performance

- Server caches verify results for 30s. A fresh verify walk over
  1M events is ~1.5s on warm disk; the cache absorbs UI traffic.
- Export uses chunked transfer-encoding NDJSON; the client streams
  to disk via `<a download>` blob URL with a Service-Worker-free
  fetch.
