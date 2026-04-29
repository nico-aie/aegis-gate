# Milestone D-M3 — Operator Views

> **Status:** Closed — D-M3 shipped.
>
> See [`README.md`](../README.md) for the track status board.

**Goal.** Live Feed, Attack Events, Audit Log, and Analytics pages
fully wired to backing data.

**Crate touched.** `aegis-control`.
**Verification.** `cargo test -p aegis-control && cargo clippy -p aegis-control -- -D warnings`.

**References.**
- [`docs/control-plane/enterprise/pages/live-feed.md`](../../docs/control-plane/enterprise/pages/live-feed.md)
- [`docs/control-plane/enterprise/pages/attack-events.md`](../../docs/control-plane/enterprise/pages/attack-events.md)
- [`docs/control-plane/enterprise/pages/audit-log.md`](../../docs/control-plane/enterprise/pages/audit-log.md)
- [`docs/control-plane/enterprise/pages/analytics.md`](../../docs/control-plane/enterprise/pages/analytics.md)

---

## New endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/audit/{request_id}` | Single event detail |
| GET | `/api/audit/since?cursor=&limit=` | Replay-after-reconnect |
| GET | `/api/audit/{id}/sinks` | Per-sink delivery status |
| GET | `/api/audit/witness` | Last witness signature + lag |
| GET | `/api/filters` | Active class/actor/route sets |
| GET | `/api/attacks/by-detector?window=` | Detector breakdown |
| GET | `/api/threat-intel/hits?window=&limit=` | Threat-intel hits |
| GET | `/api/bots/mix?window=` | Bot classification mix |
| GET | `/api/analytics/query?expr=&start=&end=&step=` | Allow-listed PromQL proxy |

## Tasks

### D-M3-T3.1 Live Feed page

- File: `assets/dashboard/pages/live.js`
- SSE consumer with pause/resume; row append batched to
  `requestAnimationFrame`.
- Filter strip + drawer wiring (drawer component completed
  here).
- Server filter: `/dashboard/sse?class=&action=&route=` (extend
  the existing SSE handler in `src/dashboard/sse.rs` to honor
  query params; predicate runs server-side before push).
- Test: SSE handler test feeds 1000 events, asserts predicate
  filters them. Drawer test asserts `/api/audit/{id}` returns
  the expected event.

### D-M3-T3.2 Live Feed reconnect / replay

- File: `src/api/audit.rs`
- `/api/audit/since?cursor=` returns events after the given
  monotonic sequence number. Backed by the existing audit
  spool reader.
- Test: write 50 events, fetch since cursor 30, assert 20
  returned in order.

### D-M3-T3.3 Attack Events page

- File: `assets/dashboard/pages/attacks.js`
- Wires detector breakdown bar chart, top firing rules table,
  threat-intel hits table, bot mix stacked bar, recent
  detections live tail (reuses the Live Feed SSE component
  with a fixed `class=detection` filter).

### D-M3-T3.4 Detector breakdown endpoint

- File: `src/api/attacks.rs`
- `/api/attacks/by-detector` extends the in-memory aggregator
  added in D-M2 to expose per-detector totals.

### D-M3-T3.5 Threat-intel hits endpoint

- File: `src/api/attacks.rs`
- Reads from the existing threat-intel store
  (`aegis-security::threat_intel`). Joins with rolling counts
  from the audit subscriber.
- Test: with a known threat-intel match, assert hit count.

### D-M3-T3.6 Bot mix endpoint

- File: `src/api/attacks.rs`
- Buckets by the existing bot classifier categories
  (`verified|suspect|malicious|unknown`). Source: audit event
  `fields.bot_category` if present.

### D-M3-T3.7 Audit Log page

- File: `assets/dashboard/pages/audit.js`
- Filter strip, paged table (cursor pagination from existing
  `/api/audit`), chain status pill, witness lag pill,
  export-NDJSON button.

### D-M3-T3.8 Witness lag endpoint

- File: `src/api/audit.rs`
- `/api/audit/witness` reads from the existing `witness.rs`
  state machine: returns last signature timestamp and lag
  seconds.
- Test: with a known last-witness time, assert lag math.

### D-M3-T3.9 Filter catalogue endpoint

- File: `src/api/filters.rs`
- `/api/filters` returns the union of classes, actors, actions,
  and route ids seen in the rolling 24h. Cheap O(1) reads from
  the audit subscriber's distinct-set.

### D-M3-T3.10 Analytics page

- File: `assets/dashboard/pages/analytics.js`
- Six chart cards as described in [`pages/analytics.md`](../../docs/control-plane/enterprise/pages/analytics.md).
- Time-range selector; on change, all cards refetch.

### D-M3-T3.11 Analytics PromQL proxy

- File: `src/api/analytics.rs`
- `expr` parameter is **not** raw PromQL — it's a key from a
  fixed allow-list (see [`api.md` §allow-list](../../docs/control-plane/enterprise/api.md#analytics)).
- Resolves the key to PromQL, calls the local prometheus
  registry's text encoder for instantaneous queries, or — for
  range queries — buckets the metrics on the fly from the
  in-process histogram.
- For range queries, falls back to a configured external
  Prometheus URL if `admin.prometheus_url` is set; otherwise
  returns 503 with `{ error.code: "no_history_backend" }`.
- Test: each allow-listed key returns a parseable response
  shape; unknown key returns 400.

## Exit gate

- All four pages render real data; SSE reconnect+replay works
  end-to-end.
- Audit chain pill flips correctly when the chain is artificially
  tampered (covered by an integration test that writes a bad
  spool line and asserts the pill turns red).
- Analytics page returns valid responses for all six allow-listed
  keys against an in-memory registry (no external Prometheus
  required for tests).

## Implement-Progress.md update

```
## Last Completed
- Task: D-M3 Operator views (Live Feed, Attack Events, Audit, Analytics)
- Crate: aegis-control
- Status: DONE

## Next Task
- Task: D-M4-T4.1 Rule Manager page
- Plan: plans/dashboard-enterprise/milestone-4-config-management.md
```
