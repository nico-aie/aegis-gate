# Console fixups — `CQF-T*`

> **Status:** ✅ HIGH + MEDIUM bucket complete (2026-05-02).
> 16 of 19 slices shipped. Three LOW slices deferred to a
> future track:
>
> - CQF-T17 (per-member drain on Upstreams) — needs a new
>   backend endpoint + per-member ready/not-ready state model
> - CQF-T18 (Latency / per-route placeholder labels) — pending
>   the Prometheus aggregator follow-up identified in run-12
> - CQF-T19 (per-rule stats tab) — needs backend per-rule hit
>   counter
>
> Round-2 verification report:
> `tests/results/run-cqa-round2-20260502/README.md`
>
> Track ID prefix `CQF-T<n>`. Two-day sprint to flip every
> Fail / Partial slice in the CQA pass to Pass.
>
> Backend is healthy (41/41 read APIs green, CSRF gate working,
> `/api/config/version` increments correctly, audit chain
> captures every mutation). All work in this track is
> **front-end** — wiring missing onClicks, replacing hardcoded
> JSX clusters with live data, adding the obvious missing
> mutation forms.

---

## 0 · Scope

Eight HIGH issues + nine MEDIUM + five LOW from the CQA
sprint backlog. Listed in execution order; each slice is
independently shippable + reviewable.

## 1 · HIGH — Round-1 risk if shown to OC

### CQF-T1 — TopBar logout button (~30 min) [F-T13-LOGOUT]

- New button in `app.jsx::TopBar` that POSTs `/admin/logout`
  with the CSRF header, clears the local cookie jar, and
  redirects to `/admin/login`.
- Reuse existing `process_admin_logout` handler — already
  returns 204 + clears both cookies.
- Acceptance: clicking lands operator on the login page;
  any subsequent mutation returns 403 (CSRF rejected
  because cookies cleared).

### CQF-T2 — Blacklist + Whitelist CRUD (~1 hr) [F-T9-CRUD]

- New audit-mutated endpoints if they don't already exist:
  `POST /api/{blacklist,whitelist}` + `DELETE
  /api/{blacklist,whitelist}/{ip}`.
- Wire "Add entry" form on `ListPage` (currently no
  `onClick`).
- Per-row Delete button.
- Acceptance: add → row appears; delete → row gone; both
  land in audit chain with action `blacklist_add` /
  `blacklist_remove` (or whitelist counterparts).

### CQF-T3 — Tier Config detector mask UI (~1.5 hr) [F-T7-MASK]

- Add Edit / Save form on `PageTierConfig` mapping each tier
  (low / med / high / critical / catch_all) to its mask
  state.
- The PUT endpoint exists (`PUT /api/detectors`,
  `handle_detectors_put` in `admin_mutate.rs`) — UI just
  doesn't call it yet.
- Acceptance: toggling a detector for a tier round-trips
  through the audit-mutated PUT and surfaces the new mask
  state on `GET /api/detectors`.

### CQF-T4 — Overview "Block" button + Live Feed drawer
actions (~45 min) [F-T1-NOOP, F-T2-DRAWER]

- Top Attackers row "Block" button → `POST /api/blacklist`
  (lands via CQF-T2).
- Drawer "Block IP" → same as above.
- Drawer "Copy as cURL" → clipboard copy of a reproducible
  curl (URL + relevant headers), no API call.
- Drawer "Whitelist" → `POST /api/whitelist`.
- Acceptance: each click produces a toast + the audit
  chain shows the mutation.

### CQF-T5 — RequestDetail live data (~1 hr) [F-T1-DETAIL]

- 8 fields (ASN, JA4, xff chain, request_id, chain_hash,
  sinks list, etc.) currently hardcoded in JSX.
- Replace with a `useApi('/api/audit/since?request_id=...')`
  lookup by clicked event's `request_id`. The
  endpoint already returns the matching audit-chain entry.
- Acceptance: clicking different events surfaces different
  values; nothing static between clicks.

### CQF-T6 — RiskHeatmap live rows (~45 min) [F-T1-HEAT]

- 8 rows hardcoded in JSX. Source the rows from
  `/api/attacks/by-detector` or add a new
  `/api/risk/heatmap` if a different aggregation is needed.
- Acceptance: rows reflect actual detector activity over
  the configured window.

### CQF-T7 — Settings cache card decision (~30 min) [F-T10-CACHE]

- The card shows 6 hardcoded demo stats and the per-cache
  Flush buttons are no-op.
- Decision (default: **remove**): we don't ship a
  query-cache layer in M1; the card is aspirational. Drop it
  from the page.
- Alternative: wire flush buttons to the existing
  `POST /__waf_control/flush_cache` endpoint and source
  stats from `/api/stats` cache section.
- Acceptance: either no card, or every stat is live + each
  Flush click drives the endpoint.

## 2 · MEDIUM — visible polish

### CQF-T8 — Risk-threshold sliders (~30 min) [F-T10-RISK]

- Sliders on Settings page render but don't PUT.
  `PUT /api/risk/thresholds` is already shipped via
  `handle_risk_thresholds_put` (CI-T12).
- Wire onChange → debounced PUT or onBlur PUT with
  optimistic update + toast.

### CQF-T9 — Sidebar footer wiring (~15 min) [F-T13-FOOTER]

- Replace hardcoded BUILD / UPTIME strings with
  `/api/about` values (`build_id` / `started_at`).

### CQF-T10 — Notifications bell (~30 min) [F-T13-BELL]

- Either remove the bell or wire it to `/api/alerts`
  (count of unacked alerts as the badge; click opens
  Tracking page filtered to firing alerts).
- Default: wire to `/api/alerts.unacked.length`; clicking
  sets `location.hash = '#/tracking'`.

### CQF-T11 — Audit Log filter + verify + paginate (~1 hr)
[F-T5-FILTER, F-T5-VERIFY, F-T5-LOAD]

- Time-range chip group (1 h / 24 h / 7 d / custom) →
  passes `since=` to `/api/audit/since`.
- "Verify chain" button → `POST /api/audit/verify` (add
  the endpoint if missing; it just walks the in-memory
  ring and checks `prev_hash` linkage).
- Replace hard `limit=200` with paged load-more.

### CQF-T12 — Defensive guards (~15 min) [F-T3-NPE]

- `malicious.pct.toFixed(1)` → `(malicious.pct ?? 0).toFixed(1)`.
- Audit other `toFixed`/`toLocaleString` calls for the same
  pattern.

### CQF-T13 — `useAlertReceiversApi` code smell (~5 min) [F-T11-SMELL]

- One-line change in `data.jsx`:
  `window.useApi('/api/alert-receivers', ...)` →
  `useApi('/api/alert-receivers', ...)`.

### CQF-T14 — TopBar drain button (~30 min) [F-T12-DRAIN]

- Plan §1.2 mentions one; not present today.
- Two-step confirm + POST `/admin/drain`.
- Surface the same toast pattern as the existing one on
  the Scaling page (single source of truth helper).

## 3 · LOW — dust

### CQF-T15 — Stop exporting Math.random simulation helpers (~10 min) [F-T14-EXPORTS]

- `useLiveFeed` + `useTrafficSeries` still
  `Object.assign(window, ...)` exported. They use
  `Math.random` for fake-data simulation; nothing in
  pages.jsx calls them anymore. Remove from the export
  list.

### CQF-T16 — Per-rule hits1h preserved (~10 min) [F-T6-HITS1H]

- The Rules adapter discards backend `hits1h` value when
  rendering the table.

### CQF-T17 — Per-member drain on Upstreams (~30 min) [F-T8-MEMBER-DRAIN]

### CQF-T18 — Latency / per-route placeholder labels (later) [F-T4-PLACEHOLDER]

### CQF-T19 — Per-rule stats tab (later) [F-T6-STATS]

## 4 · Sequencing

```
Day 1: T1 → T2 → T3 → T4 → T8 → T9    (~4 h)
Day 2: T5 → T6 → T7 → T11 → T13 → T10 (~3 h)
Tail:  T12 → T14 → T15..T17           (~1 h)
```

## 5 · Definition of Done

- [ ] All HIGH (T1..T7) shipped + live-verified by re-running
      the CQA harness.
- [ ] CQA round-2 flips every Fail / Partial → Pass.
- [ ] Mock-data audit (CQA-T14) shows zero hardcoded JSX
      clusters in render paths.
- [ ] No unintentional `onClick={() => {}}` stubs anywhere.
- [ ] `Implement-Progress.md` § Last Completed entry follows
      § 0.3 protocol.
