# Live feed ignores the Cluster-nodes scope selector — no node filter or badge on fleet-merged SSE

**Status:** 🟢 P1–P3 shipped (TDD, `fix/live-feed-node-scope`, 2026-07-02)

Implementation notes vs. plan:
- Canonical origin accessor landed in `aegis-core::audit`
  (`ORIGIN_NODE_FIELD` + `AuditEvent::origin_node()`); `fleet_events`
  refactored onto it (write side stays there).
- Backfill discovery: `/api/audit/since` has no node param, but fleet-merge
  rows carry a SECOND stamp — `fields.node_id` (ring-ingest, F10) — so the
  backfill is filtered client-side on that; SSE is filtered server-side.
  Row attribution reads `origin_node || node_id`.
- Single-node (no roster): a `node=` scope matches only stamped events —
  excluded, not guessed (test-pinned).
**Date:** 2026-07-02
**Severity:** Low–Medium (agreed with report — UX/scope-clarity only; no data-integrity issue. The feed is *more* inclusive than selected, never less.)
**Reported repro:** cluster mode → dashboard → pick one node in the Cluster-nodes selector → Live feed still streams all nodes' requests. ✅ plausible from code.

---

## Report verification (checked against `develop`, 2026-07-02)

| Report claim | Verdict |
|---|---|
| Live feed ignores the node scope selector | ✅ **Confirmed.** The scope store (`fleetScopeStore`, `data.jsx:318`) is applied only by `useApiScoped` (`data.jsx:342`), which appends `?node=` to REST URLs. The SSE hook opens `new EventSource('/dashboard/sse')` with no scope (`data.jsx:560`) and never subscribes to the store — switching nodes re-scopes every REST panel but not the feed. |
| `AuditEvent` has no node/origin field | ✅ True as a **first-class field** (`aegis-core/src/audit.rs:186-235`) — but see next row. |
| "…so fleet-merged SSE events **can't be attributed** or filtered by node" | ❌ **Wrong on attribution.** The fleet publisher stamps every cross-node event with `fields.origin_node` before PUBLISH (`aegis-proxy/src/fleet_events.rs:43`, `stamp_origin`) — the module doc says explicitly it "lets … the dashboard label which node a row came from". The attribution is already on the wire and already reaches the browser (the SSE JSON includes `fields`; the row mapper reads `ev.fields` for other columns). The dashboard just never renders or filters on it. Local rows carry no `origin_node` (implicit "this node") — that absence is itself load-bearing (echo-drop guard). |
| `EventFilter::parse_query` recognizes only class/action/route | ✅ **Confirmed** (`aegis-control/src/dashboard/sse.rs:36`; test `parse_query_recognises_documented_keys` covers exactly `class/action/route`). |
| Frontend opens `/dashboard/sse` with no `?node=` | ✅ **Confirmed** (`data.jsx:560`). |
| Fix: "Add an origin field to `AuditEvent`" | ⚠️ **Recommend against.** `fleet_events.rs:17-25` documents the deliberate decision NOT to add a field: `AuditEvent` has ~128 construction sites, and the loop/echo guard is structural (publisher reads only the local bus) + `fields.origin_node` for the Redis self-echo drop. Adding `node_id: Option<String>` would churn every constructor for data that `fields` already carries. The right fix builds on `fields.origin_node`. |

Additional facts that shape the fix:

- The fleet publisher is **rate-capped** (`max_publish_rate_per_s`,
  `fleet_events.rs:61-68`) and lossy by design — a node-scoped view of a
  **remote** node is best-effort sampling, not that node's full feed. The UI
  copy must say so (the complete feed lives on that node's own console;
  `?node=` deep-links exist for that).
- The SSE handler already threads an `EventFilter` through both the local and
  fleet arms of the merged stream (`admin_sse.rs:64-160`), so a `node` filter
  key naturally applies to both.
- The self node id needs to reach `EventFilter::event_matches` — local events
  have no `origin_node`, so "scoped to self" must match `origin absent OR
  origin == self`. Node id is available at wiring time (the same
  `our_node` accept.rs passes to `spawn_fleet_publisher`).

## Fix plan

### P1 — backend: `node` filter key on the SSE stream

1. `EventFilter` (dashboard/sse.rs): add `node: Option<String>` parsed from
   `?node=<id>` (single value; absent = no node filtering, today's behavior).
2. `event_matches`: when the filter has a node,
   `effective_origin(ev) == node`, where `effective_origin` =
   `fields.origin_node` if present, else the **self node id**. Plumb the self
   id into the filter (field set at construction: `EventFilter::with_self_node`),
   wired from the same node-identity accept.rs already holds.
3. No `AuditEvent` schema change; no publisher change (remote events are
   already stamped). Reuse/move the `origin_of` helper so sse.rs and
   fleet_events.rs share one accessor (it currently lives in fleet_events.rs
   as a private fn).

### P2 — frontend: scope the stream + per-row attribution

1. `useSse` (data.jsx): subscribe to `fleetScopeStore`; when scope ≠ 'all',
   open `/dashboard/sse?node=<id>` and re-open the EventSource on scope
   change ('all' = no param, unchanged). Mirrors `useApiScoped` semantics.
2. Row mapper: surface `node: f.origin_node || null` on each row.
3. Live feed page: in cluster mode (fleet nodes > 1), render a per-row node
   badge — `origin_node` for remote rows, "this node" style for local rows —
   and a feed-header scope label: **fleet-wide** when 'all' (matching the
   scope-clarity badge pattern from the SCOPE-P1 work), **node: X** when
   scoped.
4. When scoped to a **remote** node, show the lossiness hint: remote events
   are rate-capped samples; open that node's console (`?node=` deep-link)
   for its complete feed.

### P3 — tests + docs

- `dashboard/sse.rs`: parse test (`node=` recognized, absent = None);
  match tests: remote event matches its origin, local event (no
  `origin_node`) matches only the self node, scoped-out events dropped from
  BOTH arms of the merged stream.
- `docs/operations/ha-clustering.md` (live-feed / fleet-events section):
  document node scoping, local-rows-have-no-origin semantics, and the
  rate-cap caveat for remote-scoped views.
- Dashboard rebuild (`build.sh`) — no runtime JSX tests exist; manual pass
  per the repro.

### Alternative (report's own fallback) — NOT recommended alone

Badge + "fleet-wide" label without filtering would make the exclusion
explicit but leaves the selector half-lying (every other panel scopes, the
feed doesn't). The full fix is small because attribution already exists;
P1+P2 is the right scope.

## Estimated complexity: LOW-MEDIUM
- P1 ~2h (filter + plumbing + tests) · P2 ~2-3h (reconnect-on-scope + badge) · P3 ~1h
