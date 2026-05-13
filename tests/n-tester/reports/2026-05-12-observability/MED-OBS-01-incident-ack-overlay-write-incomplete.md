---
id: 2026-05-12-incident-ack-overlay-write-incomplete
date: 2026-05-12T07:18Z
severity: MEDIUM
area: dashboard · admin-api
component: incidents · lifecycle-overlay
status: open
test_mode: full-qc
---

# Incident Ack POST returns 200 + green toast — overlay GET shape is now in place but `acked_at` / `acked_by` never populate (partial regression on MED-SO-04 fix)

## Summary

The previous sprint's PR-MED-SRV (`1181c09`) added the incidents
overlay store + shaped `/api/incidents` response so the dashboard
can render lifecycle state (acked / snoozed / resolved). The GET
side ships:

```json
{
  "id": "DataPlaneAvailability:1778570234",
  "severity": "page",
  "window_hours": 1,
  "fired_at": "2026-05-12T07:17:14.311218Z",
  "status": "firing",
  "acked_at": null,
  "acked_by": null,
  "note": null,
  "snoozed_until": null,
  "resolved_at": null,
  "burn_rate": 999.99,
  "budget_consumed_pct": 99999.99,
  "runbook_url": "https://runbooks.aegis.local/slo/DataPlaneAvailability/1h"
}
```

Excellent shape. But the ack POST path doesn't actually write to
the overlay:

1. Click `Ack` on row 1 of Incidents.
2. Dashboard POSTs to
   `/api/incidents/DataPlaneAvailability-1h%3A1778570234/ack`.
3. Server returns **200**.
4. Dashboard renders green toast: **"Incident ack ok"**.
5. Dashboard refetches `/api/incidents` — the same incident comes
   back with `acked_at: null`, `acked_by: null`, `status:
   "firing"`. **No state transition recorded.**
6. The Audit Trail page DOES capture the action — there's an
   `incident_ack` row with `operator acknowledged incident` —
   so the chain emit is wired, just not the overlay store write.

So MED-SO-04 is half-fixed: read path works, write path doesn't.
Same operator-visible symptom as before (green toast, no UI
transition).

There's also a related ID-format mismatch: the GET response gives
each incident `id: "DataPlaneAvailability:<ts>"` (no window in
the id). The dashboard constructs the ack URL with the window
embedded: `DataPlaneAvailability-1h:<ts>`. The server accepts
that synthesized id (returns 200), but if the overlay store
looks up by the bare GET id (`DataPlaneAvailability:<ts>`) then
the synthesized id won't match — and the overlay never writes.

## Repro

```js
// Console on the dashboard (after firing test traffic so alerts fire):
const before = await (await fetch("/api/incidents", {credentials:"include"})).json();
before.incidents[0]
// → { id: "DataPlaneAvailability:1778570234", status: "firing",
//     acked_at: null, acked_by: null, ... }

// Click the Ack button on row 1, then:
const after = await (await fetch("/api/incidents", {credentials:"include"})).json();
after.incidents[0]
// → SAME shape — acked_at: null, acked_by: null, status: "firing"
```

Network panel reveals:
```
POST /api/incidents/DataPlaneAvailability-1h:1778570234/ack
→ 200 OK   (no response body inspected, presumably {ok: true})
```

But:
```
GET /api/audit/since?limit=3
→ event[0]: { action: "incident_ack", reason: "operator
   acknowledged incident", fields: {...} }
```

So the audit chain is honest; the overlay store is the gap.

## Expected

After Ack POST returns 200:
- `/api/incidents.incidents[0].acked_at` becomes a timestamp.
- `acked_by` becomes "admin".
- `status` becomes `"acknowledged"`.
- Dashboard rerenders the row as ACKED with `Snooze`/`Resolve`
  visible, `Ack` button gone.
- The Acknowledged KPI card up top increments from 0 → 1.

Same shape for snooze (`snoozed_until` populates) and resolve
(`resolved_at` populates + row moves out of the "open" filter).

## Actual

Audit chain captures; overlay store doesn't write; UI doesn't
transition. The green toast is technically dishonest (it claims
success but the operator-visible state is unchanged).

## Suggested fix

Two things to verify in the server code:

1. **ID lookup mismatch.** In
   `crates/aegis-control/src/api/incidents.rs`, the ack handler
   route is likely `/api/incidents/{id}/ack`. Check that the `id`
   path-param the server parses from
   `DataPlaneAvailability-1h:1778570234` matches the key the
   overlay store indexes on (the GET shape suggests it stores by
   `DataPlaneAvailability:<ts>` only). Fix: either embed the
   window in the stored key (so GET also returns
   `DataPlaneAvailability-1h:<ts>`), or strip the window from the
   incoming ack URL before lookup.

2. **Actual overlay write.** If the lookup matches but the
   overlay value never updates, the handler may be emitting the
   audit event without calling `overlay_store.upsert(id,
   IncidentOverlay { acked_by: actor, acked_at: now(), ... })`.
   Add the upsert call between the audit-emit and the response.

Both fixes are small and live in `incidents.rs`. ~30 min server
+ tests.

The dashboard side is already wired correctly — once the GET
returns a row with `acked_at` populated, the page transitions
the row automatically (no JSX changes required, same shape as
the existing access-list / mode overlays).

## Severity rationale

MEDIUM. The Audit chain captures the mutation (so forensics
work), and the alert is still visible to the operator (so no
"silently missed an alert" failure). But:

- This is a *regression* against the previous sprint's claim
  that PR-MED-SRV closed MED-SO-04. The QA verdict shipped
  yesterday assumed the server-side overlay write was complete.
- Operators will lose trust in the Ack affordance the second
  time they click it and see no UI change — exactly the failure
  mode MED-SO-04 documented.
- The fix is small and lives entirely in one file.

