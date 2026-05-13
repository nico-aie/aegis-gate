---
id: 2026-05-12-incident-ack-overlay-round-trip-still-broken
date: 2026-05-12T08:30Z
severity: MEDIUM
area: admin-api
component: incidents · lifecycle-overlay
status: open
test_mode: full-qc
---

# MED-OBS-01 partially-fixed: `alert_id` format now aligns (commit e6b307c) but the overlay write→read round-trip still doesn't close

## Summary

The previous-sprint MED-OBS-01 finding pointed at an ID-format
mismatch between the server's `alert_id()` and the dashboard's
synthesized ack URL. Commit `e6b307c` (fix(incidents): alert_id
includes window_hours so ack overlay write lands) addresses
exactly that — `/api/incidents.incidents[].id` is now
`DataPlaneAvailability-1h:1778574385` (with window embedded), and
the dashboard's POST URL `/api/incidents/<id>/ack` matches the
same key the server uses.

But the overlay round-trip still doesn't close:

1. Hard-reload the dashboard (`Cmd+Shift+R`).
2. Click `Ack` on row 1 of Incidents.
3. Dashboard POSTs to
   `/api/incidents/DataPlaneAvailability-1h%3A1778574385/ack`.
4. Server returns **200**.
5. Toast: "Incident ack ok" (green).
6. Dashboard refetches `/api/incidents`. Row 1 still has
   `status: "firing"`, `acked_by: null`, `acked_at: null`.
7. The Acknowledged KPI card up top stays at `0`.
8. The Audit Trail captures `INCIDENT_ACK` rows (visible in
   the chain — `Settings` → `Config history` #61 + #62 + the
   Audit Trail page). So the chain emit works; the overlay
   store value isn't being read back.

The alert_id format alignment was a necessary but not sufficient
fix. There's a second layer of mismatch somewhere — likely the
ack handler writes to one map keyed by `alert_id` while the
enrich() / GET handler reads from a different map (or reads the
right map but with a stale key cache).

## Repro

```js
// Console on the dashboard, after firing test traffic:
const before = await (await fetch("/api/incidents", {credentials:"include"})).json();
before.incidents[0]
// { id: "DataPlaneAvailability-1h:1778574385", status: "firing",
//   acked_by: null, acked_at: null, ... }

// Click Ack on the row, then:
const after = await (await fetch("/api/incidents", {credentials:"include"})).json();
after.incidents[0]
// SAME: acked_by:null, acked_at:null, status:"firing"
```

Network panel:

```
POST /api/incidents/DataPlaneAvailability-1h:1778574385/ack → 200
```

(URL-encoded as `%3A`. The POST URL key matches the GET response
id exactly.)

Audit Trail / Config history shows the action did emit:

```
#62  May 12, 12:28:45 PM  INCIDENT_ACK  admin  DASHBOARD  ▶
                          operator acknowledged incident
#61  May 12, 12:27:00 PM  INCIDENT_ACK  admin  DASHBOARD  ▶
                          operator acknowledged incident
```

So the audit chain side is honest. The overlay store is the gap.

## Expected

After the POST returns 200, the next GET shows:

```json
{
  "id": "DataPlaneAvailability-1h:1778574385",
  "status": "acknowledged",
  "acked_by": "admin",
  "acked_at": "2026-05-12T08:30:00Z",
  ...
}
```

The dashboard rerenders the row as ACKED with `Snooze` + `Resolve`
as the actionable buttons (Ack disappears). The `Acknowledged`
KPI card increments from 0 → 1.

## Actual

Round-trip silently fails. Audit chain captures the mutation;
overlay store doesn't surface it.

## Suggested fix

Trace through `crates/aegis-control/src/api/incidents.rs`:

1. The ack handler (likely
   `pub async fn ack_incident(...)`) — confirm it actually calls
   `overlay_store.upsert(alert_id, IncidentOverlay { acked_by,
   acked_at, ... })` rather than just emitting the audit event.
2. The `enrich(&self, alert: &SloAlert) -> Incident` function —
   confirm it calls `overlay_store.get(&alert_id(alert))` and
   merges the result into the returned `Incident`.
3. Add a regression test:
   ```rust
   #[tokio::test]
   async fn ack_then_enrich_returns_acknowledged_status() {
       let store = IncidentOverlay::default();
       let alert = sample_alert("DataPlaneAvailability", 1);
       let id = alert_id(&alert);
       store.ack(&id, "admin", chrono::Utc::now()).await.unwrap();
       let inc = store.enrich(&alert).await;
       assert_eq!(inc.status, "acknowledged");
       assert_eq!(inc.acked_by, Some("admin".into()));
   }
   ```
   This test would have caught both the format-mismatch from
   MED-OBS-01 and whatever residual issue is causing MED-ADM-01.

Likely candidates for the residual issue:
- Two different overlay stores (one for ack, one for enrich) —
  the previous fix may have changed the format on one side but
  not the other.
- The overlay store IS shared but uses `.entry()` with a default
  that overwrites the ack — race or stale-entry insertion.
- `enrich()` builds the `id` from a slightly different field
  ordering (e.g. uses raw `Debug` of the SLI enum, while ack
  takes the already-formatted URL param).

## Severity rationale

MEDIUM (same as MED-OBS-01). The audit chain is honest, the WAF
itself is unaffected, and the operator can still cross-reference
acks via the chain. But the dashboard's primary incident-
management workflow (ack a noisy alert so it stops showing up in
the open queue) is still broken across two sprints.

The third repro of the same operator-visible failure mode is
exactly the test-gap a `ack_then_enrich` regression test would
have closed. Recommend shipping that test along with whichever
patch closes the round-trip.

