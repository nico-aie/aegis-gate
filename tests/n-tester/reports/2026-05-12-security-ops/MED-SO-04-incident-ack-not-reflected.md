---
id: 2026-05-12-incident-ack-not-reflected
date: 2026-05-12T00:15Z
severity: MEDIUM
area: dashboard · admin-api
component: incidents lifecycle
status: open
test_mode: full-qc
---

# Incident `Ack` POST returns 200 + green toast "Incident ack ok" — but the row stays FIRING and `/api/incidents.incidents` stays empty

## Summary

The Incidents page exposes `Ack` / `Snooze 15m` / `Resolve`
buttons per firing alert. Clicking `Ack` makes the dashboard:

1. POST to the ack endpoint.
2. Get a 200 / `{ok: true}` back.
3. Render a green toast: **"Incident ack ok"**.

But:

- The same row still renders **FIRING** with an unstruck-through
  `Ack` button.
- `/api/incidents.incidents` is still `[]` (the dashboard reads
  raw alerts from `raw_alerts.firing`).
- The KPI cards still read `Firing 3 · Acknowledged 0` — the
  ack didn't transition the state.

So the operator clicks Ack, gets confirmation it landed, and
visually nothing changes. They'll either click it again
(generating audit noise) or assume the UI is just slow and walk
away believing the page-or-ticket is ack'd when in fact the state
machine never moved.

This is a state-machine seam — the ack-mutation endpoint
persists *something* server-side (the audit log shows it,
matched by an `INCIDENT_ACK` line on the Investigation Action
breakdown) but `/api/incidents` doesn't surface that overlay
back. The dashboard then has nothing to render.

## Repro

1. Drive enough traffic that SLO alerts start firing
   (`DataPlaneAvailability-*` works on a fresh dev boot since the
   stub-pool 502s reduce availability).
2. Navigate to **Incidents**. Click `Ack` on row 1.
3. Toast bottom-right: "Incident ack ok" (green).
4. Look at row 1: STATUS still FIRING. `Ack` button still
   rendered.
5. In the console:
   ```js
   const i = await (await fetch("/api/incidents", {credentials:"include"})).json();
   i.incidents.length    // 0 — no overlay
   i.raw_alerts.firing.length  // 3 — unchanged
   ```
6. Navigate to **Investigation**, scroll to "Action breakdown" —
   one `INCIDENT_ACK` line is recorded (0.5% of audit ring). So
   the audit chain saw the ack; the live state didn't transition.

## Expected

The ack mutation should produce a row in
`/api/incidents.incidents` with shape:

```json
{
  "alert_name": "DataPlaneAvailability-1h",
  "state": "acknowledged",
  "acked_by": "admin",
  "acked_at": "2026-05-12T00:14:00Z",
  "note": null,
  "snoozed_until": null,
  "resolved_at": null
}
```

The page joins `raw_alerts.firing` with `incidents` (by name) so
the row renders STATUS=ACKED, ACKED BY=admin, with `Snooze` /
`Resolve` becoming the actionable buttons and `Ack` going away.

Same shape for `snooze` (set `snoozed_until`) and `resolve` (set
`resolved_at`, drop from the open filter).

## Actual

Audit chain records the action. Page state machine is stub.

## Suggested fix

This is a server-side gap. The ack handler needs to write to an
"incidents overlay" store (in-memory + audit-chained, like the
existing access-list / blacklist overlays). `/api/incidents`
joins the overlay onto `raw_alerts.firing` and returns the
combined view.

Until that lands, the toast should NOT claim success — it should
say something like *"Ack recorded to audit chain (lifecycle UI
pending)"*, with a warn pill. The current green-toast-on-no-op is
the operator-confusing part.

Effort: server-side ~1 day, dashboard ~30 min. As a stop-gap, the
dashboard could optimistic-update the row (paint it grey / show
"acked by you") even if the API doesn't reflect — that's worse
than a real fix but better than the green-toast-no-op.

## Severity rationale

MEDIUM. The audit chain captures the ack (so forensics work), and
the alert is still visible to the operator (so no "we silently
missed an alert" failure). But:

- Operators will lose trust in the "Ack" affordance after the
  first time they see no UI change.
- The lifecycle UI ("which alerts are still firing vs. ack'd vs.
  snoozed") is what makes Incidents pages useful at scale.

