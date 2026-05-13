---
id: 2026-05-13-stale-incident-overlay-fallback-copy
date: 2026-05-13T09:30Z
severity: LOW
area: dashboard
component: incidents · toast copy
status: open
test_mode: full-qc
---

# Stale "lifecycle UI pending (server overlay not yet wired)" fallback copy in pages.jsx

## Summary

`crates/aegis-control/assets/dashboard/src/pages.jsx:8273`
carries an `else`-branch fallback toast string:

```js
: `${action} recorded to audit chain · lifecycle UI pending
   (server overlay not yet wired)`;
```

This was introduced as a stop-gap when MED-SO-04 (incident
overlay lifecycle) was first being investigated. Now that
MED-ADM-01 (`cadd01b` — percent-decode in admin_dispatch) closed
the round-trip, the overlay store reliably reflects the post-ack
state and the dashboard never falls into the `else` branch.

## Repro

Grep the source:

```bash
grep -n "lifecycle UI pending" crates/aegis-control/assets/dashboard/src/pages.jsx
# 8273:  : `${action} recorded to audit chain · lifecycle UI pending (server overlay not yet wired)`;
```

The wrapping ternary checks whether the API response carries
the new state. After MED-ADM-01 shipped, every ack/snooze/
resolve POST returns 200 + the dashboard refetch surfaces
`acked_at` / `snoozed_until` / `resolved_at`. The fallback
toast never fires.

Verified by clicking Ack on row 1 in this run — toast read
"Incident ack ok" (the success path), not the fallback.

## Expected

Delete the `else` branch or simplify the ternary to the success
case. The audit chain captures the mutation regardless; the
toast copy doesn't need to hedge.

## Actual

Dead string still in source. No operator-visible effect today.

## Suggested fix

```diff
- const msg = r.status === 200 && r.ok && r.incident
-   ? `Incident ${action} ok`
-   : `${action} recorded to audit chain · lifecycle UI pending (server overlay not yet wired)`;
+ const msg = r.status === 200 && r.ok
+   ? `Incident ${action} ok`
+   : `Incident ${action} failed: ${r.message || r.reason || 'unknown error'}`;
```

The new fallback handles the genuine failure case (server
returns non-200) with an honest error message instead of
implying the overlay isn't wired.

## Severity rationale

LOW. Dead-code-shaped but operator-invisible. Tidy this up in
the next dashboard polish PR.

