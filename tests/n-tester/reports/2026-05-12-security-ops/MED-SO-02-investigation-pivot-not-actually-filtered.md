---
id: 2026-05-12-investigation-pivot-not-filtered
date: 2026-05-12T00:18Z
severity: MEDIUM
area: dashboard
component: investigation
status: open
test_mode: full-qc
---

# Investigation page pivot input doesn't actually filter the KPI cards or the Audit timeline table — only the "Attacker context" card honors the pivot

## Summary

The Investigation page's whole purpose is "Pivot from any IP /
request_id / rule_id into the full WAF context". The UI accepts a
pivot, the URL reflects the pivot
(`#/investigation?pivot=104.21.14.6&kind=ip`), and one card
("Attacker context") actually reads the pivot's per-attacker data
from `/api/attacks/top`.

But the four KPI cards at the top and the Audit timeline table at
the bottom show aggregate data over the audit ring as a whole.
The caption "**N matching this pivot**" under the Events card is
the smoking gun — when pivoting on a single IP that has 12 hits,
the card shows `Events 200 · matching this pivot`. 200 is the
audit-ring capacity, not the pivot's hit count.

## Repro

1. Drive synthetic traffic so the audit ring is populated (this
   run: 100 attacks + 40 legit from 14 source IPs).
2. Click **Top Attackers**, click `Pivot` on the row for
   `104.21.14.6` (US, 12 hits).
3. URL updates to `#/investigation?pivot=104.21.14.6&kind=ip`.
4. **Attacker context** card correctly shows `Hits: 12 · Country:
   US · ASN: 13335 · Risk: 100 · Categories: …` ✓
5. **Events** KPI card shows `200 · matching this pivot` — wrong;
   should be `12`.
6. **Unique IPs** KPI card shows `11` — wrong; should be `1`.
7. **Top action** shows `BLOCK 142 of 200` — wrong; should be
   `BLOCK 12 of 12` (the attacker is blocked on every hit).
8. **Audit timeline** table at the bottom lists rows from many
   different IPs (`127.0.0.1`, `5.195.235.51`, `185.220.101.5`,
   etc.) — the pivot IP appears in the list but the table is not
   filtered.

## Expected

The four KPI cards and the Audit timeline table both honor the
pivot. When the pivot is an IP, the table filters to events with
`client_ip == pivot`. When the pivot is a `request_id`, the
table filters to the one matching row. When the pivot is a
`rule_id`, the table filters to events with that rule_id.

The caption underneath each KPI card should match the data it
reports.

## Actual

Pivot only drives the Attacker context card. KPI cards + Audit
timeline read straight from `/api/audit/since` with no
client-side or server-side filter applied.

## Suggested fix

Two-step:

1. **Client-side filter** (smaller, ship today): in the
   Investigation page component, after fetching
   `/api/audit/since`, filter the resulting events array by the
   pivot before rendering the KPI cards + the table. ~20 LoC.

2. **Server-side filter** (bigger, ship next sprint): add
   `client_ip` / `request_id` / `rule_id` query params to
   `/api/audit/since` so the server returns just the matching
   rows. Lets the page work on audit-ring overflow (>200 events).
   The dashboard then drops the client filter and passes the
   pivot as query params.

For the first cut do option 1. Add the
`extractResourceId(event)` helper from the previous sprint's
MED-01 fix to also drive the table filter (so `rule_id` pivots
match events where the rule ID is buried in `fields.resource` /
`fields.diff`).

## Severity rationale

MEDIUM. The page mounts, has a sensible URL, and the Attacker
context card answers half the "what did this attacker do"
question. But:

- The KPI cards are **actively misleading** — "200 matching this
  pivot" trains the operator to distrust the surface.
- The Audit timeline table is the SOC analyst's primary view of
  "what did this IP touch?" — without the filter it's just a
  raw audit log they could've gotten from `#/audit`. The pivot
  becomes vestigial.

Score-wise this is S3 going from 5 → 3 in the SOC scenario rubric.

