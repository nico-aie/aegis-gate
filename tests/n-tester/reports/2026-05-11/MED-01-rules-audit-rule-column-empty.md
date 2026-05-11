---
id: 2026-05-11-audit-rule-column-empty
date: 2026-05-11T17:18Z
severity: MEDIUM
area: dashboard
component: audit-trail
status: open
test_mode: full-qc
---

# Audit Trail RULE column shows `—` even for `rule_create` / `rule_disable` rows

## Summary

The Audit Trail table renders a `RULE` column header, but the cell
is `—` for the very events that carry a rule_id (`rule_create`,
`rule_disable`, etc.). The deep-link filter (`?rule_id=...`) does
work — F-03 fix verified — but the resulting page's data view
doesn't display the rule_id it just filtered on. Operators land
there, see no rule_id anywhere on the rows, and have to read the
URL bar to confirm the filter is active.

## Repro

1. Sign in, **Rules** → **+ New rule**, create `qa-test-rule-001`.
2. Click the rule, **Stats** tab, click "Open Audit Log filtered by
   rule_id=qa-test-rule-001 →".
3. Lands on `#/audit?rule_id=qa-test-rule-001`. Filter input is
   pre-populated correctly.
4. Observe the `RULE` column for the `rule_create` row: `—`.

## Expected

The cell shows `qa-test-rule-001` (or at minimum a chip / mono
text that matches the active filter), so the operator's eye can
match URL → filter input → row.

## Actual

`—`. Same on the `BLACKLIST_ADD` row that also carries a rule_id
in `fields.resource`. The data is present in the API response —
just not surfaced in the column.

```bash
curl -s -b cookie.jar "http://127.0.0.1:9443/api/audit/since?limit=3" \
  | jq '.events[] | {action, rule_id, fields_resource: .fields.resource}'
# action: "rule_create", rule_id: null, fields_resource: "/api/rules"
# (the rule_id sits inside fields.diff.after.rules.<id>)
```

So the underlying issue is that the `rule_id` lives inside the
diff payload, not at the event's top level. The dashboard reads
the top-level field that isn't populated for admin mutations.

## Suggested fix

Two options:

1. **Cheap**: server-side — copy `rule_id` to the top-level field
   when the action is `rule_*`. Same for `route_id` on `route_*`,
   `pool` on `pool_*`. ~10 lines in the audit emitter.

2. **Better**: dashboard-side — when the action prefix is `rule_*`,
   extract the rule_id from `fields.diff.after.rules` (the first
   key) or from `fields.resource` parsed as `/api/rules/<id>`.
   Render that in the column. Doesn't require a server change.

Pick (2) so the audit JSON schema doesn't change.

## Severity rationale

MEDIUM because the workflow is the SOC investigation flow (S3 in
the skill's scenario list) and the missing column data is a real
friction point — the analyst can't visually scan a list of rule
events. But the data is in the response and the filter works, so
the workflow is not blocked.

