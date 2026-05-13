---
id: 2026-05-12-method-path-rule-columns-empty
date: 2026-05-12T00:19Z
severity: MEDIUM
area: dashboard
component: investigation audit-timeline · live-feed table (partial)
status: open
test_mode: full-qc
---

# Investigation Audit timeline table renders METHOD as `—`, PATH as `/`, and RULE_ID as `—` on every detection row, even when the API carries the right values

## Summary

The Investigation page's "Audit timeline" table has columns TS /
ACTION / IP / METHOD / PATH / RULE_ID. For every detection row
the table renders:

- **METHOD** = `—` (real: `GET`)
- **PATH** = `/` (real: `/.env`, `/?q=<script>...`, etc.)
- **RULE_ID** = `—` (real: detectors like `recon_path`,
  combination `ssrf,open_redirect`, etc.)

The data is right there in `/api/audit/since` — the same endpoint
the Live Feed page reads from. Live Feed renders these columns
correctly. So the Investigation table is reading the wrong field
paths.

## Repro

1. Drive synthetic attacks (`make mock-load-attacks` or curl-with-XFF).
2. Navigate to `#/investigation`. Scroll to the Audit timeline.
3. Observe every detection row's METHOD / PATH / RULE_ID columns
   show `—`, `/`, `—`.
4. Compare with Live Feed: same rows render `GET`, `/.env`,
   `recon_path (score: 100)` correctly.
5. In the console:
   ```js
   const a = await (await fetch("/api/audit/since?limit=5",
                                  {credentials:"include"})).json();
   a.events[0].fields
   // → { method: "GET", path: "/.env", status: 403,
   //     detectors: ["recon_path"], rule_id: null, ... }
   ```

## Expected

Investigation Audit timeline reads `event.fields.method`,
`event.fields.path`, and either `event.rule_id` (top level) or
`event.fields.detectors[]` joined as a comma-list (mirroring
Live Feed). PATH wraps to one line; long paths get truncated
with a tooltip.

## Actual

Columns read placeholder fields. Operators get less context from
Investigation than from Live Feed — the opposite of what the
two-page split intends.

## Suggested fix

Same `extractResourceId(event)` helper introduced in the previous
sprint's MED-01 fix should drive RULE_ID resolution. METHOD /
PATH read straight from `event.fields.{method,path}` with a
fallback to the placeholders.

If the placeholders are deliberate (e.g. for non-request events
like `rule_create`), gate them on `event.class === "detection"`
vs. `"admin"`.

## Severity rationale

MEDIUM. The page mounts and the rows are countable, but the
columns the operator scans to triage are unused. Bumps S3 ("what
did this attacker do?") score down.

