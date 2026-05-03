---
id: 2026-05-03-attacker-categories-prefix-and-truncation
date: 2026-05-03T16:10Z
severity: MEDIUM
area: control-plane
component: api/attacks/top + api/attacks/by-detector
status: open
build_sha: cb95934
test_mode: smoke
---

# Attacker / by-detector category names use `detector:<name>` prefix and truncate `path_traversal` to `path`

## Summary

Two related label inconsistencies between the audit chain and
the Top-Attackers / by-detector aggregator:

1. **Prefix mismatch** — the audit `fields.detectors` array
   carries bare class names (`"sqli"`, `"path_traversal"`,
   `"recon"`).  The aggregator outputs them prefixed:
   `"detector:sqli"`, `"detector:path"`, `"detector:recon"`.
2. **Truncation** — `path_traversal` is rendered as just
   `path` in the prefixed form.  Either the prefix logic
   splits on underscore + takes the head, or there's a
   separate truncation step.

The dashboard's Top-Attackers and Investigation pages print
these labels directly to the operator.  The current shape
reads as obscure-internals rather than human-friendly UX
("you were attacked by `detector:path`" — what's `:path`?).

## Repro

```bash
make run-dev
DURATION=20 bash skills/aegis-waf-tester/scripts/drive-traffic.sh
sleep 2

# Audit shows bare class names:
curl -s -b /tmp/aegis-skill.jar \
  "http://127.0.0.1:9443/api/audit/since?limit=200" \
  | jq '[.events[] | select(.action == "block") | .fields.detectors[]?] | unique'

# Aggregators show prefixed + truncated:
curl -s -b /tmp/aegis-skill.jar \
  "http://127.0.0.1:9443/api/attacks/by-detector?window=300" | jq
```

## Expected

Both surfaces use the same labels.  Either:
- Audit emits `"detector:sqli"` everywhere and the aggregator
  echoes it (unlikely — bare `sqli` is the established shape),
- OR the aggregator drops the `detector:` prefix and emits
  the full class name (`path_traversal` not `path`).

The dashboard render should match — operators see one
canonical label per detector class.

## Actual

```jsonc
// Audit emits bare class names:
[ "sqli", "path_traversal", "recon", "xss" ]

// Aggregator prefixes + truncates:
{
  "detectors": [
    { "name": "detector:sqli",   "count": 25 },
    { "name": "detector:path",   "count": 24 },   // ← truncated
    { "name": "detector:recon",  "count": 19 },
    { "name": "unknown",         "count": 68 }
  ]
}
```

The `unknown` bucket is itself questionable — see finding #04.

## Suggested fix

Find the aggregator that builds the category strings — likely
`crates/aegis-control/src/api/attacks.rs` near where it
group-bys detector hits.  Change to emit the bare class name
that lands in `fields.detectors[]`.  Drop the `detector:`
prefix; restore full names like `path_traversal`.

## Severity rationale

MEDIUM — not load-bearing on functionality (the data is there,
just labelled confusingly), but it surfaces directly to SOC
operators on the page they look at first thing each morning.
Lower priority than the GeoIP / bot-mix HIGHs.

## Done-when

`/api/attacks/by-detector` and `/api/attacks/top.attackers[].categories`
return the same string that audit `fields.detectors[]` emits —
no prefix, no truncation.
