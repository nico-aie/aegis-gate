---
id: 2026-05-03-unknown-detector-bucket-leaks-allows
date: 2026-05-03T16:10Z
severity: MEDIUM
area: control-plane
component: api/attacks/by-detector + AttacksHandler
status: open
build_sha: cb95934
test_mode: smoke
---

# `/api/attacks/by-detector` includes an `unknown` bucket that mirrors allow-traffic counts

## Summary

`/api/attacks/by-detector?window=300` returns an `unknown`
bucket whose count exactly matches the number of allow-class
events in the same window.  Looks like the aggregator falls
through to `"unknown"` whenever an audit event has no
`fields.detectors[]` array — which is true for every allowed
request — and surfaces those alongside real detector hits.

The Investigation page's "Detector breakdown" card then shows
`unknown` as the largest category, which obscures the real
detector activity (sqli/xss/etc) in the chart.

## Repro

```bash
DURATION=20 bash skills/aegis-waf-tester/scripts/drive-traffic.sh
# 146 requests, ~50 % allow + ~50 % attack:
curl -s -b /tmp/aegis-skill.jar \
  "http://127.0.0.1:9443/api/attacks/by-detector?window=300" | jq
```

## Expected

`/api/attacks/by-detector` reports counts for *detector firings*
only — i.e. the union of `fields.detectors[]` across detection-
class events.  Allowed requests don't contribute (they didn't
fire any detector by definition).

## Actual

```jsonc
{
  "detectors": [
    { "name": "unknown", "count": 68 },     // ≈ allow count
    { "name": "detector:sqli", "count": 25 },
    { "name": "detector:path", "count": 24 },
    { "name": "detector:recon", "count": 19 }
  ]
}
```

The 68 in `unknown` mirrors the legit-traffic events count from
the same audit window.

## Suggested fix

Aggregator should filter `class == "detection"` (or
`!fields.detectors.is_empty()`) before group-by.  Bare
`"unknown"` should not exist in the output — if a detection
event genuinely has no detector list (which would be a bug
elsewhere), it deserves a louder label than `unknown`.

## Severity rationale

MEDIUM — display-only.  The Detector-breakdown card on
Investigation is meant to answer "what's hitting me right now",
not "how much traffic flowed at all".  An "unknown" bucket
absorbing allow-traffic makes the card lie.

## Done-when

`/api/attacks/by-detector` returns no `unknown` row under
realistic mixed traffic.  The Investigation page's bar list
shows real detector classes only.
