---
id: 2026-05-12-investigation-zero-detections
date: 2026-05-12T00:17Z
severity: MEDIUM
area: dashboard
component: investigation · detector-breakdown card
status: open
test_mode: full-qc
---

# Investigation page's "Detector breakdown" card reports "0 detections · last 1h" while the same window's `/api/attacks/by-detector` returns 50+ rows

## Summary

The Investigation page renders a "Detector breakdown" card with a
"last 1h" window label. After driving 100 attack requests
(detection-positive) in the last minute, the card still says:

```
0 detections · last 1h
No detections in the last hour. Drive traffic with `make mock-load-attacks`.
```

Same call against `/api/attacks/by-detector?window=3600` returns:

```json
{
  "detectors": [
    {"name":"recon_path","count":42},
    {"name":"sqli","count":16},
    {"name":"path_traversal","count":14},
    {"name":"xss","count":14},
    {"name":"open_redirect","count":7},
    {"name":"ssrf","count":7}
  ]
}
```

So the data is there. The card is either reading the wrong
endpoint or filtering the response to nothing.

## Repro

1. Drive synthetic attack traffic via X-Forwarded-For from a
   second tab (or `make mock-load-attacks`).
2. Navigate to `#/investigation` (without a pivot — the card
   should populate from the global detector counter).
3. Detector breakdown shows `0 detections · last 1h`.
4. In the console:
   ```js
   await (await fetch("/api/attacks/by-detector?window=3600",
                      {credentials:"include"})).json()
   // → 50+ detector rows
   ```

Same card on the **Overview** page ("Attack distribution") does
the right thing — same window, same API surface, populates with
the donut and the row counts. So this is specifically the
Investigation card's read path.

## Expected

The card pulls from the same `/api/attacks/by-detector` (or its
moral equivalent in the audit ring) and renders the same rows
the Overview page shows. Same window selector.

## Actual

Always-zero. The empty-state copy is helpful in fresh-boot but
becomes misleading when the WAF is busy.

## Suggested fix

Grep the Investigation page component for the detector card; the
fix is either (a) point it at `/api/attacks/by-detector`, or (b)
read from `/api/audit/since` and aggregate by `fields.detectors[]`
client-side. (a) is cheaper.

If the card is meant to filter by pivot, it should say so in the
empty-state copy ("No detections in the last 1h for `pivot`").

## Severity rationale

MEDIUM. The Detector-breakdown card is one of two top-of-page
visualisations on Investigation. With it permanently empty, the
page feels broken even when it's just one card not wired right.

