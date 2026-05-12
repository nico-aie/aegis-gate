---
id: 2026-05-12-incidents-columns-not-mapped
date: 2026-05-12T00:14Z
severity: MEDIUM
area: dashboard
component: incidents
status: open
test_mode: full-qc
---

# Incidents table renders SLI as "unknown" and FIRED / BUDGET / ACKED BY / NOTE as `—` for every row, even when the API provides the data

## Summary

The Incidents page table has columns STATUS / SEVERITY / SLI /
FIRED / BUDGET / ACKED BY / NOTE / ACTIONS. For the three
DataPlaneAvailability alerts firing on a freshly-driven WAF:

- **SLI** column shows the literal string `unknown` for all 3
  rows — but the underlying alert names are
  `DataPlaneAvailability-1h`, `DataPlaneAvailability-6h`,
  `DataPlaneAvailability-72h`. The SLI name is right there in
  `/api/alerts.firing[].name`.
- **FIRED** column shows `—` for all 3 rows — but the API
  provides `since: 2026-05-12T00:02:48.563504Z` for each alert.
- **BUDGET** column shows `—` for all 3 — the SLO definitions
  have an explicit window (1h / 6h / 72h) baked into the alert
  name; the budget the page could show is "9.36 of 10 minutes
  remaining in the 1h window" etc.
- **ACKED BY** column shows `—` — fine when no ack has happened.
- **NOTE** column shows `—` — fine for new alerts.

## Repro

```js
// In the dashboard console:
const a = await (await fetch("/api/incidents", {credentials:"include"})).json();
a.raw_alerts.firing[0]
// → { name: "DataPlaneAvailability-1h",
//     severity: "page",
//     since: "2026-05-12T00:02:48.563504Z",
//     runbook_url: "https://runbooks.aegis.local/slo/DataPlaneAvailability/1h",
//     receivers: [] }
```

Compare to what the page renders for the same row:

| STATUS | SEVERITY | SLI | FIRED | BUDGET | ACKED BY | NOTE |
|---|---|---|---|---|---|---|
| FIRING | PAGE | unknown | — | — | — | — |

## Expected

- **SLI** column: parse `alert.name` as `<sli>-<window>`. Show
  the SLI part as the cell (`DataPlaneAvailability`); show the
  window as a small chip ("1h").
- **FIRED** column: render `formatRelative(alert.since)` — e.g.
  `4m ago`. The dashboard already has `formatRelative` (used in
  the alert-channels card). Hover to see the absolute timestamp.
- **BUDGET** column: compute from SLO definition. For a 1h
  availability alert that fired 4 minutes ago, this is `56 of 60
  min remaining` or similar. Falls back to `—` if the SLO
  definition isn't reachable in this build.
- **ACKED BY** / **NOTE**: populate from the ack mutation when
  it succeeds (see MED-SO-04 which is the related "ack doesn't
  reflect" bug).

## Actual

Static `unknown` / `—` strings. The columns are dead weight.

## Suggested fix

~30 LoC in the Incidents page renderer. Pseudocode:

```js
function sliFromAlertName(name) {
  // "DataPlaneAvailability-1h" → { sli: "DataPlaneAvailability", window: "1h" }
  const m = /^(.+)-([0-9]+[hm])$/.exec(name);
  return m ? {sli: m[1], window: m[2]} : {sli: name, window: ''};
}

function renderRow(alert) {
  const {sli, window} = sliFromAlertName(alert.name);
  return (
    <tr>
      <td>{alert.state.toUpperCase()}</td>
      <td><Pill kind={alert.severity}>{alert.severity}</Pill></td>
      <td>{sli} {window && <Chip>{window}</Chip>}</td>
      <td title={alert.since}>{formatRelative(alert.since)}</td>
      <td>{computeBudget(alert) || '—'}</td>
      ...
    </tr>
  );
}
```

## Severity rationale

MEDIUM. The page mounts and the row count is correct, but the
columns operators actually scan are dead. An operator paging on
"DataPlaneAvailability-1h fired" gets less context from the
dashboard than from the underlying API — which is the exact
opposite of what a dashboard should deliver.

