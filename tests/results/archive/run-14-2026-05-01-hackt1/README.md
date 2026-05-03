# Run 14 — 2026-05-01 — HACK-T1 verification

End-to-end verification after **HACK-T1** (retire dashboard
mock data) — the first slice of the
[`plans/hackathon-readiness.md`](../../../plans/hackathon-readiness.md)
track. Removes the Round-1 elimination risk identified in
the v2.3 hackathon docs (§2.2 — Dashboard mock-data penalty).

## Headline

| Surface | Result |
|---|---|
| **`Math.random` in `pages.jsx`** | 0 occurrences (was 7 spread across PageAttackEvents + PageAnalytics + Rule details) |
| **Static fixture fallbacks** | All converted to empty arrays (CERTS / RULES / TIERS / BLACKLIST / WHITELIST / UPSTREAMS / CLUSTER / ALERTS) |
| **`synthetic data` pills** | Removed from PageAttackEvents + PageAnalytics |
| **PageAttackEvents** | Detector breakdown / bot mix / threat-intel hits all read from `/api/attacks/by-detector`, `/api/bots/mix`, `/api/threat-intel/hits` |
| **PageAnalytics** | Requests over time + Block ratio read from `/api/stats/timeseries`; SLO + Cert sections read from `/api/slo` + `/api/certs` |
| **Honest empty states** | Latency p50/p95/p99 + Error-rate-by-route + per-rule stats render an explanatory message instead of fake data |
| **Bundle** | 192,381 B (188 KB) — within 256 KB budget |
| **Workspace tests** | All pass (~2,447 default-feature) |

## Live verification

WAF binary built `--features "redis alerts"`, started against
`config/dev.yaml`, drove 13 requests (10 benign + 3 attack
probes) before screenshots.

### `/api/attacks/by-detector` (live)
```json
{ "window_seconds": 900,
  "detectors": [
    { "name": "detector:path", "count": 1 },
    { "name": "unknown",        "count": 1 }
  ]
}
```

### `/api/bots/mix` (live)
```json
{ "window_seconds": 900,
  "categories": [
    { "name": "unknown", "count": 2, "pct": 100.0 }
  ]
}
```

### `/api/threat-intel/hits` (live, empty for dev cfg without TI feed)
```json
{ "window_seconds": 900, "limit": 20, "hits": [] }
```

### `/api/stats/timeseries` (live)
First few points show 0; later points carry the 13-request
spike. Block ratio peak 16.7% reflects the 3 blocked attack
probes against ~13 total.

### `/api/slo` (live)
Reports `data_plane_availability` (current 83.33%, target
99.90%) and `audit_delivery_rate` (current 100%, target
99.99%) — actual SLI values from the running SLO engine, not
the static placeholder names that used to be hardcoded on the
page.

## Screenshots

- [`screenshots/attacks-hackt1.png`](./screenshots/attacks-hackt1.png) —
  `synthetic data` pill is gone; detector breakdown shows
  the two real counts; threat-intel honest empty-state.
- [`screenshots/analytics-hackt1.png`](./screenshots/analytics-hackt1.png) —
  `synthetic data` pill is gone; latency + error-rate-by-route
  cards show explanatory messages; SLO + Cert sections show
  live engine data.

## What's deliberately deferred

- **Latency p50/p95/p99 timeseries** — needs Prometheus
  histogram percentile rollup. The page now points operators
  at `/metrics` + Grafana for the live data.
- **Per-route error rate** — needs an audit-log per-path
  aggregator. The page points operators at the Audit Log +
  Attack Events for now.
- **Per-rule hit count** — needs a rule-id → count rollup.
  The Rule Manager stats tab now points at the audit-log
  filter for the same data.

These are honest "ships in a follow-up" notes — not random
numbers pretending to be live.

## Files touched

- `crates/aegis-control/assets/dashboard/src/pages.jsx`
  - `PageAttackEvents` (~110 LOC) rewritten against live
    `useAttacksByDetectorApi` / `useBotMixApi` /
    `useThreatIntelApi`.
  - `PageAnalytics` (~110 LOC) rewritten against
    `useTimeseriesApi` / `useSloApi` / `useCertsApi`.
  - Rule details "stats" tab Math.random sparkline replaced
    with audit-log link.
- `crates/aegis-control/assets/dashboard/src/data.jsx`
  - Three new hooks: `useAttacksByDetectorApi`, `useBotMixApi`,
    `useThreatIntelApi`.
  - All static-fixture fallbacks (CERTS / RULES / TIERS /
    BLACKLIST / WHITELIST / UPSTREAMS / CLUSTER / ALERTS)
    swapped for empty arrays.
  - `window` exports updated.
- `crates/aegis-control/assets/dashboard/app.js` — rebuilt.
- `tests/results/run-14-2026-05-01-hackt1/` — this report +
  screenshots.

## Definition of Done

- [x] Zero `Math.random` calls in `pages.jsx` (only comment
      references remain documenting the retirement).
- [x] No static-fixture fallback in any `useApi` hook in
      `data.jsx`.
- [x] PageAttackEvents + PageAnalytics show no "synthetic
      data" pill.
- [x] Bundle ≤ 256 KB (192 KB).
- [x] Workspace tests green.
- [x] Live screenshot evidence.

## What's next

- **HACK-T2** — `tests/contract/v2.3_compliance.sh` regression
  check (~2 h). CI fails on any v2.3 contract drift.
