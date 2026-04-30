# M1 — Overview

> **Status:** Queued — M1 — Overview page redesign brief.
>
> See [`README.md`](../../README.md) for the track status board.

> **Status.** seed
>
> **Effort.** ~3 days
>
> **Depends on.** M0 (foundations + chrome).
>
> **Why this milestone is first.** Highest-traffic page;
> sets the visual bar every other page must clear. If
> Overview reads template-default, every other page has
> excuse to.

## Inputs

- Design contract: [`docs/control-plane/enterprise/pages/overview.md`](../../../docs/control-plane/enterprise/pages/overview.md)
- API endpoints used:
  - `GET /api/stats` (1 s cache)
  - `GET /api/stats/timeseries?window=15m&step=5s`
  - `GET /api/upstreams/summary`
  - `GET /api/attacks/distribution?window=15m`
  - `GET /api/attacks/top?window=15m&limit=5`
  - `GET /api/loadmode` *(P7)* — surfaces in the hero band
  - `GET /api/risk?limit=5` *(P6)* — surfaces in the hero band
- Components reused from M0: `stat-card`, `line-chart`,
  `donut`, `sparkline`, `table` (compact mode), `skeleton`
- New components introduced: **none.** If the bento layout
  needs a new wrapper, justify it in the brief and add it to
  M0's component inventory retroactively.

## User goals

1. **Glance check.** "Is the WAF healthy *right now*?" in
   under 1 second of scanning.
2. **Drill to a hot lead.** Either a top attacker IP, a
   firing detector class, or a degraded upstream — one
   click takes me to the right deeper page.
3. **Confirm operational mode.** Current load mode +
   verbosity + audit-chain freshness in the same field of
   view as the throughput numbers, so I know whether
   degraded behaviour is *expected*.

## Scope

### In

- Hero band: throughput + block-rate stat tiles, current
  load-mode pill (live), connection state pill, audit-chain
  freshness badge.
- Traffic-vs-blocked chart over the configurable window
  (default 15 m, 5 s step).
- Attack distribution donut + top-5 firing detectors as a
  compact list under the donut (not a separate widget).
- Top-5 attacker IPs table (compact); each row links to
  `/risk?ip=...` deep view.
- Upstream pool summary chip strip — one chip per pool,
  colour by `--signal-*`.
- Stale-data state: every widget shows "as of N s ago" when
  the polling cycle hasn't completed, distinct from
  loading.

### Out

- Editable filters (handled on Live Feed / Attack Events).
- Per-tier breakdown of throughput (handled on Tracking).
- Detector-by-detector hit timeline (handled on Analytics).

## Acceptance

- Every user goal reachable in ≤ 1 click (this is the home
  page; clicks-to-anywhere starts here).
- Page module raw size < 32 KB. (Current `overview.js` is
  270 lines / ~9 KB; the redesign should fit comfortably.)
- 6 tiles + chart + top-5 list visible above the fold at
  1440 × 900.
- Loading: skeleton matches the final layout (no reflow on
  data arrival).
- Empty: "No requests in the last 15 m" copy on the chart;
  donut shows a neutral grey ring with "No detections —
  pipeline idle" caption.
- Error: per-widget error pill, never a full-page error
  banner. Other widgets keep refreshing.
- Stale: "as of <Ns> ago" caption appears when poll missed
  by 2× its interval.
- Both themes look intentional, not derived. (Stage 4 of
  the workflow gate.)

## Layout sketch (for the brief, not the final)

```
┌─────────────────────────────────────────────────────────┐
│  Page title           Window: 15 m ▾    Mode: elevated  │
├──────────────┬──────────────┬──────────────┬───────────┤
│ Throughput   │ Block rate   │ Active pools │ Risk      │
│  4.2k rps    │  0.4 %       │  3 / 4 ok    │  2 high   │
│  ▁▂▃▅▇▄▂     │  ▂▁▁▂▁       │              │           │
├──────────────┴──────────────┴──────────────┴───────────┤
│ Traffic vs blocked            (15 m, 5 s step)         │
│  ╱╲╱──╲╱╲────╱──╲                                      │
├────────────────────────────────┬────────────────────────┤
│ Attacks by class               │ Top attackers (15 m)   │
│   ●● sqli            42 %      │ 203.0.113.7   142  →   │
│   ●  xss             28 %      │ 198.51.100.4   97  →   │
│   ●  recon           12 %      │ 192.0.2.10     58  →   │
│   ●  …               18 %      │ …                      │
└────────────────────────────────┴────────────────────────┘
```

This is the *intent* sketch the stage-1 brief will refine
into actual ASCII + copy.

## Open questions

- Should the load-mode pill in the hero be *clickable* to
  pin / unpin? Argues for putting the pin flow on Settings
  (M10) and keeping Overview read-only. Resolve in the
  brief.
- Top-5 attackers table — refresh interval? Currently
  `/api/risk` doesn't have a window parameter; the brief
  should decide whether to poll every 5 s or wire SSE.
- Sparkline source data — for stat tiles, sample the
  timeseries endpoint or compute client-side from the
  chart data?

## Out-of-scope drift log

(Append decisions during the milestone that diverge from
the contract or this plan. Empty until work begins.)
