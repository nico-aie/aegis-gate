# Page — Overview

> Default landing page after login. Mirrors the AI-WAF reference
> screenshot: 4 KPI tiles up top, a real-time traffic-vs-blocked
> chart, an attack-distribution pie, and a top-attacker-IPs panel.

## Route

`GET /dashboard/overview` — SPA shell route.

## Data sources

| Widget | Source | Refresh |
|--------|--------|---------|
| Requests/s tile | `GET /api/stats?window=10s` → `request_rate` | poll 1s |
| Block Rate tile | `/api/stats` → `block_rate_pct` + `blocks_total` | poll 1s |
| Active Threats tile | `/api/stats` → `active_threats` (count of IPs over risk threshold) | poll 1s |
| Upstream tile | `GET /api/upstreams/summary` → `state` (`Healthy`/`Degraded`/`Down`) | poll 5s |
| Traffic vs Blocked chart | `GET /api/stats/timeseries?window=15m&step=5s` | poll 5s, append last point |
| Attack Distribution pie | `GET /api/attacks/distribution?window=15m` | poll 10s |
| Top Attacker IPs | `GET /api/attacks/top?limit=5&window=15m` | poll 5s |

The `/api/stats` aggregate is the only multi-purpose endpoint;
chart and pie endpoints are dedicated. Endpoint contracts live in
[`../api.md`](../api.md).

## Layout

```
┌────────────────────────────────────────────────────────────────┐
│ Overview                                                       │
│ Realtime WAF traffic monitoring                                │
├──────────────┬──────────────┬──────────────┬──────────────────┤
│ Requests/s   │ Block Rate   │ Active Threat│ Upstream         │
│   0.1        │   98.4%      │      0       │   Healthy        │
│ last 10s     │ 638,947 tot. │ over risk th.│ All systems ok   │
├──────────────┴──────────────┴──────┬───────┴──────────────────┤
│                                    │                          │
│   Traffic vs Blocked (realtime)    │  Attack Distribution     │
│   line chart, 15m window           │   donut/pie chart        │
│                                    │                          │
├────────────────────────────────────┴──────────────────────────┤
│  Top Attacker IPs                                             │
│  fp:985730a7cc0fc937           …                              │
│  110.35.80.116                  …                              │
│  fp:a8391a8dfcf1f208            …                              │
│  34.47.62.202                   …                              │
│  71.6.239.61                    …                              │
└───────────────────────────────────────────────────────────────┘
```

Grid: 4 columns of stat tiles on row 1; row 2 is a 2/3 + 1/3 split
(chart + pie); row 3 is full-width table.

## Stat tile widget

```
┌──────────────────────────┐
│ Requests/s         [icon]│
│ 0.1                      │
│ last 10 seconds          │
└──────────────────────────┘
```

- Heading (12px, `--text-secondary`)
- Value (28px, `--font-weight-bold`, status colour if applicable)
- Subtitle (12px, `--text-muted`)
- Icon top-right, 20×20, sets `color` from accent or status token

Status colouring rules:

- Block Rate value uses `--color-err` if > 30% else `--color-ok`.
- Active Threats: `--color-err` if > 0 else `--color-ok`.
- Upstream: pill colour drives the value colour.
- Requests/s never colours red — it is informational.

## Traffic vs Blocked chart

- Chart.js line + filled area.
- Two series: `total` (cyan) and `blocked` (red).
- 15-minute window, 5s buckets — the server returns 180 points.
- Tooltip shows the bucket timestamp + Total + Blocked.
- Empty state: small inline "No traffic yet" centred.
- Click a point → opens drawer pre-filtered by that timestamp on
  the Live Feed page (deep link).

## Attack Distribution pie

- Donut, 60% inner radius.
- Slices sized by count over the 15m window. Slice palette from
  [`../theme.md`](../theme.md) §Charts.
- Legend below for `< 1024px`, right of donut for `>= 1024px`.
- Click a slice → navigates to Attack Events filtered by category.

## Top Attacker IPs

- 5-row table.
- Columns: `Identifier` (IP or `fp:<fingerprint>`), `Hits`,
  `Categories` (small pills), `Risk`, `Action`.
- The Identifier may be a JA4/JA3 fingerprint when client IP is
  shared (mobile NATs). The server already exposes both via the
  device-fingerprinting module.
- Action column: `Block` button (writes to Blacklist), `Inspect`
  link (drawer with last 20 events).
- Mutating clicks open a confirm modal with CSRF flow.

## States

- Loading: shimmer the 4 stat values + skeleton lines for the
  chart and pie. Hide the table until first response.
- Empty traffic: tiles show 0; chart says "No traffic in the last
  15 minutes".
- Error on any single endpoint: that widget shows an error tile
  with a Retry button. Other widgets keep working.
- Stale: if any endpoint hasn't responded in > 2 polling intervals,
  show "Updated 12s ago" pill in the top right of the widget.

## Telemetry

- `waf_dashboard_overview_renders_total` (counter, server-side
  whenever `/api/stats` is hit; doubles as a usage signal).
- Page-level `console.timeStamp("overview:rendered")` for
  client-side perf debugging only — no third-party tracker.
