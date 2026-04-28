# Page — Analytics

> Historical trends, intentionally lower-frequency than Overview.
> Backed by Prometheus to avoid duplicating long-term retention in
> the WAF process.

## Route

`GET /dashboard/analytics`

## Data sources

The page queries the embedded Prometheus exporter via the existing
`/metrics` scrape — but indirectly. The server adds a small proxy
endpoint:

```
GET /api/analytics/query?expr=<promql>&start=&end=&step=
```

This proxy is **read-only**, requires session + same auth as any
other admin endpoint, and rejects any expression that doesn't
match the allow-list in [`../api.md`](../api.md) §analytics-allowlist.

The allow-list keeps operators from issuing arbitrary PromQL
that could pin CPU on a busy collector — the page only needs a
fixed set of queries.

| Widget | PromQL (template) |
|--------|-------------------|
| Requests over time | `sum(rate(waf_requests_total[$step]))` |
| Block ratio | `sum(rate(waf_decisions_total{action="block"}[$step])) / sum(rate(waf_decisions_total[$step]))` |
| Latency p50/p95/p99 | `histogram_quantile(0.95, sum(rate(waf_upstream_latency_seconds_bucket[$step])) by (le))` |
| Error rate by route | `sum by (route) (rate(waf_decisions_total{action="block"}[$step]))` |
| SLO budget remaining | `waf_slo_budget_remaining{sli=~"$sli"}` |
| Cert days to expiry | `min(waf_cert_expires_in_seconds) / 86400` |
| WAF overhead p50/p95/p99 (bench) | `histogram_quantile(0.99, sum(rate(waf_bench_overhead_seconds_bucket[$step])) by (le))` |
| Detector cost p99 (bench) | `histogram_quantile(0.99, sum by (detector,le) (rate(waf_bench_detector_cost_seconds_bucket[$step])))` |

## Layout

```
┌──────────────────────────────────────────────────────────────┐
│ Analytics                              [24h ▾] [Refresh]     │
├─────────────────────────────────┬────────────────────────────┤
│ Requests over time              │ Latency p50/p95/p99        │
│ line chart                      │ multi-series line          │
├─────────────────────────────────┼────────────────────────────┤
│ Block ratio                     │ Error rate by route        │
│ area chart                      │ stacked area               │
├─────────────────────────────────┼────────────────────────────┤
│ SLO budget remaining            │ Cert freshness             │
│ thin gauge per SLI              │ countdown rings            │
└─────────────────────────────────┴────────────────────────────┘
```

- Time-range selector: 1h, 6h, 24h, 7d, 30d.
- All charts share an auto-step: `start..end` divided into ~240
  buckets.
- A "Drill into Grafana" link opens (in a new tab) the configured
  `admin.grafana_url` if set — the dashboard embraces being a
  glance, not a replacement.

## Benchmarks subpage

> Full design — [`../../benchmark-mode.md`](../../benchmark-mode.md).
> Toggle bench mode from the Tracking page.

A subpage under Analytics (selectable from a small tab strip at the
top of the page; no extra sidebar slot) that surfaces the
benchmark-only series. Visible whenever
`/api/about` reports `benchmark.configured_mode != null`; renders
an "off — enable on Tracking" banner when `active_mode == disabled`.

Widgets:

- **Overhead p50 / p95 / p99 by tier** — multi-series line chart
  from `bench_overhead_p50/p95/p99` filtered per tier.
- **Per-detector cost heatmap** — rows = detector names, columns =
  1-min buckets, cell colour = p99 cost. Sourced from
  `bench_detector_p99` series.
- **Top-N expensive rules** — bar chart, only when
  `expose_rule_ids: true`. Sourced from a non-PromQL aggregate
  computed by `aegis-control` over the in-process samples (no
  high-cardinality Prometheus labels for rule ids).
- **Overhead vs RPS** — dual-axis line chart (left = overhead p99
  in µs, right = requests/sec). Helps spot cost growth as load
  rises.

Time-range selector and caching follow the parent Analytics page.

## Caching

The proxy caches each (expr, start, end, step) result for 30s. SSE
push for analytics is intentionally absent: the page polls on
focus, on time-range change, and on manual Refresh.

## Permissions

Same as every other admin page. No new role needed for v1. When
RBAC lands (see [`../../../future/rbac-sso.md`](../../../future/rbac-sso.md))
this page becomes the natural fit for an "operator-readonly" role.
