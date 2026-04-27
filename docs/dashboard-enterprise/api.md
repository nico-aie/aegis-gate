# API Surface

> Every route below is served by the control-plane listener
> (`cfg.admin.bind`, default `127.0.0.1:9443`) and gated by the
> auth middleware described in
> [`../dashboard-auth.md`](../dashboard-auth.md). Mutating methods
> require a CSRF header in addition to the session cookie.

## Existing endpoints — kept as-is

These already exist in `aegis-control` and are not modified.

```
GET  /healthz/{live,ready,startup}
GET  /metrics
POST /admin/login
POST /admin/logout
GET  /api/config
PUT  /api/config
GET  /api/rules
POST /api/rules
DELETE /api/rules/{id}
GET  /api/audit?since=&class=
GET  /api/audit/verify
POST /api/gdpr/erase
GET  /api/gdpr/export?subject=
GET  /dashboard/sse
```

## New endpoints

### Stats / Overview

```
GET /api/stats?window=10s
GET /api/stats/timeseries?window=15m&step=5s
GET /api/about                 — version, build sha, env label
```

`/api/stats` response shape:

```jsonc
{
  "request_rate": 0.1,
  "blocks_total": 638947,
  "block_rate_pct": 98.4,
  "active_threats": 0,
  "upstream": {
    "state": "Healthy",   // Healthy | Degraded | Down
    "healthy_members": 4,
    "total_members": 4
  },
  "ts": "2026-04-27T16:40:30Z"
}
```

`/api/stats/timeseries` response shape:

```jsonc
{
  "window_seconds": 900,
  "step_seconds": 5,
  "points": [
    { "ts": "...", "total": 12, "blocked": 3 },
    ...
  ]
}
```

### Attack analytics

```
GET /api/attacks/distribution?window=15m
GET /api/attacks/top?limit=5&window=15m
GET /api/attacks/by-detector?window=1h
GET /api/threat-intel/hits?window=1h&limit=20
GET /api/bots/mix?window=1h
```

`/api/attacks/distribution` returns the donut chart data on the
Overview page:

```jsonc
{
  "window_seconds": 900,
  "categories": [
    { "name": "ssrf",            "count": 21, "pct": 21.0 },
    { "name": "ssti",            "count": 15, "pct": 15.0 },
    { "name": "honeypot",        "count":  6, "pct":  6.0 },
    { "name": "recon",           "count":  6, "pct":  6.0 },
    { "name": "cmdi",            "count":  4, "pct":  4.0 },
    { "name": "lfi",             "count":  2, "pct":  2.0 },
    { "name": "path_traversal",  "count":  2, "pct":  2.0 }
  ]
}
```

### Live feed extras

```
GET /api/audit/{request_id}
GET /api/audit/since?cursor=<seq>&limit=200
GET /api/filters
GET /api/audit/{id}/sinks
GET /api/audit/witness
```

### Rule Manager extras

```
POST /api/rules/validate
GET  /api/rules/{id}
PUT  /api/rules/{id}
GET  /api/rules/{id}/stats?window=1h
GET  /api/rules/top?window=1h&limit=10
```

`/api/rules/validate` request body:

```jsonc
{
  "id":   "rule-…",
  "body": "<DSL>"
}
```

Response:

```jsonc
{
  "ok": true,
  "errors":   [],
  "warnings": [{ "line": 4, "col": 12, "message": "redundant action" }]
}
```

### Tier Config

```
GET /api/tiers
GET /api/tiers/{name}
PUT /api/tiers/{name}
GET /api/tiers/{name}/stats?window=1h
```

### Blacklist / Whitelist

```
GET    /api/blacklist?type=&q=&cursor=
GET    /api/blacklist/{id}
POST   /api/blacklist
PUT    /api/blacklist/{id}
DELETE /api/blacklist/{id}
POST   /api/blacklist/bulk
GET    /api/blacklist/{id}/hits?window=24h

GET    /api/whitelist?type=&q=&cursor=
GET    /api/whitelist/{id}
POST   /api/whitelist
PUT    /api/whitelist/{id}
DELETE /api/whitelist/{id}
POST   /api/whitelist/bulk
GET    /api/whitelist/{id}/bypasses?window=24h
```

### Settings (admin self-service)

```
POST   /api/admin/password
POST   /api/admin/totp/enroll
POST   /api/admin/totp/reset
GET    /api/admin/sessions
DELETE /api/admin/sessions/{id}
PUT    /api/admin/policy
GET    /api/integrations
POST   /api/admin/break-glass
POST   /api/admin/secrets/session/rotate
```

### Tracking page

```
GET /api/slo
GET /api/upstreams
GET /api/upstreams/summary
GET /api/cluster
GET /api/certs
POST /api/certs/{host}/renew
GET /api/gitops/status
GET /api/alerts
GET /api/tracking/snapshot
```

`/api/tracking/snapshot` is an aggregate read used by the Tracking
page to keep the per-tab fan-out cheap. It returns the union of
slo, upstreams summary, cluster peers, certs summary, gitops
status, and alerts in one response (~5KB JSON typical).

### Analytics

```
GET /api/analytics/query?expr=<name>&start=&end=&step=
```

The `expr` parameter is **not** raw PromQL — it's a key from a
fixed allow-list:

| `expr` value | Internal PromQL |
|--------------|-----------------|
| `requests_rate` | `sum(rate(waf_requests_total[$step]))` |
| `block_ratio` | `sum(rate(waf_decisions_total{action="block"}[$step])) / sum(rate(waf_decisions_total[$step]))` |
| `latency_p50` | `histogram_quantile(0.50, …)` |
| `latency_p95` | `histogram_quantile(0.95, …)` |
| `latency_p99` | `histogram_quantile(0.99, …)` |
| `errors_by_route` | `sum by (route) (rate(waf_decisions_total{action="block"}[$step]))` |
| `slo_budget_remaining` | `waf_slo_budget_remaining` |
| `cert_days_to_expiry` | `min(waf_cert_expires_in_seconds) / 86400` |

Any other `expr` returns 400.

## Response conventions

- All JSON responses use `application/json; charset=utf-8`.
- Timestamps are RFC 3339 with `Z`.
- Errors follow the existing envelope:

  ```jsonc
  { "error": { "code": "validation_failed", "message": "...", "details": {} } }
  ```

- Cursor pagination: `cursor` is opaque base64-encoded
  server-side state. `next_cursor` returned in the body, never as
  a `Link` header.

## Caching

- Stats / timeseries / attack analytics: server caches results for
  1s (single shared cache keyed by `(endpoint, window, step)`).
- Audit verify: cached 30s.
- Tracking snapshot: cached 2s.
- Rule stats / blacklist hits: cached 5s.
- Cache headers: `Cache-Control: private, max-age=1` on
  high-frequency endpoints to allow browser dedupe; `no-store` on
  the rest.

## Rate limiting

Per-session rate limit: 60 reqs/sec aggregated across all
endpoints under `/api/*`. Excess returns 429 with
`Retry-After: 1`. Implemented as a token-bucket layer in the
existing admin middleware.

## OpenAPI

A machine-readable schema is published at
`/api/openapi.json` and embedded as an asset under
`/dashboard/assets/openapi.json` so operators can `curl` it
without auth headers (the embedded copy is a snapshot; the live
copy reflects feature flags).
