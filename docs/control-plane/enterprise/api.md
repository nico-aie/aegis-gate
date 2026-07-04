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
GET /api/alerts
GET /api/tracking/snapshot
```

`/api/tracking/snapshot` is an aggregate read used by the Tracking
page to keep the per-tab fan-out cheap. It returns the union of
slo, upstreams summary, cluster peers, certs summary, and alerts
in one response (~5KB JSON typical).

> Removed 2026-07-04 (PE-1, committee round-2 🔴3): `GET
> /api/gitops/status`, `GET /api/audit/witness`,
> `GET /api/threat-intel/feeds`, and the never-routed
> `POST /api/certs/{host}/renew` — all were placeholder or dead
> surface; they now return 404.

### Scaling page (SC-T2)

```
GET /api/runtime    # L1 — tokio runtime sizing (workers, mode, blocking, affinity)
GET /api/cluster    # L2 — peers + leader + heartbeat (shared with Tracking page)
GET /api/state      # L3 — state-backend health (backend, connected, latency, keys, replica lag, circuit)
POST /admin/drain   # L2 mutation — flips this node's readiness to 503 (LB pulls within `inter`)
```

`/api/runtime` is restart-only (tokio doesn't permit hot resize);
the dashboard renders the boot-effective sizing without offering
a slider. `/api/state` is cached server-side at 5 s by the Redis
backend so dashboard polls don't hammer the primary. The full
three-layer reading lives in
[`architecture/scaling-model.md`](../../architecture/scaling-model.md).

### Benchmark mode

> Full design — [`../benchmark-mode.md`](../../operator/benchmark-mode.md).

```
GET  /api/benchmark/status
POST /api/benchmark/enable    { "mode": "headers"|"verbose", "ttl_seconds": 3600 }
POST /api/benchmark/disable
GET  /api/benchmark/snapshot?window=60s
```

`/api/benchmark/status` response:

```jsonc
{
  "configured_mode": "disabled",
  "active_mode":     "headers",
  "ttl_remaining_s": 423,
  "enabled_at":      "2026-04-27T17:30:00Z",
  "enabled_by":      "admin",
  "source_allowlist": ["127.0.0.1/32"],
  "expose_rule_ids":  false
}
```

`/api/benchmark/snapshot` aggregates the last `window` (max 600s) of
benchmark-gated requests into the shape the Tracking + Analytics
panels render:

```jsonc
{
  "window_seconds": 60,
  "samples": 12053,
  "overhead_us": { "p50": 412, "p95": 1180, "p99": 2240, "max": 4980 },
  "by_detector": [
    { "name": "rate", "samples": 12053, "p50": 5,  "p95": 12,  "p99": 28 },
    { "name": "sqli", "samples": 12053, "p50": 80, "p95": 220, "p99": 410 }
  ],
  "by_tier": [
    { "tier": "critical", "samples":  402, "p99_us": 3200 },
    { "tier": "high",     "samples": 4810, "p99_us": 2240 }
  ],
  "decisions": { "allow": 11890, "block": 152, "challenge": 11 }
}
```

Mutating endpoints (`enable`, `disable`) require the same admin
session + CSRF as every other mutating route, and emit
`bench_enable` / `bench_disable` audit entries. Auto-disable on TTL
expiry emits `bench_auto_disable`. `/api/about` is extended to
include `benchmark.configured_mode` so the dashboard can decide
whether to render the Benchmark panel at all.

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
| `bench_overhead_p50` | `histogram_quantile(0.50, sum(rate(waf_bench_overhead_seconds_bucket[$step])) by (le))` |
| `bench_overhead_p95` | `histogram_quantile(0.95, sum(rate(waf_bench_overhead_seconds_bucket[$step])) by (le))` |
| `bench_overhead_p99` | `histogram_quantile(0.99, sum(rate(waf_bench_overhead_seconds_bucket[$step])) by (le))` |
| `bench_detector_p99` | `histogram_quantile(0.99, sum by (detector,le) (rate(waf_bench_detector_cost_seconds_bucket[$step])))` |
| `bench_mode` | `waf_bench_mode` |

Any other `expr` returns 400. The `bench_*` queries return zero
samples when `benchmark.mode == disabled`, by design — see
[`../benchmark-mode.md`](../../operator/benchmark-mode.md).

**Backend (PE-2, 2026-07-04):** the resolved PromQL is proxied to the
external Prometheus configured at `admin.prometheus_url`
(`http://` only in v1) — `/api/v1/query` for instantaneous queries,
`/api/v1/query_range` when `start`+`end` are set (`$step` is
substituted server-side). Responses:

- `200` — instant: `{expr, promql, result_type: "scalar", value}`
  (`value` is `null` when Prometheus has no data yet — never a fake
  `0.0`), or `{..., result_type: "vector", samples: [{metric,
  value}]}` for grouped keys with >1 sample. Range:
  `{..., result_type: "matrix", series: [{metric, points: [{ts,
  value}]}]}` — grouped keys (`errors_by_route`,
  `bench_detector_p99`) keep one labeled series per dimension.
- `502 prometheus_unreachable` — connect/timeout (3 s budget),
  non-2xx, or unparseable upstream response.
- `503 analytics_not_implemented` / `503 no_history_backend` —
  `admin.prometheus_url` not configured (unchanged honest posture).

### Security toggles (P1–P8 of the security-toggle plan)

Every mutating endpoint here is gated by the [`AuditedMutate`
pipeline][p1] — CSRF cookie/header pair must match, the change
is appended to the SHA-256 hash chain, and the post-state
diff is emitted on the audit bus before the response returns.
Validation failures (e.g. compliance clamp) leave the chain
untouched so the invariant **"every chain entry is a state
change that actually happened"** holds.

[p1]: ../gitops-change-management.md

#### `GET /api/detectors` &nbsp;·&nbsp; `PUT /api/detectors`

Detection-class master switch + per-tier overrides.

```
GET /api/detectors
{
  "mask": {"sqli": true, "xss": true, ...},
  "overrides": {                       // optional per-tier overrides
    "high":   { "sqli": true, "recon": false, ... }
  },
  "locked_classes": ["sqli", "xss", "path_traversal", "ssrf"],
  "compliance_modes": ["pci"]
}

PUT /api/detectors          (CSRF + AuditedMutate)
Body: same `{ mask?, overrides? }` shape; both fields optional.
       `overrides[tier] = null` clears that tier's override.
       Falls back to the flat `{ sqli, xss, … }` body for
       backward-compat with P2 callers.
```

The hot path consults
`SharedDetectorMask::resolve(Some(tier))` once per request — one
Arc load + one match. Compliance clamp validates both base and
every override against `cfg.compliance.modes`.

#### `GET /api/risk` &nbsp;·&nbsp; `GET /api/risk/{ip}` &nbsp;·&nbsp; `PUT /api/risk/{ip}/reset`

Per-IP risk score + lifetime strikes.

```
GET /api/risk?limit=50
{
  "total_tracked": 12,
  "returned": 12,
  "clients": [
    {"ip":"10.0.0.5","score":92,"strikes":7,"idle_seconds":3,
     "level":"block","strike_blocked":true},
    ...
  ]
}

GET /api/risk/{ip}
  → 200 { "client": <RiskSnapshot> } | 404 { "error": "not_found" }

PUT /api/risk/{ip}/reset    (CSRF + AuditedMutate)
  → clears strikes + score for the IP. Body is empty.
```

The hot path bumps the per-IP score on signal hits and decays it
on clean traffic (capped at `risk.trust_recovery.per_hour` per
hour). Strikes never decay; once `risk.strikes.block_at` is
reached, the IP is permanently blocked until reset.

#### `GET /api/loadmode` &nbsp;·&nbsp; `PUT /api/loadmode`

`LoadMode { Normal | Elevated | Critical }` based on observed RPS.

```
GET /api/loadmode
{
  "mode": "normal",                 // auto-detected
  "effective_mode": "elevated",     // override wins if pinned
  "rps_last_sample": 1842,
  "override_active": true,
  "elevated_rps": 2000,
  "critical_rps": 8000
}

PUT /api/loadmode           (CSRF + AuditedMutate)
Body: { "override": "normal"|"elevated"|"critical"|"unset" }
       Use the literal string `"unset"` to clear the override.
       Field absent = no-op (also useful as a CSRF/health probe).
```

Hot path call cost: one `Relaxed` atomic add (`tick`) + one Arc
load (`current`).  `Critical` short-circuits the verbose audit
`fields` payload to `null` to keep chain writes cheap under DDoS.

#### `GET /api/logging` &nbsp;·&nbsp; `PUT /api/logging`

Operator-pinned audit-emission verbosity. Process-global per the
deferred-RBAC decision.

```
GET /api/logging
{
  "level": "info",
  "levels": ["silent", "error", "warn", "info", "debug", "trace"]
}

PUT /api/logging            (CSRF + AuditedMutate)
Body: { "level": "info" }   // any string from `levels`
```

Below `Error` → no audit emit at all (block events still go
through the inline 403 response — they just don't hit the chain).
Below `Info` → drop the verbose `fields` payload.

#### `GET /api/cold-tier`

Read-only inventory of the configured `audit.sinks` array, joined
against live per-sink delivery counters recorded by the sink tasks
(PE-2, 2026-07-04 — replaces the old `delivery: "unknown"`
placeholder). Splunk tokens are redacted before they reach the
response.

`delivery` taxonomy: `ok` (last write succeeded) · `error` (last
write failed) · `pending` (task running, nothing flushed yet) ·
`unwired` (configured but no forwarder task in this build —
Splunk/Kafka today — or the task failed to start).

```
GET /api/cold-tier
{
  "sinks": [
    {"id":"jsonl", "kind":"file", "destination":"/var/log/aegis/audit.jsonl",
     "delivery":"ok", "delivered":18234, "errors":0,
     "last_success":"2026-07-04T12:00:01Z", "last_error":null},
    {"id":"splunk", "kind":"https", "destination":"https://splunk:8088",
     "delivery":"unwired", "delivered":0, "errors":0,
     "last_success":null, "last_error":null}
  ],
  "fallback_buffer_bytes": 0
}
```

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
