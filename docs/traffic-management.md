# Traffic Management (v2, new)

> **New in v2.** Canary releases, header/cookie-based steering, shadow
> mirroring, and retries with budgets. Sits between
> [`routing-ingress.md`](./routing-ingress.md) and
> [`upstream-pools.md`](./upstream-pools.md).

## Purpose

Let operators roll out new backend versions safely, replay production
traffic to a staging environment, and retry transient backend failures
without amplifying outages.

## Canary / weighted split

A route can target a **split** instead of a single pool:

```yaml
routes:
  - id: api_v2
    host: "api.example.com"
    path: "/v2/"
    match: prefix
    split:
      - { upstream_ref: api_v2_stable,  weight: 90 }
      - { upstream_ref: api_v2_canary,  weight: 10 }
```

Weights are normalized; picking is deterministic via a hash of
`(tenant_id, client_id, request_id)` when `sticky: true` (so a client
lands on the same side for the session duration) or random otherwise.

## Header / cookie steering (A/B)

Override the weighted pick when a request carries a specific header or
cookie:

```yaml
split:
  overrides:
    - { when: "header:x-canary=true", upstream_ref: api_v2_canary }
    - { when: "cookie:ab=exp-b",      upstream_ref: api_v2_exp_b }
```

`when` expressions reuse the [`rule-engine.md`](./rule-engine.md)
condition language.

## Shadow mirroring

A route can fire-and-forget a copy of the request to a secondary pool
for comparison, replay, or perf testing:

```yaml
shadow:
  upstream_ref: api_v2_shadow
  sample_rate: 0.1
  timeout_ms: 200
  drop_body_over_bytes: 65536
```

Shadow requests:

- Never block the primary response
- Never carry authorization headers (stripped by default)
- Failures are recorded as `waf_shadow_errors_total` metric
- Latency is never charged to the user

## Retries with budgets

Per-route retry policy:

```yaml
retries:
  enabled: true
  max: 2
  retryable_statuses: [502, 503, 504]
  retryable_errors: [connect_refused, reset]
  per_try_timeout_ms: 1500
  budget:
    ratio: 0.1          # max 10% of requests can be retries
    min_per_sec: 5      # always allow some retries
```

Retry budgets prevent a retry storm from amplifying a partial outage.
Budget state is tracked per pool.

## Mirroring vs retry interaction

Shadow requests are **never retried**. Retries go to the primary pool
only (with circuit-breaker awareness — an ejected member is skipped).

## Configuration merge

Route-level settings override pool defaults, which override global
defaults, in that order.

## Implementation

- `src/traffic/split.rs` — weighted split + overrides
- `src/traffic/shadow.rs` — fire-and-forget mirror
- `src/traffic/retry.rs` — retry engine + budget
- `src/traffic/steer.rs` — `when` expression evaluator

## Performance notes

- Split pick is one `wyrand` or hash + compare — nanoseconds
- Shadow runs on a dedicated task with a bounded channel; overflow drops
- Retry state is per-pool atomics; no locks on the hot path
