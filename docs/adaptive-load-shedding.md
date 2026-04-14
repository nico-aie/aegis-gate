# Adaptive Load Shedding (v2, enterprise)

> **Enterprise addendum.** Under saturation, the WAF sheds lowest-tier
> traffic first so CRITICAL routes keep serving. Uses the **Gradient2**
> algorithm (adaptive concurrency) to find the stable concurrency
> ceiling without operator tuning.

## Purpose

Keep the WAF responsive and CRITICAL routes available under traffic
spikes, degraded backends, or CPU starvation — without a static
concurrency limit that's wrong 99% of the time.

## Gradient2

Adaptive concurrency limit inspired by Netflix `concurrency-limits`:

- Measures the minimum observed latency (`RTT_min`) as a baseline
- Measures the short-window latency (`RTT_now`) continuously
- Limit `L(t+1) = L(t) * (RTT_min / RTT_now)` bounded by step caps
- When `RTT_now` drifts above `RTT_min`, the limit shrinks
- When `RTT_now` returns to baseline, the limit grows back

Run **per pool** so a degraded backend affects its own traffic,
not unrelated pools.

## Shedding priority

When inbound rate exceeds the current limit, requests are dropped in
**reverse priority order**:

1. CATCH-ALL tier traffic first
2. MEDIUM next
3. HIGH next
4. CRITICAL **never** shed by the adaptive layer; it can only be
   blocked by a real security decision

Within a tier, noisy-neighbor tenants (over-quota) are shed first.

## Early 503

Shed requests get an immediate `503 Service Unavailable` with
`Retry-After` — no pipeline cost, no upstream contact. This is the
single most important lever for stability under overload.

## Coordination with DDoS mode

When global DDoS mode is active (see [`ddos-protection.md`](./ddos-protection.md)),
the shedder tightens more aggressively:

- CATCH-ALL dropped at 50% of normal limit
- MEDIUM dropped at 70%
- HIGH dropped at 90%

## CPU-aware backstop

A kernel-reported CPU saturation signal (`/proc/stat` load or cgroups
`cpu.stat`) feeds a global backstop. When CPU > 90%, shedding kicks
in independent of Gradient2.

## Per-tenant concurrency

Each tenant has `concurrency_soft` and `concurrency_hard`:

- Soft: tenant shares cluster pool as long as unused capacity exists
- Hard: tenant cannot exceed, even if cluster pool is idle

This prevents a burst from tenant A starving tenant B.

## Metrics

- `waf_shed_total{tier,tenant,reason}`
- `waf_concurrency_limit{pool}` (gauge)
- `waf_concurrency_inflight{pool}` (gauge)
- `waf_rtt_seconds_bucket{pool}`

## Configuration

```yaml
load_shedding:
  enabled: true
  algorithm: gradient2
  gradient2:
    min_limit: 10
    max_limit: 10000
    smoothing: 0.2
    rtt_tolerance_ratio: 2.0
  cpu_backstop:
    enabled: true
    threshold_pct: 90
  ddos_mode_tightening:
    catchall_ratio: 0.5
    medium_ratio:   0.7
    high_ratio:     0.9
  per_tenant_defaults:
    concurrency_soft: 500
    concurrency_hard: 1000
```

## Implementation

- `src/shed/gradient2.rs` — adaptive limit
- `src/shed/priority.rs` — tier + tenant priority queue
- `src/shed/cpu_backstop.rs` — cgroups / /proc reader
- `src/shed/mod.rs` — orchestrator + metrics

## Performance notes

- Limit check is one atomic `fetch_add` + compare — wait-free
- Shed decision is O(1) per request
- Gradient2 updates run on a tick, not per request
