# DDoS Protection (v2)

> **v1 → v2:** auto-block state now lives in the **clustered state backend**
> so every node agrees on who is blocked, detection runs **per tenant**, and
> L7 adaptive load shedding kicks in before the per-IP thresholds. See
> [`ha-clustering.md`](./ha-clustering.md),
> [`adaptive-load-shedding.md`](./adaptive-load-shedding.md), and
> [`multi-tenancy.md`](./multi-tenancy.md).

## Purpose

Detect and mitigate volumetric attacks before they reach the backend. Where
[`rate-limiting.md`](./rate-limiting.md) enforces steady per-user budgets,
DDoS protection handles **sudden traffic spikes** from single abusers,
botnets, or targeted L7 floods — and coordinates the mitigation across the
whole cluster.

## Detection strategies

### Per-IP burst detection

Each client IP is tracked in a 1-second sliding window. Exceeding the
threshold (default 100 req/s) auto-blocks the IP for a configurable TTL.
Counters are kept in the state backend (`in_memory`, `redis`, or `raft`)
so a burst spread across nodes is still caught.

### Global rate spike detection

Rolling average of cluster-wide RPS is maintained in the state backend.
When current RPS exceeds `spike_multiplier * rolling_avg` (default 3x),
DDoS mode is triggered cluster-wide:

- Per-IP thresholds tighten (default 20 req/s)
- New sessions are forced through a challenge (see
  [`challenge-engine.md`](./challenge-engine.md))
- Adaptive load shedder drops lowest-tier traffic first
- Operators are alerted via dashboard + audit log + SIEM

### Distributed low-and-slow

Single-IP thresholds miss distributed attacks. Layered defenses:

- JA3/JA4 clustering via [`device-fingerprinting.md`](./device-fingerprinting.md)
- Bot classification via [`bot-management.md`](./bot-management.md)
- ASN + threat-intel tagging via [`ip-reputation.md`](./ip-reputation.md)
- Behavioral anomalies via [`behavioral-analysis.md`](./behavioral-analysis.md)

## Cluster-wide auto-block list

Triggered blocks are written to the state backend under
`waf:block:{tenant}:{ip}` with an expiry. Every node consults the same
keyspace, so blocking on one node blocks everywhere within the replication
latency bound.

- **in_memory**: single-node only, DashMap fallback
- **redis**: `SET` with `EX` TTL, read on the hot path with pipelining
- **raft**: replicated log entry committed before responding

A background sweeper purges expired entries every 30 seconds.

## Per-tenant scope

All counters and block lists are keyed by `tenant_id`. A flood against
tenant A does not tighten thresholds or block IPs for tenant B. Cluster-wide
operators still see the aggregate view in the dashboard.

## Response behavior

- **Blocked IP hits the WAF:** HTTP 503, no backend contact, no inspection
- **Global DDoS mode active:** new sessions challenged; known-good sessions
  pass through untouched
- **Adaptive load shedder** drops CATCH-ALL and MEDIUM tier traffic before
  CRITICAL is affected
- Every block decision is audit-logged with trigger rate + expiry +
  `tenant_id`

## Integration with risk scoring

A DDoS-blocked IP's risk score is set to 100 for the block duration.
After expiry the score decays per [`risk-scoring.md`](./risk-scoring.md).

## Configuration

```yaml
ddos:
  enabled: true
  state_backend_ref: primary     # from state.backends[]
  per_ip:
    rps_threshold: 100
    block_ttl_s: 300
  global:
    rolling_window_s: 60
    spike_multiplier: 3.0
    tightened_per_ip_rps: 20
  per_tenant_overrides:
    acme: { rps_threshold: 500 }
```

## Implementation

- `src/ddos/detector.rs` — per-IP + global counters (state backend)
- `src/ddos/auto_block.rs` — clustered block list
- `src/ddos/sweeper.rs` — expired-entry purger
- `src/ddos/mode.rs` — global DDoS mode flag + broadcast

## Performance notes

- Hot-path check is one state-backend `GET` (pipelined with rate limiter)
- In-memory fallback is a `DashMap::get` — microseconds
- Tightened thresholds and block list are hot-reloadable during an attack
