# DDoS Protection

> **Status:** ⚠️ **Partial — observe-only single-node (Phase 1)** as of
> 2026-05-09. The `DdosRuntime` is now wired into `aegis-proxy/src/data_plane.rs`
> with `cfg.ddos.enabled = true, observe_only = true` by default. Every
> per-IP burst that exceeds the limit emits an `ddos_observed` audit event
> but **the request still proceeds** — no 503 short-circuit until Phase 2
> flips `observe_only: false`. The cluster-wide / per-tenant target design
> below stays deferred behind multi-tenancy + ha-clustering. See
> [`BUG-DDOS-STUB`](../../reports/findings/2026-05-09-internal-audit-ddos/BUG-DDOS-STUB.md)
> for the original audit and
> [`plans/issue-fix/internal-audit-2026-05-09-ddos/`](../../plans/issue-fix/internal-audit-2026-05-09-ddos/)
> for the two-phase wire-up plan.
>
> See [`../../plans/plan.md`](../../plans/plan.md#1-doc-by-doc-implementation-status) for the full matrix.

> **What works today** (Phase 1 observe-only):
> - Per-IP burst detection (sliding window) — every request runs through
>   `DdosDetector::check`. Burst-exceeded events emit `ddos_observed` audit
>   entries with `path`, `method`, `ddos_observe_only: true`,
>   `ddos_spike_active`, `reason`. Operators grep audit for `ddos_observed`
>   to bake the signal before flipping enforce on.
> - EWMA spike-detection ticker runs once per second in a tokio task —
>   `current_rps`, `baseline_rps`, `is_spike_active` are reachable on
>   `Arc<DdosRuntime>` for future dashboard surface.
> - `StateBackend::auto_block` writes a TTL'd block entry on burst-exceed,
>   so a previously-blocked IP returns `blocked: true` from the cluster
>   keyspace on its next request — useful even in observe-only mode for
>   tracking which IPs would have been 503'd.
>
> **Already on the data path independently** (partial backstop, separate
> features): per-IP token-bucket rate limiting, velocity / login-flood
> limiter, risk-strikes auto-block (default 50 strikes → permanent block),
> adaptive load shedding (Gradient2).
>
> **Still deferred** for Phase 2 + later: 503 short-circuit on blocked IPs
> (the enforce flip), Prometheus counter / gauge surface, dashboard panel,
> per-tenant scoping (depends on `multi-tenancy.md` — DEFERRED), cluster-
> wide spike-mode broadcast (depends on `ha-clustering.md`).

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
