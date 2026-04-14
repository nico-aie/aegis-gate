# Graceful Degradation & Circuit Breaker (v2)

> **v1 → v2:** circuit breaking is now **per upstream pool member** (not
> per backend), driven by the [`upstream-pools.md`](./upstream-pools.md)
> health manager, and coordinated with
> [`adaptive-load-shedding.md`](./adaptive-load-shedding.md) so the cluster
> sheds lowest-tier traffic before CRITICAL requests ever see a degraded
> path. Fail-close/fail-open is now **per route**, not just per tier.

## Purpose

Under failure — broken detector, dead backend, saturated thread pool —
the WAF must behave **predictably**. Never block everything; never let
everything through. The degradation policy governs exactly what happens
when a subsystem misbehaves.

## Failure modes

### Subsystem failure (detector crash, timeout)

Each pipeline stage runs inside a `tokio::time::timeout` with a per-tier
budget (default 2 ms). A panic is caught by `catch_unwind`. On failure:

- **CRITICAL route**: fail-close → 503, request never forwarded
- **HIGH / MEDIUM / CATCH-ALL**: fail-open → skip the stage, log, continue
- **Per-route override**: a non-CRITICAL route can opt into fail-close

### Upstream pool failure

The pool manager owns the circuit breaker state per **member**:

1. Active health probes + passive counters feed a failure window
2. `closed → open` when failures exceed threshold in the window
3. `open → half-open` after cooldown; one probe
4. `half-open → closed` on success, `→ open` on failure

While a member is open it is removed from the LB ring. If **all** members
of a pool are open:

- CRITICAL: 503 (fail-close)
- Other tiers: serve from [`smart-caching.md`](./smart-caching.md) when
  possible, otherwise 503
- Circuit events are emitted as `operational` audit events

### Config reload failure

Handled by the dry-run validator in [`config-hot-reload.md`](./config-hot-reload.md):
a bad candidate is rejected, the running config is preserved, and a
high-severity `config_reload_failed` event is emitted.

### State-backend failure

If Redis / Raft is unreachable:

- Rate limiter falls back to **local counters** with a warning banner
- Clustered block list falls back to the last-known snapshot (bounded TTL)
- DDoS global mode freezes in its current state rather than flipping

See [`ha-clustering.md`](./ha-clustering.md) for split-brain safety.

### Resource exhaustion

- OOM: process crashes; supervisor restarts; peers take over traffic
- FD exhaustion: listener backs off, `operational` event emitted
- Thread saturation: `tower::limit` + adaptive shedder return 503 early

## Circuit breaker state machine

```
            failures >= threshold
    CLOSED ──────────────────────────► OPEN
      ▲                                  │
      │ probe success           cooldown │
      │                          elapsed │
      │                                  ▼
      └──────────── HALF-OPEN ◄──────────┘
```

## Timeouts

| Stage | Default | Rationale |
|---|---|---|
| TLS handshake | 3 s | Network variability |
| Request parsing | 5 s | Slowloris defense |
| Body read | 30 s | Legitimate large uploads |
| Per-layer pipeline budget | 2 ms | Keep p99 ≤ 5 ms overhead |
| Total pipeline (pre-forward) | 10 ms | Hard ceiling |
| Backend connect | 2 s | Fast-fail dead backends |
| Backend request | 10 s | Typical app SLA |
| State-backend op | 5 ms | Fail to local counters beyond this |

Exceeding a per-layer budget triggers the tier's failure mode. Exceeding
a hard timeout returns 504.

## Configuration

```yaml
graceful_degradation:
  per_layer_budget_ms: 2
  total_pipeline_budget_ms: 10
  circuit_breaker:
    enabled: true
    failure_threshold: 5
    failure_window_s: 30
    open_duration_s: 30
    half_open_probes: 1
  timeouts:
    tls_handshake_ms: 3000
    request_parse_ms: 5000
    body_read_ms: 30000
    upstream_connect_ms: 2000
    upstream_request_ms: 10000
    state_backend_ms: 5
  per_route_overrides:
    "/payments/*": { failure_mode: fail_close }
```

## Dashboard signaling

- Red banner when any pool member's circuit is open
- Warning when a detector has failed-open > N times in the last minute
- Yellow banner when state backend falls back to local mode

## Implementation

- `src/upstream/circuit.rs` — per-member state machine
- `src/pipeline/degrade.rs` — per-stage timeout + panic catcher
- `src/state/fallback.rs` — backend-failure fallback
- `src/config/schema.rs::FailureMode` — per-route override

## Performance notes

- Circuit check is a single atomic load per member on the hot path
- Timeouts are per-future with `tokio::time::timeout`, no thread overhead
- Fail-open skip does not allocate
