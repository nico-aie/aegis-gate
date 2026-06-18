---
id: 2026-06-18-healthz-ready-misreports-redis-down
date: 2026-06-18T07:55Z
severity: MEDIUM
area: admin-api
component: health (/healthz/ready, state_backend_up)
status: open
test_mode: full-qc
---

# `/healthz/ready` reports `state_backend_up: true` while Redis is down

## Summary
With the WAF's Redis backend fully stopped (`docker stop aegis-cluster-redis`),
the dashboard state endpoint `/api/state` correctly detects the outage
(`connected: false`, `circuit: half_open`, `key_count: null`), **but the
machine-readable readiness probe `/healthz/ready` keeps reporting
`checks.state_backend_up: true` and overall `status: "ok"`** for the entire
outage window. The two health surfaces disagree. An orchestrator, load
balancer, or monitoring system that polls `/healthz/ready` (the standard
integration point, and the endpoint the benchmarker uses for startup per
contract §8) would never observe that the state backend degraded.

The underlying behavior is otherwise excellent — see "Not a bug" below.

## Repro
1. Confirm baseline: `GET /healthz/ready` → `checks.state_backend_up: true`,
   `GET /api/state` → `connected: true`.
2. Stop the WAF's Redis: `docker stop aegis-cluster-redis` (the container bound
   to `127.0.0.1:6379`).
3. Poll both endpoints for ~15 s:

```
/api/state      -> { backend:"reconciling", connected:false,
                     circuit:"half_open", key_count:null }     # correct
/healthz/ready  -> { status:"ok",
                     checks:{ state_backend_up:true, ... } }   # WRONG
/healthz/live   -> 200                                         # fine (process alive)
```

`state_backend_up` stayed `true` across 7 consecutive samples (0–12 s) while
`/api/state.connected` was `false` the whole time.

## Expected
`/healthz/ready.checks.state_backend_up` should reflect the same backend
connectivity `/api/state` already computes — i.e. flip to `false` when the
Redis circuit is open/half-open and `connected:false`. Whether the overall
`status` should remain `ok` (degraded-but-serving) or move to a
`degraded`/`warn` value is a design choice, but the `state_backend_up` boolean
must not contradict the actual connection state.

## Actual
`state_backend_up` is hard-`true` independent of the live Redis connection
state; `/healthz/ready` and `/api/state` are driven by different code paths and
the readiness path does not consult the same circuit/connection signal.

## Suggested fix
Source `state_backend_up` from the same `StateBackend` health/circuit signal
that `/api/state` reads (`connected` && circuit==closed/half_open-probing).
Add a regression test that stops/black-holes the backend and asserts
`/healthz/ready.checks.state_backend_up == false` while `/healthz/live` stays
`200`.

## Severity rationale
MEDIUM. It does not affect traffic handling — the data plane stays fully
operational (see below) — so it is not HIGH. But a health-check field named
`state_backend_up` returning `true` during a real backend outage actively
masks the incident from any automated monitor/orchestrator consuming the
standard readiness endpoint, which is precisely when accurate signal matters.
The operator-facing dashboard is unaffected (it reads `/api/state`, which is
correct), which caps the blast radius below HIGH.

## Not a bug (strong positive, recorded for context)
With Redis down, the WAF degraded gracefully via in-memory fallback:
- process stayed alive (`/healthz/live` 200), control plane responsive (200);
- data plane kept serving: clean → `allow` (7 ms), XSS → `block`;
- risk scoring still escalated correctly with no Redis: allow:25 → challenge:50
  → challenge:75 → block:100 (~2 ms/req).
This is exactly the documented "Redis-primary + local-fallback" behavior, and
it works. Only the `/healthz/ready` reporting is wrong.
