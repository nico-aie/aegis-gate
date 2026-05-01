# Run 13 — 2026-05-01 — SC-T1 + SC-T2 verification

End-to-end verification after **SC-T1** (`/api/state` Layer-3
backend health endpoint) + **SC-T2** (Console "Scaling" page)
landed.

## Headline

| Surface | Result |
|---|---|
| **Workspace tests** | 173 (core, +10 SC-T1) + 862 (control, +9 SC-T1) + 426 default / 463 etcd (proxy, +2 SC-T1) + 41 (bin) + 888 (security) = **2,402 default-feature** |
| **`cargo build -p aegis-bin --features production`** | Clean |
| **Dashboard bundle** | `app.js` 192,132 B (188 KB) — within 256 KB budget |
| **`/api/state` live** | Returns `{"backend":"in_memory","connected":true,"key_count":0,"circuit":{"state":"closed"}, …}` HTTP 200 against `config/dev.yaml` (in-memory backend) |
| **Scaling page** | Renders L1 + L2 + L3 cards in one stack — see `screenshots/scaling.png` |
| **Existing pages** | 12 prior screenshots still OK; new total **13/13 pages** rendered |

## Live `/api/state` round-trip

```
$ curl -s http://127.0.0.1:9443/api/state
{
  "backend": "in_memory",
  "connected": true,
  "latency": null,
  "key_count": 0,
  "replica_lag_ms": null,
  "server_version": null,
  "circuit": { "state": "closed" }
}
```

Note: `latency: null` because the in-memory backend doesn't
measure round-trip latency — only the Redis impl populates
the rolling sample buffer. `key_count: 0` matches a fresh
boot before any traffic touches the state plane.

## What works (verified live)

### SC-T1 — Layer-3 backend health endpoint

- `BackendHealth` / `LatencyP::from_samples` (nearest-rank
  percentile) / `CircuitState { Closed | HalfOpen | Open { … } }`
  added to `aegis-core::state`.
- Default `health()` on the `StateBackend` trait returns
  `BackendHealth::unknown()` — backwards-compatible.
- **In-memory backend**: `connected: true`, `key_count` =
  `DashMap::len`, latency / replica / version omitted.
- **Redis backend** (`--features redis`): 5 s server-side
  cache; `PING` + `INFO server` + `INFO replication` +
  `DBSIZE`; 256-sample rolling latency ring fed by every
  `with_timeout` op so percentiles reflect real traffic;
  circuit derives from PING success + a recent-error timer.
- **Reconciling backend**: proxies primary, rebrands
  `backend` to `"reconciling"`, forces `HalfOpen` while
  partitioned.
- **MeteredStateBackend** (the wrapper applied at boot)
  forwards `health()` to its inner backend so the dashboard
  sees the real backend identifier, not `"unknown"`.
- `aegis-control/src/api/state.rs` defines `StateView`
  (externally-tagged `state` field on `circuit`).
- Wired through `DashboardServices.state_backend:
  Option<Arc<dyn StateBackend>>` (None falls back to unknown
  for test bundles).
- `aegis-proxy::admin_dispatch::handle_admin_request`
  intercepts `GET /api/state` ahead of the sync
  `admin_router` (sync can't `.await` health()).
- OpenAPI: `/api/state` path + `StateResponse` /
  `StateLatency` / `StateCircuit` schemas in
  `docs/control-plane/api.openapi.yaml`.

### SC-T2 — Console "Scaling" page

- New nav item **Scaling** under Tracking group, hash route
  `#/scaling`.
- Three cards stacked top-to-bottom:
  - **L1 In-node workers** (consumes `useRuntimeApi`):
    workers (with logical-CPU context), mode badge
    (auto/fixed), blocking-pool size + stack, CPU affinity
    state (active / requested-inactive / off). Footer note
    documents that L1 is restart-only.
  - **L2 Cluster peers** (consumes `useClusterApi`):
    peers table (node, healthy/down pill, last-heartbeat
    age, leader/replica role), our-node row highlighted.
    **Drain this node** button gated behind a two-step
    confirm (idle → "Confirm — drain X?" → final POST).
    Posts to existing audit-mutated `/admin/drain` with
    CSRF cookie+header. Result pill (drained / failed)
    rendered after the response.
  - **L3 Shared state** (consumes new `useStateApi`,
    polled every 5 s to match Redis cache TTL):
    Connection live/down pill, Circuit closed/half_open/open
    pill (with last-open timestamp on open), Keys count
    (DBSIZE), Replica lag (warn pill ≥ 1 s), p50/p95/p99
    latency chips (auto-formatted µs / ms / s).
- Empty / fallback states for every field — matches the
  CI-T1..CI-T8 conventions used elsewhere in the dashboard.
- i18n strings (`scaling.*` keys) in `i18n.json` — 36 new
  entries.

## Files touched

### Rust (SC-T1)

- `crates/aegis-core/src/state.rs` — `BackendHealth`,
  `LatencyP`, `CircuitState`, default `health()` on the
  trait.
- `crates/aegis-proxy/src/state/in_memory.rs` —
  `health()` override.
- `crates/aegis-proxy/src/state/redis.rs` —
  `LatencyRing`, `CachedHealth`, `parse_info_field`,
  `compute_replica_lag_ms`, `health()` override.
- `crates/aegis-proxy/src/state/reconcile.rs` —
  `health()` proxy with re-brand + partition force.
- `crates/aegis-control/src/api/state.rs` (new) — wire
  shape + serde tags.
- `crates/aegis-control/src/api/mod.rs` — `pub mod state;`.
- `crates/aegis-control/src/dashboard_services.rs` —
  `state_backend: Option<Arc<dyn StateBackend>>`.
- `crates/aegis-control/src/metrics/state_ops.rs` —
  `MeteredStateBackend::health` forwards to inner.
- `crates/aegis-proxy/src/admin_dispatch.rs` —
  `/api/state` async dispatch arm + `handle_state_get`.
- `crates/aegis-proxy/src/accept.rs` —
  `admin_accept_loop` accepts the new `state_backend`
  parameter and stamps it on `services`.
- `crates/aegis-proxy/src/run.rs` — passes the metered
  backend through to `admin_accept_loop`.
- `crates/aegis-control/tests/api_smoke.rs` — +2 SC-T1
  integration tests (unwired → unknown / wired → backend
  health via stub `StateBackend`).
- `docs/control-plane/api.openapi.yaml` — `/api/state` +
  `StateResponse` / `StateLatency` / `StateCircuit`.

### Dashboard (SC-T2)

- `crates/aegis-control/assets/dashboard/src/data.jsx` —
  `useStateApi` hook + `adminDrainPost` helper + window
  exports.
- `crates/aegis-control/assets/dashboard/src/pages.jsx` —
  `PageScaling` (with `ScalingL1Card`, `ScalingL2Card`,
  `ScalingL3Card` sub-components, `Stat` and `LatencyChip`
  primitives).
- `crates/aegis-control/assets/dashboard/src/app.jsx` —
  nav entry + route case for `scaling`.
- `crates/aegis-control/assets/dashboard/i18n.json` — 36
  new `scaling.*` keys.
- `tests/dashboard/capture-screenshots.mjs` — `scaling`
  added to `ROUTES` (12 → 13).

## Run context

| Field | Value |
|---|---|
| Date | 2026-05-01 |
| Host | macOS 23.1.0 arm64, 12 logical CPUs |
| Binary | `target/release/waf` built `--features "redis alerts"` |
| Config | `config/dev.yaml` (in-memory state, single mock upstream :9999) |
| Bundle | `app.js` 188 KB |
| Playwright | npm `playwright@1.59.1` |

## What's next

- **SC-T3** — Settings-page banner pointing to Scaling
  (~1 h, pure markdown + JSX one-liner).
- **SC-T5** — Doc consolidation
  (`docs/architecture/scaling-model.md` + cross-links).
- **SC-T4** (optional polish) — `tokio_unstable` runtime
  metrics → Prometheus.
- After SC-T3/T5: resume **MTLS-T2** (rustls inbound
  wiring) per `plans/mtls.md`.
