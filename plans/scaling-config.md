# Scaling Configuration — `SC-T*` (a.k.a. "config workers")

> **Status:** **SC-T1 + SC-T2 + SC-T3 + SC-T5 ✅ shipped
> 2026-05-01.** SC-T4 (`tokio_unstable` runtime metrics) is the
> only remaining slice — optional polish, feature-gated, off
> by default. Track ID prefix `SC-T<n>`. Belongs alongside
> Phase B follow-ups.

## 0 · One-line summary

Surface the existing three-layer scaling model as a single
**Scaling** feature in the Aegis WAF Console — read controls for
all three layers, the one safe write (drain), and the missing
backing endpoint for Layer 3 health.

## 1 · Three-layer scaling model (recap — already shipped)

| Layer | Mechanism | Code today | Endpoint |
|---|---|---|---|
| **L1 — In-node** | `tokio::runtime` worker threads, `blocking_threads`, `cpu_affinity` | `aegis_core::config::RuntimeConfig` + `aegis-bin/main.rs::build_runtime` | `GET /api/runtime` (read-only) ✅ |
| **L2 — Cross-node** | HA cluster behind a single VIP (HAProxy / Envoy / k8s ingress) | `aegis_control::cluster::Roster` + `cluster-a.yaml` / `cluster-b.yaml` fixtures + `deploy/haproxy/haproxy.cfg` | `GET /api/cluster` (peers, is_leader) ✅ |
| **L3 — Shared state** | Redis primary (sub-ms, strong-within-primary); `in_memory` for dev; `ReconcilingBackend` for split-brain safety | `aegis_security::state::*` + `aegis-bin/state_select.rs` | **none today** — gap closes in SC-T1 |

Layer 1 is **restart-only** by design (tokio cannot resize a
running runtime). Layer 2 is operator-orchestrated (k8s / Helm
HPA / fleet manager — already in `deploy/helm/aegis-gate/`).
Layer 3 hot-swaps via `WafConfig` ArcSwap.

This plan does **not** invent new scaling mechanisms — it
exposes the ones already in production.

## 2 · Requirements restatement

The Console must show, for the running node:

1. The effective **Layer 1** sizing (workers, blocking threads,
   affinity) and whether the boot picked up the YAML the
   operator expected.
2. The current **Layer 2** roster (peers, leader, last-heartbeat
   per peer, "this is me" highlight) plus a single safe write —
   "drain this node".
3. **Layer 3** backend health — type, reachable Y/N, recent
   latency, replica lag, key count — the read-side gap that
   forces operators into `redis-cli` today.

It must **not** offer hot-edit of restart-only L1 knobs (a
slider would lie). It must **not** offer to add or remove cluster
peers (orchestrator's job).

## 3 · Phases

### SC-T1 — `GET /api/state` (Layer-3 health) — ✅ shipped 2026-05-01
**Target crate:** `aegis-control` + `aegis-proxy` (dispatch).

New module `aegis-control/src/api/state.rs` returning
`StateView`:

```rust
pub struct StateView {
    pub backend: &'static str,        // "redis" | "in_memory" | "reconciling"
    pub connected: bool,
    pub latency_us: Option<LatencyP>, // p50/p95/p99 over rolling window
    pub key_count: Option<u64>,       // best-effort DBSIZE; None on in_memory
    pub replica_lag_ms: Option<u64>,  // INFO replication offset diff
    pub server_version: Option<String>, // INFO server.redis_version
    pub circuit: CircuitState,        // open / half_open / closed + last_open_at
}
```

- **Source.** `StateBackend` trait gains a `fn health(&self) ->
  BackendHealth` default-method returning `BackendHealth::unknown()`;
  Redis impl populates from `INFO` + a rolling `RingBuffer<Duration>`
  fed by every `incr`/`get` round-trip.
- **Cache.** 5s server-side cache; admin port already polls
  /api/cluster at 5s, same cadence.
- **Wire-up.** Dispatch in `aegis-proxy/src/lib.rs` next to
  `/api/cluster` and `/api/runtime`.
- **Tests.** Unit tests in `state.rs` (round the percentile
  computation; verify in_memory backend reports
  `connected: true, key_count: None`); router smoke test in
  `crates/aegis-control/tests/router_smoke.rs` for
  `/api/state` shape.
- **OpenAPI.** Add path + schema to
  `docs/control-plane/api.openapi.yaml`.

### SC-T2 — Console "Scaling" page — ✅ shipped 2026-05-01
**Target:** `crates/aegis-control/assets/dashboard/src/`.

- New route `/scaling` (icon `Workers`, label `Scaling`) inserted
  after Cluster in the nav.
- One card per layer, stacked top-to-bottom:
  - **L1 card** — `useRuntimeApi()` (already exists in
    `data.jsx:405`). Shows `workers / host_logical_cpus`, mode
    badge (`auto`/`fixed`), `blocking_threads`, `stack_size_kb`,
    affinity badge ("active"/"requested but inactive"/"off").
    Footer note: "Restart required to change. Edit
    `runtime:` in waf.yaml."
  - **L2 card** — `useClusterApi()` (already exists in
    `data.jsx:399`). Peers table (`node_id`, `healthy`, `leader`,
    `last_heartbeat_age`). Our node highlighted. Single button
    **Drain this node** → `POST /admin/drain` (already
    audit-mutated, CSRF-gated). Double-confirm modal before
    POST.
  - **L3 card** — new `useStateApi()` hook (calls SC-T1's
    endpoint). Backend pill, connected dot, p50/p95/p99 latency
    chips, key count, replica lag. Sparkline of last 60 latency
    samples (re-uses the existing `<Sparkline>` widget).
- Empty / fallback states for every field — consistent with
  CI-T1..CI-T8 conventions.
- i18n strings in `i18n.json` (en + zh tracks already
  established).

### SC-T3 — Settings page hint — ✅ shipped 2026-05-01
**Target:** `pages.jsx::PageSettings`.

One-liner banner above the settings list when `useRuntimeApi()`
returns a `runtime:` block: "Runtime sizing (workers, blocking
threads, CPU affinity) is restart-only — see the
[Scaling page](#/scaling)." No layout churn.

### SC-T4 — Tokio unstable runtime metrics → Prometheus
**Target:** `aegis-bin` (feature gate) + `aegis-proxy/src/metrics.rs`.

- Add `tokio_unstable` Cargo feature alias on `aegis-bin`
  (off by default — opt-in to keep production builds on
  stable APIs).
- When enabled, expose:
  - `aegis_runtime_active_workers`
  - `aegis_runtime_blocking_queue_depth`
  - `aegis_runtime_blocking_threads`
  - `aegis_runtime_io_driver_fd_count`
- Wire into the L1 card "Runtime metrics" mini-strip.
- Document the trade-off in `runtime-tuning.md` — the
  `tokio_unstable` flag implies non-SemVer guarantees from
  tokio.

### SC-T5 — Doc consolidation — ✅ shipped 2026-05-01
**Target:** `docs/`.

- New landing page `docs/architecture/scaling-model.md` —
  3-section overview that cross-links the three layer-specific
  docs. No duplication of existing content.
- Update `docs/operations/runtime-tuning.md` § Verifying →
  point to the new Scaling page.
- Update `docs/operations/ha-clustering.md` § Cluster topology →
  add 1-line "operator visibility: /api/cluster +
  /api/state".
- Update `docs/control-plane/api.md` — add `/api/state` row in
  the endpoint table.
- Update `docs/control-plane/api.openapi.yaml` — full schema
  (already noted in SC-T1).
- Refresh `docs/control-plane/enterprise/README.md` (design
  spec) with the Scaling page.

## 4 · Impact on currently-shipped features (the question the user asked)

| Area | Impact | Why |
|---|---|---|
| `/api/runtime` | **None** — already shipped, remains read-only | SC-T2 just consumes it |
| `/api/cluster` | **None** — already shipped | SC-T2 just consumes it |
| `/admin/drain` | **None** — already audit-mutated, CSRF-gated | SC-T2 binds the existing endpoint to a button |
| Settings page (CI-T6 / CI-T12) | **Cosmetic** — adds the SC-T3 banner | One paragraph; no logic change |
| Hot-reload pipeline | **None** — restart-only invariant on `runtime:` is preserved server-side | Validation already rejects PUT to those keys |
| Audit chain | **None** — only existing audit-mutated endpoints called | No new mutations introduced |
| State backend (Redis impl) | **Trait surface adds `health()` default-method** — backwards compatible | Default returns "unknown"; only Redis impl populates real numbers |
| OpenAPI contract | **Adds `/api/state` path** — additive, no break | New optional endpoint |
| `tests/api/openapi-shape.sh` (25-check) | **+1 check** for `/api/state` schema | Trivial extension |
| Helm chart / Dockerfile | **None** | No new ports, no new deps |
| `cargo test --workspace` | **+~15 tests** (state handler + router smoke + i18n) | Net positive coverage |
| Bundle size budget (256 KB) | **+~3-5 KB** for the Scaling page React component | Comfortably inside budget |

**Nothing in the existing feature set degrades or changes
contract.** This is a pure additive surface.

## 5 · Out of scope (deferred / explicit non-goals)

- Hot-resize of tokio worker pool — tokio API doesn't permit it.
- Per-route worker pinning / multi-runtime — not in the model.
- Auto-scaler logic — Helm `HorizontalPodAutoscaler` already handles it; not the WAF's job.
- Cluster membership write-API — orchestrator's job; would require leader election + quorum work that breaks the "operator owns topology" invariant.
- Redis Cluster slot-hashing — tracked separately in the
  Phase B "not yet" list; would change SC-T1's response shape
  if/when it lands.
- Multi-tenancy splits per the "Future phases" pointer.

## 6 · Risks

| Risk | Severity | Mitigation |
|---|---|---|
| `INFO` against a busy Redis adds load | LOW | 5s server-side cache; identical cadence to /api/cluster |
| `tokio_unstable` flag breaks on tokio bump | LOW | Feature-gated; default off; CI matrix includes the off-state |
| Drain button mis-click | MEDIUM | Double-confirm modal; show drain side-effects ("readiness flips to 503; LB pulls node") |
| L3 latency widget hides a real outage | LOW | Sparkline + numeric chips; pill turns red on `connected=false` |
| Scaling page extends nav past the existing density | LOW | Replaces nothing; insertion after Cluster is natural |

## 7 · Estimated complexity: **MEDIUM**

| Phase | Work |
|---|---|
| SC-T1 | 3-4 h (Rust handler + StateBackend trait health() default + Redis impl + tests + OpenAPI) |
| SC-T2 | 4-5 h (React page + nav + i18n + drain modal + sparkline reuse) |
| SC-T3 | 1 h (copy update + link) |
| SC-T4 | 2-3 h (tokio_unstable feature + metrics + doc note) |
| SC-T5 | 2 h (doc merge + screenshots + OpenAPI) |
| **Total** | **12-15 h** |

SC-T4 is optional polish — sequence as `T1 → T2 → T3 → T5 → T4`
so the page ships without depending on the unstable flag.

## 8 · Sequencing & dependencies

```
SC-T1 (state endpoint)
   └─> SC-T2 (Scaling page consumes T1)
         └─> SC-T3 (Settings hint links to T2)
               └─> SC-T5 (doc cross-links to T2)
SC-T4 (optional metrics) — independent, can land anytime after T2
```

T1 is the only piece that touches Rust crates; T2/T3 are dashboard
edits; T5 is markdown only; T4 is opt-in.

## 9 · Definition of Done

- [ ] `GET /api/state` documented in OpenAPI, returns the full
      shape, cached at 5s.
- [ ] Scaling page renders all three cards with real data on a
      healthy node.
- [ ] Drain button drains via the existing `/admin/drain` and
      flips `/healthz/ready` to 503.
- [ ] Settings page shows the runtime-restart hint linking to
      Scaling.
- [ ] `cargo test --workspace` green (no regressions; +~15 tests).
- [ ] Bundle ≤ 256 KB after SC-T2.
- [ ] OpenAPI shape smoke (`tests/api/openapi-shape.sh`) green
      with the new check.
- [ ] `docs/architecture/scaling-model.md` published; the three
      layer-specific docs cross-link to it.
- [ ] `Implement-Progress.md` Last Completed entry follows § 0.3
      protocol.

## 10 · Files (likely touched)

- `crates/aegis-core/src/state.rs` — add `BackendHealth` +
  default `health()` on the trait
- `crates/aegis-security/src/state/redis.rs` — populate health
  via `INFO` + rolling latency buffer
- `crates/aegis-control/src/api/state.rs` — new module
- `crates/aegis-control/src/api/mod.rs` — `pub mod state;`
- `crates/aegis-control/src/dashboard/dispatch.rs` — route
- `crates/aegis-proxy/src/lib.rs` — `/api/state` dispatch arm
- `crates/aegis-control/assets/dashboard/src/data.jsx` —
  `useStateApi()` hook
- `crates/aegis-control/assets/dashboard/src/pages.jsx` —
  `PageScaling`
- `crates/aegis-control/assets/dashboard/src/app.jsx` — nav
  + route
- `crates/aegis-control/assets/dashboard/src/widgets.jsx` —
  reuse `<Sparkline>` if needed
- `crates/aegis-control/assets/dashboard/i18n.json` — strings
- `docs/control-plane/api.openapi.yaml` — `/api/state` path +
  `StateView` schema
- `docs/control-plane/api.md` — endpoint row
- `docs/architecture/scaling-model.md` — new
- `docs/operations/runtime-tuning.md` — cross-link
- `docs/operations/ha-clustering.md` — cross-link
- `tests/api/openapi-shape.sh` — +1 check
- `Implement-Progress.md` — track entry + next task
- `plans/README.md` — status-board row

---

**Awaiting confirmation.** Reply `proceed` to start with SC-T1
(`/api/state` endpoint), or `modify: …` to adjust the plan
(e.g. "drop SC-T4", "rename track to RT-T*", "merge SC-T1 into
SC-T2").
