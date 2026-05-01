# Scaling Model

> **Three-layer scaling model.** Every WAF deployment scales along
> three independent axes — in-node CPU, cross-node redundancy, and
> shared state. The Aegis WAF Console surfaces all three on one
> page (the **Scaling** route under Tracking) so operators can
> verify each layer without reaching into config files or
> `redis-cli`.
>
> This page is the reading-order entry. Each layer has its own
> deeper doc; cross-links below.

## Why three layers

A single-process WAF can scale up only as far as one box's CPU and
one network card. Beyond that, scaling is necessarily *out* — onto
more boxes — and any state shared between requests (rate-limit
counters, risk scores, auto-block lists) has to live somewhere
both boxes can see.

That gives three orthogonal scaling axes:

| Layer | Axis | Goal | Mechanism in Aegis |
|---|---|---|---|
| **L1** | In-node CPU | Higher single-box throughput | tokio worker threads + CPU affinity |
| **L2** | Across nodes | Redundancy + horizontal capacity | HA cluster behind a single VIP |
| **L3** | Shared state | Cross-node consistency | Redis primary (or in-memory for dev) |

None of these *replaces* the others. A two-node cluster (L2) with
a single tokio worker per node (L1) and an in-memory backend (L3,
dev only) is a valid topology — it just trades capacity for
operational simplicity. The console renders each layer
independently so operators can see each tradeoff explicitly.

## Layer 1 — In-node workers (`runtime:`)

**What it controls.** The size of the tokio worker pool and the
blocking-thread auxiliary, plus optional CPU affinity pinning.
Each request lives on one worker; CPU-bound detector chains
benefit from more workers up to the box's logical-CPU count.

**Restart-only by design.** tokio cannot resize a running
runtime — there is no API for "add another worker". The
console's L1 card reflects this: it shows the effective sizing
but offers no slider. Changes go into `waf.yaml` under
`runtime:` and require a process restart (or rolling restart in
HA mode).

**Endpoint.** `GET /api/runtime` returns the boot-effective
sizing (`workers`, `workers_mode`, `blocking_threads`,
`stack_size_kb`, `cpu_affinity_*`, `host_logical_cpus`). Cached
60 s — the answer is stable across the process lifetime.

**Deep dive.** [`docs/operations/runtime-tuning.md`](../operations/runtime-tuning.md)
covers sizing recipes (CPU-bound vs IO-bound), the affinity
feature flag, and the boot-time verification protocol.

## Layer 2 — Cross-node cluster (`cluster:` + LB)

**What it controls.** Redundancy across boxes, behind a single
virtual IP (HAProxy / Envoy / k8s ingress / cloud LB). Every
node runs the full stack (data plane + admin plane); the LB
distributes data-plane traffic by L4 or L7. Admin-plane traffic
goes to whichever node the operator picks (typically the
leader, but any node serves identical reads).

**Operator-orchestrated.** The console exposes the *roster*
(peers, leader, last-heartbeat age) and the single safe write —
"drain this node" — but never offers add/remove peer mutations:
that's the orchestrator's job (k8s `HorizontalPodAutoscaler`,
Helm chart upgrades, Nomad jobs, fleet manager). Aegis trusts
the orchestrator to own topology.

**Endpoint.** `GET /api/cluster` returns the peers list with
healthy/down state and last-heartbeat age. `POST /admin/drain`
flips this node's readiness to 503 so the LB pulls it within
one health-check interval.

**Deep dive.** [`docs/operations/ha-clustering.md`](../operations/ha-clustering.md)
covers the roster schema, leader election, witness reconciliation,
and split-brain safety. LB patterns
(HAProxy / Nginx / k8s) live in the same doc under "Load
balancer patterns".

## Layer 3 — Shared state (`state:` backend)

**What it controls.** Where rate-limit counters, risk scores,
auto-block lists, and session nonces live. Three backends ship:

- **`in_memory`** — process-local DashMap. Sub-microsecond ops.
  Loses state on restart. Single-node only — counters reset and
  rate-limits don't share across the cluster.
- **`redis`** — primary Redis (optionally with replicas). Sub-
  millisecond ops. Strong-within-primary consistency. The
  production default for HA clusters.
- **`reconciling`** — Redis primary with in-memory fallback.
  Buffers writes during partition; replays on heal. Trades
  per-op latency for split-brain safety.

**Hot-swap-able at boot only today.** Backend selection lives
under `state.backend` in `waf.yaml`; changing it requires a
restart (the trait is `Arc<dyn StateBackend>` baked into the
boot path). Future work could add live backend swap, but the
operational story (cutting Redis over without losing counters)
is hard enough that boot-only is the safer default.

**Endpoint.** `GET /api/state` returns the current backend
identifier, reachability, latency p50/p95/p99 (microseconds),
key count (best-effort `DBSIZE` for Redis), worst-case primary-
to-replica lag, server version, and circuit-breaker state.
Cached 5 s server-side so dashboard polls don't add load.

**Deep dive.** Backend implementations live in
`crates/aegis-proxy/src/state/{in_memory,redis,reconcile}.rs`.
The trait + health types are in `crates/aegis-core/src/state.rs`.

## Operator visibility — the Scaling page

The Console (admin port) renders all three layers at
`#/scaling`:

- **L1 card** — workers, mode badge, blocking pool, affinity.
  Reads `/api/runtime`. Restart-only footer note.
- **L2 card** — peers table, our-node highlight, leader badge,
  `Drain this node` button (two-step confirm).
  Reads `/api/cluster`, posts `/admin/drain`.
- **L3 card** — backend pill, connected dot, latency chips,
  key count, replica lag, circuit pill. Reads `/api/state`.

Polling cadence: L1 60 s (rarely changes), L2 5 s, L3 5 s
(matches the Redis backend's server-side cache TTL).

A one-line banner on the Settings page reminds operators that
runtime sizing is restart-only and links them here — that's
the only place a "workers" knob would otherwise be expected.

## What's *not* in the model

These are deliberate exclusions, not roadmap items:

- **Hot-resize of tokio worker pool** — tokio API doesn't
  permit it. Operators restart instead.
- **Per-route worker pinning / multi-runtime** — not in scope;
  routes share the runtime.
- **Auto-scaler logic** — Helm `HorizontalPodAutoscaler`
  already handles it. The WAF stays out of orchestration.
- **Cluster membership write API** — orchestrator's job.
  Adding peer-add/remove mutations would require leader
  election + quorum work that breaks the "operator owns
  topology" invariant.
- **Redis Cluster slot-hashing** — tracked separately in the
  Phase B "not yet" list; would change `/api/state`'s response
  shape (per-shard health) when it lands.

## Related

- [Operations · Runtime tuning](../operations/runtime-tuning.md)
  — L1 sizing recipes and verification.
- [Operations · HA clustering](../operations/ha-clustering.md)
  — L2 roster, leader election, LB patterns.
- [Control plane · API reference](../control-plane/api.md) —
  HTTP shapes for `/api/runtime`, `/api/cluster`, `/api/state`.
