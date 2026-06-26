# DDoS spike detection — cross-node (fleet-wide) RPS aggregation

**Status:** Future / deferred design (not scheduled)
**Filed:** 2026-06-20
**Origin:** P3 deferred item from
[`../issues/PLAN-ddos-spike-enforcement-2026-06-20.md`](../issues/PLAN-ddos-spike-enforcement-2026-06-20.md)
(spike *enforcement* + hysteresis shipped; this is the remaining "cluster-wide" piece).
**Related:** [`../issues/PLAN-shed-per-pool-isolation-2026-06-20.md`](../issues/PLAN-shed-per-pool-isolation-2026-06-20.md),
[`../issues/PLAN-conn-layer-dos-gaps-2026-06-20.md`](../issues/PLAN-conn-layer-dos-gaps-2026-06-20.md) —
the other volumetric-DoS layers; this one only changes the **spike signal**, not the per-IP gate.

## Problem

Spike detection is **per-node**. Each node keeps its own rolling-RPS EWMA:
`DdosDetector::rolling_rps` (`crates/aegis-security/src/ddos.rs:212`) is a process-local
`AtomicU64`; `tick_rps` (`ddos.rs:~668`, scheduled every 1 s at
`crates/aegis-proxy/src/run.rs:1066`) compares **this node's** `current` against **this
node's** `baseline`. Config (`spike_multiplier`, `tightened_per_ip_rps`, dwell ticks) is
fleet-wide + durable via the config plane, but the *signal* that flips `spike_active` is local.

Consequences:
- A flood evenly fanned across N nodes raises each node's RPS to only `total/N`. If that per-node
  share stays under `spike_multiplier × baseline`, **no node engages spike** even though the
  fleet is clearly under attack. (In practice an LB usually fans a single source IP to every
  node so each node sees it — but that's an assumption, not a guarantee, and it breaks for
  many-IP distributed floods or sticky-session LBs.)
- Nodes can disagree: some engage, some don't → inconsistent per-IP tightening across the fleet
  for the same client, depending on which node terminates the connection.

This is **not** a correctness hole in the per-IP gate (that already auto-blocks per node and
propagates blocks cluster-wide via the backend); it's a **sensitivity/consistency** gap in the
surge *detector*.

## Why it was deferred

- For single-node / hackathon and LB-fan-to-all-nodes topologies, per-node detection is adequate
  (documented as such on `rolling_rps` and in `config/dev.yaml`).
- The per-IP **auto-block** is already cluster-wide via the `StateBackend`, so the most damaging
  single-IP floods are caught regardless.
- Adds a periodic Redis round-trip on the 1 s tick (cheap, but it's new shared-state coupling and
  a new failure mode to reason about).

## Design (proposed)

**Primitives already exist** — no new `StateBackend` methods needed:
`incrby` / `get_counter` / `expire` / `scan_prefix` are on the trait
(`crates/aegis-core/src/state.rs:175-200`) and implemented by both the in-memory
(`crates/aegis-proxy/src/state/in_memory.rs:288+`) and Redis backends.

**Per-second fleet counter (bucketed):**
1. On each request the node already bumps the local `rolling_rps`. Additionally, the **tick task**
   (not the hot path) writes this node's last-second count into a shared per-second bucket:
   `INCRBY ddos:fleet:rps:<epoch_sec> <node_count>` + `EXPIRE` a few seconds (TTL ≈ 3–5 s so old
   buckets self-clean; no `scan_prefix` sweep needed).
2. The tick task reads the **previous** complete second's bucket (`GET ddos:fleet:rps:<sec-1>`) as
   the fleet `current_rps`, and maintains the EWMA `baseline` over **fleet** values.
3. Spike compare + the existing P2 hysteresis/dwell run unchanged, but on fleet numbers → every
   node converges on the same `spike_active` within one tick.

**Keep it off the request hot path.** Aggregation is tick-only (1/s), so the per-request cost is
zero. The local `rolling_rps` accumulation stays as-is; only the 1 s tick gains the Redis I/O.

**`tick_rps` becomes async (or gains an async sibling).** It currently is sync (`fn tick_rps`).
Either:
- add `async fn tick_rps_fleet(&self)` used when a backend is wired, falling back to the local
  `tick_rps` when not, or
- make the scheduler do the I/O and pass the fleet `current` into a
  `tick_with_current(current: u64)` seam (keeps the EWMA/hysteresis logic unit-testable with
  injected values — matches how the P2 dwell tests already drive it).

**Failure mode = fail-safe to per-node.** If the backend read/write errors or times out, the tick
falls back to the local `rolling_rps` value (today's behaviour) and logs at debug. Spike detection
must never *block the tick* or panic on a Redis blip — degrade to per-node, don't fail closed.

**Config gate.** Add `ddos.spike_scope: per_node | fleet` (serde default `per_node` to preserve
current behaviour; flip to `fleet` when a backend is present). Surfaced in the dashboard DDoS
panel alongside the dwell knobs (same wiring as P2's `spike_engage_ticks`).

## Phases

- **P1** — ✅ Shipped 2026-06-26 (this PR). `DdosDetector::tick_with_current(current)` seam +
  `drain_rolling_rps()`; `tick_rps()` = drain + `tick_with_current`. EWMA/hysteresis now driven by
  an injected value. No behaviour change — the per-node dwell tests are the regression guard.
- **P2** — ✅ Shipped 2026-06-26 (this PR). `SpikeScope { per_node (default) | fleet }` on boot +
  runtime `DdosConfig` (+ derive). `DdosRuntime::fleet_current(node_count, now_epoch)` —
  `INCRBY ddos:fleet:rps:<epoch>` + `EXPIRE` (5 s TTL) + `GET ddos:fleet:rps:<epoch-1>` (prior
  complete second). `tick_rps_fleet_at(epoch)` (testable) / `tick_rps_fleet()` (scheduler, run.rs):
  drain → fleet sum in `fleet` scope, **fail-safe to per-node** on any backend error (debug log,
  never panics/stalls) → `tick_with_current`. `per_node` skips the backend entirely (byte-identical
  today). `spike_scope` round-trips through the `/api/gates/ddos` view + PUT so a dashboard edit
  can't clobber a YAML `fleet`.
- **P3** — *Partial.* API surface done (P2): `spike_scope` is in `DdosConfigView` + `DdosPutBody`.
  **Remaining:** the DDoS-panel JSX (show/edit `spike_scope`; display `fleet_rps` vs `node_rps`).
- **P4** — Docs: update `rolling_rps` / `dev.yaml` comments (drop the "deferred" breadcrumb),
  document the Redis key shape + TTL. **Remaining.**

## Acceptance gates

- [ ] Deterministic unit tests: injected per-second fleet sequence engages/releases identically to
      the per-node dwell tests (reuse the seam).
- [ ] Multi-node integration (or a 2-backend test): a flood split below per-node threshold but
      above fleet threshold engages spike on **all** nodes within ~2 ticks.
- [ ] Redis outage mid-run → tick degrades to per-node, no panic, no tick stall; recovers when
      Redis returns.
- [ ] `spike_scope: per_node` reproduces exactly today's behaviour (regression guard).
- [ ] No measurable per-request latency change (aggregation is tick-only).

## Risks

| Sev | Risk | Mitigation |
|---|---|---|
| MEDIUM | Redis on the 1 s tick adds a shared-state failure mode | Fail-safe to per-node on any error; tight timeout; never block the tick |
| LOW | Clock skew across nodes mis-buckets the per-second key | Read the *previous* complete second; TTL tolerates a few seconds of skew |
| LOW | Bucket key churn (1/s) | Short TTL self-cleans; no `scan_prefix` sweep |
| LOW | Behaviour change surprises operators | `spike_scope` defaults to `per_node`; opt into `fleet` explicitly |

## Out of scope

- Per-tier fleet aggregation (one global fleet RPS is enough; tiers tune limits, not the spike signal).
- Replacing the per-IP auto-block path (already cluster-wide via the backend).
- σ-band adaptive threshold (separate research item noted in the parent plan's P4).

## Complexity: MEDIUM
Primitives + scheduler + config gate exist; the work is the async seam, the fail-safe wiring, and
deterministic multi-node tests. The hysteresis/enforcement logic is already shipped and reused unchanged.
