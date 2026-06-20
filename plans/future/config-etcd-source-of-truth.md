# Config source-of-truth: Redis → etcd — durable config plane on a real KV/watch store

**Status:** Future / deferred design (not scheduled)
**Filed:** 2026-06-20
**Origin:** Resource-constrained hackathon shortcut — Redis was reused as the
config store to avoid a second infra dependency. This plan revisits that once
the constraint lifts.
**Related:** [`config-auto-restore.md`](./config-auto-restore.md) (the
durability follow-up this would subsume), [`world-class-waf-roadmap.md`](./world-class-waf-roadmap.md),
[[project_config_plane_doc_vs_file]], [[project_api_mode_no_cluster_publish]],
[[project_apply_and_swap_helper_guard]]

## Problem

The config **source of truth** is a single versioned document in Redis,
`config:waf:doc` (`crates/aegis-proxy/src/config_source/config_store.rs:34`),
with immutable per-version snapshots `config:waf:v:{n}` and a pub/sub nudge on
`config:waf:bump`. The sibling **control plane** (interop modes, reset-epoch,
access-lists) lives in `control:waf:*`
(`crates/aegis-control/src/interop/cluster_sync.rs:41-208`). Both are durable,
low-write, fleet-wide-consensus data — exactly what a real consensus KV store
is built for, and exactly what Redis is *not*.

Redis was chosen because it was already in the stack for the hot path
(rate-limit windows, risk scoring, nonces, leases, smart-cache L2). Folding
config onto it meant one fewer dependency during the hackathon. But for the
durable config plane specifically it has real seams:

- **No native watch.** Convergence is a **3 s poll** (`DEFAULT_POLL`,
  `crates/aegis-proxy/src/config_source/redis_source.rs:39`) *plus* a best-effort
  `config:waf:bump` pub/sub nudge. Redis pub/sub is fire-and-forget: a node that
  is briefly disconnected **misses** the nudge and only catches up on the next
  poll tick. The poll exists precisely to paper over that gap.
- **CAS is bolted on.** Optimistic concurrency uses a hand-written Lua script
  (`cas_script`, `crates/aegis-proxy/src/state/redis.rs:658-684`) rather than a
  first-class transaction. It works, but every durable-write primitive is
  re-implemented in Lua.
- **Durability is not guaranteed by default.** A Redis restart without AOF/RDB
  returns an **empty** `config:waf:doc` — the failure mode that
  [`config-auto-restore.md`](./config-auto-restore.md) exists to recover from.
  etcd is durable-by-design (Raft log + fsync), removing the root cause rather
  than detecting-and-restoring after it.
- **Per-node ACK TTLs are emulated.** `config:waf:applied:<node>` uses a 30 s
  `PSETEX` TTL (`config_store.rs:52,246-254`) to expire stale node ACKs — a
  pattern etcd expresses natively with **leases**.

Consequences:

- Convergence latency on a missed nudge is bounded only by the 3 s poll, not by
  the change event.
- Two re-implemented primitives (Lua CAS, TTL ACKs) that a consensus store
  offers as built-ins.
- Config durability depends on correct Redis AOF provisioning, an
  easy-to-misconfigure operational footgun.

## Why Redis was chosen (and why that was right at the time)

- One dependency, not two. Redis was already mandatory for the ephemeral hot
  path; config rode along for free.
- The `StateBackend` / `FleetBus` trait abstraction
  (`crates/aegis-core/src/state.rs:134-253`, `crates/aegis-core/src/fleet.rs:32-45`)
  meant config was **never coupled to Redis directly** — the cost of the
  shortcut was deliberately kept low and reversible. This plan is the payoff of
  that decision.

This is not a rewrite. It is swapping one implementor of an existing seam.

## The key constraint: split durable from ephemeral, do not "port StateBackend"

The naive move — "implement all of `StateBackend` on etcd" — is **wrong**. The
same trait carries the **hot-path ephemeral keyspace**, which etcd must never
hold:

| Keyspace | Examples | Store |
|---|---|---|
| Durable config plane | `config:waf:doc`, `config:waf:v:{n}`, `config:waf:applied:*`, `control:waf:*` | **→ etcd** |
| Hot ephemeral | `g:rl:sw:*`, `g:rl:tb:*`, `g:risk:*`, `g:block:*`, `g:nonce:*`, leases, `fleet:*`, smart-cache L2 | **stays Redis** |

etcd is a low-write-throughput consensus store; pushing rate-limit counters or
nonces at it would be a performance and correctness disaster (it is not a
counter store, and Raft fsync per write is the opposite of what the hot path
needs). The durable keyspace, by contrast, is written only on operator config
edits — a perfect etcd workload.

So the design is a **trait split**, then a second implementor of the *durable*
half only.

## Design (proposed)

**1. Extract a durable-config seam from `StateBackend`.** Introduce a narrow
`ConfigBackend` (working name) trait in `aegis-core` covering exactly what the
config + control planes use:

```
get(key) -> Option<bytes>
put(key, value)                       // no TTL — durable
delete(key)
range(prefix) -> Vec<(key, value)>    // replaces scan_prefix
txn_compare_and_set(key, expected, new) -> Committed | Conflict
```

`ConfigStore` (`config_source/config_store.rs:96`) and the control-plane
`cluster_sync` / `control` modules switch from `Arc<dyn StateBackend>` to
`Arc<dyn ConfigBackend>`. `RedisBackend` keeps implementing **both** traits, so
this step is a pure refactor with zero behavior change — the existing structural
guard test (`redis_source.rs:631-665`) and the apply-helper wiring stay green.

**2. Replace the nudge bus with a real watch.** `FleetBus`'s publish/subscribe
nudge becomes a `ConfigWatch` capability:

```
watch(prefix) -> stream of change events
```

For Redis this is implemented as today (pub/sub bump + poll fallback). For etcd
it is a **native Watch** on the `config:waf:` / `control:waf:` prefix — no
missed events, no poll fallback needed. The 3 s `DEFAULT_POLL` becomes a
slow safety heartbeat (e.g. 30 s) rather than the primary convergence path.

**3. Implement `EtcdBackend` + `EtcdWatch`.** Use the `etcd-client` crate (async,
tonic/gRPC, etcd v3 API — KV, Txn, Watch, Lease):

- `get`/`put`/`delete`/`range` → KV `Get` / `Put` / `Delete` / `Get` with
  `WithPrefix`.
- `txn_compare_and_set` → etcd `Txn` with a `Compare` on the key's
  mod-revision (or value), replacing the Lua CAS. This is the single biggest
  cleanup: optimistic concurrency becomes a first-class primitive.
- Per-node applied ACKs (`config:waf:applied:<node>`) → an **etcd lease**
  attached to the key; the node keeps it alive, and the ACK disappears
  automatically when the node dies — the TTL semantics we emulate today, native.
- Immutable version snapshots `config:waf:v:{n}` → plain `put`; etcd's MVCC
  also gives us historical revisions for free as a backstop.

**4. Wire backend selection.** Add an etcd arm to
`crates/aegis-bin/src/state_select.rs:32-57` and the nudge-bus construction in
`crates/aegis-proxy/src/run.rs:1282-1410`. Config: a new
`config_plane.backend: redis | etcd` knob (default `redis`) plus etcd endpoint
/ TLS / auth settings. The ephemeral `StateBackend` selection is **untouched** —
Redis stays mandatory for the hot path regardless of config backend.

**5. Control plane rides the same seam.** `cluster_sync` /`control` use
`cas_set` / `incrby` on `control:waf:*`
(`crates/aegis-control/src/interop/cluster_sync.rs`). The `cas_set` paths move
onto `ConfigBackend::txn_compare_and_set`. (Any genuine counter use, if present,
stays on Redis — audit during P3.)

## Phases

- **P1 — Extract `ConfigBackend` + `ConfigWatch` traits (pure refactor,
  RED-safe).** Retarget `ConfigStore` and the control-plane modules off
  `StateBackend`/`FleetBus` onto the new narrow traits, still implemented by
  `RedisBackend`. No behavior change; all existing tests stay green, including
  the apply-helper structural guard.
- **P2 — `EtcdBackend` + `EtcdWatch` behind `config_plane.backend: etcd`,
  default off.** Implement the etcd KV/Txn/Watch/Lease impl. Add a **shadow /
  dual-read** mode: read from Redis (authoritative), mirror-write to etcd, and
  compare, to validate parity under real traffic before any cutover.
- **P3 — Cutover.** Flip `config_plane.backend` to etcd as the authoritative
  store for both config and control planes. Provide a one-shot **migration**
  that copies the live `config:waf:doc` + `config:waf:v:*` + `control:waf:*`
  into etcd and verifies the active version. Keep a documented rollback to
  Redis.
- **P4 — Docs + runbook.** Update `deploy/CONFIG-PLANE-RUNBOOK.md`, the
  cluster/HA docs, and `plans/README.md`. Mark
  [`config-auto-restore.md`](./config-auto-restore.md) **superseded** for the
  durability half (etcd removes the empty-store root cause), keeping only its
  fleet-reconciliation ideas if still wanted.

## Acceptance gates

- [ ] P1: config + control planes compile and pass against the new traits with
      Redis still backing them; apply-helper structural guard test
      (`redis_source.rs:631-665`) unchanged and green.
- [ ] etcd `txn_compare_and_set` returns `Conflict` on a stale expected-version
      (parity with the Lua CAS 409 path) — deterministic unit test.
- [ ] etcd Watch delivers a config change to a peer node without relying on the
      poll fallback — integration test with the heartbeat poll disabled.
- [ ] Per-node ACK key vanishes on node loss via lease expiry (no manual TTL).
- [ ] P2 shadow mode: 24 h soak with zero Redis-vs-etcd config divergence.
- [ ] P3 migration copies the active doc + all version snapshots + control-plane
      keys, and the fleet converges to the same active version post-cutover.

## Risks

| Sev | Risk | Mitigation |
|---|---|---|
| MEDIUM | Adds a second mandatory infra dependency (etcd) alongside Redis | Default stays Redis; etcd opt-in. Ephemeral hot path never moves, so Redis is required regardless — etcd is *additive for config durability*, justified only at the scale where that durability matters |
| MEDIUM | Live migration of an in-use `config:waf:doc` | Dual-read shadow (P2) proves parity before cutover; one-shot copy verifies active version; documented Redis rollback |
| MEDIUM | Control-plane parity (modes/reset-epoch) drifts from config-plane cutover | Both move on the *same* `ConfigBackend` seam in the same phase (P3); audit `cluster_sync` for any true counter use that must stay on Redis |
| LOW | etcd operational unfamiliarity for operators | Runbook (P4); keep the Redis backend as a supported fallback, not a removed path |

## Out of scope

- Moving the **ephemeral** keyspace (`g:*`, `fleet:*`, smart-cache L2, leases)
  off Redis — it stays on Redis by design.
- Removing Redis. Redis remains mandatory for the hot path.
- Multi-region / cross-cluster config replication (etcd makes this *more*
  tractable later, but it is not part of this cutover).
- Re-litigating the `config:waf:doc` vs. boot-YAML validation model
  ([[project_config_plane_doc_vs_file]]) — that behavior is preserved as-is.

## Complexity: L

Two trait extractions touching the config + control planes, a new etcd
backend with Txn/Watch/Lease, a shadow-validation phase, and a live data
migration. Mechanically additive (an existing seam gets a second implementor),
but it spans two planes and a stateful cutover, so it is large and phased.
