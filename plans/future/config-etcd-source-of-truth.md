# Config source-of-truth: Redis → etcd — durable config plane on a real KV/watch store

**Status:** Designed · prerequisites SHIPPED · build gated behind a default-off
cargo feature (constraint-respecting). Not yet scheduled for cutover.
**Filed:** 2026-06-20 · **Updated:** 2026-06-24
**Origin:** Resource-constrained hackathon shortcut — Redis was reused as the
config store to avoid a second infra dependency. This plan revisits that once
the constraint lifts.
**Related:** [`config-single-source-of-truth.md`](./config-single-source-of-truth.md)
(H1/H2a — the prerequisites, now shipped), [`config-auto-restore.md`](./config-auto-restore.md)
(the durability follow-up this would subsume),
[`world-class-waf-roadmap.md`](./world-class-waf-roadmap.md),
[[project_config_plane_doc_vs_file]], [[project_config_h2a_split_progress]],
[[project_api_mode_no_cluster_publish]], [[project_apply_and_swap_helper_guard]]

## Decisions (2026-06-24)

1. **Prerequisites are done.** H1 (single writer) and **H2a (the
   `BootstrapConfig`/`DynamicConfig` split)** shipped. The config doc now holds
   the **dynamic config only** (`DynamicConfig` YAML — bootstrap is stripped on
   write and reconstructed at runtime via `WafConfig::from_parts(boot, dynamic)`).
   etcd stores that **same dynamic blob**; only the transport (KV/Txn/Watch/Lease)
   changes. The file-vs-doc authority model is resolved, so the etcd cutover
   inherits one applier + one source of truth, exactly as this plan assumed.
2. **Build it behind a default-off cargo `etcd` feature** (mirrors the existing
   `redis` feature). The default binary pulls in **no etcd client / dependency**,
   so the "one external dependency" constraint is respected at the *shipped
   default*; the code can still be built + tested under `--features etcd` now,
   and the gate lifts by shipping that build when a second dependency is
   acceptable. The runtime knob is validated to **reject `etcd` on a binary built
   without the feature** (loud, like the `ai` / `raft` guards).
3. **The runtime knob is `config_plane.store: shared_state | etcd`** (default
   `shared_state`), **NOT** `backend: redis | etcd`. Rationale: the word "redis"
   on a config-plane knob wrongly implies a global Redis-vs-etcd choice, but
   **Redis is never optional** — `state.backend: redis` always backs the data
   plane (rate-limit / risk / nonce / auto-block / smart-cache L2 / Track-A
   durability). `shared_state` = the config doc rides the existing data-plane
   state backend (today's behavior); `etcd` = the config doc lives in a dedicated
   etcd cluster. etcd is **additive for config durability**, never a Redis
   replacement.

> Anchor note: the file:line references below predate H1/H2a and have drifted
> (the structural guard was rewritten in H2a; `ConfigStore`, `state_select`, and
> the run.rs nudge wiring moved). Re-verify against current code at build time.

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

**4. Wire config-store selection (feature-gated).** Add an etcd arm to the
config-plane wiring (the `state_select` / `run.rs` nudge construction). Config:
a new **`config_plane.store: shared_state | etcd`** knob (default
`shared_state`) plus an `config_plane.etcd: { endpoints, tls, auth }` block
consulted only when `store: etcd`. The `EtcdBackend` impl + the `etcd-client`
dependency live behind a **default-off cargo `etcd` feature**, so the default
build has no etcd code or dependency; `store: etcd` on a binary built without
the feature is a loud boot error. The ephemeral `StateBackend` selection
(`state.backend`) is **untouched** — Redis stays mandatory for the hot path
regardless of where the config doc lives. `shared_state` means "the config doc
rides `state.backend`" (today's behavior, zero change).

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
- **P2 — `EtcdBackend` + `EtcdWatch` behind the `etcd` cargo feature +
  `config_plane.store: etcd`, default off.** Implement the etcd KV/Txn/Watch/
  Lease impl under `#[cfg(feature = "etcd")]`. Add a **shadow / dual-read** mode:
  read from the shared-state store (authoritative), mirror-write to etcd, and
  compare, to validate parity under real traffic before any cutover. The doc
  payload is the H2a `DynamicConfig` blob unchanged.
- **P3 — Cutover.** Flip `config_plane.store` to `etcd` as the authoritative
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

## Complexity & effort: L (~3–4 weeks)

Two trait extractions touching the config + control planes, a new etcd
backend with Txn/Watch/Lease, a shadow-validation phase, and a live data
migration. Mechanically additive (an existing seam gets a second implementor),
but it spans two planes and a stateful cutover, so it is large and phased.

**Effort grade: L** (roadmap scale: S ≤~3 d, M ~1–2 wk, **L ~3 wk+**).
**Risk: MEDIUM overall** — no CRITICAL/HIGH items in the risk table; opt-in with
Redis as the default and rollback path is what keeps it off HIGH.

Per-phase estimate, single engineer on this codebase:

| Phase | Work | Estimate |
|---|---|---|
| **P1** | Extract `ConfigBackend` + `ConfigWatch` traits; retarget config + control planes off `StateBackend`/`FleetBus`, Redis still backing. Pure refactor, RED-safe. | ~2–4 d |
| **P2** | `EtcdBackend` + `EtcdWatch` (etcd-client: KV/Txn/Watch/Lease) + dual-read shadow mode + 24 h parity soak | ~1–1.5 wk |
| **P3** | Cutover, one-shot migration tool (copy `config:waf:doc` / `config:waf:v:*` / `control:waf:*`), verify active version + documented rollback | ~3–5 d |
| **P4** | Runbook + cluster/HA docs; mark [`config-auto-restore.md`](./config-auto-restore.md) superseded | ~1–2 d |

**Total: ~3–4 weeks of focused work.** Caveats: the long pole is the P2
shadow-soak (wall-clock, not effort); add buffer if etcd provisioning /
TLS / auth in the deploy environment is greenfield (ops time outside the code
estimate). P1 is RED-safe, so the risky work doesn't begin until a clean
refactor has landed.
