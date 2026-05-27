# Cluster Config Sync & Scaling (next round)

> **Status:** In progress (2026-05-27). **Phase A wired end-to-end:**
> Phase 0 KV primitives (`dcdd96f`), `ConfigStore` + `redis_source`
> watcher (`e9691d1`), boot-site watcher spawn (`e4bc458`), and
> `PUT /api/config` + rollback via the new async `AuditedMutate::apply_async`
> (`912b16e`). Edit → shared store → every node converges, survives leader
> failover. **Phase A complete** — `GET /api/config` drift view (`312ab8d`)
> + Scaling-page `ConfigVersionCard` (`30d22f9`) landed. **Next:** Phases
> B–D. Target:
> each team runs N WAF nodes behind a VIP; security state AND configuration
> are shared and survive leader failover; config is editable from the
> console and converges on every node.
>
> Author context: written 2026-05-26 after auditing the current HA story
> (see [`../../docs/operations/ha-clustering.md`](../../docs/operations/ha-clustering.md)).
> Grounded in the real code, not the design docs (several of which
> overstate what's wired — verify before trusting).

---

## 1. Problem statement

The WAF already scales horizontally for **security state** but **not for
configuration**. Concretely, today:

| Concern | Today | Multi-node ready? |
|---|---|---|
| Rate-limit counters, risk scores, challenge nonces, auto-block list | Shared via Redis `StateBackend` | ✅ yes |
| Leader election | Redis `SET NX PX` lease + heartbeat (`cluster_lease/redis.rs`) | ✅ yes |
| Declarative config (`WafConfig`: routes, upstreams, detector defaults, tiers, TLS) | Per-node file watcher, or optional etcd blob watcher | ⚠️ only if every node points at the same source |
| **Console mutations** (detector mask, AI on/off, tier thresholds, upstream CRUD, rules) | Swap **in-process** stores on the node that served the request; detector mask persists to a **local file** only | ❌ **node-local — does not propagate** |
| Redis availability | Single primary | ❌ SPOF |
| `node_id` | hostname + PID | ❌ unstable across restart |
| Cluster roster (`/api/cluster.peers`) | always `[]` | ❌ no membership |

**The core gap:** aegis-control and aegis-proxy run in the *same process*
(`aegis-bin`), so a console `PUT` only mutates that node's memory. There is
**no write-back to a shared source and no cross-node propagation**
(verified: no `fs::write` / etcd PUT / git push from the control plane
except the per-node detector snapshot). So in a cluster, a console edit on
node A never reaches node B, and is lost on that node's next restart unless
it's the detector mask.

This plan closes that gap and hardens the HA path so the requirement holds:

> **Requirement.** Edit config in the console → it syncs to every node.
> The leader can die → a new leader is elected → the config is intact and
> keeps syncing, because config lives in a shared, replicated store, not in
> the leader's process.

---

## 2. Goals / non-goals

**Goals**
1. One **versioned config document** is the source of truth for the whole
   cluster, stored in shared infra (not a node's memory).
2. Console edits (declarative *and* runtime toggles) write to that document
   and converge on every node within seconds.
3. Leader failover never loses config; the new leader continues to
   coordinate writes; in-flight reads keep serving the last-good config.
4. Keep the per-request hot path lock-free (`ArcSwap` swap stays the apply
   mechanism).
5. Remove the Redis SPOF; give nodes a stable identity; expose the roster.

**Non-goals (this round)**
- Full GitOps signed-commit pipeline (keep as a later overlay; the
  `GitClient` trait exists but the poll driver is unwired).
- `redis_cluster` slot-hashing unless we actually hit the single-primary
  throughput ceiling (~50k rps/primary).
- Embedded Raft (kept as a stretch alternative in §8).

---

## 3. Architecture decision: Redis-backed config plane

We already run Redis for state and leader election. **Reuse it as the
config bus** rather than introducing etcd. Rationale:

- Zero new infra: the `StateBackend` + `cluster_lease` plumbing is here.
- Failover-safe by construction: config lives in Redis (replicated via
  Sentinel/managed), so leader death doesn't lose it.
- The apply machinery (`config_source/reload.rs`) and the boot-time
  `ArcSwap<WafConfig>` swap already exist — we add a *source*, not a new
  config model.

Trade-off vs etcd / Raft, for the record:

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| **Redis config plane** (this plan) | reuse infra, simple, failover-safe with Sentinel | not linearizable; needs CAS for concurrent edits; SPOF until Sentinel | **chosen** |
| etcd config source (`etcd_source.rs`, exists) | linearizable, native watch+lease | extra cluster to run; team explicitly avoiding it | keep as opt-in only |
| Raft (`openraft`, unbuilt) | no external store, linearizable | large build; new failure modes | §8 stretch |

> **Implementation reality check:** the real `StateBackend` trait
> (`aegis-core/src/state.rs:135`) has `get`/`set`/`del` (key→bytes) but
> **no generic `watch`**. So propagation is **version-key polling** (mirrors
> `EtcdConfigSource::watch_loop`'s range-poll), optionally upgraded to Redis
> keyspace notifications / pub-sub later for lower latency. Design around
> polling first.

---

## 3.5 Prior art — how world-class edge/WAF platforms do it

The three reference designs below independently converge on the same shape.
We should copy the shape, not the scale.

**Cloudflare — Quicksilver.** A purpose-built KV store distributes billions
of config KV pairs to every edge data center. Lessons:
- **Each edge node must serve even if cut off from central config** — config
  is replicated *to* the node and read locally (LMDB), never fetched
  per-request. This is their #1 requirement → for us: **fail-static**, read
  from the local `ArcSwap`.
- **Monotonically increasing sequence numbers** in the distribution protocol
  guarantee changes propagate accurately and in order regardless of network
  state → our `config:waf:version`.
- Fan-out / tiered caching for scale; eventual consistency is fine for
  config (propagation in seconds).

**Envoy/Istio — xDS.** The de-facto standard for control-plane → data-plane
config. Lessons:
- **Control plane is authoritative; the proxy is a read replica.** Edits
  never mutate a serving node directly — they go to the control plane, which
  pushes versioned config out.
- **Versioned snapshots + ACK/NACK with a nonce.** The proxy reports back
  *which version it applied* (ACK) or rejects an update and keeps the old
  one (NACK). The control plane therefore always knows each node's applied
  version → drift is observable, not silent.
- **Push (gRPC streaming) for low latency; delta updates** to avoid shipping
  a full snapshot every time.

**Fastly.** Lessons:
- **Immutable, versioned configs with atomic activation and second-scale
  rollback.** A pushed version is locked immutably so rollback = re-activate
  the previous version. Dynamic data (ACLs/dictionaries) reaches the edge in
  ~30s.
- **Staging / dry-run before activate** — validate before it can affect
  traffic.

**Distilled invariants we adopt:**
1. Control plane authoritative; nodes are read-mostly replicas (never edit a
   node directly).
2. Config is an **immutable, versioned, atomically-activated** snapshot —
   never partial.
3. **Monotonic version** + **per-node applied-version ACK** so drift is
   visible; **NACK** (keep old config + alert) on apply failure.
4. **Fail-static**: a node serves its last-good config when the store is
   unreachable.
5. Read-local, lock-free hot path (our `ArcSwap`); eventual consistency
   (seconds) is acceptable for config; strong consistency only at the
   write/activation point.
6. Push for latency, poll as the safety net; delta only if config grows
   large.

Our Redis-config-plane design already matches 1–2 and 4–5; the additions
this prior art forces are explicit **version history + rollback** (Fastly)
and **per-node ACK / NACK drift tracking** (xDS), folded in below.

## 4. Design — the config plane

### 4.1 Shared config document

Store one versioned document in Redis:

```
config:waf:current   → the active version number (the activation pointer)
config:waf:version   → monotonic u64, bumped on every accepted write
config:waf:v:<n>      → immutable YAML snapshot for version n (same blob the
                       file/etcd loaders accept — single validation surface)
config:waf:meta:<n>   → { version, actor, ts, source, sha256, summary }
config:waf:applied    → hash: node_id → applied version (per-node ACK)
```

Keep YAML-as-blob (same decision as `config_source/mod.rs`) so every config
still flows through `WafConfig::validate` — no second schema. **Snapshots
are immutable** (Fastly model): a write creates `config:waf:v:<n+1>` and
flips `config:waf:current` to it. **Rollback = flip `current` back to a
prior `n`** — no re-validation needed, the snapshot already passed. Keep the
last K snapshots (e.g. 50) + GC older ones.

### 4.2 Write path (console edit → cluster)

Any node can accept an edit; serialize writes with a CAS on `version`:

1. Console `PUT /api/...` (detector mask, upstreams, tier, rule, …) builds
   the **next** full `WafConfig` (current doc + the requested patch).
2. **Dry-run validate** (same path CI/file-reload uses) — reject on failure,
   nothing written.
3. **CAS write**: `version` must equal the value the editor started from
   (optimistic concurrency). Implement as a small Lua script (we already
   use Lua in `cluster_lease/redis.rs`) — `WATCH`/`MULTI` alternative is
   fine. On mismatch → `409 Conflict`, console reloads and retries.
4. **Activate atomically**: write the new immutable snapshot
   `config:waf:v:<n+1>` + `meta:<n+1>`, then flip `config:waf:current` to
   `n+1` in the same Lua transaction (the flip is the activation point).
   Emit an `operational` audit event with actor + version + diff summary.
5. The writing node swaps its own `ArcSwap` immediately (read-your-writes);
   other nodes converge via §4.3.

> Optional hardening: route writes through the **leader** (forward non-leader
> `PUT`s to `leader_node`) to reduce CAS contention. Not required for
> correctness — CAS already serializes — but simpler operator mental model.
> If we forward, the new leader after failover transparently becomes the
> write coordinator; the store is unchanged.

### 4.3 Propagation (every node)

Add a `RedisConfigSource` watcher mirroring `etcd_source.rs`:

- Poll `config:waf:current` every `poll_interval` (default 2–5s).
- On change: `GET config:waf:v:<n>` → `WafConfig::validate` → hand to the
  existing `config_source/reload.rs` apply path → atomic-swap `cfg_swap`
  (rebuilds route table + TLS resolver, same as file/etcd reload today).
- **ACK** (xDS lesson): on successful apply, write `node_id → n` into
  `config:waf:applied`. The console reads this hash to show a **per-node
  applied-version table** and flag drift (a node stuck on an old version).
- **NACK**: if validate/apply fails on a node, **keep the current
  `ArcSwap`** (do not serve a bad config), leave `applied` at the old
  version, and emit a `Page`-severity alert. A bad version can never take a
  node out of rotation silently.

Latency target: ≤ 1 poll interval (seconds) for full-fleet convergence.
Upgrade path: Redis keyspace notifications (`__keyspace@*__:config:waf:current`)
to make it event-driven; the poll stays as the safety net (Quicksilver +
xDS both keep a reconcile loop behind the push).

### 4.4 Fold runtime toggles into the shared document (the real fix)

Today these are separate in-process stores that don't propagate:
`SharedDetectorMask` (+ local-file snapshot), `TierStore`, the AI
`runtime_enabled` atomic, response-filter, rules. **Re-express each as a
field/overlay on the shared `WafConfig` document** so a single versioned doc
drives everything:

- `PUT /api/detectors`, `/api/ai/enabled`, `/api/tiers/<t>`,
  `/api/upstreams/*`, `/api/rules/*`, `/api/response-filter` → build the
  patched `WafConfig` → §4.2 write path.
- The `RedisConfigSource` apply (§4.3) re-derives the in-process stores from
  the new doc (the same way boot derives them from the file today), so the
  hot path is unchanged.
- Retire the per-node detector-mask file snapshot (`detectors_persist.rs`) —
  the shared doc is now the durable store. Keep the local snapshot only as an
  offline fallback if the store is unreachable at boot.

This is what makes "edit in console → all nodes" and
"survives leader failover" true for *every* surface, not just declarative
config.

### 4.5 Failover behavior (the requirement, restated)

- Config is in Redis, not the leader's RAM → leader death loses nothing.
- New leader is elected by the existing Redis lease (`leader:cluster`); it
  inherits write-coordination with no special config handoff.
- A node serving during a Redis partition keeps its last-good `ArcSwap`
  config (fail-static) and resumes polling on heal; writes are refused with
  a clear error while the store is unreachable (config edits are rare and
  must not split-brain).

---

## 5. HA hardening (close the SPOFs)

These are existing `ha-clustering.md` roadmap items; promote to P1:

1. **Redis HA** — Sentinel or managed (ElastiCache/MemoryDB) with automatic
   failover. Verify `state/redis.rs` reconnects on primary swap (add a
   `tests/cluster/07-redis-failover.sh`). Kills the #1 SPOF.
2. ~~**Stable `node.id` config knob**~~ — **already implemented** (HA-T3,
   verified 2026-05-27): `aegis-bin::lease_select::derive_node_id` resolves
   `cfg.node.id` → `AEGIS_NODE_ID` → `${HOSTNAME}-${PID}-${NANOS}`. Set
   `node.id: "${POD_NAME}"` in YAML for a restart-stable identity. The
   config-plane watcher already reuses this via `lease_store.self_id()`.
   (Both this plan and `ha-clustering.md` Roadmap #3 understated it.)
3. **Cluster roster** — populate `/api/cluster.peers`: each node registers
   `node:<id>` with a TTL heartbeat in Redis; `/api/cluster` reads the set.
   Drives a real roster + "applied config version per node" view in console.

---

## 6. Throughput / scaling

- **LB reference deploy** — add an `aegis-lb` HAProxy container to
  `deploy/docker-compose.dev.yml` (pattern C in `ha-clustering.md`) and a
  Helm `values` toggle; measure cluster-wide RPS through one VIP (currently
  unmeasured).
- **Local-first rate limiting stays** — the per-IP volumetric guard is
  per-node `DashMap` by design (no Redis round-trip under flood); only the
  named-bucket limiter is cluster-shared. Document the N×B fleet ceiling.
- **`redis_cluster` backend** — only if one primary becomes the bottleneck
  (>~50k rps). Pulls existing Lua onto a cluster-aware pool. Defer unless
  load testing shows the need.
- **Connection reuse** — ensure LB→node keepalive (the run-04 perf trap);
  bake `keepalive`/`least_conn` into the reference LB config.

---

## 7. Phased roadmap

### P0 — Config plane MVP (unblocks the requirement)
- [ ] `config:waf:{blob,version,meta}` schema + Lua CAS write script.
- [ ] `RedisConfigSource` poll-and-swap watcher (mirror `etcd_source.rs`),
      wired as a `ConfigReloadSource::Shared` variant in `run.rs`.
- [ ] Write path on `PUT /api/config` (full-doc) with dry-run + CAS + audit.
- [ ] Console: show applied version + a 409-conflict reload-and-retry.
- [ ] Immutable snapshots + **one-click rollback** (flip `current` to a prior
      `n`) — Fastly model.
- [ ] Per-node **ACK table** (`config:waf:applied`) + drift flag in console;
      **NACK** keeps last-good + pages — xDS model.
- [ ] `tests/cluster/08-config-sync.sh` — edit on node A, assert node B
      converges; edit during induced leader failover, assert no loss; push a
      deliberately-invalid version, assert nodes NACK + stay on last-good.

### P1 — Fold runtime toggles + HA hardening

**Implementation notes (traced 2026-05-27 — read before starting):**

- **Fold toggles** — ✅ **AI toggle done** (`32c8325` apply-side, `3d2ca70`
  write-side) — this establishes the **reusable pattern** for the rest:
  - *Write side* (handler): patch the field on the shared doc's YAML blob
    at the **`serde_yaml::Value`** level (`WafConfig` isn't `Serialize`),
    seed from the boot config file when no doc exists, validate via
    `load_config_str`, activate via `services.mutate.apply_async` →
    `ConfigStore::activate` (200/409). See `handle_ai_enabled_put` +
    `patch_ai_enabled` in `admin_mutate.rs`.
  - *Apply side* (the real work): add `reload::apply_cfg_change_to_<x>`
    that re-derives the in-process store from `new_cfg`, add it to
    `redis_source::ApplyTargets`, call it in `apply_and_swap`, and pass the
    handle at the `run.rs` spawn site. See `apply_cfg_change_to_ai`.
  - **Remaining toggles — NOT mechanical** (traced 2026-05-27). AI was
    the one clean fold because `cfg.ai.enabled` *fully represents* the
    runtime state. The others hit a **config-schema gap**: the runtime
    store holds state `WafConfig` doesn't carry, and the doc blob is
    validated with `deny_unknown_fields`, so there's no overlay escape —
    each needs a **`WafConfig` schema extension** in aegis-core (+ its
    validation + boot seeding) *before* it can be folded. This is a design
    decision (do we want these runtime stores to live in `WafConfig`?):
    - ✅ `handle_tier_put` — **DONE** (`08a8e65` plumbing + `eacaa4b` fold).
      Required (a) the boot-path refactor — `TierStore` now created in
      `run.rs` and threaded into both the watcher's `ApplyTargets` AND
      `DashboardServices::spawn_with_mask_and_leader` (test-facing
      `spawn`/`spawn_with_mask` pass a fresh store, so those call sites are
      untouched) — and (b) extending `TierThresholdConfig` with
      block_threshold / cumulative_* / pipeline + `TierStore::
      apply_optional_overrides`. The plumbing is the reusable template for
      the remaining services-level folds (rules / blacklist).
    - ✅ `handle_response_filter_put` — **DONE** (`a5b818d`). Added
      `cfg.response_filter` to `WafConfig` (3 bools, default true →
      behaviour-preserving), boot-seed + `apply_cfg_change_to_response_filter`
      + folded handler. The proof that the schema-extension path works.
    - ✅ `handle_detectors_put` — **DONE** (2026-05-27, full fold). The
      "apply-side already done" claim was only true for the **base**:
      `apply_cfg_change_to_mask` re-derived base via `DetectorMask::from_config`
      and *preserved* live per-tier overrides, never reading
      `cfg.detectors.per_tier`. Folding the PUT naively would have **silently
      dropped** per-tier overrides on the next ~3s poll, so the full
      bidirectional mapping was built:
      - `DetectorMask::resolve_tier_override` (tri-state `TierDetectorMask` →
        full mask, `None`=inherit base) + `MaskState::from_detectors_config`
        (base + `Ai` from sibling `cfg.ai.enabled` + per-tier overlays) — one
        constructor shared by boot + all watchers.
      - `apply_cfg_change_to_mask` now `store_state`s the FULL `MaskState`.
        **Contract change** (file/etcd/redis in lockstep): `cfg.detectors.per_tier`
        is the source of truth; a live override absent from cfg is cleared.
        Bugfix side effect: file+etcd reloads now set the base `Ai` bit from
        `cfg.ai.enabled` (was clobbered off before).
      - `patch_detectors` (write side) maps PUT body → `cfg.detectors.<class>.enabled`
        (`ai`→`cfg.ai.enabled`) + `cfg.detectors.per_tier.<tier>` (`null`=remove);
        `handle_detectors_put` rewritten to the `apply_async`/`activate` template.
        Retires the per-node local-snapshot override model.
    - ✅ `handle_upstreams_config_put` (+ pool upsert/delete) — **DONE**
      (2026-05-27, full fold). The "sizable risky feature" was overstated:
      the live pool rebuild already existed (`PoolRegistry::apply` does the
      atomic pool + circuit-breaker + connection-pool swap, used by the
      audit-mutated PUT). The only gaps were (a) calling it from the *reload*
      path and (b) async DNS (the watcher's `apply_and_swap` was sync). Shipped:
      `apply_cfg_change_to_upstreams` (async — per-node `expand_hostname_members`
      + `PoolRegistry::apply`); `apply_and_swap` made `async`; ApplyTargets
      `upstream_writer`; `patch_upstreams_replace`/`_pool_set`/`_pool_remove`
      (raw JSON → YAML since `PoolConfig` isn't `Serialize`); all 3 handlers
      folded to `apply_async`/`activate`. Doc keeps operator hostnames; each
      node resolves with its own resolver view (chosen over freezing IPs).
    - ✅ `handle_rules_*` — **DONE** (2026-05-27, full fold). The blocker
      was real: `cfg.rules` was `{paths, max_rule_count, strict_compile}`
      (rule *files*) with **no rule-list representation**, and the dashboard
      `RuleStore` + engine `RuleSet` both boot **empty** (`cfg.rules.paths`
      feeds only the snapshot/backup tooling, never the live engine), so
      dashboard rules were ephemeral + node-local. The fold added the missing
      feature and made rules durable + cluster-propagated:
      - `cfg.rules.inline: Vec<RuleDef{id,body,enabled}>` (new schema;
        `cfg.rules.paths` untouched).
      - `RuleStore::replace_all` (store ← inline, source of truth) +
        `apply_cfg_change_to_rules` (store + engine re-derive on every swap).
      - `RuleStore` lifted to `run.rs` (TierStore plumbing template) +
        ApplyTargets `rules`/`active_ruleset`; boot-seeded from inline.
      - All 4 CRUD handlers patch `cfg.rules.inline` + activate, with
        existence checks against the doc (eventual-consistency-safe).
  - **Unblocking the services-level folds (tier / rules / blacklist) — do
    this ONCE to enable all of them.** The blocker is that the config
    watcher's `ApplyTargets` is assembled in `run.rs` before
    `DashboardServices` is built, so it can only re-derive run.rs-level
    handles. Two ways out:
    - **(1) Lift the stores to `run.rs`** — create + seed `TierStore`
      (etc.) in `run.rs`, pass the `Arc` into both the watcher and
      `DashboardServices::spawn_with_mask_and_leader` (new param; the
      constructor currently makes its own at `dashboard_services.rs:409`).
    - **(2) Spawn the watcher after services** — move the
      `redis_source::spawn_watcher` call into the post-`DashboardServices`
      boot site and thread the run.rs-level targets (mask / rate-limiter /
      tls / ai) into it. Then `ApplyTargets` can include `services.tiers`
      etc. directly.
    Either is a boot-path refactor; (1) is more localized. Until done,
    only run.rs-level stores (AI, response-filter) are foldable.
  - **Eventual semantics** (option A): folded toggles now apply on the
    next watcher poll (~3s) on ALL nodes incl. local — the store is the
    single source of truth. The file/etcd watchers don't yet call the new
    `apply_cfg_change_to_*` helpers (only `redis_source` does); wire them
    there too if file/etcd-driven reloads should re-derive these stores.

- **`node.id` knob** — ✅ already implemented (HA-T3, see §5).

- **`/api/cluster.peers` roster** — ✅ **already implemented** (HA-T4,
  verified 2026-05-27). `accept.rs` runs a `members:<node_id>` heartbeat
  lease (15s TTL) + a 5s poller that calls
  `lease_store.list_keys_with_prefix("members:")` (RedisLease + InProcess
  both implement it) and `leader_view.set_members(...)`; `render_cluster`
  serialises `peers`. `ClusterPeer.addr`/`leases` are empty today (id +
  WAF version + last_heartbeat are populated) — enriching addr/leases is
  the only follow-up. The "`peers` always `[]`" claim in
  `ha-clustering.md` Roadmap #8 is **stale**.

- **Redis Sentinel/managed + reconnect test** — `tests/cluster/07-redis-failover.sh`;
  verify `state/redis.rs` (deadpool lazy reconnect) survives a primary swap.

### P2 — Throughput + polish
- [ ] HAProxy reference deploy + single-VIP cluster RPS benchmark.
- [ ] Redis keyspace-notification fast path (poll stays as fallback).
- [ ] Console "fleet view": per-node applied config version + drift alarm.
- [ ] `redis_cluster` backend *iff* load testing demands it.

---

## 8. Stretch alternative — Raft (store-free)

If we want the cluster to own consensus without depending on external Redis
(regulated/air-gapped, or to make config linearizable): embed `openraft`,
form a Raft group across WAF nodes, and put config writes through the log.
Leader replicates to followers; failover is native. This is the "correct"
HA config primitive but a large build with new failure modes — out of scope
this round, revisit if the Redis-plane CAS proves painful.

---

## 9. Risks / open questions

- **Concurrent edits**: CAS gives last-writer-wins-with-conflict; is that
  acceptable UX, or do we want field-level merges? (Start with CAS + 409.)
- **Config vs state boundary**: keep auto-block/risk/counters in the state
  keyspace (high-write, TTL'd); config is low-write, versioned, durable —
  don't conflate the two keyspaces or their reconcile semantics.
- **Validation cost**: full `WafConfig::validate` on every poll bump — fine
  at config-edit rate, but skip re-validate if `sha256` is unchanged.
- **Boot ordering**: a fresh node with an empty store must fall back to its
  bundled file, then adopt the store once it has content (don't serve an
  empty config).

---

## 10. Files this will touch

```
crates/aegis-core/src/state.rs              ← (maybe) add get/set already suffice; CAS via Lua
crates/aegis-proxy/src/config_source/
  redis_source.rs   (new)                   ← poll-and-swap watcher
  mod.rs / reload.rs                        ← register Shared source, reuse apply path
crates/aegis-proxy/src/run.rs               ← ConfigReloadSource::Shared variant + spawn
crates/aegis-proxy/src/cluster_lease/redis.rs ← reuse Lua pattern for config CAS
crates/aegis-control/src/api/
  config.rs (new or extend)                 ← PUT full-doc write path + versions
  detectors.rs / tiers / upstreams / rules  ← route through shared doc
  tracking.rs                               ← peers roster + applied version
crates/aegis-bin/src/{state_select,lease_select}.rs ← node.id knob
deploy/helm/... , deploy/docker-compose.dev.yml ← aegis-lb, redis HA, node.id
tests/cluster/07-redis-failover.sh, 08-config-sync.sh (new)
```
