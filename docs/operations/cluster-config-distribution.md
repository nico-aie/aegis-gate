# Cluster Config Distribution (control-plane → fleet)

> **Status:** In progress (2026-05-27). **Built:** the `StateBackend`
> generic KV primitives (`incrby` / `expire` / `scan_prefix` / `cas_set`)
> and the shared `ConfigStore` (versioned `config:waf:doc` + immutable
> snapshots + per-node applied-version ACK) + the `redis_source` watcher
> that applies new versions on every node (reusing the file/etcd apply
> path) with ACK / NACK / fail-static semantics. **Not yet wired:** the
> `PUT /api/config` write endpoint, the boot-site watcher spawn in
> `run.rs`, and the console applied-version drift view. See
> [`../../plans/future/cluster-config-sync-and-scaling.md`](../../plans/future/cluster-config-sync-and-scaling.md)
> for the full roadmap and
> [`./ha-clustering.md`](./ha-clustering.md) for the surrounding HA model.

## Why

A console edit must reach every node and survive leader failover. The
pre-existing gap: aegis-control and aegis-proxy run in one process, so a
console `PUT` only mutated *that node's* memory — it never propagated and
was lost on restart. Config now lives in the shared store, not a node's
RAM, so failover loses nothing and any node converges.

## Model (control-plane authoritative; nodes are read replicas)

This follows the same shape as Cloudflare Quicksilver, Envoy xDS, and
Fastly:

1. **Authoritative store.** One versioned document, `config:waf:doc`
   (JSON: `{ version, blob (YAML), actor, ts, summary }`), lives in the
   `StateBackend` (Redis in multi-node; in-memory single-node). Each
   version's YAML is also written write-once to `config:waf:v:<n>` for
   rollback.
2. **Atomic activation.** A write is an optimistic-concurrency
   compare-and-set (`StateBackend::cas_set`) on the doc key: the editor's
   `expected_version` must still be current, else the write is a
   `Conflict` → HTTP 409 → reload-and-retry. Activation = the CAS flip;
   never a partial config.
3. **Propagation.** Every node runs the `redis_source` watcher, polling
   the doc version (default 3 s) and applying a new version through the
   existing `config_source::reload` helpers (route table, detector mask,
   IP rate-limit, TLS resolver, then the `ArcSwap` swap) — identical side
   effects to the file/etcd watchers.
4. **ACK / NACK.** After a successful apply the node records its applied
   version under `config:waf:applied:<node_id>` (TTL'd). A version whose
   blob fails to validate is **not** applied — the node keeps its
   last-good `ArcSwap` config and emits `config_reload_failed`. The
   console reads the per-node applied map to surface drift.
5. **Fail-static.** When the store is unreachable a node keeps serving its
   current config and retries on the next tick.

## Keys

| Key | Contents |
|---|---|
| `config:waf:doc` | active `ConfigDoc` (JSON) — the CAS target / activation pointer |
| `config:waf:v:<n>` | immutable YAML snapshot of version `n` (rollback source) |
| `config:waf:applied:<node_id>` | the version a node has applied (TTL ~30 s) |

## Implementation

- `crates/aegis-core/src/state.rs` — `StateBackend::{incrby, expire,
  scan_prefix, cas_set}` (generic KV primitives; default impls keep stub
  backends compiling).
- `crates/aegis-proxy/src/state/{redis,in_memory,reconcile}.rs` —
  concrete impls + wrapper delegation (`CAS_SET_LUA` for atomic CAS;
  config CAS mirrors to the reconcile fallback on success).
- `crates/aegis-proxy/src/config_source/config_store.rs` — `ConfigStore`
  (`load` / `activate` / `rollback` / `record_applied` / `applied_map`)
  and `ConfigDoc` / `Activate`.
- `crates/aegis-proxy/src/config_source/redis_source.rs` — the watcher
  (`spawn_watcher` + `ApplyTargets`).

## Remaining (tracked)

- `PUT /api/config` (full-doc) write handler: dry-run validate →
  `ConfigStore::activate` → audit; `409` on conflict; rollback endpoint.
- Boot wiring: build a `ConfigStore` from the runtime `StateBackend` and
  `spawn_watcher` alongside the file/etcd watchers in `run.rs`.
- Console: applied-version badge + per-node drift table from
  `applied_map`.
- Fold the in-process console toggles (detectors / tiers / upstreams /
  rules) through this write path so they propagate too (Phase B).
