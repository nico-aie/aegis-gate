# Cluster Config Distribution (control-plane → fleet)

> **Status: ✅ Shipped (2026-05-27).** The full config plane is live: the
> `StateBackend` KV primitives, the versioned `ConfigStore`, the
> `redis_source` watcher (spawned at boot in `run.rs`), the
> `PUT`/`POST /api/config` write + rollback endpoints, the `GET /api/config`
> drift view, and **every in-process console toggle/CRUD folded through the
> write path** so edits propagate fleet-wide (AI, response-filter, tier,
> detectors, rules, upstreams). For the step-by-step deploy + operate
> runbook an AI assistant can drive, see
> [`../../deploy/CONFIG-PLANE-RUNBOOK.md`](../../deploy/CONFIG-PLANE-RUNBOOK.md).
> Design history + per-fold notes:
> [`../../plans/archive/cluster-config-sync-and-scaling.md`](../../plans/archive/cluster-config-sync-and-scaling.md);
> surrounding HA model: [`./ha-clustering.md`](./ha-clustering.md).

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
   `config_source::reload` helpers (route table, detector mask, IP
   rate-limit, TLS, tiers, rules, upstreams, then the `ArcSwap` swap) —
   identical side effects to the file/etcd watchers.
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

## API surface

All endpoints are on the **admin** plane, admin-session-gated, and
CSRF-gated (the mutating ones). All run through the audit chain.

| Method + path | Purpose | Success / conflict |
|---|---|---|
| `GET /api/config` | Drift view: active version + each node's applied version | `200` JSON |
| `PUT /api/config` | Activate a full new config version | `200 {version}` / `409 {current}` |
| `POST /api/config/rollback` | Re-activate an earlier version's snapshot | `200 {version}` / `409` |

`PUT /api/config` body: `{ "expected_version": <u64>, "blob": "<full WafConfig YAML>", "summary": "<text>" }`.
The blob is dry-run validated (`aegis_core::load_config_str`) before the CAS;
an invalid blob is rejected with `400` and nothing is written.

### Folded console toggles (Phase B — propagate via the same write path)

These previously mutated only the serving node's in-process state. They now
patch the shared config document and activate, so the change converges on
every node within one watcher poll (~3 s) and survives restart/failover:

| Endpoint(s) | Patches | Notes |
|---|---|---|
| `PUT /api/ai/enabled` | `ai.enabled` | |
| `PUT /api/response-filter` | `response_filter.{scrub_stack_traces,mask_internal_ips,redact_dlp}` | |
| `PUT /api/tiers/{name}` | `tiers.<name>` (thresholds + pipeline) | |
| `PUT /api/detectors` | `detectors.<class>.enabled` (+ `ai.enabled`) + `detectors.per_tier.<tier>` | base **and** per-tier |
| `POST/PUT/DELETE /api/rules`, `…/toggle` | `rules.inline[]` | rules now durable + cluster-wide |
| `PUT /api/upstreams/config`, `…/pool/{id}` (PUT/DELETE) | `upstreams` | per-node DNS re-resolve at apply |

**Pre-req for the folds:** the node must be able to seed version 0 — either
it booted from a **file** config (`--config <path>`, auto-seeds from the file
on the first fold) **or** an operator has already published a baseline via
`PUT /api/config`. On an etcd/static boot with no prior baseline, a fold
returns `400 "no shared config activated yet — publish a baseline via PUT
/api/config first"`.

## New config fields (introduced with the folds)

- **`rules.inline: [{ id, body, enabled }]`** — the persistent, cluster-
  propagated rule list (the dashboard `RuleStore` is seeded from it at boot).
  `rules.paths` is unchanged and feeds only the backup/snapshot tooling, not
  the live engine. Previously dashboard rules were ephemeral + node-local.
- **`detectors.per_tier.<tier>.<class>: true|false`** — now **consumed** (was
  schema-only). Tri-state per-tier override (`true` force-on, `false`
  force-off, omitted = inherit the base). The config document is the source
  of truth: a live per-tier override absent from `detectors.per_tier` is
  cleared on the next reload.

## Single-node vs multi-node

| | `state.backend: in_memory` (single-node) | `state.backend: redis` (multi-node) |
|---|---|---|
| Config plane | In-process: folds + `PUT /api/config` work, persist nothing across restart | Shared `config:waf:doc`; edits converge fleet-wide + survive failover |
| Metrics aggregation (Phase C) | **Off** — endpoints read the local rings | **On** — `/api/analytics/route-activity`, `/api/{blacklist,whitelist}/hits` show a cluster-wide sum |

## Implementation

- `crates/aegis-core/src/state.rs` — `StateBackend::{incrby, expire,
  scan_prefix, cas_set, get_counter}` (generic KV primitives; default impls
  keep stub backends compiling).
- `crates/aegis-proxy/src/state/{redis,in_memory,reconcile}.rs` —
  concrete impls + wrapper delegation (`CAS_SET_LUA` for atomic CAS).
- `crates/aegis-proxy/src/config_source/config_store.rs` — `ConfigStore`
  (`load` / `activate` / `rollback` / `record_applied` / `applied_map`).
- `crates/aegis-proxy/src/config_source/redis_source.rs` — the watcher
  (`spawn_watcher` + `ApplyTargets`; `apply_and_swap` calls every
  `reload::apply_cfg_change_to_*` helper).
- `crates/aegis-proxy/src/admin_mutate.rs` — `PUT /api/config` + the folded
  toggle handlers (each `patch_*` the shared doc then `apply_async`).
- `crates/aegis-control/src/metrics/window_flush.rs` — Phase C cluster
  counter flush + aggregated read cache.
