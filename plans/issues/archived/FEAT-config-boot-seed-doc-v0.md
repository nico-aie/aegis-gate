# FEAT — seed the boot YAML into `config:waf:doc` as version 0 at startup (genesis-only)

- **Type:** FEAT (config plane / boot sequence)
- **Status:** 🟢 Implemented (TDD) on `feat/config-boot-seed-doc-v0` — pending review/merge.
  `seed_boot_config_if_genesis` + `SeedOutcome` in `config_source/redis_source.rs`,
  wired in `run.rs` before `spawn_watcher`; 5 unit tests (all branches), full
  `aegis-proxy` lib suite 975 green, clippy clean for the new code.
- **Wave:** Wave 0 of [`../implementation-sequence.md`](../implementation-sequence.md);
  Horizon 1 · **P0** of [`../future/config-single-source-of-truth.md`](../future/config-single-source-of-truth.md).
- **Effort:** S (~½–1 d).
- **Area:**
  - `crates/aegis-proxy/src/run.rs` — config watcher spawn block (~`1360`–`1422`); seed goes just **before** `spawn_watcher`.
  - `crates/aegis-proxy/src/config_source/config_store.rs` — `ConfigStore::{load,activate}` (reused as-is).
  - `crates/aegis-proxy/src/config_source/redis_source.rs` — the marker/`is_store_revert` detection that the seed must NOT mask.
  - `crates/aegis-proxy/src/admin_mutate.rs:2677` — lazy-seed fallback (left in place; see Non-goals).

## Goal

Eliminate the boot ↔ first-mutation **divergence window** (failure mode **C** in
the config-single-source-of-truth plan): today `config:waf:doc` stays empty until
the first dashboard/API mutation lazily seeds it from the file
(`load_active_config_doc`, `admin_mutate.rs:2677-2686`). Until then the file and
the (absent) doc disagree by construction. Fix: **eagerly publish the boot config
as doc v0 at startup**, so the versioned doc is populated from the first moment —
the on-ramp for the rest of the config arc (P1 single-writer, H2 type split).

## Design

At startup, in the existing config-watcher setup block (`run.rs:~1360`), **before**
`spawn_watcher`, run a one-shot seed:

```
seed if ALL of:
  - config_yaml_path.is_some()                 (a boot file exists to seed from)
  - store.load().await? == None                (no active doc yet)
  - no prior-applied marker present            (GENESIS, not a wipe — see below)
then:
  blob = std::fs::read_to_string(config_yaml_path)   // verbatim file text, the
                                                      // same single-validation
                                                      // surface the lazy path uses
  match store.activate(0, blob, "boot-seed", "genesis seed of boot config").await {
      Applied { version }      => info!(version, "config plane seeded from boot file"),
      Conflict { current }     => info!(current, "config plane already seeded by a peer; skipping"),
      Err(e)                   => warn!(%e, "boot seed failed; lazy seed remains the fallback"),  // do NOT fail boot
  }
```

Then `spawn_watcher` runs as today: it loads v1 and applies it — re-applying the
config already live from boot, which is idempotent.

### Why genesis-only (the key interaction)

The shipped config-loss **detect+alert** (commit `3f3d719`) keys off
`store.load() == None` *after* a version was applied (marker present →
`is_store_revert`). If we seeded unconditionally, a cold boot after a **Redis
wipe** would re-seed v1 and **mask the data-loss detection**. So the seed fires
**only on true genesis** — no last-applied marker. The wipe case (marker present,
store empty) is deliberately **not** seeded here; it stays the watcher's
detect+alert job, and the future `config-auto-restore` re-publish.

The marker path is the same `config_yaml_path.with_file_name(".aegis_last_applied_config.json")`
already computed at `run.rs:1408`. "No marker" ⇒ genesis. (In-memory single-node
has no marker path and starts empty each boot → seeds every boot, which is the
correct genesis semantics for an ephemeral store.)

### Concurrency (multi-node cold start)

N nodes booting against one empty shared store all call `activate(0, …)`; the CAS
in `ConfigStore::activate` (`config_store.rs:159-225`) makes exactly one win (v1)
and the rest get `Conflict` → logged and skipped. First-writer-wins; we do **not**
blob-compare here (that dedup is P1's publisher concern). Losers' watchers load
the winner's v1 — correct under the SSOT model.

## Non-goals (explicitly deferred)

- **Tier-1/2/3 classification, read-only-UI, and the structural-guard extension**
  (the other half of the plan's P0 bullet) — larger surface; split to a follow-up
  ticket. This ticket is the **seed only**.
- **Deleting the lazy-seed fallback** in `load_active_config_doc`. It is NOT fully
  dead after this change — the wipe case (we don't seed) can still leave the doc
  empty when a mutation arrives. Keep it as the fallback; revisit in P1.
- Any change to the file watcher / `apply` paths — that's P1.

## Implementation steps

1. Add an async `seed_boot_config_if_genesis(...)` helper in `config_source`
   (or inline in `run.rs`) taking `&ConfigStore`, `config_yaml_path`, and the
   marker path; returns `()` and only logs (never fails boot).
2. Call it in `run.rs` immediately before `spawn_watcher` (store is already
   constructed at `:1362`; `config_yaml_path` + marker path already in scope).
3. Keep `load_active_config_doc`'s lazy-seed branch unchanged (fallback).

## Tests (TDD — write first)

- **genesis seeds:** empty in-memory store + a boot file + no marker → after seed,
  `store.load()` is `Some(v1)` with the file blob.
- **existing doc skipped:** pre-activated doc (v3) → seed is a no-op, version stays 3.
- **wipe NOT seeded:** marker present (v7) + empty store → seed does **nothing**
  (store stays empty so the watcher's revert detection still fires).
- **no file path:** `config_yaml_path = None` → no-op, no panic.
- **CAS conflict handled:** simulate a concurrent winner (store already at v1 when
  the CAS runs) → `Conflict` is swallowed, boot proceeds.
- **boot does not fail on seed error:** unreadable file / backend error → warn +
  continue (lazy fallback still available).

## Acceptance criteria

- [x] Cold boot with empty store + boot file → `config:waf:doc` is v1
      (`seed_writes_v1_on_genesis`); seed runs before `spawn_watcher` in `run.rs`,
      so the doc is present before the first request and the lazy file read is
      bypassed.
- [x] Restart with an existing doc → **no** version bump
      (`seed_skips_on_conflict_when_a_peer_already_seeded`: CAS conflict, version
      stays put).
- [x] Cold boot after a simulated wipe (marker present, store empty) → seed does
      NOT run, store stays empty so the revert detector still fires
      (`seed_skips_when_marker_present_so_a_wipe_is_left_for_detection`).
- [x] Multi-node cold start → exactly **one** v1; peers get `Conflict` and stand
      down (CAS in `ConfigStore::activate`; covered by the conflict test).
- [x] `cargo test -p aegis-proxy --lib` green (975 passed); clippy clean for the
      new code; no rustfmt churn outside it ([[project_rustfmt_whole_crate_hazard]]).

## Risks

| Sev | Risk | Mitigation |
|---|---|---|
| MEDIUM | Masking the config-loss detection | Genesis-only guard (no-marker); explicit wipe-not-seeded test |
| LOW | Boot regression if seed errors | Seed only logs; never fails boot; lazy fallback retained |
| LOW | Double apply at boot (seed v1, watcher re-applies) | Idempotent apply, pre-traffic; covered by the smart-cache/reload paths already |
| LOW | rustfmt reformatting a large file | Hand-match style; only fmt the new helper ([[project_rustfmt_whole_crate_hazard]]) |
</content>
