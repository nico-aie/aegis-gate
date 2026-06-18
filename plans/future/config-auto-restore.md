# Config auto-restore — re-publish last-known-good after a shared-store wipe (future plan)

> **Status:** Drafted 2026-06-18. Deferred follow-up to the shipped
> *detect + alert* fix for the `runtime-config-lost-on-redis-data-loss`
> finding (commit `3f3d719` on `develop`). That fix made the failure
> **loud**; this plan makes recovery **automatic**. Not started — the crux
> (fleet split-brain on re-publish) needs a decision before any code.
> Related: [[project_health_signals_reported_not_gating]],
> `deploy/CONFIG-PLANE-RUNBOOK.md` (AOF note).

## Goal

When the Redis-backed shared config store (`config:waf:doc`) comes back
**empty** after a data-loss (Redis restarted without AOF/RDB), have the WAF
**re-publish its last-known-good config** back into the store automatically,
instead of leaving the operator to re-apply it by hand from the dashboard or a
`waf` snapshot.

Today the node detects the wipe, alerts, and keeps serving the on-disk file
baseline — but the *runtime-added* pools/routes/rules that lived only in Redis
stay gone until a human acts.

---

## 1. What already ships (the foundation)

Verified in `crates/aegis-proxy/src/config_source/redis_source.rs` after
`3f3d719`:

- **Local marker** `.aegis_last_applied_config.json` written next to the boot
  config on every successful apply — currently holds **only** `{version, ts}`
  (`ConfigMarker`), *not* the config blob.
- **Detection** — `is_store_revert(applied_version, highest_seen)` +
  `config_store_degraded` health flag + the `config_store_reverted_to_baseline`
  audit event, emitted once per episode.
- **Recovery path already exists** — `ConfigStore::activate(expected, blob,
  actor, reason)` (`config_source/config_store.rs`) is the CAS publish the
  dashboard uses; auto-restore would call the same path.

So the only *new data* auto-restore needs is the **blob**, and the only new
*action* is calling `activate` at the right moment under the right guard.

---

## 2. Design

### 2.1 Persist the blob, not just the version
Extend the local snapshot (the report's original suggestion (b)) to hold the
full last-known-good document:

```jsonc
// .aegis_last_applied_config.json
{ "version": 7, "ts": "...", "blob_sha": "…", "blob": "<full WafConfig YAML>" }
```

Write it in the same place the marker is written today (the apply-success
branch of `watch_loop`). Keep it atomic (write-temp + rename). Gate on a size
cap so a huge config can't bloat the file unexpectedly.

### 2.2 Re-publish on detected wipe
In the `Ok(None)` revert branch, when a local snapshot is present and
`is_store_revert` is true:

1. Read the snapshot blob; verify `blob_sha`.
2. `store.activate(expected = None /* empty store */, blob, "auto-restore",
   "re-publish last-known-good after empty shared store")`.
3. On CAS success: the normal watcher apply+ACK flow takes over, clears
   `config_store_degraded`, emits `config_reload`. Emit an additional
   `config_store_auto_restored` audit event.
4. On CAS conflict (someone/another node already wrote): **stand down** — a
   newer doc exists; do nothing.

### 2.3 Single-writer guard (the hard part — see risks)
Re-publish must be done by **exactly one** node. Options, in order of
preference:
- **Lease-elected restorer.** Reuse the existing per-task lease mechanism
  (`lease_store`, used elsewhere for singleton side-tasks) — only the lease
  holder may auto-restore.
- **CAS-only race.** Let all nodes attempt `activate(expected=None, …)`; CAS
  guarantees one winner. Cheap, but see split-brain below.

---

## 3. Open decisions (must resolve before building)

1. **Fleet split-brain.** Each node holds its own last-known-good. After a wipe
   they may hold *different* versions (a node that was lagging has an older
   blob). With plain CAS, whichever fires first wins — possibly the **stale**
   one. Mitigation: elect a single restorer (lease) **and/or** make the blob
   carry `version`+`ts` so a node only restores if its snapshot is the newest
   it can observe. This is the real design work and why it's deferred.
2. **Intent ambiguity.** An empty store could mean *accidental data loss*
   (restore!) or a *deliberate reset* (don't!). Proposal: auto-restore only
   when `config_store_degraded` was raised by the *revert* path (we had a
   version), never on a genuine first boot — which the current marker logic
   already distinguishes. Consider a config kill-switch
   (`config_plane.auto_restore: false`) for operators who want manual-only.
3. **Double swap at boot.** The node already serves the file baseline; an
   auto-restore is a second config swap seconds later. Confirm the apply path
   is idempotent/clean back-to-back (it is for the dashboard case, but
   re-verify under the boot timing).
4. **Secrets in the snapshot file.** The blob is the full `WafConfig` YAML —
   may contain sensitive material (tokens, CA refs). The file must inherit the
   boot config's permissions; document it; consider opt-in.

---

## 4. Phasing

- **P1** — Extend the snapshot to carry the blob + `blob_sha` (atomic write,
  size cap, perms). No behavior change yet. Unit tests for write/read/verify.
- **P2** — Auto-restore behind a config flag **default off**: single-node only
  (no fleet election), CAS publish on detected wipe, `config_store_auto_restored`
  audit. Integration test against an in-memory/empty store.
- **P3** — Fleet-safe: lease-elected restorer + newest-wins reconciliation.
  Default on once P3 lands.

## 5. Tests
- Snapshot blob round-trips + `blob_sha` mismatch is rejected.
- Empty store + local snapshot (flag on) → exactly one `activate`, flag clears,
  `config_store_auto_restored` emitted.
- First boot (no snapshot) → no restore.
- CAS conflict → stand down, no duplicate publish.
- (P3) two nodes, only the lease holder restores.

## 6. Out of scope
- Redis AOF/RDB provisioning itself (ops; documented in the runbook).
- Cross-region / multi-store replication.
