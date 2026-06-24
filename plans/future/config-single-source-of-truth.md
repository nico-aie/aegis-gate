# Config single-source-of-truth — end YAML/Redis dual-authority on the live data plane

**Status:** Future / design (not scheduled) — drafted 2026-06-23
**Origin:** Operator-reported confusion — "I update a single key and other config
seems to change too." Investigation traced it to **two uncoordinated config
writers** racing on one live config slot, not to the whole-config swap itself.
**Scope:** spans a near-term correctness fix (Horizon 1, §5) **and** a long-term
target architecture (Horizons 2–3, §10) — the structural `BootstrapConfig` /
`DynamicConfig` type split and a real config control plane.
**Decisions finalized (2026-06-23):** (1) **Option B** — file becomes a publisher
to the doc, not bootstrap-only (§4); (2) after H2 the file holds **both**
`BootstrapConfig` + `DynamicConfig`, the latter as genesis seed + DR fallback with
precedence etcd → last-applied cache → file (§2c); (3) the file **stays a live
publisher** in the etcd era (§2c). Pragmatic-then-structural split (§3) stands as
sequenced, not a fork.
**Related:**
[`config-etcd-source-of-truth.md`](./config-etcd-source-of-truth.md) (this is the
*prerequisite cleanup* that the etcd cutover assumes — etcd explicitly puts the
file-vs-doc model out of scope),
[`config-auto-restore.md`](./config-auto-restore.md),
[[project_config_plane_doc_vs_file]], [[project_apply_and_swap_helper_guard]],
[[project_api_mode_no_cluster_publish]]

---

## 1. Problem — dual authority, not whole-vs-partial swap

The live config is **one** `Arc<ArcSwap<WafConfig>>` (`cfg_swap`), fed by **two
independent watchers that never coordinate**:

| Writer | Source | Applies via | Writes |
|---|---|---|---|
| File watcher | boot YAML on disk (`notify`, 100 ms debounce) | `apply_folded_stores` | `cfg.store(...)` — `supervisor.rs:668` |
| Redis-doc watcher | `config:waf:doc` (3 s poll + `config:waf:bump` nudge) | `apply_and_swap` | `cfg.store(...)` — `redis_source.rs:421` |

Both share the same `cfg_swap` (passed to each at `run.rs:1273` and
`run.rs:1414`). There is **no last-writer-wins arbitration, no merge, no
source-of-truth marker.** Whoever fires last wins the slot and all ~16 derived
per-section handles (route table, pools, detector mask, tiers, rules, TLS, …).

This produces four concrete failure modes (all verified in code):

- **A. File edit silently clobbers API/Redis-converged state.** When a doc
  exists, a stray file save still reloads the file and overwrites `cfg_swap` +
  derived handles. The Redis watcher will **not** restore it: on its next poll
  `doc.version == applied_version`, so it only re-stamps the ACK
  (`redis_source.rs:201-203`) and never re-applies. Runtime state reverts to the
  file until the next *new* doc version is activated.
- **B. File-only sections go stale (the [[project_config_plane_doc_vs_file]]
  memory).** API mutations read `config:waf:doc.blob` as their base
  (`admin_mutate.rs:2676`), never the live file, once any doc exists. A section
  edited only in the file (e.g. `zero_trust`) lives in `cfg_swap` but is absent
  from the doc. The next unrelated API edit re-activates the stale blob → the
  Redis watcher swaps `cfg_swap` back, **erasing the file edit**. **This is the
  operator's "I changed one key and another key changed" report.**
- **C. Boot file is never activated into the doc.** No startup `activate` of the
  boot YAML. Between boot and the first mutation, file and doc disagree by
  construction and the doc is empty.
- **D. The two apply paths are not feature-symmetric.** The file path
  (`apply_folded_stores`) omits `apply_cfg_change_to_receivers` (alerting
  receivers) — that helper is Redis-watcher-only. The structural completeness
  guard (`redis_source.rs:646`) covers only the Redis watcher; the file watcher
  has **no** equivalent guard, exactly the
  [[project_apply_and_swap_helper_guard]] hazard.

**The whole-config swap is not the bug.** Replacing the entire validated
`WafConfig` atomically is correct and matches industry practice (see §2). The bug
is having **two authorities** for one live slot. "Only change the updated key" is
already handled correctly at the *authoring* layer — the API `patch_*` functions
do surgical single-key YAML edits, re-validate the whole document, then `activate`
(`admin_mutate.rs:185-225`). The surprise cross-key effects come purely from
file↔doc divergence, i.e. dual authority.

---

## 2. How global systems manage config (and what we should copy)

The mature pattern across distributed data planes is **one source of truth for
dynamic config, with a strict one-directional flow** — never two live writers.

- **Envoy (most relevant — also a proxy/data plane).** Hard split:
  - *Bootstrap config* — static YAML, loaded **once at process start**. Holds
    only enough to come up and reach the control plane. **Never hot-reloaded.**
  - *Dynamic config (xDS)* — listeners/routes/clusters/endpoints stream from the
    control plane, which is the single source of truth. Even "State-of-the-World"
    xDS replaces a **whole resource type** atomically (it does not merge keys);
    Delta/Incremental xDS is an *optimization*, not a correctness mechanism.
  - **Lesson:** separate bootstrap (file) from dynamic (control plane). Don't let
    the file be a second live authority.
- **Kubernetes / etcd.** etcd is the single source of truth; the apiserver is the
  only writer; components *watch*. A ConfigMap mounted as a file is **downstream
  of etcd**, not an independent writer — the file is an output of the SSOT, never
  a competing input. **Lesson:** if a file participates at runtime, it flows
  *through* the store, it doesn't bypass it.
- **Consul / etcd / ZooKeeper (consensus KV).** Versioned keys, CAS/txn,
  watches, leases. Our `config:waf:doc` already mirrors this well (monotonic
  version, optimistic-concurrency CAS, immutable `config:waf:v:{n}` snapshots,
  pub/sub nudge, per-node ACK TTL) — the `config-etcd-source-of-truth.md` plan
  swaps the *backend*; this plan fixes *who is allowed to write*.
- **Layered precedence (12-factor & friends).** Deterministic, one-directional
  merge: `defaults < file < env < remote/dynamic < runtime-override`. Higher
  layers win; lower layers never silently overwrite higher ones. We currently
  have the *opposite* — a file save can stomp a higher-precedence runtime change.
- **GitOps / immutable infrastructure.** The Git-managed file is the desired
  state; a reconciler **publishes** it to the runtime store. The file is an
  *input to* the SSOT, applied through one controlled path — not hot-swapped into
  the data plane behind the store's back.

**Synthesis for Aegis:** the versioned config doc (Redis now → etcd later) is the
single source of truth for the *live data plane*. The YAML file is **bootstrap +
an optional authoring input that flows through the doc**. There is exactly **one
applier** (`apply_and_swap`) and **one guard**.

---

## 3. What lives where — the bootstrap/dynamic split (and why it's mandatory)

If the file is read **only at startup** and the doc becomes the source of truth,
some config still **cannot** move into the doc — so the split must be explicit.
The good news: it already exists **implicitly**. The set of
`apply_cfg_change_to_*` helpers (`reload.rs`) *is* the dynamic surface. Anything
with a helper can be hot-applied; anything without one is **already** de-facto
bootstrap-only (editing it in the file + reload does nothing live today). Mapping
the 23 top-level `WafConfig` fields against the 16 helpers gives three tiers:

| Tier | Sections | Reload helper? | Authority |
|---|---|---|---|
| **1 — Pure bootstrap** | `state`, `listeners`, `admin` (binds), `node`, `cluster` | none | **file/env only — NEVER in the doc** |
| **2 — Dynamic** | `routes`, `upstreams`, `tls`, `zero_trust`, `rules`, `rate_limit`, `risk`, `detectors`, `bots`, `tiers`, `ddos`, `fail_mode_by_tier` | dedicated helper each | **doc is SSOT; file is the seed** |
| **3 — Partially dynamic (the trap)** | `observability` (only `.copilot`), `alerting` (only `.receivers`), `compliance` (only the mask clamp), `dlp`/`response_filter`, `streaming`, `audit` | partial / per-field | mixed — must be labeled per-field |

- **Tier 1 is irreducible.** `state` is the chicken-and-egg case: you cannot
  store *"where the config DB is"* inside the config DB. `listeners`/`admin` binds
  and `node`/`cluster` identity define *how the node comes up and joins the
  store*, so they can't be applied live. This is exactly Envoy's bootstrap config.
- **Tier 3 is where "I changed one key and it didn't take / something else moved"
  bites hardest** — granularity is per-*field*, not per-section, so a
  section-level mental model misleads.

### Recommendation for the split: pragmatic now, structural later

- **Pragmatic (ship with P0/P1):** keep the full `WafConfig` in the doc blob, but
  (a) on boot read **Tier-1 fields only from the file/env**, ignoring the doc's
  copy; (b) mark Tier-1 (and known Tier-3 restart-only fields) **read-only /
  "restart required"** in the API + dashboard so edits don't silently no-op; (c)
  **derive the partition from the helper set in code** and extend the existing
  structural guard (`redis_source.rs:646`) to assert the bootstrap/dynamic
  partition so the two can't drift. Low effort, removes the confusion immediately.
- **Structural (future target, natural to fold into the etcd cutover):** split the
  type into `BootstrapConfig` (file/env) + `DynamicConfig` (the doc blob), so the
  compiler makes it **impossible** to put a Tier-1 field in the DB. Higher effort
  (serialization, `patch_*`, validation surface, existing-doc migration).

This refines §1's claim: feeding the file through the doc retires the staleness
class for **Tier 2**, but Tier 1 stays file-authoritative by design and Tier 3
needs per-field labeling — hence the explicit classification rather than "nothing
is file-only anymore."

## 4. Recommendation

Adopt the Envoy/k8s discipline: **one applier, one source of truth, file demoted
to bootstrap + publisher.** **Decision (finalized): Option B** — it removes the
dual authority *and* keeps the edit-the-file workflow, and it is the behavior the
H2 end-state (§2c) and the H3 GitOps reconciler build on. Option A is recorded
below as the rejected simpler alternative.

### Option B — File becomes a *publisher* to the doc (DECISION)
- Boot: load + validate file → **auto-seed as doc v0** (fixes C).
- File watcher is **retained but inverted**: on change it loads + validates, then
  calls `store.activate(expected_version, blob, actor="file-watch", …)` **instead
  of** writing `cfg_swap` directly. It no longer calls any `apply_cfg_change_to_*`
  helper.
- The **single** Redis-doc watcher (`apply_and_swap`) is now the *only* thing that
  touches `cfg_swap` and the derived handles → fixes A, B, D at the root, and the
  cluster converges for free (file edit on one node propagates to all).
- **Dedup:** if the file blob equals the current `doc.blob`, skip `activate`
  (no-op) — avoids restart/touch churn and CAS storms when N nodes mount the same
  file.
- **Multi-node file ownership:** when several nodes mount the same file, the
  CAS makes it safe — first writer wins, the rest see their blob already current
  and stand down. (Document the recommended topology: one canonical file / GitOps
  writes one node, or all nodes mount the same ConfigMap — both are correct under
  CAS+dedup.)

The chosen design keeps **whole-config validated swaps** (correct, §1/§2) and the
existing CAS/versioning/snapshot/rollback machinery untouched.

> *Rejected alternative — Option A (file is bootstrap-only):* file loaded once at
> boot and auto-seeded as doc v0, then the file watcher is **deleted** entirely —
> all live changes flow through the API / doc watcher. Simplest and most
> predictable (exactly Envoy bootstrap), but operators lose the edit-the-file-live
> workflow and GitOps flows that rewrite the file expecting hot reload break. Kept
> as the record of the call; revisit only if the publisher path proves not worth
> its weight.

### Why this slots *before* the etcd plan
`config-etcd-source-of-truth.md` assumes a clean single-writer config doc and
explicitly puts the file-vs-doc model out of scope. Doing this first means the
etcd cutover inherits one applier and one authority, not two. It also retires the
[[project_config_plane_doc_vs_file]] staleness class **for Tier-2 sections** once
the file feeds the doc (Tier 1 stays file-authoritative by design — see §3).

---

## 5. Phases (Option B)

> **Shipped:** P0 (boot-seed → doc v0) — PR #74, 2026-06-23.
> **P1+P2 (file watcher → publisher; single applier; `config_plane.file_watch`
> flag, default `publish`)** — 2026-06-23 (`FEAT-config-file-watch-publisher`).
> The file watcher no longer writes the live config; it validates + activates
> into `config:waf:doc` and the shared-store watcher is the sole applier.

- **P0 — Auto-seed boot file → doc v0 (fixes C) + classify the split.** At
  startup, if `config:waf:doc` is absent and a boot file path exists,
  `activate(expected=None, blob=<boot file>, actor="boot-seed")`. Idempotent: an
  existing doc is left untouched. This removes the boot/first-mutation divergence
  window and makes the lazy-seed-from-file branch in `load_active_config_doc`
  (`admin_mutate.rs:2677-2686`) dead/simplifiable. **Pragmatic split (§3):** on
  boot, read **Tier-1 fields from the file/env only** (ignore the doc's copy);
  derive the Tier-1/2 partition from the helper set and extend the structural
  guard (`redis_source.rs:646`) to assert it; mark Tier-1 + known restart-only
  Tier-3 fields **read-only / "restart required"** in the API + dashboard.
- **P1 — Invert the file watcher into a publisher.** Replace the
  `apply_folded_stores` + `cfg.store` body of `supervisor.rs` `watch_loop` with
  load → validate → blob-dedup → `store.activate(...)`. Remove the file watcher's
  direct `cfg_swap` write and all its `apply_cfg_change_to_*` calls. The Redis
  watcher remains the sole applier. Behind a flag
  `config_plane.file_watch: publish | off` (default `publish`; `off` = Option A).
- **P2 — Collapse to one applier + one guard.** Delete the now-unused file-side
  apply wiring; ensure `apply_and_swap`'s structural guard (`redis_source.rs:646`)
  is the single completeness check (fixes D — `receivers` asymmetry disappears
  because there's only one path). Update the apply-helper guard memory note.
- **P3 — Docs + runbook.** `deploy/CONFIG-PLANE-RUNBOOK.md`, cluster/HA docs,
  `plans/README.md`. Document the new flow (file = bootstrap + publisher; doc =
  SSOT), the multi-node file-ownership guidance, and the `file_watch` knob.
  Update the [[project_config_plane_doc_vs_file]] memory (staleness class largely
  retired).

---

## 6. Acceptance gates

- [ ] P0: cold boot with empty Redis seeds doc v0 from the file; an existing doc
      is left untouched (no version bump on restart).
- [ ] P1: editing the boot file activates a **new doc version** and the live data
      plane reflects it via the Redis watcher (not via a direct file swap);
      an identical-content save is a **no-op** (no version bump).
- [ ] P1: a runtime API change is **no longer reverted** by a subsequent unrelated
      file save (failure mode A gone) — integration test.
- [ ] P1: a file edit on one node converges to a second node through the doc
      (cluster propagation for free) — integration test.
- [ ] P2: exactly one applier path; the structural guard covers it; `receivers`
      propagates on a file edit (failure mode D gone).
- [ ] B-only: concurrent identical file mounts on N nodes produce **one** new
      version, not N (CAS + dedup) — unit/integration test.
- [ ] Split guard: editing a **Tier-1** field via the API/dashboard is rejected
      (read-only); the structural guard asserts every non-helper section is
      classified bootstrap so the partition can't silently drift.
- [ ] H2 fallback (2c): with etcd **empty/unreachable**, a node boots **fully
      configured** from the file's `DynamicConfig` (not half-configured) and
      serves; a live etcd value always wins over the file copy (no merge); the
      local last-applied cache is preferred over the file baseline when present.

---

## 7. Risks

| Sev | Risk | Mitigation |
|---|---|---|
| MEDIUM | Behavior change for operators relying on file hot-reload as a *live* path | `config_plane.file_watch` knob; default `publish` preserves the edit-the-file workflow (it just routes through the doc now); runbook |
| MEDIUM | Multi-node: every node mounting the same file races to `activate` | CAS makes it safe; blob-dedup makes it a no-op for already-current content; document topology |
| LOW | P0 double-swap at boot (serve file baseline, then seed) | Seed is idempotent and pre-traffic; verify back-to-back apply is clean (same concern noted in `config-auto-restore.md` §3.3) |
| LOW | A GitOps pipeline that rewrites the file and expects an *instant* in-process swap now waits one doc round-trip | Sub-second via the `config:waf:bump` nudge; documented |

---

## 8. Out of scope

- Moving the config **backend** Redis → etcd — that's
  [`config-etcd-source-of-truth.md`](./config-etcd-source-of-truth.md); this plan
  is its prerequisite (one writer first, then swap the store).
- Auto-restore after a store wipe —
  [`config-auto-restore.md`](./config-auto-restore.md) (complementary; P0's
  seed-from-file overlaps its "re-publish last-known-good" idea and should be
  cross-checked when either is built).
- Partial/delta apply or per-key transactional swaps — explicitly **not** pursued;
  whole-config validated swap is the correct model (§1/§2).
- The ephemeral hot-path keyspace (rate-limit, risk, nonces, leases) — unaffected.

---

## 9. Effort & complexity

**Effort grade: S–M** (roadmap scale: S ≤~3 d, M ~1–2 wk). P0 is a small,
high-value, low-risk fix on its own. P1 is the substantive change (inverting the
watcher + flag + tests). P2 is deletion + guard consolidation. Mechanically this
*removes* a code path rather than adding a subsystem, and the CAS/versioning
machinery it leans on already exists.

| Phase | Work | Estimate |
|---|---|---|
| **P0** | Auto-seed boot file → doc v0; simplify lazy-seed branch | ~0.5–1 d |
| **P1** | Invert file watcher to publisher + dedup + `file_watch` flag + tests | ~3–5 d |
| **P2** | Delete file-side apply wiring; one guard; memory update | ~1–2 d |
| **P3** | Runbook + cluster/HA docs + `plans/README.md` | ~1 d |

**Recommendation: do P0 now regardless** (it's a standalone correctness win and
closes failure mode C), then P1+P2 as the dual-authority fix when scheduled.

---

## 10. Long-term arc — toward a config control plane

§1–§9 fix the *immediate* correctness bug. The end-state this should converge on
is the **Envoy/k8s model done fully**: a single declarative config control plane
that owns desired state, with data-plane nodes as pure consumers that *watch and
converge*. The work sequences into three horizons; each is independently
shippable and leaves the system correct.

### Horizon 1 — One writer, one source of truth (this plan, §5)
P0–P3: file demoted to bootstrap + publisher, the versioned doc is SSOT, one
applier, pragmatic Tier-1/2/3 classification enforced by the structural guard.
**Outcome:** the dual-authority bug class is gone; the split exists but is
convention + a guard test, not yet the type system. **S–M.**

### Horizon 2 — Make the split structural, then move the store to etcd

**2a. `BootstrapConfig` / `DynamicConfig` type split (the compiler enforces §3).**
Today everything is one `WafConfig` and the doc blob is a *full* `WafConfig`, so a
Tier-1 field *can* be written to the doc (it's just inert + misleading). Replace
the convention with types:

```
struct BootstrapConfig {            // Tier 1 — file/env only, read once at boot
    listeners, state, admin, node, cluster, /* + Tier-3 restart-only fields */
}
struct DynamicConfig {              // Tier 2 — the doc blob; the ONLY thing the
    routes, upstreams, tls, zero_trust, rules, rate_limit, risk, detectors,
    bots, tiers, ddos, fail_mode_by_tier, /* + Tier-3 dynamic fields */
}
struct WafConfig { bootstrap: BootstrapConfig, dynamic: DynamicConfig }  // boot view
```

- The config doc (`config:waf:doc.blob`) serializes **`DynamicConfig` only** — it
  becomes *structurally impossible* to put a bootstrap field in the DB, retiring
  the whole [[project_config_plane_doc_vs_file]] class for good (not just Tier-2).
  (The **file** still holds *both* halves as the bootstrap + DR fallback — the
  doc-only-Dynamic rule is about the DB, not the file. See **2c**.)
- `cfg_swap` holds `DynamicConfig`; `BootstrapConfig` is an immutable
  `Arc<BootstrapConfig>` set once at boot and never swapped (so the
  "edits-do-nothing" footgun can't compile).
- The `apply_cfg_change_to_*` helpers now take `&DynamicConfig`; the structural
  guard (`redis_source.rs:646`) tightens from "every section has a helper" to
  "every `DynamicConfig` field has a helper" — total coverage by construction.
- Tier-3 fields are split at the *field* level into the struct they belong to
  (e.g. `observability.copilot` → `DynamicConfig`; OTLP exporter endpoint →
  `BootstrapConfig`), which is the only place the per-field labeling from §3 has
  to be made once.
- **Migration:** `deny_unknown_fields` + a one-shot doc rewrite that strips
  Tier-1 keys from the active `config:waf:doc` blob (and all `config:waf:v:*`
  snapshots, or version-gate the reader). Keep a `serde` compatibility shim for
  one release so an old full-`WafConfig` blob still loads. `patch_*` functions
  retarget to mutate `DynamicConfig` YAML; the validation surface
  (`load_config_str`) splits into `load_bootstrap` + `load_dynamic`.
- **Effort: M.** Touches serialization, every helper signature, `patch_*`, the
  validation surface, and a stateful doc migration — but it's mechanical and
  RED-safe behind the Horizon-1 single-writer model.

**2b. etcd backend** — the existing
[`config-etcd-source-of-truth.md`](./config-etcd-source-of-truth.md) plan, now
much cleaner: it inherits one writer (H1) and a doc that is *only* dynamic config
(2a). Native Watch/Txn/Lease replace poll + Lua-CAS + emulated ACK TTLs. **L.**
The `BootstrapConfig.state` field is exactly what tells a node where etcd is —
reinforcing why it can never live in the DB.

**2c. What the YAML file holds after H2 — and the boot precedence (finalized).**
The file keeps **both** `BootstrapConfig` and `DynamicConfig` — *not* just
bootstrap. The doc/etcd holds `DynamicConfig` **only** (2a); the file is the
complete, self-sufficient definition so a node can come up **fully configured and
serving correctly even when etcd is empty or unreachable**, not half-configured.
The two roles of the file's two halves differ:

```
waf.yaml
  ├─ BootstrapConfig  ── authoritative, file/env only ──────────────► Runtime
  │                      (etcd can't hold it: it's what tells the node where etcd IS)
  └─ DynamicConfig    ── genesis seed + DR fallback ──► etcd (runtime SSOT) ──► Runtime
                         (lower precedence than etcd; never merged live)
```

**Boot precedence for `DynamicConfig`** (highest wins; strict fallback, never a
merge):

1. **etcd** — if reachable and non-empty → authoritative. The file's
   `DynamicConfig` is **not** read into the live plane.
2. **local last-applied cache** (`.aegis_last_applied_config.json`, the freshest
   machine-written snapshot — see [`config-auto-restore.md`](./config-auto-restore.md),
   which extends that marker to carry the full blob) → used when etcd is
   empty/unreachable, because it is fresher than the operator's file baseline.
   Optionally auto-republished into etcd (that *is* config-auto-restore).
3. **`waf.yaml` `DynamicConfig`** — the genesis baseline: seeds etcd on first
   boot (H1 P0), and the cold-start floor if there is no etcd value *and* no
   local cache.

**The discipline that keeps this from resurrecting failure mode B:** the file's
`DynamicConfig` is **strictly lower precedence** and is read **only** when no
authoritative etcd value exists. It is never merged with, nor allowed to override,
a live etcd value — so a stale file copy can never clobber runtime state (the
original dual-authority bug). It is a *floor*, not a competing writer.

**Keeping the fallback fresh.** The operator's `waf.yaml` `DynamicConfig` can age
the moment any change is made via the API/dashboard (etcd advances, the file does
not). That staleness is bounded by the **last-applied cache** (precedence 2),
which every successful apply rewrites — so DR restores the *freshest* safe value,
not the genesis baseline. The file baseline stays meaningful as the
version-controlled "intended" config and the absolute cold-start floor.

**Decision (finalized): the file stays a live publisher in the etcd era.**
Editing `waf.yaml` `DynamicConfig` validates and re-publishes to etcd (the H1
publisher behavior carried straight through) → GitOps-friendly, keeps the file
fresh when edits go through it, and is the on-ramp to H3's GitOps reconciler. API
/ dashboard edits still advance etcd ahead of the file, but that drift is exactly
what the last-applied cache (precedence 2) is there to bound, so it is safe.

> *Rejected alternative — file as genesis-seed + DR-fallback only* (not a live
> publisher; etcd edited solely via the API/control plane). Marginally cleaner
> SSOT, but it loses the edit-the-file-live workflow and breaks the continuity
> from H1's publisher into H3's reconciler. Kept here only as the record of the
> call.

### Horizon 3 — Config as a safe, declarative, multi-region control plane

Once config is a clean versioned `DynamicConfig` document on a watch-native store,
the high-value control-plane capabilities become tractable — these are the gap vs
Cloudflare/Envoy-grade config management:

- **Staged / canary config rollout + auto-rollback.** Activate a new version to a
  subset of the fleet (or one node), watch health/error-rate, and **auto-roll
  back** on regression instead of fleet-wide instant apply. Builds on the existing
  version snapshots + `rollback` path + per-node applied-ACK map; pairs with the
  health-signal work ([[project_health_signals_reported_not_gating]]). Audit
  `rollback.rs` for the node-local-publish bug recorded in
  [[project_api_mode_no_cluster_publish]] while here.
- **Declarative desired-state reconciliation (GitOps-native).** The file-publisher
  from H1 generalizes into a reconciler: Git is desired state, a controller
  publishes to the doc, drift between applied and desired is detected (the
  applied-ACK map already exists) and reconciled on a loop. Config becomes
  `kubectl apply`-shaped rather than imperative dashboard edits.
- **Schema versioning + migrations.** As `DynamicConfig` evolves, ship versioned
  schema migrations for the doc (today `deny_unknown_fields` hard-fails on an
  unknown key — fine for safety, brittle for rolling upgrades where an old node
  must read a new doc). A `schema_version` on the doc + forward/back-compat
  migration shims.
- **Multi-region / cross-cluster replication.** Explicitly out of scope for the
  etcd cutover; here it becomes real — etcd mirroring or a higher-level config
  federation so a global fleet converges on one desired state with regional
  override layers (the layered-precedence model from §2, applied across regions).
- **Policy-as-code surface.** Express rules/tiers/detectors as a reviewed,
  versioned policy artifact with the same canary + rollback + audit guarantees,
  rather than free-form YAML — the managed-ruleset/virtual-patching direction in
  the roadmap leans on this.

**Effort: L+ and genuinely deferred** — H3 is a multi-quarter direction, not a
scheduled task. It is listed so H1/H2 are built *toward* it (e.g. H1's publisher
is shaped to become H3's reconciler; 2a's clean `DynamicConfig` is what makes
canary rollout and schema migration sane) rather than in a way that has to be
re-litigated later.

### Dependency order

```
H1 (single writer + pragmatic split)        ← do first; standalone correctness
   └─ 2a (BootstrapConfig/DynamicConfig type split)   ← structural, retires staleness for good
        └─ 2b (etcd backend)                           ← existing plan, now clean
             └─ H3 (canary rollout · GitOps reconcile · schema mig · multi-region · policy-as-code)
```

Each arrow is "assumes, not requires-simultaneously" — H1 stands alone, 2a is
valuable even if etcd never happens, and H3 items can be picked individually once
2a lands.

---

## 11. H2a execution notes (code-checked 2026-06-24)

**Status:** **Track B — scheduled after `redis-interim-durability` P1–P3**
(foundation-first; the two are code-independent). H1 (P0–P2) shipped; H2a is the
structural type split. A blast-radius pass against current code surfaced three
things to handle before/within the refactor:

1. **`fail_mode_by_tier` has no applier** (`config.rs:265`, "wiring lands in
   Phase E") yet §10 files it under `DynamicConfig`. The tightened guard ("every
   `DynamicConfig` field has a helper") will **fail** on it. **Decide first:**
   either write a trivial `apply_cfg_change_to_fail_mode_by_tier` (it's a
   per-tier failure-mode map → a small reconcile) **or** reclassify it as
   not-yet-dynamic (keep it Tier-3/bootstrap until its consumer wiring lands).
   Recommended: reclassify now, promote when the consumer ships — don't invent a
   helper for an unconsumed field.
2. **Migration is a fail-closed footgun (HIGH).** Every existing
   `config:waf:doc.blob` is a **full `WafConfig` as YAML text**
   (`config_store.rs:67`), and `deny_unknown_fields` is on. The first
   `load_dynamic` after deploy **hard-fails on the Tier-1 keys → bricks the
   config plane**. **Required:** land the serde compat shim / one-shot doc
   rewrite (strip Tier-1 keys from the active doc + `config:waf:v:*` snapshots,
   keep a full-`WafConfig` fallback parse for one release) as PR **B0**, before
   the type split flips on. This is the single highest risk in H2a.
3. **Blast radius (mechanical but wide).** The doc blob is YAML *text*, so the
   change is to the **parse/validation surface**, not stored bytes: `load_config`
   / `load_config_str` split into `load_bootstrap` + `load_dynamic`
   (`config.rs:33/63`); ~20 `load_config_str` call sites in `admin_mutate.rs`;
   all 17 `apply_cfg_change_to_*` + `apply_and_swap` (`&WafConfig`→`&DynamicConfig`);
   the `ArcSwap<WafConfig>` carrier → `ArcSwap<DynamicConfig>` + a separate
   `Arc<BootstrapConfig>`; `ProxyContext::build` (`proxy.rs:251`), `run.rs`,
   `accept.rs:251`. **Fiddliest:** sub-field dynamics
   (`observability.copilot`, `upstreams[].cache`, `zero_trust.downstream`) force
   the split to descend into `ObservabilityConfig`/`PoolConfig`/`ZeroTrustConfig`.
   The structural guard test (`redis_source.rs:823`) inverts from helper-scrape
   to field-coverage — a rewrite, not an edit.

**PR shape (Track B):** **B0** migration shim + `fail_mode_by_tier` decision
(S) → **B1** the `BootstrapConfig`/`DynamicConfig` split + signature churn +
guard rewrite (M). Note: any `persistence:` section added by
`redis-interim-durability` (Track A, §10.3) gets classified here.
