# Runtime gate toggles (DDoS, risk thresholds) are hot-flippable but not restart-durable

**Status:** Open — reproducible
**Filed:** 2026-06-18
**Reporter:** operator (Round 2 preprod, `aiagent.waf-exams.info`)
**Severity:** High — operator-visible dashboard state silently reverts on restart

## TL;DR

Dashboard PUTs to `/api/gates/ddos` and `/api/risk/thresholds` apply to the live
runtime immediately and are appended to the chain audit log, but they do **not**
publish a new shared-config version to Redis (`config:waf:doc`). On the next WAF
boot the shared-config rehydrate reapplies the `waf.yaml` defaults, silently
reverting both toggles. The dashboard's "Changes apply immediately — no restart
required" subtitle promises hot-apply but the operator reasonably expects
durability across restart.

## Reproduction (verified end-to-end on staging)

1. **Pre-state.** `waf.yaml` ships with the defaults:
   ```yaml
   risk: { thresholds: { enabled: true, ... } }
   ddos: { enabled: true, ... }
   ```
2. **Boot.** WAF starts cleanly; `applied:waf-1 = 95`; `config:waf:doc` value
   `version=95` carries `ddos.enabled: true` and `risk.thresholds.enabled: true`.
3. **Operator action.** In dashboard, flip **Cumulative IP risk thresholds → OFF**
   and **DDoS Gate → OFF**. UI shows the "OFF" pill / banner. Live traffic
   behavior changes as expected (gates inert).
4. **Verify hot-apply.** Audit chain records two entries (extracted from
   `logs/audit/audit-2026-06-18.ndjson`, both within 8 s of each other):
   ```json
   { "action": "risk_thresholds_set",
     "resource": "/api/risk/thresholds",
     "diff": { "before": { "enabled": true, ... },
               "after":  { "enabled": false, ... } } }
   { "action": "ddos_set",
     "resource": "/api/gates/ddos",
     "diff": { "before": { "enabled": true, ... },
               "after":  { "enabled": false, ... } } }
   ```
5. **Restart.** `./run-staging.cmd build` (rebuild + redeploy). New process boots,
   logs `applied shared config version 95`.
6. **Post-state — bug observed.** Dashboard reads:
   - Cumulative IP risk thresholds → **ON** (waf.yaml default)
   - DDoS Gate → **ENFORCING / ON** (waf.yaml default)

   The operator's two PUTs from step 3 are silently gone from the live state
   even though they're still in the chain audit log.

## Diagnostic confirming the root cause

The shared-config plane in Redis still points at `version=95` and the published
blob matches `waf.yaml` byte-for-byte for both fields:

```sh
$ docker exec aegis-redis redis-cli KEYS 'config:waf:v:*' | wc -l
95
$ docker exec aegis-redis redis-cli GET config:waf:applied:waf-1
95
$ docker exec aegis-redis redis-cli GET config:waf:doc | jq -r '.blob' | grep -A2 'risk:\|ddos:'
risk:
  ...
  thresholds: { enabled: true, ... }     # ← still the waf.yaml default
ddos: { enabled: true, ... }              # ← still the waf.yaml default
```

There is no `config:waf:v:96` or later — i.e., the two PUTs in step 3 never bumped
the shared-config version. The hot-flip mutated in-memory state only; the
audit-log entry is durable but the config-plane publication step is missing.

Confirmation from the WAF's own boot lines:
```
aegis_proxy::run: ddos: runtime installed; enabled is hot-flippable via
                  PUT /api/gates/ddos initial_enabled=true ...
```
"Hot-flippable" matches the observed behavior.

## Affected endpoints (known)

Both have been verified to exhibit this:
- `PUT /api/gates/ddos`              → `action: "ddos_set"`
- `PUT /api/risk/thresholds`         → `action: "risk_thresholds_set"`

Likely also affected by the same pattern (need verification — same handler
shape, all show "hot-flippable" / "runtime installed" boot lines):
- `PUT /api/ai/enabled`             — AI detector on/off (per `crates/aegis-proxy/src/run.rs` "runtime toggle wired")
- `PUT /api/gates/bots`             — bot classifier gate
- `PUT /api/mode`                   — enforce / log_only global mode flip

Endpoints that ARE durable (proven by audit history reaching v95 across many
config changes) and can be used as a reference for the fix:
- `PUT /api/config` (full config publish — what's used for risk weights/etc.)
- `POST /api/upstreams/...`
- Per-pool / per-rule mutations going through `cas_set` config plane writes.

## Expected behavior

A successful PUT to one of these gate toggles should:
1. Apply the new state to the in-memory runtime (already works).
2. Append the audit-chain entry (already works).
3. **Publish a new `config:waf:v:N+1` to Redis and CAS-set `config:waf:doc` and
   `config:waf:applied:<node_id>` to N+1** so the next boot rehydrate picks up
   the operator's intent. (Missing.)

Step 3 is what the other PUT handlers (rules, upstreams, full-config) already
do via the shared-store writer; it's a one-or-two-line addition in the gate
PUT handlers.

## Suggested fix scope

- `crates/aegis-control/src/api/risk.rs`        (thresholds_set handler)
- `crates/aegis-control/src/api/gates.rs`       (ddos / bots handlers)
- Likely also `api/ai.rs`, `api/mode.rs` for the same family of toggles.

Add the same `state.config.publish_new_version(...)` call the durable handlers
already make, BEFORE returning 200. Audit the entry only after the publish CAS
succeeds, so audit and config-plane stay consistent (right now they can diverge
silently, which is exactly the surface-level bug).

## Operator workarounds until fix lands

Either:
1. **Bake the desired state into `waf.yaml`.** Authoritative on every boot.
   ```yaml
   risk:
     thresholds: { enabled: false, ... }
   ddos: { enabled: false, ... }
   ```
2. **Re-issue the PUTs on every restart** (via `./run-staging.cmd ai/ddos off`
   or a post-boot script). Brittle but works without yaml edits.

## Why this matters

- Operator changes via the dashboard are presented as first-class config
  mutations (they appear in Config history, have audit-chain entries, the UI
  doesn't warn about non-durability). Silently losing them on restart breaks
  the operator's mental model and erodes trust in the dashboard.
- During hackathon round 2, the operator hit this twice on consecutive
  redeploys — losing both Cumulative IP risk thresholds OFF and DDoS gate OFF
  state — and only noticed because they happened to look at the gates page.
  On a benchmark phase this could mean traffic gets blocked unexpectedly
  because a gate the operator thought was disabled comes back on.
- Chain audit also looks inconsistent: it records `enabled: true → false`,
  then later boots silently apply `enabled: true` with no `*_set` event of
  their own — so reconstructing "what was the operator-intended state at time
  T" from the audit log gets messier than it should be.

## Related

- `crates/aegis-proxy/src/run.rs` — emits the "runtime installed" boot lines for
  the affected gates; useful for grepping all hot-flippable surfaces.
- `crates/aegis-control/src/api/upstreams_config.rs` — example of a PUT handler
  that does publish a new shared-config version (reference for the fix).

---

## QC verification + resolution (2026-06-18)

Traced the durable-publish primitive (`ConfigStore::activate` →
`config:waf:doc` v N+1; boot rebuilds every runtime from that doc) and audited
**all 50 mutating handlers** in `crates/aegis-proxy/src/admin_mutate.rs`.

**Root cause confirmed.** `handle_ddos_put` / `handle_risk_thresholds_put`
applied only to the in-memory runtime inside the `AuditedMutate` closure and
never called `activate`. Verdict: report is correct.

**Corrections to the report's guesses:**

- `PUT /api/ai/enabled` and `PUT /api/ai/confidence` are **already durable** —
  they ARE the reference pattern (patch shared blob → validate → `activate`,
  then apply locally). The suggested-scope line pointing at `api/ai.rs` was a
  false lead. `api/risk.rs` / `api/gates.rs` are read/validation-only modules;
  the real write handlers live in `admin_mutate.rs`.
- `PUT /api/mode` uses a **separate plane** (`publish_modes` →
  `config:waf:modes`), not `config:waf:doc`. Restart-durability there is a
  distinct question (does boot rehydrate the modes plane?) — **filed separately**,
  not part of this fix.

**Additional non-durable toggles found (not in the original report):**

- `PUT /api/gates/strikes`     (`strikes_set`)
- `PUT /api/rate-limit`        (`rate_limit_set`)
- `PUT /api/risk/canary-paths` (`risk_canary_paths_set`)

`/api/logging` (verbosity) and `/api/loadmode` are also node-local-only but are
arguably intentional operational knobs — left as-is pending an intent call.

**Architecture note:** the live config watcher has a reload helper for
`rate_limit` but **none** for `ddos`/`risk`/`strikes`/`bots`/`canary`. Restart
durability works for all of them regardless, because **boot rebuilds every
runtime from `config:waf:doc`** — the watcher only governs live cross-node
convergence (moot on single-node).

### Resolution — SHIPPED

Fixed all **six** confirmed toggles with the "keep instant in-memory apply +
publish a durable doc version" model (mirrors `handle_ai_confidence_put`):

1. `handle_ddos_put`, `handle_risk_thresholds_put`, `handle_bots_put`,
   `handle_strikes_put`, `handle_rate_limit_put`, `handle_risk_canary_paths_put`
   now load the active doc (seed from boot YAML if none), patch only their
   section via a new `patch_*` helper, re-validate with `load_config_str`, and
   `ConfigStore::activate` it.
2. Ordering matches the report's ask: the audit entry + local in-memory apply
   happen **only after `activate` returns `Applied`**; a version `Conflict`
   returns `409` with nothing applied or audited, so audit / config-plane /
   live runtime stay consistent.
3. `rate_limit` persists into the `rate_limit.buckets` `scope: global, key: ip`
   entry that `derive_ip_rate_cfg` selects at boot (creating it if absent).
4. `ddos` patches only the 7 operator-editable scalars — YAML-only
   `tier_overrides` / `failure_mode` are left byte-stable.

Tests: 8 new `patch_*` unit tests (each round-trips through `load_config_str`
to prove the published blob boots); full `admin_mutate` suite green (43).
Implementation in `crates/aegis-proxy/src/admin_mutate.rs`.
