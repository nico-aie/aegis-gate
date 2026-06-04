# n-tester suite — cluster + AI confidence_threshold (QC rounds 1–2 closed)

> **Status:** ✅ **CLOSED 2026-05-31** — 12 tests, 9 pass, 0 fail, 3
> expected skips on commit `6db09b1`. Two `R2-009` UI sub-findings
> (A + B) deferred; everything else addressed.
>
> **Branch:** all changes on `develop`.
>
> **Campaign window:** QC ran the suite 2026-05-29 (round 1), filed
> 4 findings, fixes landed same day; 2026-05-30 (round 2), filed 9
> more findings, fixes + a forced live-propagate product fix landed
> 2026-05-30/31; round-3 was the verification run on 2026-05-31 and
> caught nothing new.

## What this suite covers

`tests/n-tester/` is the QC suite for two features that shipped
through 2026-05:

1. **Cluster config plane** — versioned `config:waf:doc`, CAS
   activation, per-node ACK, leader failover, rollback. Track plan:
   `plans/archive/cluster-config-sync-and-scaling.md`.
2. **AI `confidence_threshold` adjust** — adjustable from the
   dashboard, hot-swap via `Arc<AtomicU32>` shared with the AI
   detector, persisted through the config plane. Shipped commit:
   `e77d379`.

Two test layers:
- **`nt-01..12-*.sh`** — automated shell tests, one cluster per
  test, JSON report under `tests/n-tester/reports/`.
- **`ui/nt-ui-01..07-*.md`** — manual playbooks QC pastes into
  Claude Desktop with a Chrome MCP extension, then walks through
  the dashboard.

Convention mirrors `tests/l-tester/`: numbered shell scripts,
`_common.sh`, `run-all.sh`, JSON reports.

---

## Findings + fixes

### Round 1 (2026-05-29) — 4 findings

QC findings at
`tests/n-tester/reports/findings/2026-05-29/`.

| Sev | ID | Symptom | Fix | Commit |
|---|---|---|---|---|
| **HIGH** | cluster-yaml-missing-dashboard-auth | every `/admin/login` against `cluster-{a,b}.yaml` returned 401 → harness aborted silently before any assertion ran | top-level `admin: { dashboard_auth: { password_hash_ref, csrf_secret_ref, … } }` added to both fixture YAMLs (argon2 hash for `aegis-test-1234`, same CSRF secret as `dev.yaml`) | `3b5c350` |
| LOW | fail-message-stderr-vs-stdout | `fail()` wrote `_red` to stdout; `run-all.sh` captured only stderr → empty `stderr_tail` for every failure | `fail()` + `skip()` now redirect via `>&2` | `3b5c350` |
| LOW | login-silent-on-no-cookie | `grep \| sed \| tr \| head` inside `$()` aborted on grep-not-found under `set -euo pipefail`, masking the underlying HTTP error | `login()` checks HTTP status FIRST, tolerates grep-not-found with `\|\| true` after a confirmed 200 | `3b5c350` |
| LOW | run-all-skip-bookkeeping | `skip()` exited 0 → counted as pass; no SKIP column in the report | `skip()` exits **77** (autotools convention); `run-all.sh` reads exit 77 as skip and captures the reason (ANSI-stripped) | `3b5c350` |

### Round 2 (2026-05-30) — 9 findings

QC findings at
`tests/n-tester/reports/findings/2026-05-30/`.

| Sev | ID | Symptom | Fix | Commit |
|---|---|---|---|---|
| **HIGH** | R2-001 cluster-yaml-admin-scheme-mismatch | admin listener binds plaintext (`http://…:9443`) but every UI playbook + Round-2 prompt used `https://` → Chrome ERR_SSL_PROTOCOL_ERROR; QC dead-in-the-water | flipped `https://127.0.0.1:9{443,543}` → `http://` across `ui/README.md` + 7 `nt-ui-*.md` files | `3b5c350` |
| **HIGH** | R2-002 nt01/nt08-ack-scan-races-watcher-poll | `acks=$(redis-cli --scan…)` ran immediately after `wait_for converged_on_b` → watcher hadn't yet called `record_applied`, scan came back empty | `nt-01` + `nt-08` wrap the ACK scan in `wait_for acks_present 10` | `3b5c350` |
| **HIGH** | R2-003 nt02-does-not-race | `login "$NODE_B_ADMIN"` inside the B-side subshell took 100-300 ms, A's PUT completed first, CAS conflict never fired | pre-login both nodes BEFORE forking; subshells get their own `COOKIE`/`CSRF` | `3b5c350` |
| MED | R2-004 response-filter-not-rollbackable | `/api/config/versions/<n>/rollback` is gated by `ROLLBACKABLE_ACTIONS` (audit-ring replay) which doesn't include the folded toggles — error message gave no pointer to the right endpoint | (a) `nt-04` switched to `POST /api/config/rollback` (config-plane endpoint, re-activates YAML snapshot, no per-action gate); (b) `NotRollbackable` arm in `handle_rollback` now returns a body naming the config-plane endpoint + explaining why | `3b5c350` + `6db09b1` |
| **HIGH** | R2-005 nt05/nt09-silent-fails | three flavours hidden behind pipefail: (i) `nt-05` grep over a YAML key that doesn't exist in cluster-b.yaml; (ii) `nt-07/09` strict `awk` equality on f32-round-tripped floats (0.85 → 0.8500000238418579); (iii) related silent paths | (i) `\|\| true` on the grep pipeline; (ii) new `floats_eq` helper in `_common.sh` for ε-tolerant compares used by nt-06/07/08/09; (iii) opt-in `enable_err_trap` for future silent fails (prints line + last command) | `3b5c350` |
| **HIGH** | R2-006 nt07-restart-races-watcher | post-restart node B reported the cfg default (0.85), not the cluster doc value (0.42); test read immediately after `wait_ready` (which gates on `/healthz/ready`, not the config-plane watcher) | `nt-07` wraps the post-restart read in `wait_for a_at_target 10` | `3b5c350` |
| LOW | R2-007 nt03-jq-null-leader-failover | `jq` runtime error `Cannot iterate over null (null)` on `.peers[]` early in boot | `(.peers // [])[]` guards + explicit `peer_count == 0 → skip` check before the `is_leader` filter | `3b5c350` |
| MED | R2-008 start-cluster-no-port-conflict-check | a stale `waf run` on the test ports caused `start_node` to spawn a binary that fail-bound + exited; `wait_ready` then succeeded against the squatter; `reset_redis_config_plane` wiped the squatter's state | `start_cluster` now runs an `lsof -i :PORT` LISTEN check up front (fail with a kill hint), plus `kill -0` post-spawn alive checks on both nodes that dump the log tail on death | `3b5c350` |
| LOW | R2-009 sub-C feature-off-error-mis-references-gate | `PUT /api/ai/enabled` on a feature-off binary said "rebuild with `FEATURES=… ai` and set `cfg.ai.enabled = true`" — but the gate is **either** missing `--features ai` **or** missing `cfg.ai.model_path`. The recommended action was misleading for binaries built with the feature | message rewritten to name both gates accurately; adds `ai_feature_built` field so the response disambiguates without forcing the operator to read `GET /api/ai/confidence` | `6db09b1` |

### Out of round-2 (the green run forced one more product fix)

| Sev | Symptom | Fix | Commit |
|---|---|---|---|
| HIGH | AI `confidence_threshold` was synchronously written into the originator's `Arc<AtomicU32>` by `handle_ai_confidence_put`, but `apply_cfg_change_to_ai` (called by every watcher on every config swap) only carried the **toggle + mask**, not the threshold. Sibling nodes + restarted nodes regressed to `cfg.ai.confidence_threshold` from `waf.yaml`. nt-07 caught it; nt-08 had a `TODO(live-propagate)` block | extend `apply_cfg_change_to_ai` with an `ai_threshold: Option<&Arc<AtomicU32>>` parameter (writes `new_cfg.ai.confidence_threshold.to_bits()` on every swap, no-op when None). Threaded through `FoldedReloadTargets` (file + etcd watchers) AND `ApplyTargets` (redis config-plane watcher) so every watcher path propagates. nt-07 PASS; nt-08 asserts node-B's live atomic flips | `6db09b1` |

### Round 3 (2026-05-31) — verification only, 0 new findings

12 tests · **9 pass / 0 fail / 3 skip**. Skips all intentional:
- `nt-03` — `/api/cluster/peers` not in this build (404)
- `nt-10` — binary built **with** `--features ai`; this test is for the no-ai build (mutually exclusive)
- `nt-11` — needs `AEGIS_AI_E2E=1` (opt-in for the live model exercise)

Report: `tests/n-tester/reports/run-20260531T131537Z.json`.

---

## Deferred (R2-009 sub-A + sub-B)

Two UI polish items from R2-009. Not blocking, but worth picking up
the next time the AI row gets edited:

- **sub-A** — when `feature_present: false`, the threshold input is
  HIDDEN rather than RENDERED-disabled-with-the-cfg-default-as-value.
  Either render the input read-only with `default` as its value, or
  add a one-line "current default: 0.85" caption next to the rebuild
  hint. The threshold spec said "disabled and visible".
- **sub-B** — the disabled `Enable` button on the feature-off path
  has `disabled` (good) but no `title=`, no `aria-disabled="true"`,
  and `cursor: pointer` (should be `not-allowed`). A11y miss; same
  pattern that nt-ui-07 tests for the threshold input. Both fixes
  go in `crates/aegis-control/assets/dashboard/src/pages.jsx`'s
  `AiDetectorRow` (the `feature_present === false` branch).

---

## Re-running the suite

```sh
cd /Users/nico/waf-code/aegis-gate

# 1. Release binary with the cluster-relevant features.
cargo build -p aegis-bin --release \
  --features "redis geoip alerts ai affinity"

# 2. Make sure no waf process is squatting the test ports.
pkill -f 'target/release/waf' 2>/dev/null

# 3. Run.
tests/n-tester/run-all.sh

# 4. (Optional) Exercise the AI live hot-swap nt-11 covers.
AEGIS_AI_E2E=1 tests/n-tester/run-all.sh --filter 'nt-11*'
```

Expected on `6db09b1` and later: **9 pass / 0 fail / 3 skip**.

---

## Hand-off for the next QC round

- The Round-2 prompt I gave QC (search chat history for "Round-2
  prompt") is still mostly right. The key thing to update before
  the next paste-in: name commits **`3b5c350` + `6db09b1`** in the
  "WHAT CHANGED SINCE YOUR LAST RUN" section, and remind them to
  validate the regression-check items don't reproduce.
- AI feature is now baked into the cluster fixtures
  (`config/cluster-{a,b}.yaml` ship `ai.model_path:
  data/ai_model/waf_model.onnx` + `enabled: true`), so the dashboard
  will show the live AI row (green pill, not 🔒). NT-UI-06
  (feature-off banner) will skip with the right reason; this is
  intentional. If you want to exercise the feature-off path, build
  without `--features ai` and re-run only that playbook.
- NT-11 (live-effect) is now genuinely exercisable. Set
  `AEGIS_AI_E2E=1` and verify the borderline-attack flip
  (high-gate → 200, low-gate → 403) lands.
- R2-009 sub-A + sub-B (above) are the two known deferrals — if QC
  re-files them, point at this note rather than re-opening.
