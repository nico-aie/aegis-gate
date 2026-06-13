# Fix plan — detector-toggle UX + global config lag + velocity mask bypass

> **Status:** Drafted 2026-06-12. Code-verified against `develop`.
> Addresses three linked issues reported together:
> 1. Velocity detector can't be turned off via the mask (QC report:
>    `VELOCITY_SEQUENCE_BUG_REPORT.md`).
> 2. Detector toggles lag + throw "Toggle failed: mask changed under you";
>    some toggles never land.
> 3. Config saves lag on **every** page (Detectors, Zero Trust, Settings, …).
>
> They share one substrate — the cluster config-plane mutation path — so
> they're planned together but fixable independently.

---

## Issue 1 — Velocity detector bypasses the mask (HIGH, trivial fix)

### Root cause (confirmed)
`VelocitySequenceDetector::id()` returns `"velocity_sequence"`, but
`DetectorClass::Velocity::as_str()` is `"velocity"`. The dispatcher gates each
detector with `mask.is_enabled_id(d.id())`, which does
`DetectorClass::from_id("velocity_sequence")` → `None` →
**falls back to `true` ("unknown detectors run unconditionally")**. So the
detector runs regardless of the mask, and "disable all detectors" never
silences `velocity_login_to_deposit` / `_withdrawal` etc.

The unknown-id→`true` fallback is itself intentional (it let `jwt_inspection`
ship in Phase A1 before it had a class). The bug is the *silent* mismatch.

### Fix
- `crates/aegis-security/src/detectors/velocity_sequence.rs` — `id()` returns
  `"velocity"` (matches `DetectorClass::Velocity`). Signal *tags*
  (`velocity_login_to_deposit`, …) are built from `EndpointTag`, not `id()`, so
  they don't change — dashboard rule names stay the same.
- Update the `id_is_velocity_sequence` unit test assertion.

### Guard against recurrence (do this, not optional)
Add a drift-guard test in `detectors/mod.rs` (or `mask.rs`):
```rust
#[test]
fn all_registered_detectors_map_to_a_class() {
    let cfg = aegis_core::config::DetectorsConfig::default();
    for d in default_detectors_with(&cfg) {
        assert!(
            DetectorClass::from_id(d.id()).is_some(),
            "detector '{}' has no DetectorClass — mask gating silently no-ops",
            d.id(),
        );
    }
}
```
This fails the build the next time a detector's `id()` drifts from its class.
(Cross-checked: every other current default detector — incl. `jwt_inspection`
— already maps to a class; only velocity is broken.)

**Effort:** ~30 min incl. test. No config/API/dashboard changes.

---

## Issue 2 — "mask changed under you" 412 churn (MEDIUM, frontend)

### Root cause (confirmed)
The detector toggle uses optimistic concurrency: `GET /api/detectors` returns
`config_version`; the dashboard echoes it in `If-Match` on `PUT /api/detectors`;
the server 412s if the **global config-doc version** moved
(`admin_mutate.rs:3810`).

The dashboard sources the version from cached GET data
(`pages.jsx:3328` `const configVersion = api.data?.config_version`). On a
**successful** toggle it calls `api.reload()` but **never updates the version
from the PUT response** (`pages.jsx:3463-3473`). The PUT returns
`{ ok, version }`. So:

- Toggle 1 succeeds: server version N → N+1. Client still holds N (reload is
  async + itself lagged by Issue 3).
- Toggle 2 (before reload lands) sends `If-Match: N` → server is N+1 → **412**.
- The 3-attempt retry loop re-fetches (another lagged GET) and retries; under
  sustained lag the window stays stale, the toast flashes, and a fast clicker
  sees some toggles "never change."

There is **no background version churn** — no periodic re-activation loop exists
(only the unrelated readiness reconcile). The churn is self-inflicted by the
stale-version bug + lag.

### Fix (frontend, `pages.jsx`)
1. **Update the version from the PUT response on success.** Capture
   `r.version` (parse the 200 body) and write it back to the source the next
   `commitToggle` reads — a local `versionRef` seeded from `configVersion` and
   updated on every successful PUT — so back-to-back toggles use the fresh
   version without waiting for the GET reload. This alone removes the common
   412.
2. **Serialize toggles against the shared version.** A single in-flight mask
   mutation at a time (a module-level lock/queue, not just per-row `rowBusy`):
   queue clicks, apply sequentially, each seeding `If-Match` from the previous
   response's version. Prevents two toggles from racing the same version.
3. Keep the bounded-retry + reload fallback as the safety net for *real*
   concurrent edits (a second operator), where the 412 message is correct.

No backend change required for Issue 2; it's a client state-management bug.
After Issue 3 lands (lower latency), the residual race basically disappears.

**Effort:** ~half day in `pages.jsx`; rebuild `app.js`.

---

## Issue 3 — Config saves lag on every page (HIGH, backend)

### Root cause (confirmed, mechanism; magnitude needs profiling)
Every config mutation — detector toggle, Zero Trust, Settings, … — runs the
same whole-document pipeline:

1. Load current full config blob + version.
2. `patch_<section>(whole_blob, body)` → produce a new **whole** blob.
3. `aegis_core::load_config_str(whole_blob)` — **parse + validate the entire
   WAF config** (large) on every small change.
4. `services.mutate.apply_async(...)` — append a **hash-chained audit** entry.
5. `store.activate(expected, whole_blob, …)` (`config_store.rs:159`), which does
   **four serial Redis round-trips**:
   - `self.load().await` — re-reads the doc the handler *already* read
     (redundant),
   - `cas_set(snapshot_key)` — immutable snapshot write,
   - `cas_set(DOC_KEY)` — the atomic activation CAS,
   - `fire_nudge()` — pub/sub wake.

So each save pays: full-config reserialize + full-config parse/validate +
audit-chain append + ~4 serial Redis RTTs. That's the per-page lag, and it
widens the stale-version window that drives Issue 2.

### Plan
**Step 3a — Profile first (don't optimize blind).** Add temporary
`tracing` spans / timings around: `patch_*`, `load_config_str`, `apply_async`
(audit), and each Redis op in `activate`. Drive a few toggles + a Zero-Trust
save and read the breakdown. Confirm which dominates (parse/validate vs Redis
RTTs vs audit) before cutting.

**Step 3b — Cheap, safe latency cuts (likely high-yield):**
- **Drop the redundant `load()` in `activate()`.** The handler already loaded
  the current doc + version and passes `expected_version`; `activate` re-loads
  it at line 166. Pass the already-loaded `expected_bytes` (or the `ConfigDoc`)
  in, so the CAS uses them directly — removes one Redis RTT per save.
- **Move the snapshot write off the critical path.** `cas_set(snapshot_key)` is
  best-effort rollback history; do it *after* the activation CAS succeeds (or
  fire-and-forget via `tokio::spawn`) so the operator's 200 doesn't wait on it.
- **Confirm `apply_async` doesn't block on fleet ACK.** The 200 should return
  after the local CAS + nudge; per-node propagation is already eventual
  ("propagates to all nodes within a few seconds"). Verify the audit append
  isn't a synchronous extra Redis RTT on the hot path; batch/spawn if it is.

**Step 3c — Avoid full-config re-validation per small patch (only if 3a shows
parse/validate dominates).** Options, in order of safety:
- Cache the parsed config and validate only the patched section, OR
- Keep an in-memory `Arc<ConfigDoc>` mirror updated on activation so reads
  (GETs) don't re-hit Redis + re-parse on every page load.
This is the riskiest change (validation is a safety gate) — gate it behind the
profiling result.

**Step 3d — GET-side lag (if page *loads* also lag, not just saves).** Check
whether each page's `GET /api/<section>` re-reads + re-parses the whole doc from
Redis. If so, serve reads from the in-memory mirror (3c) instead.

**Effort:** 3a ~1–2 h; 3b ~half day (low risk, likely the bulk of the win);
3c/3d only if profiling justifies.

---

## Sequencing

| Order | Item | Why first |
|---|---|---|
| 1 | **Issue 1** (velocity id + drift guard) | Trivial, HIGH severity (false-positive blocks), zero blast radius. Ship immediately. |
| 2 | **Issue 3b** (drop redundant Redis load + off-path snapshot) | Low-risk latency win that *also* shrinks the Issue-2 race window. |
| 3 | **Issue 2** (frontend version-from-response + serialize) | Kills the 412 churn; benefits from 3b's lower latency. |
| 4 | **Issue 3a/3c/3d** (profile, then deeper cuts if needed) | Only if 3b didn't get latency acceptable. |

Issues 1 and 3b/2 are independent PRs. Suggest PR1 = velocity (quick), PR2 =
toggle UX + config-plane latency.

## Testing
- Velocity: unit test for `id() == "velocity"`; the new drift-guard test;
  integration — disable the `velocity` mask bit, replay a login→deposit
  sequence, assert **no** `velocity_*` signal / no block. Mind the dev
  single-IP / XFF gates ([[feedback_dev_xff_single_ip_gates]]).
- Toggle UX: rapid-toggle several detectors; assert no 412 toast on
  single-operator use; version advances monotonically; Undo still works.
- Latency: before/after timing from 3a on a toggle + a Zero-Trust save.
- Verify actual outcome via HTTP status + `X-WAF-Mode`, not `X-WAF-Action`
  ([[feedback_waf_action_vs_mode]]).

## Related
- `VELOCITY_SEQUENCE_BUG_REPORT.md` (Issue 1 source).
- [[project_config_plane_doc_vs_file]] — pool/config mutations validate against
  the Redis `config:waf:doc`, not the boot YAML.
- Prior N2 work — "config-apply latency + Save UX" (session 2026-06-12) touched
  the same path; this extends it.
