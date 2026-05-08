# tester-n 2026-05-07 regression rerun — fix plan

> **Source:** [`tests/n-tester/reports/2026-05-07-regression/QA-RUN-2-SUMMARY.md`](../../../tests/n-tester/reports/2026-05-07-regression/QA-RUN-2-SUMMARY.md)
> **Status:** plan, awaiting confirmation. No code changes yet.
> **Branch target:** `develop` (operator merges to `Test/UI` for re-check after each phase)

---

## Run-2 outcome at a glance

15 of 18 Run-1 findings fully closed. Three carry over and five new ones surfaced:

| Carry-over | Status | Notes |
|---|---|---|
| **C002** AI FP rate | ⚠️ Partial | Threshold 0.85 still over-fires ~75 % on benign traffic; v2.3 `set_profile` escape works |
| **M009** SLO at 39.67 % | ⚠️ Open | Pure downstream of C002; not a bug in the SLO machinery itself |

| New | Severity | Verified against current code |
|---|---|---|
| **NEW-1** Risk thresholds not updated on hot-reload | CRITICAL | ✓ confirmed — `supervisor.rs` doesn't call `risk.set_thresholds()` |
| **NEW-2** Challenge body missing PoW solving fields (contract violation) | HIGH | ✓ confirmed — `data_plane.rs:608-619` body has only `challenge_type`; no nonce, difficulty, submit_to, expires_at; no submit endpoint |
| **NEW-3** Scaling page renders phantom peer row | HIGH | ✓ confirmed — root cause is **field-name mismatch**, not stale data (see §NEW-3) |
| **NEW-4** `X-WAF-Risk-Score: 0` on blocked responses | MEDIUM | ✓ confirmed — risk tracker is keyed on XFF-resolved IP, response stamper looks up under raw TCP peer |
| **NEW-5** `challenge_at: 99998` default makes challenge tier dead | LOW | ✓ confirmed — intentional but underdocumented |
| **S7** "Why is my SLO red?" UX score 3/5 | LOW UX | ✓ confirmed — no root-cause hint on Health & SLOs page |

The QA report's wording is mostly accurate. Two clarifications worth flagging up-front:

- **NEW-1 method name:** the report calls the missing call `update_thresholds`. The actual method on `RiskTracker` is `set_thresholds(t: RiskThresholds)`. Same bug, different name. (The method exists, see `crates/aegis-security/src/risk/tracker.rs:110`; the supervisor just never calls it.)
- **NEW-3 root cause:** the QA suspected stale data. The actual root cause is that the dashboard reads `p.node_id`, `p.healthy`, `p.last_heartbeat_age_s`, `p.leader` — none of which exist on the `ClusterPeer` struct (`id`, `addr`, `version`, `last_heartbeat`, `leases`). The single self-peer that the membership writer publishes shows up as a row with `down / replica / —` because every field name lookup misses. M008's empty-id filter helped; this is a separate bug.

---

## Phase plan

| Phase | Items | Approx effort | PR shape |
|---|---|---|---|
| [Phase 1 — CRITICAL](./PHASE-01-critical.md) | NEW-1 (hot-reload thresholds) · C002 (AI default tightening) | 2.5 h | One `fix(critical)` PR |
| [Phase 2 — HIGH](./PHASE-02-high.md) | NEW-2 (PoW challenge body + verify endpoint) · NEW-3 (Scaling peer fields) | 5 h | Two PRs (challenge engine is non-trivial; peer fix is small) |
| [Phase 3 — MEDIUM](./PHASE-03-medium.md) | NEW-4 (risk-score header) · M009 closure verification | 1.5 h | One PR |
| [Phase 4 — LOW](./PHASE-04-low.md) | NEW-5 (`challenge_at` default doc) · S7 (SLO root-cause tooltip) | 1 h | One PR |

**Total estimated effort: ~10 hours focused work**, spread across 5 PRs so each is reviewable.

---

## Sequencing

1. **Phase 1 first.** NEW-1 unblocks operators changing risk thresholds at runtime — same hot-reload story as the detector mask / route table / rate-limit blocks already wired. C002 default-tightening prevents the dev SLO from sitting red and prevents accidental prod deployment with a 75 % FP detector.
2. **Phase 2 next.** NEW-2 is a v2.3 contract violation (§3 explicitly requires "enough information for automated challenge solving"). The benchmark harness can't get past the challenge tier without it. NEW-3 ships alongside since both are dashboard / data-plane reads gated on the same QA re-check.
3. **Phase 3.** NEW-4 closes the last contract header gap. M009 should auto-recover after C002 if alerts get ack'd.
4. **Phase 4** is polish — ship after the contract gaps are closed.

H001/H002/H003 + M001-M008 + L001-L004 stay closed. No regressions introduced by Run-1 fixes per QA's verification matrix.

---

## What we're NOT doing in this round

- **Retrain the AI model** to fix the underlying ~75 % FP rate. That's a data + ML problem, not a code fix; the operator workflow (default `enabled: false` or `log_only` via set_profile) is the documented mitigation until a retrain ships. Track separately under an ML/data plan.
- **Per-deployment AI calibration tooling.** A "run this script against your real upstream's clean traffic to pick a threshold" tool would let operators tune safely; out of scope for this fix-pass.
- **Backend mutation handlers for M004 read-only Settings sections** (terminate session, toggle break-glass, update integrations). Same call as Run-1 — these need their own audit-mutated handler design pass; the read-only surfaces are good enough until then.
- **Multi-node deployment plan execution** — that lives under [`plans/multi-node-deployment/`](../../multi-node-deployment/) and waits on SA Team answers.

---

## Cross-cutting risks

| Risk | Mitigation |
|---|---|
| Hot-reload of risk thresholds could surprise operators if they don't realise their edit takes effect immediately | Audit-log the change with before/after, surface "thresholds reloaded" in the dashboard's audit trail (already audited via the existing PUT /api/risk/thresholds path; hot-reload should mirror that audit shape) |
| PoW challenge nonce reuse / replay if the verify endpoint isn't strict | Existing `ChallengeTokens` machinery already does single-use nonce consumption via `state.consume_nonce` — reuse that primitive |
| Tightening AI defaults could cause operator confusion when they used to see AI signals in dev logs | Document the change in `docs/security/detectors/ai-detector.md`; ship the dashboard's AI toggle flipped off by default with a clear "enable after calibration" hint |
| Field-name fix on Scaling peer table could regress if a different consumer of `/api/cluster` depends on the wrong-but-consistent shape | Grep first; the API JSON shape doesn't change — only the dashboard reader is corrected |
| NEW-2 PoW addition is a non-trivial new endpoint; rushing risks shipping a half-working verification path | Phase 2 splits NEW-2 into its own PR; explicitly excludes scheduled-delivery / multi-step challenge flows |

---

## Acceptance for the whole round

- [ ] All 5 new findings have a corresponding fix or accepted-as-design close
- [ ] C002 follow-up shipped (default tightening + doc)
- [ ] M009 verified to recover (or explicitly tracked as ML retrain follow-up)
- [ ] No regression in the 15 fixed Run-1 findings
- [ ] All workspace tests pass; new regression tests cover NEW-1 + NEW-3 + NEW-4
- [ ] `STAGING-BENCHMARK.md §challenge` updated with the new PoW shape (Phase 2)

---

## File map

```
plans/issue-fix/tester-n-2026-05-07-regression/
├── README.md             ← this file (index, sequencing, cross-check)
├── PHASE-01-critical.md  ← NEW-1 + C002 follow-up
├── PHASE-02-high.md      ← NEW-2 + NEW-3
├── PHASE-03-medium.md    ← NEW-4 + M009
└── PHASE-04-low.md       ← NEW-5 + S7
```
