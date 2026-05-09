# tester-n 2026-05-08 Run-4 (security) — fix plan

> **Source:** [`tests/n-tester/reports/2026-05-07-regression/QA-RUN-4-SECURITY.md`](../../../tests/n-tester/reports/2026-05-07-regression/QA-RUN-4-SECURITY.md)
> **Status:** plan, awaiting confirmation. No code changes yet.
> **Branch target:** `develop` (operator merges to `Test/UI` for re-check after each phase)

---

## Run-4 outcome at a glance

The WAF passes the bulk of v2.3 — all control-plane endpoints, all 6 mandatory headers, 45/48 attack probes, full `log_only` lifecycle, full PoW challenge engine. The QA opened 6 new findings; **two are misreads, one is a design-decision rather than a bug, three are real fixes.**

| Finding | QA Severity | Verified | Reclassified |
|---|---|---|---|
| **SEC-C001** AI 50 % FP on clean traffic | CRITICAL | ✓ confirmed (manifestation of RUN3-NEW-1: stale `waf.yaml`) | **HIGH** — strengthen RUN3-NEW-1's drift handling from warning to hard abort |
| **SEC-M001** Audit log field names diverge from contract | MEDIUM | ✗ **MISREAD** — QA inspected `/tmp/aegis-dev-audit.jsonl` (dashboard audit, `AuditEvent` schema) and applied contract assertions. The contract audit is `./waf_audit.log` (`MinimalAuditEntry` schema with `request_id, ts_ms, ip, method, path, action, risk_score, mode` — exactly the §6 shape). | **DOC** — clarify which file is which; no schema change needed |
| **SEC-M002** cmdi parameter-name sensitivity | MEDIUM | ✓ confirmed but **root cause is different**: there's no dedicated command-injection detector; `$()`, `|`, backticks only catch via AI or incidental path_traversal regex overlap. Disabling AI removes the only consistent cmdi catcher. | **MEDIUM** — add a real `command_injection` detector |
| **SEC-M003** Post-reset risk_score=100 on first hit | MEDIUM | ✓ confirmed but **probably correct behavior**: `total_score = signals.iter().map(\|s\| s.score).sum()`. A single multi-class attack (sqli=50 + path_traversal=45 + ai=50) sums past `max=100` and clamps. | **DESIGN** — choose between max-clamp accumulation (current) vs per-request cap to `max(signal)` |
| **SEC-L001** Docker REST API not in recon | LOW | ✓ confirmed — `recon.rs` patterns lack `/v\d+\.\d+/(containers\|images\|networks)` etc. | **LOW** — add patterns |
| **SEC-L002** X-Forwarded-Host poisoning not detected | LOW | ✓ confirmed — `header_injection.rs` only scans query values for CRLF, doesn't inspect XFH header value. | **LOW** — add header inspection |

The QA's "Priority Action Items" list reads BLOCKER → HIGH → MEDIUM → MEDIUM. After re-verification: there's **one HIGH, one DOC, two MEDIUM, two LOW** — and the BLOCKER label is misplaced (the AI default already ships `enabled: false` in `dev.yaml`; the issue is operators with stale local `waf.yaml`).

---

## Phase plan

| Phase | Items | Approx effort | PR shape |
|---|---|---|---|
| [Phase 1 — HIGH](./PHASE-01-high.md) | SEC-C001 (re-frame): turn RUN3-NEW-1's drift WARNING into a hard ABORT requiring `FORCE=1` or `KEEP=1` to proceed | 30 min | One `fix(makefile)` PR |
| [Phase 2 — MEDIUM](./PHASE-02-medium.md) | SEC-M002 dedicated `command_injection` detector + capabilities wiring + tests | 1.5 h | One `feat(detectors)` PR |
| [Phase 3 — DESIGN](./PHASE-03-design.md) | SEC-M001 audit-file documentation; SEC-M003 risk accumulation review (chose: cap per-request contribution to `max(signal)` not `sum(signal)`) | 1 h | One PR |
| [Phase 4 — LOW](./PHASE-04-low.md) | SEC-L001 Docker REST recon patterns; SEC-L002 X-Forwarded-Host inspection | 30 min | One `fix(detectors)` PR |

**Total estimated effort: ~3.5 hours**, 4 small focused PRs.

---

## Sequencing

1. **Phase 1 first** — same reasoning as Run-3: without a stricter drift behavior, every CI run + every developer's bench-dev keeps masking signal. Highest leverage.
2. **Phase 2** — adds a real cmdi class. The existing pipeline is short on this; AI was carrying the load. Once disabled (per C002 follow-up), this is the single biggest detection gap.
3. **Phase 3** — half doc, half a small data-plane tweak. The audit-file doc is trivial. The risk-accumulation question is more interesting (current behavior is "any 2 detectors firing → score=100" which makes risk lifecycle tests hard to interpret).
4. **Phase 4** — small detector additions. Independent of phases 1-3.

All 4 are independent — could ship in parallel if reviewers can absorb 4 small PRs at once.

---

## What we're NOT doing in this round

- **Re-architect the audit log layer** to unify the contract sink (`MinimalJsonlSink` writing `MinimalAuditEntry`) and the dashboard audit (`AuditEvent`). They're two intentionally separate sinks for two different consumers (benchmark harness vs SOC operator). Documentation makes it crystal clear; no merging.
- **Train a dedicated cmdi ML model**. The Phase-2 fix is a regex-based detector mirroring sqli/xss shape. AI can be a force-multiplier later; rule-based is the floor.
- **Reset_state scope-aware behavior.** The QA noticed `{scope: "all"}` and `{scope: "risk"}` both work, suggesting our handler ignores scope. Re-checked — `reset_state` doesn't take a scope param; it runs all callbacks. The contract's `set_profile` has scope, not `reset_state`. The QA may have been writing exploratory bodies; both are accepted (body ignored). No fix needed.
- **AI model retrain.** Same as Run-2/Run-3 — out-of-scope code; data/ML problem to track separately.

---

## Cross-cutting risks

| Risk | Mitigation |
|---|---|
| Hard-aborting bench-dev on drift could break CI workflows that run multiple times in a row | The abort fires only when `dev.yaml` is newer than `waf.yaml`. CI checks out fresh, so no `waf.yaml` exists → copy branch fires. Existing CI is unaffected |
| Dedicated cmdi detector triggers FPs on legitimate URL paths containing `|` or `$()` | False-positive screening: regex requires shell-context cues (`$(\w+)`, ` \| \w+`, `; \w+ -`) rather than bare `\|` or `$`. Test set covers expected FP paths (e.g. base64 with `=`, regex query strings) |
| Capping per-request risk to `max(signal)` weakens detection vs current `sum(signal)` | Pure accumulation policy change — total score stays bounded by `max=100`, just no longer reaches it on a single multi-detector hit. Net effect: legit-but-suspicious traffic gets less aggressive risk pile-up; attackers still trip thresholds within 2-3 requests |
| Adding XFH inspection trips on legitimate proxy chains (e.g. K8s ingress) | Heuristic: flag XFH that doesn't match Host or known-good-proxy allowlist; default-allow when allowlist is unset (zero new FPs without operator config) |

---

## Acceptance for the whole round

- [ ] All 6 new findings have a fix or accepted-as-design close
- [ ] No regression in Run-1 + Run-2 + Run-3 fixed findings
- [ ] All workspace tests pass; new tests cover SEC-M002 (cmdi), SEC-L001 (Docker recon), SEC-L002 (XFH)
- [ ] Manual verification: `make bench-dev` with stale waf.yaml aborts with a clear FORCE/KEEP prompt; cmdi probes catch in rule-based path; Docker REST + XFH probes get blocked

---

## File map

```
plans/issue-fix/tester-n-2026-05-08-run4/
├── README.md             ← this file (index, sequencing, cross-check)
├── PHASE-01-high.md      ← SEC-C001 hard-abort drift in bench-dev
├── PHASE-02-medium.md    ← SEC-M002 dedicated command_injection detector
├── PHASE-03-design.md    ← SEC-M001 audit-file doc + SEC-M003 risk cap policy
└── PHASE-04-low.md       ← SEC-L001 Docker REST + SEC-L002 X-Forwarded-Host
```
