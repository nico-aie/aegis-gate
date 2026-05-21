# QA Run-6 fix plan (2026-05-09)

> **Source:** [`tests/n-tester/reports/2026-05-09-run6/QA-RUN-6-FINAL.md`](../../../../tests/n-tester/reports/2026-05-09-run6/QA-RUN-6-FINAL.md)
>
> **Branch:** all changes target `develop`. Operator merges to Test/UI for re-check.
>
> **Pre-condition:** read the [score-tier framework](../tester-n-2026-05-08-run5/README.md#score-tier-framework) — every score below uses the same 5-tier ladder we calibrated for Run-5.

---

## Run-6 headline

Aegis-Gate scored **A-** overall: 18/18 contract, 18/18 dashboard pages, 39/40 SOC UX, 88.1% detection (up from 68.6% in Run-5), 5,128 RPS peak, **0% false positives**. Five residual detection gaps remain — all minor variants in partially-covered classes — plus two cosmetic UX nits.

---

## Verified state — what's already shipping

Cross-checked every "remaining gap" claim against current `develop`. Findings:

| Claim | Code state | Action |
|---|---|---|
| Log4Shell `${${::-j}…}` UA missed | LOG4SHELL_PATTERNS pattern 3 already matches this shape; HEADER_SCAN_ALLOWLIST includes user-agent | **Verify with a regression test** before assuming a fix is needed |
| Log4Shell `${${lower:j}ndi:…}` UA missed | LOG4SHELL_PATTERNS pattern 4 already covers this | **Verify** |
| Twig `{{7*'7'}}` missed | Current `\{\{\s*\d+\s*\*\s*\d+\s*\}\}` requires bare `\d+` on both sides; quotes break it | **Extend pattern** |
| Freemarker `<#assign>` missed | Pattern `(?i)<#\s*(?:assign\|list\|...)` already covers this | **Verify with regression test** |
| Bare `/actuator` missed | Current pattern requires a known-dangerous subpath (heapdump/env/etc.) | **Add bare-actuator + `/rails/info` patterns** |
| Bare `/metrics` missed | Deliberately not caught — operator-hosted endpoint | **Keep current behaviour, document the trade-off** |
| `phpinfo.php` missed | Current `phpinfo\(\)` matches the function call shape, not the file | **Add file-shape pattern** |
| X-Original-URL / X-Rewrite-URL → `/admin` missed | SSRF detector scans these headers but only against SSRF_PATTERNS (private IPs, schemes); admin-path values don't fire | **New header_injection sub-rule** |
| XSS HTML-entity `&#60;script&#62;` missed | XSS detector doesn't run HTML-entity decode | **Add HTML-entity normalisation pre-pass** |
| CMDi `;sleep+5;echo+done` missed | CMDI_PATTERNS doesn't list `sleep`/`timeout` builtins | **Extend cmdi shell-builtin allowlist** |
| Compliance mode badge | Settings/Compliance pages don't surface `enforce`/`log_only` as readable text | **UI-only — add badge** |
| Detector class names | Detectors page chip grid uses class strings already; arguably good enough | **Optional UI polish** |

---

## Score-tier framework (reminder)

Every score below sits on the **calibrated 5-tier ladder** from Run-5. Don't introduce new scores outside this set without an explicit note + ladder update + simulator run.

| Tier | Score | Calibration |
|---|---:|---|
| Critical RCE / CVE | **60** | One hit warrants challenge or block. |
| High-confidence injection | **50** | One hit shouldn't block; two should. |
| Broader pattern | **45** | Same impact ceiling as injection; pattern is more permissive. |
| Header heuristic | **35–40** | Strong signal in the right context, weaker in the wrong one. |
| Phishing / info disclosure | **30** | Indirect compromise; signal accumulation is the point. |
| Probe / canary | **25** | Single hit is information-only; rate matters more than score. |

The interaction with `risk.thresholds.challenge_at` (40) and `block_at` (80) is what makes the ladder meaningful — see [`docs/operator/risk-tuning.md`](../../../../docs/operator/risk-tuning.md) for the full rationale.

---

## Phases (sequencing)

Three phases match Run-5's grouping. Each phase is one PR. Bundle within a phase only when commits share a touched file.

### [Phase 1 — P1 (HIGH)](./PHASE-01-high.md)

| GAP | What | Effort |
|---|---|---:|
| GAP-008b | **Verify** Log4Shell UA obfuscation already catches `${${::-j}...}` / `${${lower:j}ndi:...}`. Add regression tests. If genuinely missed, extend patterns. | ~30 min |
| GAP-011 | URL-override-header bypass: `X-Original-URL` / `X-Rewrite-URL` carrying admin/internal paths (`/admin`, `/console`, `/__internal/...`). New header_injection sub-rule, score 40. | ~45 min |

### [Phase 2 — P2 (MEDIUM)](./PHASE-02-medium.md)

| GAP | What | Effort |
|---|---|---:|
| GAP-006b | SSTI Twig `{{7*'7'}}` (quoted operand). Verify Freemarker `<#assign>` (regression test). | ~20 min |
| GAP-001b | Recon: bare `/actuator` (discovery page itself), `/rails/info/properties`, `phpinfo.php`. Bare `/metrics` stays operator-hosted (document explicitly). | ~30 min |

### [Phase 3 — P3 (LOW)](./PHASE-03-low.md)

| GAP | What | Effort |
|---|---|---:|
| GAP-012 | XSS HTML-entity decode pre-pass — `&#60;script&#62;` should normalise to `<script>` before pattern match. | ~30 min |
| GAP-013 | CMDi extend shell-builtin allowlist with `sleep`, `timeout` (blind-sleep DoS / time-based RCE primitives). | ~10 min |
| UX S6  | Compliance page — add visible enforce/log_only badge to the heading. | ~20 min |
| UX S5  | Detectors page — surface class names alongside chip toggles (already implemented in Run-5 follow-up #293; verify visibility). | ~10 min |

### Skipped

- **GAP-014 (XXE billion-laughs DoS)** — explicitly low-priority per QA report ("DoS, not injection"). Tracked separately under hardening; not addressed in this round.
- **Bare `/metrics`** — deliberately not flagged. Operator-hosted Prometheus endpoint. Document the trade-off in `recon.md` so future QA runs don't re-flag.
- **GAP-003 (waf.yaml stale AI config)** — QA "status unknown, not re-tested". If it shows up in Run-7, add to that batch.

---

## Acceptance bar (every phase)

For each gap closed:

- [ ] At least 4 positive tests (one per documented variant) + 2 negative tests (operator-controlled cases that must NOT fire)
- [ ] Existing tests still pass (`cargo test --workspace` green)
- [ ] Per-detector doc updated (new variants + score rationale)
- [ ] Cross-refs updated (`detectors/README.md` tag table, `security-engine.md` tag table + risk-weight ladder, `implementation-matrix.md`)
- [ ] No false positives on `tests/security/corpus/` (existing corpus regression)
- [ ] Score chosen from the 5-tier ladder; if outside, comment + simulator run + tier-table update

---

## Sequencing rationale

- **Phase 1 first** because P1 gaps cover Log4Shell (the highest-impact CVE in the corpus) and URL-override headers (auth bypass primitive). Both are direct compromise vectors.
- **Phase 2 next** because the SSTI variant + recon gaps are evasion shapes — caught means defense-in-depth, missed means a determined attacker can probe successfully.
- **Phase 3 last** because the XSS / CMDi gaps are minor variants and the UX nits are cosmetic. Operator workflow is not blocked by either.

After all three phases: re-run the QA harness on `develop`. Expect detection rate ≥ 95% (was 88.1%) with FP rate still 0%.

---

## Cross-refs

- [Run-5 plan + score-tier framework](../tester-n-2026-05-08-run5/README.md)
- [`docs/operator/risk-tuning.md`](../../../../docs/operator/risk-tuning.md) — operator action map for tuning posture
- [`docs/security/security-engine.md`](../../../../docs/security/security-engine.md) — pipeline + risk-weight ladder
- [`crates/aegis-security/src/detectors/scores.rs`](../../../../crates/aegis-security/src/detectors/scores.rs) — single source of truth for every detector score
