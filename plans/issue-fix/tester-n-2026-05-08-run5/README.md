# tester-n 2026-05-08 Run-5 (security & load) — improvement plan

> **Sources:**
> - [`tests/n-tester/reports/2026-05-08-run5/QA-RUN-5-SECURITY-LOAD.md`](../../../tests/n-tester/reports/2026-05-08-run5/QA-RUN-5-SECURITY-LOAD.md)
> - [`tests/n-tester/reports/2026-05-08-run5/QA-RUN-5-SECURITY-LOAD-v2.md`](../../../tests/n-tester/reports/2026-05-08-run5/QA-RUN-5-SECURITY-LOAD-v2.md) (v3 dataset extension)
>
> **Status:** plan, approved. Implementation in progress.
> **Branch target:** `develop` (operator merges to `Test/UI` for re-check after each phase)

---

## Scoring framework

Detector signal scores feed `record_malicious(peer_ip, max(signal))` per request (post Run-4 SEC-M003 fix). With default thresholds **challenge_at=40 / block_at=80 / max=100**, two confirmed bad requests reach challenge, three reach block.

The score for each new detector is chosen against this calibrated scale, not defaulted:

| Tier | Score | Meaning | Examples |
|---|---|---|---|
| **Critical RCE / known CVE** | **60** | One hit pushes to block within 2 requests; pattern is so specific FP is essentially 0 | Log4Shell `${jndi:` |
| **High-confidence injection** | **50** | One-shot challenge threshold; two confirmed hits → block. Patterns are specific enough that legit traffic rarely matches | sqli, xss, ssrf, cmdi (existing); SSTI, NoSQL (new) |
| **High-impact, broader pattern** | **45** | Same impact ceiling but slightly looser pattern → conservative score | path_traversal (existing); prototype pollution (new) |
| **Header injection / XFH** | **35** | Lower confidence (heuristic shape match) | header_injection (existing) |
| **Phishing / info disclosure** | **30** | Real impact but higher FP risk; operators may want allowlist | open_redirect (new), recon (existing) |

Scores below 30 aren't used — too low to ever cross a default block threshold.

---

## Run-5 outcome at a glance

This is the **first QA run that's mostly favorable**. Every contract requirement passes; runtime metrics are healthy:

| Metric | Result |
|---|---|
| v2.3 contract requirements (18/18) | ✅ PASS |
| Peak throughput | 5,000 RPS @ 300 concurrent, 0 errors |
| Overhead p50 (clean) | 0.208 ms |
| Overhead p99 (clean) | 2.155 ms |
| `X-WAF-Overhead-Latency` header | ✅ Validated on 700/700 responses |
| FP rate (clean baselines + load) | 0 % |
| Run-4 fixes verified | ✅ all (cmdi, audit schema, Docker recon, drift abort, header) |

**The new findings are coverage-extension, not bugs.** The expanded v3 dataset (220 cases across 14 attack classes) surfaced gaps in attack classes the WAF didn't yet enumerate. That's expected when the test surface grows.

### Gap inventory (cross-checked against current code)

| Gap | QA Severity | Verified | Reclassified | Action |
|---|---|---|---|---|
| **GAP-006** SSTI not detected | HIGH (RCE) | ✓ no SSTI patterns anywhere | **HIGH** | New `template_injection` detector |
| **GAP-007** NoSQL injection not detected | HIGH | ✓ no `$ne`/`$where` patterns | **HIGH** | New `nosql_injection` detector |
| **GAP-008** Log4Shell obfuscation | HIGH (CVE-2021-44228 RCE) | ✓ no `${jndi:` patterns; the 2/5 the QA caught hit incidentally via SSRF `gopher://`/`dict://` overlap | **HIGH** | Extend `command_injection` with JNDI shapes |
| **GAP-001** Framework recon (Spring/Swagger/GraphQL/K8s/...) | MEDIUM | ✓ no actuator/swagger/graphql patterns | **MEDIUM** | Extend `recon.rs` RECON_PATHS |
| **GAP-009** Open redirect | MEDIUM | ✓ no redirect-param scanning | **MEDIUM** | New `open_redirect` detector |
| **GAP-010** Prototype pollution | MEDIUM | ✓ no `__proto__` JSON scanning | **MEDIUM** | Extend `body_abuse.rs` |
| **GAP-002** Path traversal evasion (overlong UTF-8, Docker socket) | LOW-MED | ✓ existing patterns cover Windows backslash + double-encode but not overlong UTF-8 | **LOW-MED** | Extend `path_traversal.rs` |
| **GAP-004** SSRF URL credentials (`http://user:pass@host/`) | LOW | ✓ no `userinfo@` pattern | **LOW** | Extend `ssrf.rs` |
| **GAP-005** XFH residue | LOW | ⚠️ Run-4 SEC-L002 catches obvious-keyword XFH (`evil`, `attacker`, `<>`) but misses bare-internal-IP poisoning (`X-Forwarded-Host: 127.0.0.1`) | **LOW** | Extend `xfh_is_suspicious` heuristic |
| **GAP-003** Stale `waf.yaml` AI config | LOW (dev only) | ✓ Closed by Run-4 SEC-C001 hard-abort + operator deleted local `waf.yaml` | **CLOSED** | No action |

The QA report's GAP-003 was tested against a pre-Run-4 build — the hard-abort drift behavior shipped in Run-4 SEC-C001 closes this. No code change needed.

---

## Phase plan

| Phase | Items | Approx effort | PR shape |
|---|---|---|---|
| [Phase 1 — HIGH RCE classes](./PHASE-01-high.md) | GAP-006 SSTI + GAP-007 NoSQL + GAP-008 Log4Shell | ~3.5 h | 3 small PRs (each detector standalone) |
| [Phase 2 — MEDIUM coverage](./PHASE-02-medium.md) | GAP-001 framework recon + GAP-009 open redirect + GAP-010 proto pollution | ~2 h | 2 PRs (recon extension + proto, then open_redirect) |
| [Phase 3 — LOW residue](./PHASE-03-low.md) | GAP-002 path traversal evasion + GAP-004 SSRF userinfo + GAP-005 XFH residue | ~1 h | 1 bundled PR |

**Total estimated effort: ~6.5 hours**, 5-6 small focused PRs.

Per the operator's standing instruction (Run-4): every new detector ships with `docs/security/detectors/<name>.md` + cross-ref updates to `docs/security/detectors/README.md`, top-level `README.md`, `docs/security/security-engine.md`, `docs/security/tiered-protection.md`, `docs/operator/profiles.md`, and `plans/implementation-matrix.md`.

---

## Sequencing

1. **Phase 1 first.** SSTI, NoSQL, Log4Shell are all RCE classes — highest exploitability. SSTI and NoSQL are particularly trivial to weaponize against the relevant stacks (Flask/Jinja2, MongoDB).
2. **Phase 2 next.** Framework recon is operator-impact (info disclosure on misconfigured endpoints). Open redirect + proto pollution are real but lower-blast-radius.
3. **Phase 3 last.** Three small-surface extensions to existing detectors. Bundled into a single PR.

All three phases are independent — could ship in parallel if reviewers can absorb.

---

## What we're NOT doing in this round

- **AI model retrain.** Confirmed out-of-scope per prior operator directive.
- **Open redirect with strict allowlist enforcement.** The phase-2 detector flags suspicious external-domain shapes in known redirect params (`?next=`, `?url=`, etc.) without requiring operator config — false positive rate is the risk. If real-world FPs appear, a follow-up adds an operator-configurable `cfg.detectors.open_redirect.allowed_domains` list.
- **Browser-side blake3 fixture for the PoW challenge** (Run-3 carryover, still not blocking).
- **HTTP/2 request smuggling polyglot probes** (Run-5 v2 ran 5/5 cases all blocked at 100 % — no new work).

---

## Cross-cutting risks

| Risk | Mitigation |
|---|---|
| New SSTI patterns FP on legitimate template-output APIs (e.g. an API that echoes Jinja2 syntax in error messages) | Trigger requires `{{...}}` or `${...}` + suspicious internals (`config`, `__class__`, `mro`); plain matched braces alone don't fire. Operator can toggle via `set_profile { policies: ["template_injection"], mode: "log_only" }` |
| NoSQL `[$op]` query string scanner FPs on legitimate Postgres / MS SQL apps using `$1` parameter placeholders | Pattern requires `[$<word>]` not bare `$1`; placeholders pass. Document the trade-off in the detector's per-doc page |
| Log4Shell pattern over-broad on real `${VAR}` template strings | Pattern requires `j.*n.*d.*i:` somewhere inside the braces; hits the obfuscated `${${::-j}${::-n}${::-d}${::-i}:...}` shapes without firing on `${USER}` or other plain envvars |
| Framework recon over-broad on legitimate `/api/v1/...` paths matching `actuator` / `metrics` / `health` patterns operators host themselves | Patterns require the full known-vulnerable shape (`/actuator/heapdump`, `/api/v3/api-docs`, `/graphql` + body keyword) — bare `/health` / `/metrics` are NOT flagged |
| Prototype pollution scanner FPs on JSON bodies with `_proto_` field names | Pattern is exact match on `__proto__` and `constructor.prototype`/`Object.prototype` paths — single-underscore variants don't fire |

---

## Acceptance for the whole round

- [ ] All 8 actionable gaps closed (3 closed-as-done already: GAP-003, GAP-005-partial)
- [ ] No regression in Run-1 → Run-4 fixed findings
- [ ] All workspace tests pass; new tests cover all 6 new/extended detectors
- [ ] Per-detector docs landed for the 3 new detectors (SSTI, NoSQL, open_redirect)
- [ ] Cross-ref doc updates landed
- [ ] FP rate against `clean_baselines.json` stays at 0 %
- [ ] Detection rate against v3 dataset rises from 68.6 % to ≥ 95 %

---

## File map

```
plans/issue-fix/tester-n-2026-05-08-run5/
├── README.md             ← this file (index, sequencing, cross-check)
├── PHASE-01-high.md      ← GAP-006 SSTI + GAP-007 NoSQL + GAP-008 Log4Shell
├── PHASE-02-medium.md    ← GAP-001 framework recon + GAP-009 open redirect + GAP-010 proto pollution
└── PHASE-03-low.md       ← GAP-002 path traversal evasion + GAP-004 SSRF userinfo + GAP-005 XFH residue
```
