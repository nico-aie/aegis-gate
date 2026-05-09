# Issue-fix plan — 2026-05-07 QA findings

> **Source report:** `tests/n-tester/reports/findings/2026-05-07/`
>
> **Strict spec:** `Hackathon_Doc/EN_waf_interop_contract_v2.3.md` —
> every fix MUST follow the contract verbatim. No hard-coded behavior
> for the benchmark (§2.5: *"MUST NOT relax, boost, or special-case
> detection logic for undisclosed benchmark cases"*).
>
> **Target branch:** `develop` (operator will merge to `Test/UI` later
> for re-check).
>
> **Plan author:** AI assistant. Findings cross-checked against the
> live code on 2026-05-07. **No code has been written yet.** This
> plan is a proposal — confirm the open questions at the bottom
> before implementation begins.

---

## Operator's three clarifications applied

| # | User directive | Applied as |
|---|---|---|
| 1 | "Fix on develop branch" | All fixes target `develop`. C001 cherry-picks `dfc487c` from `staging` onto `develop` (drop the 21 MB mmdb binaries). |
| 2 | "Accept log_only" for C002 (do not re-introduce `mode: observe \| enforce` config field) | C002 is now solved purely via the v2.3 control plane: expose AI as a toggleable policy (`rules_engine.ai`) so the OC can run `set_profile { scope:"policies", feature:"rules_engine", policies:["ai"], mode:"log_only" }` to neutralize AI without touching config. The dev `confidence_threshold` bump is the only config-side fix. |
| 3 | "H003 maybe caused by missing `/__waf_control/**` on port 8080" | H003 is now sequenced **after** C001 — re-test once the data-plane control endpoint is live. Plan keeps the repro step; fix only if the eviction persists. |

---

## Findings recap

| Severity | Count | Phase |
|---|---:|---|
| CRITICAL | 2 | [Phase 1](./PHASE-01-critical.md) |
| HIGH | 3 | [Phase 2](./PHASE-02-high.md) |
| MEDIUM | 9 | [Phase 3](./PHASE-03-medium.md) |
| LOW | 4 | [Phase 4](./PHASE-04-low.md) |
| **Total** | **18** | |

---

## Cross-check summary (real bug? code matches the report?)

| ID | Finding | Verified | Notes |
|---|---|---|---|
| C001 | `/__waf_control/*` blocked by SSRF detector on data port | ✅ real | `accept.rs` has no `__waf_control` short-circuit. Fix lives on `staging` (commit `dfc487c`) — needs to land on `develop`. |
| C002 | AI threshold 0.5 over-fires (~77% FP) | ✅ real | `waf.yaml:127` = `0.5`; default = `0.85`. **Strict v2.3 fix**: bump threshold + expose AI as a toggleable policy so OC can flip to `log_only` per §2.5. |
| H001 | SSRF detector scans `Referer` | ✅ real | `ssrf.rs:61` includes `"referer"` in `scan_headers`. |
| H002 | Investigation pivot drops query params | 🟡 untrusted code path | Frontend SPA-router; trust the report. Small fix. |
| H003 | `reset_state` evicts admin sessions | ⚠ **re-test post-C001** | Our reset callbacks (`risk + ip_rate_limiter + attacks_agg`) don't touch sessions. May vanish once C001 lands. |
| M001 | UUID v4 variant nibble not RFC 4122 compliant | ✅ real | `admin_dispatch.rs:805` — `h[16..20]` unmasked. |
| M002–M009, L001–L004 | dashboard / config issues | 🟡 trust report | Mostly UI/UX. Per-item validation in Phase 3 / 4. |

---

## Strict v2.3 spec re-read — what must be true

Cited inline because the operator asked for strict compliance:

| § | Requirement | Our implementation status |
|---|---|---|
| 2.1 | Four endpoints required: `capabilities`, `reset_state`, `set_profile`, `flush_cache` | ✅ implemented; **C001 fixes data-plane reachability** |
| 2.2 | `X-Benchmark-Secret` header gates all four; missing/invalid → 403 | ✅ |
| 2.3 | `capabilities` response: `{ok, features, active.{default_mode, overrides}}`. Feature names are implementation-defined but **stable** for a benchmark run. | ✅ structure matches; **C002 adds `ai` policy under `rules_engine`** so AI is OC-toggleable |
| 2.4 | `reset_state` MUST clear: risk state, rate-limit counters, cache state, challenge/session state, temp client metadata, temp enforcement state. **MUST NOT** delete/truncate the audit log. | ✅ wired (risk + rate-limit + AttacksAggregator + audit preserved). H003 needs post-C001 re-test. |
| 2.5 | `set_profile` MUST support `scope: all \| features \| policies` × `mode: enforce \| log_only`. **Hard-coding behavior for the benchmark is forbidden.** | ✅ implemented; **C002's AI toggle relies on this** — no new config field |
| 2.6 | `flush_cache` if cache exists; else MAY return clear not-supported response | ✅ returns `supported: false` |
| 2.7 | `X-WAF-Mode` MUST reflect the policy that produced the final reported `X-WAF-Action` | ✅ wired via `rule_map::mode_for_rule` |
| 5.1 | Six required `X-WAF-*` headers on every response | ✅ |
| 5.3 | log_only: report intended action via `X-WAF-Action`, set `X-WAF-Mode: log_only`, but DO NOT block | ✅ wired in data plane (log_only_intent path) |
| 6 | Audit log JSONL with 8 required fields; append-only across resets | ✅ |
| 8 | `./waf` binary, `./waf run`, `./waf.yaml` in cwd, `./waf_audit.log` default | ✅ via `make stage` |
| 10 | IP field = TCP peer (NOT XFF) | ✅ |

---

## Sequencing rationale

1. **Phase 1 (CRITICAL) first.** Without C001 the contract is broken on the data port. Without C002 benchmark numbers are dominated by FP noise.
2. **Phase 2 (HIGH).** H001 unblocks normal browser usage (loopback dev). H002 fixes the S3 SOC pivot. H003 re-tested **after** C001 — likely closes as N/A.
3. **Phase 3 (MEDIUM).** Parallelizable polish + spec compliance items.
4. **Phase 4 (LOW).** Single consolidated polish PR.

---

## Estimated effort

| Phase | Effort | Risk |
|---|---|---|
| Phase 1 | ~1.5–2 hours | LOW — small surgical changes |
| Phase 2 | ~2-3 hours | LOW (after H003 re-test) |
| Phase 3 | ~6-8 hours | MEDIUM — touches many UI surfaces |
| Phase 4 | ~1 hour | LOW |
| **Total** | **~10–14 hours** | |

(Phase 1 dropped from 2-3h to 1.5-2h after dropping the AiMode config-field work per directive 2.)

---

## Open questions before implementation

**All three of the operator's clarifications are now baked into the plan.** Remaining:

1. **C001 cherry-pick mechanics**: should I cherry-pick `dfc487c` (the staging commit) onto `develop` directly, OR create a fresh commit on `develop` matching the staging diff? Cherry-pick preserves authorship, fresh commit lets me write a more descriptive message tying it to F-CRITICAL-001.

2. **C002 — naming the AI policy**: `rules_engine.ai` (consistent with sqli/xss as siblings) vs a new top-level feature `ai_detector` (cleaner separation, but adds a feature name). Recommendation: `rules_engine.ai` — minimum churn, consistent grouping.

3. **Phase 3 ordering**: ship all 9 mediums in one PR, or split into the 7 PRs I outlined? Recommendation: split — easier review.

---

## Files in this plan

- [`README.md`](./README.md) — this file
- [`PHASE-01-critical.md`](./PHASE-01-critical.md) — C001 + C002 (strict v2.3 path)
- [`PHASE-02-high.md`](./PHASE-02-high.md) — H001, H002, H003 (re-test post-C001)
- [`PHASE-03-medium.md`](./PHASE-03-medium.md) — M001–M009
- [`PHASE-04-low.md`](./PHASE-04-low.md) — L001–L004
