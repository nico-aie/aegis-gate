---
id: 2026-06-17-contract-v2.6-verification
date: 2026-06-17T00:00Z
test_mode: source-review
contract: Hackathon_Doc/EN_waf_interop_contract_v2.6.md
checklist: reports/CONTRACT_v2.6_REQUIREMENTS_CHECKLIST.md
scope:
  - Verify the aegis-gate WAF against EVERY requirement section of
    Interop Contract v2.6 (§1–§13), one section at a time.
  - Code reviewed (contract-relevant surface):
    A) crates/aegis-control/src/interop/{control,mode,headers,audit,rule_map}.rs
    B) crates/aegis-proxy/src/{accept,admin_dispatch,data_plane,responses}.rs
    C) crates/aegis-security/src/{rate_limit/*, challenge}
    D) crates/aegis-core/src/{audit,config,risk}.rs
tester: Claude (Opus 4.8) — source review + cited file:line spot-verification
note: >
  This is a SOURCE REVIEW, not a live benchmark run. Findings cite
  file:line. Where a claim depends on runtime/deploy config (e.g. the
  §8 health-probe path, operator risk.max), it is flagged "VERIFY-LIVE"
  rather than asserted pass/fail. Supersedes the 2026-05-17 control
  audit, which was against contract v2.3.
---

# Aegis-Gate — Interop Contract v2.6 compliance verification — 2026-06-17

**Mode:** Section-by-section source review against `EN_waf_interop_contract_v2.6.md`.
Each contract section was read in the original, mapped to the requirement
IDs in `CONTRACT_v2.6_REQUIREMENTS_CHECKLIST.md`, then checked against the
live code path.

**Headline:** The WAF is **largely v2.6-compliant**. The control plane,
challenge/rate-limit (self-built), audit log, startup contract, and the
6 mandatory headers are all implemented and wired into the real data path.
**No CRITICAL contract breakers were found.** The open items are a small
number of **header-format** and **error-status** issues that strict graders
can fail on, plus config-dependent edge cases.

> Important v2.6 delta vs the old 2026-05-17 audit: v2.6 §5.1 **relaxed**
> `X-WAF-Request-Id` from "UUID v4" to "any unique token, 8–64 chars,
> `[A-Za-z0-9._-]`". The old F-HIGH-headers H-01 (blake3-not-UUID) is
> therefore **no longer a violation**, and the live path now uses
> `uuid::Uuid::new_v4()` anyway (`admin_dispatch.rs:1302`).

---

## Finding counts

| Severity | Count | Notes |
|---|---|---|
| CRITICAL | 0 | — |
| HIGH | 1 | F-V26-001 (rule-id format on every non-hyphen decision) |
| MEDIUM | 2 | F-V26-002 (set_profile 422 may abort run), F-V26-003 (risk-score >100 leak) |
| LOW | 2 | F-V26-004 (deny_unknown_fields), F-V26-005 (pow None fallback) |
| VERIFY-LIVE | 2 | health-probe path (§8), challenge cookie issuance (§4) |
| **Total** | **7 findings + 2 to confirm live** | |

---

## Per-section compliance matrix

| Contract § | Area | Verdict | Evidence / blocker |
|---|---|---|---|
| §1 | Observability + determinism + control plane present | ✅ PASS | headers on every response (`stamp_interop_response`), control plane wired |
| §2.1 | 4 control endpoints, local-only, not proxied, accept body, SLA | ✅ PASS | `accept.rs:1752` always intercepts `/__waf_control/*`; `admin_dispatch.rs:976` |
| §2.2 | `X-Benchmark-Secret` on every method, 403 otherwise, constant-time | ✅ PASS | `admin_dispatch.rs:964-974`, `control.rs:30 constant_time_eq` |
| §2.3 | capabilities shape, stable names, active overrides | ✅ PASS | `control.rs:305 capabilities()` |
| §2.4 | reset_state atomic/sync, clears runtime, preserves audit+config | ✅ PASS | `control.rs:348 reset_state_async`, RAII reset guard `admin_dispatch.rs:1010` |
| §2.5 | set_profile scopes all/features/policies, unsupported list | ⚠️ MOSTLY | F-V26-002 — unknown feature in `policies` scope → 422 (v2.6 prefers 200) |
| §2.6 | flush_cache 200/501-not-404 when no cache | ✅ PASS | `control.rs:517 flush_cache` returns 200 + `supported:false` |
| §2.6b | single Rust binary, hot-reload exists | ✅ PASS | `./waf run`; ArcSwap mode + rule hot-reload |
| §2.7 | `X-WAF-Mode` per firing policy, log_only intent only | ✅ PASS | `admin_dispatch.rs:1311 mode_for_rule`; challenge log_only arm `data_plane.rs:1444` |
| §3 | 6 decision classes exact strings | ✅ PASS | `headers.rs:50 Action::as_str` (tested) |
| §3.1 | threat→action semantic map | ✅ PASS (by design) | detectors emit block/challenge/rate_limit; allow+risk supported |
| §4 | HTTP behavior, **self-built** rate-limit + PoW challenge, formats | ✅ PASS | `data_plane.rs:706` (429+Retry-After), `data_plane.rs:1368` PoW Format A, `admin_dispatch.rs:1096` verify |
| §5.1 | 6 headers on every response, exact formats | ⚠️ MOSTLY | F-V26-001 (rule-id underscores/commas), F-V26-003 (risk-score clamp) |
| §5.3 | header consistency (action/mode/risk/cache/request-id) | ✅ PASS | `stamp()` replaces not appends; header+audit share request_id & score |
| §6 | JSONL `./waf_audit.log`, 8 fields, ip=TCP peer, append-only | ✅ PASS | `interop/audit.rs`, `admin_dispatch.rs:1348 ip=peer.ip()` |
| §7 | decision normalization (enforce/log_only) | ✅ PASS | log_only forwards upstream + reports intended action |
| §8 | `./waf run`, config, health 200 before timeout | ✅ PASS / ⚠️ VERIFY-LIVE | health endpoint exists; confirm benchmark polls the right (auth-free) path |
| §9 | `X-WAF-Cache` on every response, BYPASS default, flush | ✅ PASS | `headers.rs:286` always stamps cache; smart-cache wired |
| §10 | peer_addr primary, XFF supplementary, 127.0.0.x distinct | ✅ PASS | audit ip=peer; risk key built from peer + fp |
| §11/§11b | no hard-coding, same binary both phases, enforce in battle | ✅ PASS | single binary; no payload hard-coding observed in control path |
| §13 | Minimum Viable checklist | ✅ PASS | all precondition items satisfied |

---

## CRITICAL findings

None.

---

## Findings index

| ID | Sev | Title | File |
|---|---|---|---|
| F-V26-001 | HIGH | `X-WAF-Rule-Id` emits underscores + comma-joined lists, violating §5.1 "alphanumeric + hyphens" | [F-V26-001](F-V26-001-rule-id-format.md) |
| F-V26-002 | MEDIUM | `set_profile` returns 422 for an unknown feature in `policies` scope — v2.6 §2.5 says this aborts the benchmark run | [F-V26-002](F-V26-002-set-profile-422-aborts-run.md) |
| F-V26-003 | MEDIUM | `X-WAF-Risk-Score` (header + audit) not clamped to 100 when operator sets `risk.max > 100` | [F-V26-003](F-V26-003-risk-score-clamp.md) |
| F-V26-004 | LOW | `SetProfileRequest` uses `deny_unknown_fields` — a future/extra benchmark field 400s the call | [F-V26-LOW](F-V26-LOW-and-verify-live.md) |
| F-V26-005 | LOW | Challenge `None` fallback (pow_issuer unwired) emits an unsolvable 429 → recorded FAILED per §4 | [F-V26-LOW](F-V26-LOW-and-verify-live.md) |
| VERIFY-LIVE-1 | — | Confirm the benchmark's §8 startup health probe hits an endpoint that does NOT require `X-Benchmark-Secret` | [F-V26-LOW](F-V26-LOW-and-verify-live.md) |
| VERIFY-LIVE-2 | — | Confirm `/challenge/verify` success issues the session cookie/token that lets the original request proceed (§4) | [F-V26-LOW](F-V26-LOW-and-verify-live.md) |

---

## Section detail files

```
QA-RUN-SUMMARY.md                       (this file)
SECTION-02-control-plane.md             §2 full walkthrough
SECTION-03-decision-classes.md          §3 + §3.1
SECTION-04-rate-limit-challenge.md      §4
SECTION-05-headers.md                   §5
SECTION-06-audit-log.md                 §6
SECTION-07-to-13-misc.md                §7,§8,§9,§10,§11,§13
F-V26-001-rule-id-format.md             HIGH
F-V26-002-set-profile-422-aborts-run.md MEDIUM
F-V26-003-risk-score-clamp.md           MEDIUM
F-V26-LOW-and-verify-live.md            LOW + VERIFY-LIVE
```

---

## Verdict

Aegis-Gate **meets the v2.6 Minimum Viable WAF checklist (§13)** and the
bulk of §§1–11. There are **no contract-breaking CRITICALs**. The single
HIGH (F-V26-001) is a 1-site centralized fix (sanitize rule-id at stamp
time) that protects every response against a strict §5.1 grader. The two
MEDIUMs are a 1-line status change (`Unsupported → 200 + unsupported list`)
and a 1-line clamp. Fixing all three is < 20 LoC and removes essentially
all of the contract-shape risk surface for the Phase-1 automated benchmark.

### Fix order (smallest, highest leverage first)
1. **F-V26-002** — change `policies`-scope unknown-feature from `422` to
   `200` + `unsupported:["feature.x"]` (`control.rs:596`). ~3 LoC. Removes
   run-abort risk.
2. **F-V26-003** — `.min(100)` on `effective_risk_score`
   (`admin_dispatch.rs:1322`). 1 LoC. Header + audit both fixed at the
   single stamp site.
3. **F-V26-001** — add `sanitize_rule_id()` in `headers.rs::stamp` (map
   `_`→`-`, drop non `[A-Za-z0-9-]`). ~6 LoC. Covers all current + future
   underscore/comma emitters.
