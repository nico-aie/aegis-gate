---
id: 2026-05-14-l-tester-run6-7-fix-plan
date: 2026-05-14
status: in_progress
source_reports:
  - tests/l-tester/reports/2026-05-13-run6/LT-RUN-6-SECURITY-AUDIT.md
  - tests/l-tester/reports/2026-05-13-run7/LT-RUN-7-TEST-SUITE-AUDIT.md
prior_sprint: plans/issue-fix/2026-05-13-FINAL-release-readiness/README.md
---

# Fix plan — L-tester Run 6 (security audit) + Run 7 (test suite audit)

## Headline

Two static audits flagged 16 + 9 = 25 issues. **Before planning fixes
I cross-checked every Critical / High finding against the actual
source code paths.** Four of the audit's top-severity findings are
misclassified (the auditor read trait-surface code that the
production hot path bypasses); two are real bugs in code that's
currently unused (deferred-engine debt — still worth fixing while
cheap); three are stubs already deferred via PR #9. The remaining
items are either test-quality issues (Run 7) or design notes /
documented stubs.

The FINAL release-readiness QC from 2026-05-13 measured a 96% attack
detection rate against 120k attacks. That empirically corroborates
the "detectors are NOT bypassed" verdict for SEC-07.

## Verification matrix

Every finding cross-checked against the actual production source.

### Run 6 (security audit)

| ID | L-tester sev | Source-verified status | Plan |
|---|---|---|---|
| **SEC-07** detectors disconnected from `inbound()` | Critical | **MISCLASSIFIED.** Detectors fire from `aegis-proxy::data_plane.rs:507` via `run_all_filtered_timed`. The auditor read `AegisSecurityPipeline::inbound()` (which is unused — zero callers in `aegis-proxy`). 96% attack detection in FINAL QC confirms detectors are live. | **Phase 3** — doc + optional wire (clean up the dead trait surface so static audits stop hitting this) |
| **EVAL-01** `Condition::IpIn` uses string-prefix | Critical | **Real code bug** at `rules/eval.rs:199`. BUT `rules::evaluate()` has zero callers in `aegis-proxy` today — only used by `pipeline::inbound()` (also dead). Zero production impact in current builds. | **Phase 2** — fix anyway, cheap & future-proofs the rule engine for when it's wired |
| **EVAL-02** `RateLimit` ignores key/limit | High | **Real code bug.** Same caller-status as EVAL-01 — zero production impact. | **Phase 2** — same reasoning |
| **SEC-16** nonce race in `challenge/token.rs` | High | Module is `#[allow(dead_code)]` (PR #9). Production uses `pow.rs` which has an `AtomicU64` counter — safe. | **Phase 5** — already deferred |
| **SEC-20** `on_response_start()` returns PassThrough | High | **Confirmed in source.** Data plane doesn't call this trait method either (only `on_body_frame` is reached). ICAP wiring is a substantive feature, not a bug. | **Phase 5** — document, defer |
| **DDOS-01** `tick_rps()` never called | Medium | **MISCLASSIFIED.** Called every second from `tokio::spawn` at `run.rs:725-731`. Auditor only searched `aegis-security`. | No action — close as false positive |
| **THREAT-01** domain check exact-match only | Medium | **Real code bug** but `check_domain` has zero production callers. Threat-intel hits in production come from audit-event fields, not the in-memory checker. | **Phase 5** — defer (track in stubs catalog) |
| **RL-01 / RISK-01** `IpRateLimiter` / `RiskTracker` dead-code | Medium | Already tracked in `plans/future/unwired-stubs-catalog.md`. | No action — already deferred |
| **BOTS-01** trusts caller-supplied `reverse_dns` | Medium | BotClassifier has zero production callers (no proxy code populates `BotSignals.reverse_dns`). | **Phase 5** — defer |
| **NOOP-01** `NoopSecurityPipeline` lacks `#[deprecated]` | Low | Confirmed missing attribute. | **Phase 3** — small fix |
| **SEC-19** JA3 blake3 vs MD5 | Low | Documented intentional design. | No action |
| **DLP-FPE** XOR-mod10 stub | Low | Documented stub. | No action |
| **BASIC-01** blake3 password hash | Low | Zero callers, deferred per PR #9. | No action |
| **GQL-01** GraphQL complexity formula coarse | Low | Real but `analyze_query` has zero production callers. | **Phase 5** — defer |

### Run 7 (test suite audit)

| ID | Verified status | Plan |
|---|---|---|
| **TS-01** SEC-16 test polls safe PoW endpoint | Confirmed — would silently always pass | **Phase 4** — skip with note |
| **TS-02** PoW solver uses sha256, no `:`, wrong difficulty | Confirmed all three bugs | **Phase 4** — fix solver (blake3 + bit count) |
| **TS-03** BOTS-01 test wrong layer (header vs struct) | Confirmed | **Phase 4** — add comment doc |
| **TS-04** Assertion-inversion convention undocumented | Confirmed | **Phase 4** — header comment block |
| **TS-05** HTTP smuggling not deliverable via `urllib` | Confirmed Python limitation | **Phase 4** — raw socket helper |
| **TS-06** Concurrent tests share `Client.opener` | Confirmed | **Phase 4** — per-thread Client |
| **TS-07** Mass-flood URL has literal `<>` | Confirmed | **Phase 4** — pre-encode |
| **TS-08** Counter format accidentally correct | Note only | **Phase 4** — preserve behavior |
| **TS-09** DLP-FPE / SEC-19 / BASIC-01 coverage gaps | Intentional | **Phase 4** — header comment listing intentional omissions |

## Phase plan

### Phase 1 — Plan doc + verification (this file) ✅ done

### Phase 2 — Rule-engine real bug fixes (EVAL-01 + EVAL-02)

The rule engine has zero production callers today, but the
simulator docstring promises it'll be wired and operators may
reach for it later. Fixing while cheap.

**Files**
- `crates/aegis-security/src/rules/eval.rs`:
  - **EVAL-01:** Replace `Condition::IpIn` prefix logic with `ipnet::IpNet::contains()`. The `ipnet` crate is already a dependency.
  - **EVAL-02:** Add a `RateLimiter` accessor on `EvalContext`. In the `RateLimit` arm, call `IpRateLimiter::consume()` (already exists in `rate_limit/ip_limiter.rs`) keyed by `RuleAction::RateLimit.key`. Returns `Allow` when window not exhausted, `RateLimited{retry_after_s}` when it is.
- Unit tests: `cidr_24_matches_host_inside_subnet`, `cidr_24_does_not_match_outside_subnet`, `ratelimit_allows_first_n_then_429`, `ratelimit_recovers_after_window`.

**Effort:** ~2-3h.

### Phase 3 — Dead-code cleanup (SEC-07 closure + NOOP-01)

**Files**
- `crates/aegis-security/src/pipeline.rs`:
  - Doc-comment block on `AegisSecurityPipeline::inbound()` /
    `on_response_start()` documenting:
    - These trait methods are NOT the production entry points.
    - Production hot path: `aegis-proxy/src/data_plane.rs:507`
      calls `run_all_filtered_timed` directly with the detector
      list seeded in `aegis-proxy/src/lib.rs:143`.
    - L-tester static audits keep flagging "detectors not wired in `inbound()`" — that's expected; this method is a legacy trait surface kept for the Pipeline trait shape and tests.
  - **(Optional follow-up)** wire `inbound()` to delegate to
    `run_all_filtered_timed` so the trait-level surface matches
    production. Out of scope for this sprint per the doc-only
    recommendation; track as a follow-up in `plans/future/`.
- `crates/aegis-security/src/noop.rs`:
  - Add `#[deprecated(note = "NoopSecurityPipeline bypasses all security. Use AegisSecurityPipeline for production. This type exists for tests only.")]` to the struct declaration.
  - Wherever Noop is used internally for tests, suppress the
    warning explicitly with `#[allow(deprecated)]` so the build
    stays green.

**Effort:** ~1h.

### Phase 4 — Test suite quality fixes

**Files**
- `tests/lt_run6_extended_tests.py`:
  - **TS-02 (top priority):** rewrite `test_pow_full_flow` solver
    to use `blake3` (or subprocess-shell to a small Rust helper
    if blake3 isn't pip-available) + the `:` separator + bit-
    count difficulty. Unlocks `test_pow_replay_check` and
    `test_pow_invalid_mac` downstream.
  - **TS-01:** mark `test_sec16_*` with `pytest.skip` + comment
    referencing `challenge/token.rs` zero callers per PR #9.
  - **TS-03:** add docstring on BOTS-01 tests noting that the
    trust boundary is in the proxy struct-population code and
    not exercisable via HTTP header.
  - **TS-05:** add `RawSocketClient` helper for the 5 smuggling
    cases; keep urllib for the rest of the suite.
  - **TS-06:** per-thread `Client` in `test_rl01_burst_concurrent`
    and `test_admin_concurrent_rule_write`.
  - **TS-07:** pre-encode `<>` in mass-flood payloads via
    `urllib.parse.quote(..., safe='')`.
- `tests/lt_run6_live_tests.py`:
  - **TS-04:** header comment block explaining the assertion-
    inversion convention (✓ = bug confirmed, ✗ = bug fixed).
    Optionally factor `R.bug_confirmed()` / `R.bug_fixed()`
    helpers for cleaner CI output.
  - **TS-09:** header note listing intentionally-omitted coverage
    (DLP-FPE, SEC-19, BASIC-01).

**Effort:** ~3h.

### Phase 5 — Deferrals (no code, doc updates only)

Append entries to `plans/future/unwired-stubs-catalog.md` for the
items that remain deferred:

- `aegis-security::rules::evaluate` and `AegisSecurityPipeline::inbound` — both deferred (engine has zero production callers; will be wired in a future sprint when the dashboard simulator graduates).
- `on_response_start` / ICAP — wire ICAP into the response pipeline (substantive feature, not in scope here).
- `challenge/token.rs` nonce race — already documented stub.
- `BotClassifier::classify` + `BotSignals.reverse_dns` population in proxy — track FCrDNS work.
- `threat_intel::check_domain` subdomain walk — track wildcard matching.
- `api_security::graphql::analyze_query` proper complexity — track.

Plus a one-line summary entry in `Implement-Progress.md` so the
next L-tester audit can cross-reference the verified status of
each Run-6 finding instead of re-flagging false positives.

**Effort:** ~30 min.

## Risk register

- **Phase 2 EVAL-02 needs a state-backend handle on `EvalContext`.**
  Today's `EvalContext` carries the live cfg + geoip but not a
  rate-limit backend. We'll plumb an `Option<&IpRateLimiter>`
  through. Won't break callers because the engine has zero
  callers in production.
- **Phase 3 deprecation of `NoopSecurityPipeline`** triggers
  `#[deprecated]` warnings wherever it's used (internal tests).
  Suppress with `#[allow(deprecated)]` at each test call site —
  small mechanical fan-out.
- **Phase 4 TS-02 blake3 pip dep.** Try `pip install blake3`
  first. If the test venv lacks it, fall back to subprocess-
  shelling to a precompiled helper (the WAF binary already
  links blake3, so `./target/release/waf` could expose a one-
  shot `pow-solve` subcommand if needed).
- **L-tester audit accuracy.** Three Critical/High findings turned
  out to be false positives caused by reading the wrong trait
  surface. Adding a clear `Implement-Progress.md` entry pointing
  static auditors at the production hot path
  (`data_plane.rs:507`, `run.rs:725`) will save effort on the
  next audit.

## Out of scope

- ICAP wiring (substantive feature work).
- FCrDNS DNS lookup in BotClassifier (defer).
- AES-FF1 in DLP (defer).
- argon2 in basic-auth (defer).
- Wiring the rules engine into the data plane (Phase 5 of
  `plans/future/`).
- Implement-Progress.md broader updates beyond the L-tester audit
  cross-reference.
