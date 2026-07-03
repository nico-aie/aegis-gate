# PLAN — l-tester perf & hardening: convert the audit/scorecard findings into shippable work

> **Type:** PLAN (performance + operability track) · **Status:** ⬜ Not started · **Branch:** `feat/ltester-perf-*` (per stage)
> **Track ID prefix:** `LT-P1<–8>`
> **Derived from:** `tests/l-tester/CODE_AUDIT_2026-07-02.md` (§5 optimization, §6 improvement, §7 verification) + `tests/l-tester/JUDGING_SCORECARD_2026-07-02.md` (103/120; Performance 15/20 is the biggest gap-to-ceiling).
> **Honors:** [[project_rustfmt_whole_crate_hazard]] (repo NOT rustfmt-clean — hand-match style, only rustfmt files you fully author) · [[feedback_test_suite_green_baseline]] (`cargo test --workspace` green baseline; FP-reduction tests go stale by design) · [[feedback_e2e_docker_cleanup]] (bench harness restart recipe) · [[project_admin_public_http_contract]] (public-HTTP admin is a committee contract, not a bug — don't "harden" it away) · [[project_health_signals_reported_not_gating]]

**Goal (one line):** capture the cheapest points on the scorecard — the Performance bucket (release-profile tuning, single-pass regex) and the correctness-adjacent defaults/verification items — as concrete PRs, each measured against `deploy/STAGING-BENCHMARK.md`.

**Verified 2026-07-03 (load-bearing claims re-checked against the tree):** no `[profile.release]` in root `Cargo.toml` ✅ · `DEFAULT_LIMIT = 1_000_000` per 60s at `crates/aegis-security/src/rate_limit/ip_limiter.rs:46` ✅ (audit said `aegis-proxy` — path was wrong, claim correct) · CI has only a **v2.3** contract gate (`.github/workflows/ci.yml:205-237`), no v2.6 ✅ · **zero** `RegexSet` usage in `aegis-security` (O-2 is greenfield) ✅ · 39 module-level `#![allow(dead_code)]` across `crates/*/src` ✅.

---

## Why this plan exists

The scorecard's own "highest-ROI" list is: release profile (+2–3 Perf), realistic per-IP default / prove ddos coverage (+2–3 Sec), decay-on-allow proof (+1–2 Intel), panic/dead-code triage (+1 Arch). Those are exactly LT-P1…LT-P4 below. Projected ceiling if LT-P1–P4 land and the live battle matches code quality: **~110–113/120**.

Everything here is either a pure perf win or a verification/hygiene item — **none changes the contract surface**. Measure Perf items before/after; the release-profile change in particular must be quantified, not assumed.

---

## LT-P1 — `[profile.release]` tuning · **S** · *(audit O-1 · Performance, highest ROI)*
Root `Cargo.toml` has no `[profile.release]` → ships cargo defaults (`opt-level=3`, `lto=false`, `codegen-units=16`). For a latency-sensitive L7 proxy this is free p99/throughput left on the table.
```toml
[profile.release]
lto = "thin"          # measure "fat" too
codegen-units = 1
panic = "abort"       # smaller/faster — CONFIRM no test/prod path relies on unwinding
strip = "debuginfo"
```
- **`panic = "abort"` caveat:** the workspace has 182 non-test `panic!` + 495 `.expect(` (LT-P4). With `abort`, any of those on the request path takes down the process instead of unwinding one task. **Do LT-P4's hot-path triage first, or ship LT-P1 without `panic="abort"` initially** and add it after triage. Also confirm no integration test depends on catching unwind.
- **Verify:** `cargo build --release -p aegis-bin --features "redis alerts geoip"` clean; run `deploy/STAGING-BENCHMARK.md` before/after and record p99 + throughput delta here. This is the single cheapest Performance win — it must be measured, not claimed.

## LT-P2 — per-detector `Vec<Regex>` → `RegexSet` single pass · **M** · *(audit O-2 · Performance)*
~16 detectors each hold `LazyLock<Vec<Regex>>` and loop every pattern per request — many independent scans of the same bytes. A `regex::RegexSet` matches all patterns in **one pass**; only a surviving detector runs the specific-rule attribution pass.
- Start with the heaviest scanners on the largest inputs: `sqli.rs`, `xss.rs`, `header_injection.rs` (1,281 LOC, largest), `ssrf.rs`.
- **Keep attribution:** `RegexSet` says *which* patterns matched but not *where*; retain a per-hit second pass only on the matched subset for the audit `rule_id`/score.
- **Coordinate with AC-P1-d** (XSS body decode parity): if that lands first, build its added patterns into the `RegexSet` from the start rather than a new `Vec<Regex>` loop.
- **Verify:** identical detection results on the existing detector test corpus (no coverage regression — [[feedback_test_suite_green_baseline]]) + benchmark CPU/p99 on large query/body inputs before/after.

## LT-P3 — realistic default per-IP limit OR documented ddos division-of-labor · **S** · *(audit O-3 / I-2 · Security+Perf)*
`DEFAULT_LIMIT = 1_000_000` per 60s (`ip_limiter.rs:46`) is a "backstop, not a throughput cap" — but at 1M/min the local per-IP volumetric gate effectively **never fires** unless buckets are configured. Under the §7 "DDoS aimed at the WAF" scenario this leaves a single flooding source un-throttled by *this* gate.
- **Option A:** lower `DEFAULT_LIMIT` to a sane backstop (a few thousand/min) — but validate it can't collaterally throttle the benchmark's own load generator (which may come from one IP). This is the risk; measure against the harness traffic shape first.
- **Option B (safer if A regresses benchmark):** keep the high backstop but **prove + document** that `ddos.rs` (the per-`(tier,ip)` flood window, 1000 req/10s default) fully covers the volumetric case, and state the division of labor in a comment + runbook. Pairs with AC-P3-d (L4 posture doc).
- **Verify:** confirm which gate fires first under a single-IP L7 flood in staging; document the answer either way.

## LT-P4 — triage non-test `panic!` / `.expect(` on request paths · **M** · *(audit I-1 · Code Quality / graceful degradation; prereq for LT-P1 `panic=abort`)*
182 `panic!` + 495 `.expect(` workspace-wide (majority in `#[cfg(test)]`). Hot files (`data_plane.rs`, `accept.rs`) are already `unwrap`-clean, but e.g. a poisoned-lock `expect` in the control plane (`reset_callbacks.lock().expect(...)`) aborts the thread if a callback panics under the lock. §5.8 mandates graceful degradation.
- `rg 'panic!|\.expect\(' crates/*/src` filtered to non-test modules; triage each on a request-handling path → convert to `fail_open`/`fail_close` per route tier (the tier failure-mode machinery already exists, `data_plane.rs:715`).
- **Gates LT-P1's `panic="abort"`** — finish the hot-path subset before enabling abort.
- **Verify:** targeted tests that a poisoned lock / callback panic degrades per tier instead of aborting the process.

## LT-P5 — verify risk **decay** shows on allowed-response `X-WAF-Risk-Score` · **M** · *(audit I-3 / scorecard §3 · Intelligence)*
Decay is configured (`decay_half_life`, default 5 min; `reconcile.rs`) but described as "monotonic in practice, decreased via separate `add_risk(_, -decay)`." Rules §5.5 requires score to **decrease on sustained normal behavior**, and the benchmarker validates accumulation *and* decay on **allowed** responses.
- Confirm the decay path runs on the **allow** path (not only explicit reset) and that `X-WAF-Risk-Score` on allowed responses reflects it over a quiet window.
- **This is verification-first:** if decay already surfaces correctly, close with a regression test. If it only applies on reset, that's a real fix (small).
- **Verify:** integration test — accumulate risk, then a quiet window of allowed requests shows a monotonically *decreasing* `X-WAF-Risk-Score`.

## LT-P6 — add a v2.6 contract-compliance CI gate · **S** · *(audit §7.4 / I-… · Deployment)*
CI wires only the **v2.3** compliance script (`ci.yml:205-237` → `tests/contract/v2.3_compliance.sh`); the codebase targets **v2.6**. Add a v2.6 gate (new script or extend the existing) so contract drift is caught in CI, not at judging.
- **Verify:** the gate runs the v2.6 control-plane surface (`capabilities`/`reset_state`/`set_profile`/`flush_cache`, unsupported→200+`unsupported[]`, required headers) against a booted binary.

## LT-P7 — confirm judged config `trusted_proxies: []`, enforce `is_unsafe_trusted_proxy` at load · **S** · *(audit I-2 · Security / Contract §6)*
Default is safe (empty `trusted_proxies` → TCP peer wins). But if the judged config ever trusts loopback/private CIDRs, `with_proxy_via` makes the audit `ip` the *asserted* client, breaking §6 (audit ip MUST be TCP peer) and the XFF-spoof test family. The `is_unsafe_trusted_proxy` guard exists — make it **reject/warn at config load**, not just be available.
- **Not the admin-HTTP exposure** — that's a committee contract ([[project_admin_public_http_contract]]); this is specifically the `trusted_proxies`/XFF trust list.
- **Verify:** config with `127.0.0.0/8` in `trusted_proxies` is rejected (or loudly warns) at boot; judged config asserted `[]`.

## LT-P8 — hygiene: module-level `#![allow(dead_code)]`, TODO sweep, doc-comment nits · **M** · *(audit I-4/I-5, O-4 · Code Quality; folds the ASSESSMENT doc nits)*
- Replace the 39 module-level `#![allow(dead_code)]` with per-item `#[allow]` or delete genuinely-unused paths (`ip_limiter.rs` IP-only variants superseded by `*_with_key`). Per-file allows mask real dead surface (e.g. the assessment's dead `behavior.rs`/`velocity.rs`).
- Sweep 41 `TODO/FIXME/XXX/HACK` before the next round; none should hide a broken branch.
- Add a module doc to `aegis-core/src/risk.rs` (98 LOC thin type module) pointing to where accumulation/decay/thresholds actually live (`state/{in_memory,reconcile}.rs`).
- **Fold the two doc-hygiene nits from the coverage assessment's *Corrections*:** fix the stale `// Enforce — 503` comment at `data_plane.rs:678` (the block is 403) and the stale `canary.rs:6` "score 90" (emits 100).
- **Style caution:** [[project_rustfmt_whole_crate_hazard]] — the repo is not rustfmt-clean; hand-match style, don't `cargo fmt` whole files you didn't author.

---

## Sequencing & ROI

| Order | Item | Effort | Payoff | Bucket |
|---|---|---|---|---|
| 1 | LT-P1 release profile (minus `panic=abort`) | S | High | Performance |
| 2 | LT-P4 hot-path panic/expect triage | M | Med | Code Quality → unlocks `panic=abort` |
| 3 | LT-P1b add `panic="abort"` after LT-P4 | S | Low | Performance |
| 4 | LT-P2 `RegexSet` single-pass | M | Med | Performance |
| 5 | LT-P5 decay-on-allow verify | M | High | Intelligence |
| 6 | LT-P3 per-IP default / ddos doc | S | Med | Security/Perf |
| 7 | LT-P7 trusted_proxies guard | S | High | Security/Contract |
| 8 | LT-P6 v2.6 CI gate | S | Med | Deployment |
| 9 | LT-P8 hygiene + doc nits | M | Low | Code Quality |

LT-P1 + LT-P2 are the direct Performance-bucket wins (15→~18). LT-P5 + LT-P7 protect points that are otherwise "held pending live verification." LT-P4 is both a hardening win and the gate for LT-P1's `panic=abort`.

## Definition of done / archival

- Every Perf item records a before/after benchmark delta here; the release-profile PR must show the actual p99/throughput numbers.
- LT-P8 closes the two ASSESSMENT doc-hygiene nits (503 comment, canary 90/100) — note that back on the ASSESSMENT when done.
- When the committed set has merged, move this file to `plans/issues/archived/`; if the l-tester audit/scorecard docs are point-in-time snapshots, leave them in `tests/l-tester/` as historical record (don't archive the source reports — only this plan).
