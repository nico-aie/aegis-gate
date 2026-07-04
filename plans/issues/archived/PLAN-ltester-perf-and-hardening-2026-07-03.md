# PLAN — l-tester perf & hardening: convert the audit/scorecard findings into shippable work

> **Type:** PLAN (performance + operability track) · **Status:** ✅ **CLOSED 2026-07-04 — archived.** Shipped: LT-P1 release profile, LT-P8 hygiene sweep (+ watcher-test hardening, PR #150). Rejected on evidence: LT-P2 RegexSet (measured slower), LT-P1b panic=abort (defeats unwind isolation), LT-P4 (purpose removed with P1b). **Owner-skipped 2026-07-04: LT-P3, LT-P5, LT-P6, LT-P7** — deliberate scope cut, not silent drops; see each stanza. · **Branch:** `feat/ltester-perf-*` (per stage)
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
- **`panic = "abort"` — DO NOT ADD (rejected 2026-07-04, see LT-P1b below).** It defeats the WAF's per-connection tokio unwind isolation, turning any handler panic into a whole-process DoS. LT-P1 shipped (merged) deliberately without it; keep it that way.
- **Verify:** `cargo build --release -p aegis-bin --features "redis alerts geoip"` clean; run `deploy/STAGING-BENCHMARK.md` before/after and record p99 + throughput delta here. This is the single cheapest Performance win — it must be measured, not claimed.

## LT-P2 — per-detector `Vec<Regex>` → `RegexSet` single pass · **REJECTED (measured slower) 2026-07-03** · *(audit O-2 · Performance)*

> **Outcome: evaluated, implemented, benchmarked, and reverted — `RegexSet` is _slower_ here, not faster.** The audit's "many independent scans of the same bytes" intuition is wrong for this codebase: the `regex` crate already compiles a highly-optimized **literal prefilter** (memchr / Aho-Corasick) into *each individual* `Regex`, so on the dominant benign traffic every pattern rejects in ~one memchr pass. Collapsing them into one `RegexSet` builds a larger combined automaton whose single prefilter is *worse* than N cheap per-pattern ones.
>
> **Measured** (release micro-bench, ~10 KB benign input, sqli's 18-pattern set, 20 k iters, 3 runs — the guard test `sqli.rs::regexset_single_pass_is_faster_than_vec_loop`):
>
> | | ns/scan |
> |---|---|
> | `Vec<Regex>` + `.iter().any(is_match)` (shipped) | ~16,600 |
> | `RegexSet::is_match` | ~22,300 |
> | **speedup** | **0.74× (26–34 % _slower_)** |
>
> End-to-end (prod-balanced-5k, 100 %-large-body worst case) the delta washed out to noise because the regex scan is a small fraction of per-request cost (I/O-bound at ~12.5 k rps loopback), i.e. there was **no upside to bank and a real CPU regression to risk**. The `RegexSet` swap (sqli / xss / ssrf / header_injection, all corpus-green) was reverted; the micro-bench stays as a `#[ignore]` regression guard so a future well-meaning retry re-measures first.
>
> **Do not reopen** without a materially different approach — e.g. a hand-built shared literal pref​ilter, or `regex-automata`'s multi-pattern DFA with explicit prefilter control — and a micro-bench that beats the per-`Regex` prefilter baseline above. The plain `RegexSet` path is a dead end here.

## LT-P3 — realistic default per-IP limit OR documented ddos division-of-labor · **S** · *(audit O-3 / I-2 · Security+Perf)* — ❌ **OWNER-SKIPPED 2026-07-04.** SKIPPED — the DDoS gate (1000 req/10s per (tier,ip), default-ON) is the volumetric gate in practice; the 1M/min ip_limiter stays a backstop. AC-P3-d's L4-posture runbook already states the division of labor.
`DEFAULT_LIMIT = 1_000_000` per 60s (`ip_limiter.rs:46`) is a "backstop, not a throughput cap" — but at 1M/min the local per-IP volumetric gate effectively **never fires** unless buckets are configured. Under the §7 "DDoS aimed at the WAF" scenario this leaves a single flooding source un-throttled by *this* gate.
- **Option A:** lower `DEFAULT_LIMIT` to a sane backstop (a few thousand/min) — but validate it can't collaterally throttle the benchmark's own load generator (which may come from one IP). This is the risk; measure against the harness traffic shape first.
- **Option B (safer if A regresses benchmark):** keep the high backstop but **prove + document** that `ddos.rs` (the per-`(tier,ip)` flood window, 1000 req/10s default) fully covers the volumetric case, and state the division of labor in a comment + runbook. Pairs with AC-P3-d (L4 posture doc).
- **Verify:** confirm which gate fires first under a single-IP L7 flood in staging; document the answer either way.

## LT-P1b — `panic = "abort"` · **REJECTED (unsafe here) 2026-07-04** · *(Performance)*

> **Outcome: rejected — `panic="abort"` defeats the WAF's per-connection unwind isolation and turns any handler panic into an adversarially-triggerable whole-process DoS.** The accept loops spawn a `tokio::spawn` task **per connection** (`accept.rs:205,586,816,1261,…`). Under the shipped `panic = unwind`, a panic in a request handler kills **only that connection's task** — the runtime + process survive and the WAF keeps serving everyone else. Under `panic="abort"` the same panic **aborts the whole process**: find one input that panics a handler and you kill the entire WAF. That's a direct availability regression and undercuts the §5.8 graceful-degradation posture.
>
> Supporting facts: the only `catch_unwind` in the tree is in **tests** (shed.rs, upstream/mod.rs) — production resilience is entirely tokio task-per-connection unwind isolation, not explicit catching. The §5.8 `fail_open`/`fail_close` machinery (`data_plane.rs:732+`) handles **backend errors** (Result-based), not panics, so it doesn't cover the abort case. `catch_unwind` and `panic="abort"` are fundamentally incompatible — you cannot have both graceful per-request degradation and abort.
>
> **Keep `panic = unwind`.** The marginal binary-size / perf gain is not worth converting every handler panic into a WAF-wide outage. (Same shape as the LT-P2 rejection — the perf intuition didn't survive contact with the codebase's availability model.) The shipped `[profile.release]` (LT-P1, merged) deliberately omits `panic="abort"` and should stay that way.

## LT-P4 — triage non-test `panic!` / `.expect(` on request paths · **SKIPPED 2026-07-04 (purpose removed by LT-P1b rejection)** · *(audit I-1 · Code Quality)*

> **Skipped.** LT-P4's entire justification was to be the gate for LT-P1b's `panic="abort"`. With LT-P1b rejected (above), that gate is moot. Under the retained `panic = unwind` build the request path already has the isolation LT-P4 was meant to provide: hot files (`data_plane.rs`, `accept.rs`) are `unwrap`-clean, the per-request mode read is **lock-free** (`ArcSwap`, `mode.rs:88`), and `reset_state` snapshots callbacks under the lock then runs them **unlocked** with a panic-free critical section (`control.rs:331-337`) — so the cited "poisoned-lock cascade" is largely theoretical, and poison-recovery is irrelevant under a build that never enables abort. A panicking request-handler or reset cleaner already degrades to a dropped connection / dead task, not a process abort. General panic-hygiene remains a nice-to-have but is low-value and not tracked here.
>
> *Original scope (for the record):* 182 `panic!` + 495 `.expect(` workspace-wide (majority `#[cfg(test)]`); triage request-path sites to `fail_open`/`fail_close`. Not pursued.

## LT-P5 — verify risk **decay** shows on allowed-response `X-WAF-Risk-Score` · **M** · *(audit I-3 / scorecard §3 · Intelligence)* — ❌ **OWNER-SKIPPED 2026-07-04.** SKIPPED — verification-only item; decay-on-read ships (`decay_on_read` in tracker) and no judging feedback flagged it. Revive only if a scorecard run shows non-decreasing scores on quiet traffic.
Decay is configured (`decay_half_life`, default 5 min; `reconcile.rs`) but described as "monotonic in practice, decreased via separate `add_risk(_, -decay)`." Rules §5.5 requires score to **decrease on sustained normal behavior**, and the benchmarker validates accumulation *and* decay on **allowed** responses.
- Confirm the decay path runs on the **allow** path (not only explicit reset) and that `X-WAF-Risk-Score` on allowed responses reflects it over a quiet window.
- **This is verification-first:** if decay already surfaces correctly, close with a regression test. If it only applies on reset, that's a real fix (small).
- **Verify:** integration test — accumulate risk, then a quiet window of allowed requests shows a monotonically *decreasing* `X-WAF-Risk-Score`.

## LT-P6 — add a v2.6 contract-compliance CI gate · **S** · *(audit §7.4 / I-… · Deployment)* — ❌ **OWNER-SKIPPED 2026-07-04.** SKIPPED — v2.3 gate stays the only CI contract check; v2.6 surface is exercised by the l-tester scripts run manually.
CI wires only the **v2.3** compliance script (`ci.yml:205-237` → `tests/contract/v2.3_compliance.sh`); the codebase targets **v2.6**. Add a v2.6 gate (new script or extend the existing) so contract drift is caught in CI, not at judging.
- **Verify:** the gate runs the v2.6 control-plane surface (`capabilities`/`reset_state`/`set_profile`/`flush_cache`, unsupported→200+`unsupported[]`, required headers) against a booted binary.

## LT-P7 — confirm judged config `trusted_proxies: []`, enforce `is_unsafe_trusted_proxy` at load · **S** · *(audit I-2 · Security / Contract §6)* — ❌ **OWNER-SKIPPED 2026-07-04.** SKIPPED — default is safe (empty list) and the judged config is owner-controlled; the load-time reject stays unbuilt.
Default is safe (empty `trusted_proxies` → TCP peer wins). But if the judged config ever trusts loopback/private CIDRs, `with_proxy_via` makes the audit `ip` the *asserted* client, breaking §6 (audit ip MUST be TCP peer) and the XFF-spoof test family. The `is_unsafe_trusted_proxy` guard exists — make it **reject/warn at config load**, not just be available.
- **Not the admin-HTTP exposure** — that's a committee contract ([[project_admin_public_http_contract]]); this is specifically the `trusted_proxies`/XFF trust list.
- **Verify:** config with `127.0.0.0/8` in `trusted_proxies` is rejected (or loudly warns) at boot; judged config asserted `[]`.

## LT-P8 — hygiene: module-level `#![allow(dead_code)]`, TODO sweep, doc-comment nits · **M** · *(audit I-4/I-5, O-4 · Code Quality; folds the ASSESSMENT doc nits)* — ✅ **COMPLETE 2026-07-04** (`chore/ltester-lt-p8-hygiene`)
> Outcome: all 39 module-level blankets removed; the compiler then flagged only **6 genuinely dead items** (the rest were live via test targets) — deleted all 6 (acme_instant poll consts, assets `SVG` content-type, three inert `serde(default)` fns on the Serialize-only `RouteSummary`, tracker's superseded `DEFAULT_TRUST_PER_HOUR`) plus the plan-named `ip_limiter` IP-only wrappers (`consume`/`consume_at`/`reset` — test-only callers, migrated to `_with_key`). Workspace now compiles with **zero warnings** (also cleared 5 pre-existing unused-import/var warnings). TODO sweep: the audit's "41" was inflated by `HACK-T3/T4/T5` **task-ID** references and the rules-validator's own TODO-marker strings — only **4 real TODOs** existed; 2 were stale docs now fixed (acme.rs claimed the instant-acme provider was still a follow-up — it shipped; accept.rs claimed route hot-reload hadn't landed — it did), 2 are honest documented seams kept (run.rs leader-lease seam, velocity_sequence hardcoded-ruleset note). `risk.rs` module doc added (types here; behavior in `risk/tracker.rs` + `state/{in_memory,reconcile}.rs`). Bonus: hardened the `reload_on_file_change_publishes_new_version` flake (FSEvents drops/latency-spikes on a loaded box — mutation-retry with generous budget; 3/3 full-workspace runs green, previously ~always 1 fail under load).
- Replace the 39 module-level `#![allow(dead_code)]` with per-item `#[allow]` or delete genuinely-unused paths (`ip_limiter.rs` IP-only variants superseded by `*_with_key`). Per-file allows mask real dead surface (e.g. the assessment's dead `behavior.rs`/`velocity.rs`).
- Sweep 41 `TODO/FIXME/XXX/HACK` before the next round; none should hide a broken branch.
- Add a module doc to `aegis-core/src/risk.rs` (98 LOC thin type module) pointing to where accumulation/decay/thresholds actually live (`state/{in_memory,reconcile}.rs`).
- **Fold the two doc-hygiene nits from the coverage assessment's *Corrections*:** fix the stale `// Enforce — 503` comment at `data_plane.rs:678` (the block is 403) and the stale `canary.rs:6` "score 90" (emits 100). ✅ **DONE 2026-07-03** (LT-P8 doc-nits PR) — both comments corrected; noted back on the ASSESSMENT. The rest of LT-P8 (dead-code allows, TODO sweep, `risk.rs` module doc) remains.
- **Style caution:** [[project_rustfmt_whole_crate_hazard]] — the repo is not rustfmt-clean; hand-match style, don't `cargo fmt` whole files you didn't author.

---

## Sequencing & ROI

| Order | Item | Effort | Payoff | Bucket |
|---|---|---|---|---|
| 1 | LT-P1 release profile (minus `panic=abort`) | S | High | Performance ✅ shipped |
| 2 | ~~LT-P4 hot-path panic/expect triage~~ | — | — | **SKIPPED** (gate removed) |
| 3 | ~~LT-P1b add `panic="abort"`~~ | — | — | **REJECTED** (abort defeats unwind isolation) |
| 4 | LT-P2 `RegexSet` single-pass | M | Med | Performance |
| 5 | LT-P5 decay-on-allow verify | M | High | Intelligence |
| 6 | LT-P3 per-IP default / ddos doc | S | Med | Security/Perf |
| 7 | LT-P7 trusted_proxies guard | S | High | Security/Contract |
| 8 | LT-P6 v2.6 CI gate | S | Med | Deployment |
| 9 | LT-P8 hygiene + doc nits | M | Low | Code Quality |

LT-P1 is the direct Performance-bucket win (LT-P2 rejected, measured slower). LT-P5 + LT-P7 protect points that are otherwise "held pending live verification." LT-P4/LT-P1b are rejected/skipped: `panic="abort"` is unsafe here (defeats per-connection unwind isolation → adversarial whole-process DoS), so its hot-path-triage gate has no purpose.

## Definition of done / archival

- Every Perf item records a before/after benchmark delta here; the release-profile PR must show the actual p99/throughput numbers.
- LT-P8 closes the two ASSESSMENT doc-hygiene nits (503 comment, canary 90/100) — note that back on the ASSESSMENT when done.
- When the committed set has merged, move this file to `plans/issues/archived/`; if the l-tester audit/scorecard docs are point-in-time snapshots, leave them in `tests/l-tester/` as historical record (don't archive the source reports — only this plan).
