# Aegis-Gate — Code Audit Report

**Date:** 2026-07-02
**Auditor:** Automated code review (l-tester)
**Reference docs:** `Hackathon_Doc/EN_waf_interop_contract_v2.6.md`, `Hackathon_Doc/WAF_Hackathon_2026_offical_rules.pdf` (§5.3 detection coverage, §7 extended attack scenarios)
**Scope:** `crates/aegis-core`, `aegis-proxy`, `aegis-security`, `aegis-control`, `aegis-bin` (~170k LOC Rust)

---

## 1. Executive summary

The codebase is **strong and largely contract-compliant**. The v2.6 interop control plane, observability headers, audit-log semantics, IP-trust model, self-built rate-limiter and challenge engine are all implemented deliberately, with heavy inline reasoning that cites specific contract clauses and prior audit findings. Test coverage is exceptional (~3,900 test functions), and the hot path avoids panics (`unwrap`) almost entirely.

The gaps are not correctness holes in the contract surface; they are **performance tuning left on the table**, a few **default-config values that blunt built-in defenses**, and **verification/hygiene** items. None are disqualifying, but several map directly to scored criteria (Performance = 20 pts, Intelligence & Adaptiveness = 20 pts, Architecture & Code Quality = 15 pts).

| Area | Grade | Notes |
|---|---|---|
| Contract v2.6 compliance | A | Control plane, headers, audit log, decision classes all present & correct |
| Attack coverage (OWASP + company-specific) | A− | Full detector suite; verify per-test PASS thresholds under load |
| Code quality / idiomatic Rust | A− | Clean crate boundaries, `ArcSwap`/`DashMap`/`LazyLock`, `thiserror`; some `#![allow(dead_code)]` |
| Performance readiness | B | No release-profile tuning; per-detector regex iteration; loosened default limits |
| Operational hardening / graceful degradation | B+ | Fail-open/close + circuit breaker present; audit prod-path `panic!` sites worth review |
| Verification (build/clippy/test in this session) | Incomplete | Could not run `cargo` here; CI gates exist — see §7 |

---

## 2. Contract v2.6 compliance

Verified against the actual source, not just docs.

| Contract clause | Status | Evidence |
|---|---|---|
| §2.1 control endpoints (`capabilities`/`reset_state`/`set_profile`/`flush_cache`) | ✅ | `crates/aegis-control/src/interop/control.rs` |
| §2.2 `X-Benchmark-Secret`, 403 on miss/invalid | ✅ | `check_auth` + **constant-time** compare (`constant_time_eq`) — defeats timing side-channel |
| §2.4 `reset_state` synchronous, atomic, audit-log preserved | ✅ | `reset_state_async` runs sync chain then awaits async cleaners before returning; `audit_log_preserved: true` |
| §2.4 reset must NOT revert `set_profile`/config modes | ✅ | Only temporary trackers cleared; `ModeStore` untouched |
| §2.5 `set_profile` scope all/features/policies | ✅ | `validate_and_apply` |
| §2.5/§2.8 unsupported → **200 + `unsupported[]`**, not punitive 422 | ✅ | Unknown feature/policy pushed to `unsupported`, returns `Ok` (avoids run-abort) — see the explicit v2.6 comment at control.rs:605 |
| §2.5 tolerant reader (no `deny_unknown_fields`) | ✅ | Deliberate, documented at control.rs:92 to avoid stray-field 400s |
| §2.6 `flush_cache` returns 200 `supported:false` when no cache (never 404) | ✅ | `flush_cache()` |
| §5.1 required headers (`Request-Id`, `Risk-Score`, `Action`, `Rule-Id`, `Cache`, `Mode`) | ✅ | `interop/headers.rs`; `CacheState::{Hit,Miss,Bypass}` all emitted |
| §6 audit log = TCP peer IP (not XFF) | ✅ (default-safe) | `trusted_proxies` defaults empty ⇒ TCP peer always wins; XFF ignored |
| §10 IP trust model (XFF supplementary only) | ✅ | `ip_rep/xff::resolve_client_ip` walks XFF *only* when peer ∈ trusted CIDRs; `is_unsafe_trusted_proxy` guard flags loopback/private CIDRs as unsafe to trust |
| §4 self-built rate-limit + PoW challenge (no third-party) | ✅ | `rate_limit/ip_limiter.rs` (sliding-window log), `challenge/pow.rs` |

**Capabilities feature list** (`build_interop_runtime`) exposes `access_control`, `rules_engine` (16 detector policies incl. `graphql`, `canary`, `velocity`, `behavior_signals`), `rate_limit`, `risk_engine`, `ddos` — with hardcoded features reported per §2.5. This is comprehensive and honest.

**No benchmark hard-coding detected.** Greps for payload/IP/sequence special-casing surface only *comments explaining the absence* of hardcoding (e.g. proxy.rs:472, run.rs:2610). This matters — §11 and Rules §9 disqualify hard-coding.

---

## 3. Attack-scenario coverage (Rules §5.3 + §7 extended)

Detectors present under `crates/aegis-security/src/detectors/`:

- **OWASP Top 5:** `sqli` (classic/blind/time-based/UNION, regex `LazyLock` with documented FP fixes), `xss`, `path_traversal` (incl. `%2e%2e`), `ssrf` (internal ranges, metadata), `header_injection` (CRLF, Host, XFF spoof — 1,281 LOC, the largest).
- **Company-specific:** `brute_force`, `recon`, `body_abuse` (oversized/nested/content-type mismatch), `canary`/honeypot (→ risk MAX), `velocity_sequence` (Login→OTP→Deposit cross-endpoint), `behavior_signals` (zero-depth, timing, missing Referer), device fingerprinting (`fingerprint/ja3.rs`, `ja4.rs`, `h2.rs`, `device_ip_tracker.rs`).
- **Extended (§7):** DDoS L4/L7 (`ddos.rs` + per-IP limiter), relay/proxy (`ip_rep/asn.rs`, `xff.rs`), transaction fraud (`velocity_sequence`), recon/OPTIONS abuse (`recon.rs`).

Coverage is complete on paper. The residual risk is **per-test PASS thresholds** (contract §3.1 notes these are organizer-defined) and **behavior under concurrent load** — see §5.

---

## 4. What's good (keep doing this)

1. **Contract-anchored engineering.** Comments cite clause numbers and dated audit IDs (e.g. `F-CRITICAL-002`, `PROXY-05`, `P1-XFF`). This is unusually disciplined and makes the compliance story auditable.
2. **Security-correct primitives.** Constant-time secret compare; composite rate-limit/risk keying (`IP + device_fp + session`) so a NAT'd attacker can't 429 a co-located legit user; cardinality caps on both the risk tracker and limiter to survive unique-key floods.
3. **Idiomatic concurrency.** `ArcSwap` for lock-free hot-reload of limiter config, `DashMap` for per-shard locking, `parking_lot` try-lock amortized sweeps, `LazyLock` compiled regex. Hot path (`data_plane.rs`, `accept.rs`) has **zero `unwrap()`** before the test module.
4. **Clean architecture.** Strict crate layering — control plane injects reset callbacks into the data plane rather than upcalling (`no aegis-control → aegis-proxy` dependency). Audit sinks are pluggable (JSONL/CEF/LEEF/ECS/OCSF/Splunk/syslog/Kafka).
5. **Real CI gates.** `.github/workflows/ci.yml` runs `cargo fmt --check`, `cargo clippy --workspace -- -D warnings`, `cargo test --workspace` across feature matrices, plus a v2.3 contract compliance script.

---

## 5. Optimization opportunities

Ordered by expected impact on the Performance criterion (p99 ≤ 5 ms, ≥ 5,000 req/s, memory footprint).

### O-1 — No `[profile.release]` tuning *(high impact, low effort)*
`Cargo.toml` has **no `[profile.release]` section** — the binary ships with cargo defaults (`opt-level = 3`, `lto = false`, `codegen-units = 16`). For a latency-sensitive proxy this leaves measurable p99 and throughput on the table. Recommend:

```toml
[profile.release]
lto = "thin"          # or "fat" for max; measure both
codegen-units = 1
panic = "abort"       # smaller/faster; confirm no test relies on unwinding
strip = "debuginfo"
```

Validate against `deploy/STAGING-BENCHMARK.md` before/after. This is the single cheapest win for the 20-point Performance bucket.

### O-2 — Per-detector regex iteration on the hot path *(medium impact)*
`detectors/sqli.rs` (and peers) hold `LazyLock<Vec<Regex>>` and loop each pattern per request. Across ~16 detectors this is many independent scans of the same request bytes. A `regex::RegexSet` per detector matches all patterns in a **single pass** over the input, then only the surviving detector needs the specific-rule attribution pass. Expect a real CPU reduction on large bodies/query strings.

### O-3 — Loosened default per-IP limit blunts the built-in DDoS backstop *(medium impact / correctness-adjacent)*
`rate_limit/ip_limiter.rs`: `DEFAULT_LIMIT = 1_000_000` per 60 s. The comment explains it's a "backstop, not a throughput cap," but at 1M/min the local per-IP volumetric gate effectively **never fires** unless an operator explicitly configures buckets. Under the §7 "DDoS aimed at the WAF" scenario (Graceful Degradation, scored), a single flooding source won't be locally throttled by this gate. Recommend a saner default (e.g. a few thousand/min) *or* confirm `ddos.rs` fully covers the volumetric case and document the division of labor.

### O-4 — `#![allow(dead_code)]` at module scope hides unused surface *(low impact / hygiene)*
`ip_limiter.rs` opens with `#![allow(dead_code)]`. 52 such allows exist workspace-wide. Module-level allows suppress clippy's dead-code signal for the *whole* file, which can mask genuinely unused methods (`consume`, `reset`, `config` here appear to have IP-only variants that may be superseded by the `*_with_key` forms). Prefer per-item `#[allow]` or delete the unused paths.

---

## 6. Improvement areas (weak / unfinished)

Severity: 🔴 verify before Attack Battle · 🟡 quality · 🟢 nice-to-have.

### I-1 🟡 Production-path `panic!` / `expect` under load
Workspace totals: **182 `panic!`, 495 `.expect(`, 3,779 `.unwrap()`** (the large majority in `#[cfg(test)]` — ~3,906 test fns exist). The hot files are clean, but a lock `poisoned` `expect` in the control plane (`reset_callbacks.lock().expect(...)`) will abort the thread if a callback ever panics while holding the lock. Given §5.8 mandates graceful degradation, audit non-test `panic!`/`expect` on request-handling paths and convert to `fail_open`/`fail_close` per route tier. Action: `rg 'panic!|\.expect\(' crates/*/src` filtered to non-test modules, triage each.

### I-2 🔴 Audit-log IP semantics when a trusted proxy IS configured
Default is safe (empty `trusted_proxies`). **But** `with_proxy_via` intentionally makes the audit `ip` the *asserted client* (not TCP peer) when a trusted PROXY-protocol/XFF hop is present. Contract §6 says `ip` MUST be the TCP peer. In the benchmark sandbox (loopback, no trusted proxy) this is fine. **Verify the config used for judging has `trusted_proxies: []` and does not include `127.0.0.0/8`** — otherwise §6 correlation and the XFF-spoofing test family break. The `is_unsafe_trusted_proxy` guard exists; confirm it's enforced (reject/warn) at config load, not just available.

### I-3 🟡 Risk decay correctness (Rules §5.5)
Decay is configured (`decay_half_life`, default 5 min; `reconcile.rs` notes risk is "monotonically increasing in practice, decay via separate `add_risk(_, -decay)`"). Rules §5.5 requires score to **decrease on sustained normal behavior**. Confirm the decay path actually runs on the allow path (not only on explicit reset) and that `X-WAF-Risk-Score` on *allowed* responses reflects decay — the benchmarker validates accumulation *and* decay on allowed responses (§5.3 of the benchmark spec).

### I-4 🟢 TODO/FIXME backlog
41 `TODO|FIXME|XXX|HACK` markers remain. None are on the critical control path from the sample, but sweep them before Round 3 so none hide a known-broken branch under live attack.

### I-5 🟢 Core `risk.rs` is a thin type module (98 LOC)
The actual risk engine lives in `aegis-proxy/src/state/{in_memory,reconcile}.rs`. That's a reasonable split, but the Architecture score rewards discoverability — a short module doc in `aegis-core/src/risk.rs` pointing to where accumulation/decay/thresholds are implemented would help reviewers (and judges reading the code).

---

## 7. Verification gaps (do these before judging)

I could not execute `cargo` in this session, so the following are **recommended checks**, not confirmed results:

1. `cargo build --release -p aegis-bin --features "redis alerts geoip"` — confirm the judged binary builds clean.
2. `cargo clippy --workspace -- -D warnings` — CI runs it; run locally after any change from §5/§6.
3. `cargo test --workspace` — ~3,900 tests; confirm green.
4. `tests/contract/` scripts — run the v2.6 compliance suite (only a v2.3 script is wired into CI at `ci.yml:237`; **add a v2.6 compliance gate** if one isn't present).
5. Load test per `deploy/STAGING-BENCHMARK.md` **before and after O-1** to quantify the release-profile win.

---

## 8. Prioritized action list

| # | Action | Effort | Payoff | Criterion |
|---|---|---|---|---|
| 1 | Add `[profile.release]` (lto/codegen-units/panic=abort), re-benchmark | S | High | Performance |
| 2 | Confirm judged config `trusted_proxies: []`; enforce `is_unsafe_trusted_proxy` at load | S | High | Security/Contract §6 |
| 3 | Verify risk **decay** shows on allowed-response `X-WAF-Risk-Score` | M | High | Intelligence |
| 4 | Set a realistic `DEFAULT_LIMIT` or document ddos.rs coverage of volumetric floods | S | Med | Intelligence/Perf |
| 5 | Switch per-detector `Vec<Regex>` → `RegexSet` single-pass | M | Med | Performance |
| 6 | Add a v2.6 contract-compliance CI gate | S | Med | Deployment |
| 7 | Triage non-test `panic!`/`expect` on request paths | M | Med | Code Quality/Degradation |
| 8 | Replace module-level `#![allow(dead_code)]`; clear TODOs | M | Low | Code Quality |

---

*Report generated by l-tester audit pass. Findings are grounded in source reads of the crates listed in §Scope; items in §7 remain unverified pending a local `cargo` run.*
