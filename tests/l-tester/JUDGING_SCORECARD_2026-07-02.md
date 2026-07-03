# WAF Mini Hackathon 2026 — Judging Scorecard

**Team / Project:** Aegis-Gate
**Judge:** Organizing Committee (simulated)
**Date:** 2026-07-02
**Rubric:** `WAF_Hackathon_2026_offical_rules.pdf` §6 — Total 120 points
**Basis:** Static evaluation of the submitted source (~170k LOC Rust) + interop contract v2.6 compliance review.

> ⚠️ **Scoring basis & honesty note.** This scorecard is a **code-grounded projection**, not the result of the live Attack Battle (Round 3) or the automated benchmark (Round 2 Phase 1). Two buckets — **Security Effectiveness** and **Performance** — are ultimately decided by measured detect-rate / false-positive-rate and measured p99/throughput, which cannot be produced from a code read. Those scores below are *projected ranges* with the assumptions stated. Numbers may move up or down once the harness runs.

---

## Final score

# **103 / 120  (85.8%)  — Grade A−**

| # | Criterion | Weight | Awarded | % |
|---|---|---:|---:|---:|
| 1 | Security Effectiveness | 40 | **35** | 87% |
| 2 | Performance | 20 | **15** | 75% |
| 3 | Intelligence & Adaptiveness | 20 | **17** | 85% |
| 4 | Architecture & Code Quality | 15 | **14** | 93% |
| 5 | Extensibility | 10 | **9** | 90% |
| 6 | Dashboard UI/UX & Realtime Config | 10 | **8** | 80% |
| 7 | Deployment & Operability | 5 | **5** | 100% |
| | **Total** | **120** | **103** | **85.8%** |

---

## 1. Security Effectiveness — 35 / 40

**What earns the points.** Coverage is complete against Rules §5.3 (OWASP Top 5 minimum) and extends well past it:

- OWASP: `sqli` (classic/blind/time-based/UNION, regex with deliberate FP-reduction), `xss`, `path_traversal` (incl. `%2e%2e`), `ssrf` (internal ranges + metadata), `header_injection` (CRLF / Host / XFF spoof).
- Company-specific: device fingerprinting (`ja3`/`ja4`/`h2`/`device_ip_tracker`), `behavior_signals` (zero-depth, timing, missing Referer), `velocity_sequence` (Login→OTP→Deposit), `canary`/honeypot (→ risk MAX), `brute_force`, `recon`, `body_abuse`.
- Self-built (no third-party, per §4): sliding-window rate limiter + PoW challenge.
- Contract-critical correctness: constant-time secret compare; **composite risk/rate keying (IP + device_fp + session)** so a NAT'd attacker can't collaterally 429 a co-located user; XFF trusted only when peer ∈ configured trusted CIDRs.

**Deductions (−5).**
- Detect-rate / FP-rate against the live Red Team is unproven here; §6 explicitly weights this bucket on measured battle performance. Holding back points pending Round 3.
- Default `DEFAULT_LIMIT = 1_000_000/60s` means the local per-IP volumetric gate effectively won't fire on an L7 flood unless buckets are configured — a risk under the §7 "DDoS aimed at the WAF" scenario. Confirm `ddos.rs` covers the volumetric case.
- Per-test PASS thresholds (risk-score gating) are organizer-defined; a couple of "allow + elevated risk" categories depend on decay/accumulation behaving exactly to §5.5.

## 2. Performance — 15 / 20 *(provisional — not benchmarked)*

**What earns the points.** Performance-conscious hot path: **zero `unwrap()`** in `data_plane.rs` / `accept.rs` before test modules, `ArcSwap` for lock-free config hot-swap, `DashMap` per-shard locking, `LazyLock` precompiled regex, amortized try-lock sweeps, cardinality caps to stay bounded under unique-key floods.

**Deductions (−5).**
- **No `[profile.release]` tuning** in `Cargo.toml` — ships with cargo defaults (no LTO, `codegen-units=16`). This directly costs p99 and throughput for free. (See audit O-1.)
- Each of ~16 detectors iterates its own `Vec<Regex>` per request; a `RegexSet` single-pass would cut hot-path CPU.
- p99 ≤ 5 ms and ≥ 5,000 req/s are **not measured** in this evaluation. If the staging benchmark (`deploy/STAGING-BENCHMARK.md`) already meets targets, this rises toward 18.

## 3. Intelligence & Adaptiveness — 17 / 20

**What earns the points.** Risk score accumulates per {IP + device + session} (confirmed composite key), `velocity_sequence` handles cross-endpoint fraud (deposit-after-login, withdrawal-after-deposit), decay is configured (`decay_half_life`, default 5 min), and graceful degradation is real: fail-open/fail-close **per route tier** plus an upstream circuit breaker (`api/upstreams.rs`). This maps cleanly to the §5.5 / §5.8 requirements.

**Deductions (−3).**
- Decay is described as "monotonic in practice, decreased via separate `add_risk(_, -decay)`." Need to confirm decay actually reflects on the `X-WAF-Risk-Score` of **allowed** responses (the benchmarker validates accumulation *and* decay on allow).
- Fail-open/close tiering is present but its correctness "per endpoint" is the kind of thing the OC verifies live.

## 4. Architecture & Code Quality — 14 / 15

**What earns the points.** This is the strongest bucket. Clean crate layering (`core` / `proxy` / `security` / `control` / `bin`) with the control plane injecting reset callbacks into the data plane rather than upcalling. Idiomatic throughout (`thiserror`, `ArcSwap`, `DashMap`, `LazyLock`). ~3,900 test functions, many encoding contract clauses and regression IDs. CI (`ci.yml`) gates on `cargo fmt --check`, `cargo clippy --workspace -- -D warnings`, and `cargo test` across a feature matrix. Comments cite exact contract §§ and dated audit findings — unusually auditable.

**Deductions (−1).**
- 52 module-level `#![allow(dead_code)]` can mask unused surface; 41 `TODO/FIXME`; 182 non-test `panic!` + 495 `expect` to triage on request paths for graceful degradation. Documentation is heavy but `aegis-core/risk.rs` (98 LOC) under-signposts where the real risk engine lives.

## 5. Extensibility — 9 / 10

**What earns the points.** Hot-reload without rebuild via **three** sources (file-watcher, etcd, Redis config-plane) sharing one `config_source/reload.rs` path, with atomic detector-mask re-derivation and a compliance clamp. Rule system supports per-scope (IP/user/session/device/tier/route) and priority resolution. Plugin-ready: pluggable audit sinks (JSONL/CEF/LEEF/ECS/OCSF/Splunk/syslog/Kafka), toggleable detectors, configurable response filter (`scrub_stack_traces`, `redact_dlp`).

**Deductions (−1).** Rule add/edit/delete is exercised through the team's own admin surface (per contract §2.6b, that's allowed) — the breadth is excellent, but a single documented end-to-end "add a rule live, see it fire" walkthrough would close the last point.

## 6. Dashboard UI/UX & Realtime Config — 8 / 10

**What earns the points.** A real React SPA (`assets/dashboard`, ~1,650 LOC jsx + i18n) with live request feed (SSE), attack visualization, hot config (toggle action / threshold without restart), and an audit-log viewer — matching §5.6. Structured JSONL audit log with the required fields plus rich extras.

**Deductions (−2).** The Dashboard is judged **live, under load** during Round 3 (§11b makes OC monitoring mandatory). Runtime smoothness, accuracy-under-attack, and UX polish can't be confirmed from source. Points held pending live view.

## 7. Deployment & Operability — 5 / 5

**What earns the points.** Single binary, one-command startup (`./waf run`, binary + `waf.yaml` in cwd per §8), Docker + Compose + Helm deploy paths, upstream circuit breaker, and documented fail behavior. QUICKSTART wires the OC-harness handoff. Fully meets the §6 5-point bar.

---

## How to move the score up (highest ROI first)

1. **+2–3 Performance:** add `[profile.release]` (`lto="thin"`, `codegen-units=1`, `panic="abort"`, `strip`), re-run the staging benchmark. Cheapest points on the board.
2. **+2–3 Security:** set a realistic default per-IP limit (or prove `ddos.rs` covers volumetric floods); confirm no benchmark config trusts loopback in `trusted_proxies` (protects §6 + XFF-spoof tests).
3. **+1–2 Intelligence:** demonstrate risk **decay** on allowed-response `X-WAF-Risk-Score` over a quiet window.
4. **+1 Architecture:** triage non-test `panic!`/`expect` on request paths; clear TODOs; drop module-wide `allow(dead_code)`.
5. **Lock in Dashboard/Security live points:** rehearse the Attack Battle so the Dashboard stays smooth under load and detect-rate holds.

**Projected ceiling if items 1–4 land and the live battle matches the code quality: ~110–113 / 120.**

---

*Simulated OC scorecard. Buckets 1, 2, and 6 are inherently live-measured; values here are code-based projections with assumptions stated inline. Not an official result.*
