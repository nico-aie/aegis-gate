# Benchmark Mode — Task Plan

> **Status:** Folded — Benchmark mode (B-T1..B-T6) folded into Phase B as **B5-T2** — see [`phase-b/README.md`](./phase-b/README.md#b5--protocols--benchmark).
>
> See [`README.md`](./README.md) for the track status board.

> **Read first:**
> 1. [`../Requirement.md`](../Requirement.md) §3 (perf targets), §34
>    (benchmark mode)
> 2. [`../Architecture.md`](../Architecture.md) §5 (pipeline), §28.5
>    (benchmark mode)
> 3. [`../docs/operator/benchmark-mode.md`](../docs/operator/benchmark-mode.md) — design spec
> 4. [`./plan.md`](./plan.md) — assistant guide
> 5. The cross-crate types referenced below live in `aegis-core`
>    (`config::benchmark`, `types::benchmark`); see B-T1.x.

> **Parallelism.** This track is parallel to the dashboard track (D-).
> B-T1..B-T3 (data-plane work) is unblocked. B-T4 (dashboard panels)
> is gated on D-M3+ landing the chrome and chart components it builds
> on.

## Mission

Ship a gated, opt-in benchmark mode that exposes per-request WAF
diagnostics on response headers, the dashboard, and Prometheus —
without touching production hot-path performance when off.

## Crate scope

- **In scope:** `aegis-core` (config + types), `aegis-proxy` (gate
  + header injection + TTL), `aegis-security` (per-detector timing),
  `aegis-control` (API + dashboard + metrics), `aegis-bin` (CLI).
- **Out of scope:** Per-route mode, trace export, cluster aggregation
  (deferred — see design spec).

## Constraints

- **No new top-level deps.** `blake3` (HMAC), `hmac`, `tokio`,
  `serde`, `prometheus`, `chrono` are already on the workspace.
- **Zero overhead when `mode: disabled`.** Verified by a criterion
  bench gate (B-T6.4): same workload with feature on but mode
  disabled must be within 1 % of the no-benchmark baseline.
- **Headers stay ≤ 1024 bytes.** Truncation rule per design spec.
- **All changes additive.** Existing endpoints, headers, audit chain
  format, config schema all stay backward-compatible. The new
  `benchmark:` config block is optional (`serde(default)`).
- **Audit-first.** Every state change (enable / disable / auto-disable
  / gate failure) produces an audit entry. No silent toggles.

## Task IDs

This track uses the prefix `B-` (Benchmark) so its IDs never collide
with the original `M{n}-T{x}.{y}` (proxy/security/control) or the
dashboard's `D-M{n}-T{x}.{y}`.

## Sub-tracks

### B-T1 — `aegis-core` foundation

| ID | File | Outcome |
|----|------|---------|
| B-T1.1 | `crates/aegis-core/src/config/benchmark.rs` | `BenchmarkConfig` struct, `Mode` enum, validation (TTL ≤ max_ttl, allowlist non-empty when on, etc.). `serde(default)` so existing configs keep working. |
| B-T1.2 | `crates/aegis-core/src/types/benchmark.rs` | `BenchmarkContext`, `StageSample`, `DetectorSample`, stage / detector name enums. |
| B-T1.3 | `crates/aegis-core/src/config/mod.rs` | Wire `benchmark: BenchmarkConfig` into top-level `Config`; load + validate path. |
| B-T1.4 | `crates/aegis-core/tests/benchmark_config.rs` | Snapshot tests for config validation: rejects TTL > max_ttl, rejects empty allowlist when on, accepts `0.0.0.0/0` with WARN, rejects `expose_rule_ids: true` in `headers` mode. |

### B-T2 — `aegis-proxy` data-plane integration

| ID | File | Outcome |
|----|------|---------|
| B-T2.1 | `crates/aegis-proxy/src/benchmark/gate.rs` | IP allowlist + token-HMAC verification. Token format = `hex(hmac(secret, ts \| method \| path))`. ≤60 s skew. |
| B-T2.2 | `crates/aegis-proxy/src/benchmark/state.rs` | Runtime state (active_mode, enabled_at, ttl, expose_rule_ids) behind `ArcSwap`. Auto-disable tokio task with cancellation on re-enable. |
| B-T2.3 | `crates/aegis-proxy/src/benchmark/headers.rs` | Header serialiser (`X-Aegis-Tier`, `Decision`, `Overhead-Us`, `Upstream-Us`, `Detectors`, `Pipeline`, `Rules`, `Build`); 1024-byte truncation; ASCII-only. |
| B-T2.4 | `crates/aegis-proxy/src/proxy.rs` (modify) | Wire `BenchmarkContext` into request lifecycle (allocate iff gated; pass to security pipeline; call header serialiser before response write). |
| B-T2.5 | `crates/aegis-proxy/src/proxy.rs` (modify) | Always emit `X-Aegis-Request-Id` (independent of benchmark mode). |
| B-T2.6 | `crates/aegis-proxy/tests/benchmark_gate.rs` | Headers emitted iff gated; rule ids suppressed by default; rate-limited gate-failure audit entry on bad token. |
| B-T2.7 | `crates/aegis-proxy/benches/benchmark_overhead.rs` | Criterion bench: `mode: disabled` vs baseline must be ≤ 1 %. |

### B-T3 — `aegis-security` per-detector timing

| ID | File | Outcome |
|----|------|---------|
| B-T3.1 | `crates/aegis-security/src/pipeline.rs` (modify) | Pipeline accepts `Option<&BenchmarkContext>` and passes it down. |
| B-T3.2 | Each detector (`sqli.rs`, `xss.rs`, `path_traversal.rs`, `ssrf.rs`, `header_inj.rs`, `body_abuse.rs`, `recon.rs`, `bots.rs`, `dlp_in.rs`, `dlp_out.rs`, `api_guard.rs`, `risk.rs`, `challenge.rs`, `rate.rs`) | Wrap entry/exit with `bench.detector(name, started)` helper. Naming registry is the canonical source for `X-Aegis-Detectors` values. |
| B-T3.3 | `crates/aegis-security/tests/benchmark_samples.rs` | Run detectors with a `BenchmarkContext`, assert all expected names appear with non-zero `us`. |

### B-T4 — `aegis-control` API + dashboard + metrics

> **Gate.** Tasks B-T4.5..B-T4.7 are blocked on D-M3 (chart + table
> components). B-T4.1..B-T4.4 are unblocked.

| ID | File | Outcome |
|----|------|---------|
| B-T4.1 | `crates/aegis-control/src/api/benchmark.rs` | `GET /api/benchmark/status`, `POST /api/benchmark/enable`, `POST /api/benchmark/disable`, `GET /api/benchmark/snapshot`. Mutating routes require admin session + CSRF. |
| B-T4.2 | `crates/aegis-control/src/api/about.rs` (modify) | `/api/about` now reports `benchmark.configured_mode` so the dashboard knows whether to render the panel. |
| B-T4.3 | `crates/aegis-control/src/metrics/benchmark.rs` | Register `waf_bench_overhead_seconds_bucket{tier,decision}`, `waf_bench_detector_cost_seconds_bucket{detector}`, `waf_bench_mode` gauge. Populate from `BenchmarkContext` finaliser. |
| B-T4.4 | `crates/aegis-control/src/audit/admin.rs` (modify) | Emit `bench_enable` / `bench_disable` / `bench_auto_disable` / `bench_gate_failed` audit entries. |
| B-T4.5 | `crates/aegis-control/assets/dashboard/pages/tracking.js` (modify under D-M5) | Render Benchmark panel: state, TTL countdown, enable/disable buttons, inline 60 s overhead histogram. Hidden when `/api/about` reports `null`. |
| B-T4.6 | `crates/aegis-control/assets/dashboard/pages/analytics.js` (modify under D-M3) | Add Benchmarks subpage: p50/p95/p99 by tier, per-detector heatmap, top-N rules (when allowed), overhead-vs-RPS dual axis. |
| B-T4.7 | `crates/aegis-control/tests/dashboard/benchmark_panel.rs` | Integration test: enable via API, assert /api/about flips, /api/benchmark/snapshot returns shape. |

### B-T5 — `aegis-bin` CLI

| ID | File | Outcome |
|----|------|---------|
| B-T5.1 | `crates/aegis-bin/src/cmd/bench.rs` | `waf bench enable [--ttl] [--mode]`, `waf bench disable`, `waf bench status`. Calls the admin API over the local control-plane socket; reuses existing admin token loader. |
| B-T5.2 | `crates/aegis-bin/tests/bench_cli.rs` | Invoke the subcommand against a temp control plane; assert state transitions. |

### B-T6 — Cross-cutting

| ID | File | Outcome |
|----|------|---------|
| B-T6.1 | `config/waf.yaml` (modify) | Add commented `benchmark:` block (mode disabled). |
| B-T6.2 | `config/README.md` (modify) | Document the new section. |
| B-T6.3 | `tests/load/bench-headers.js` | k6 script reading `X-Aegis-Overhead-Us`, producing CSV for the SLO harness. |
| B-T6.4 | CI gate | Run B-T2.7 criterion bench in CI nightly; fail if regression > 1 %. |
| B-T6.5 | `docs/operator/usage.md` (modify) | "Benchmarking your WAF" section with a copy-paste recipe (enable, run k6, read CSV, disable). |
| B-T6.6 | `Implement-Progress.md` | Track entries per §0.3 protocol after each task. |

## Definition of Done

- `cargo test --workspace` green; ≥ 30 new tests landed across the
  five crates.
- `cargo clippy --workspace -- -D warnings` clean.
- B-T2.7 criterion bench shows mode-disabled overhead ≤ 1 % of baseline.
- A reference k6 run with mode `headers` produces a CSV that matches
  the Prometheus `waf_bench_overhead_seconds` series within 5 %
  (sanity check that headers and metrics agree).
- `docs/operator/benchmark-mode.md` and `plans/benchmark-mode.md` cross-link
  from `docs/README.md`, `Architecture.md`, `Requirement.md`,
  `plans/plan.md`, and `Implement-Progress.md`.
- A live demo on the dashboard: toggle benchmark mode, watch the
  Tracking panel and Analytics page populate, disable, watch them
  empty.

## Sequence

```
B-T1.1 → B-T1.2 → B-T1.3 ─┬─ B-T2.1 ─ B-T2.2 ─ B-T2.3 ─ B-T2.4 ─ B-T2.5 ─ B-T2.6 ─ B-T2.7
                          │
                          ├─ B-T3.1 ─ B-T3.2 ─ B-T3.3
                          │
                          └─ B-T4.1 ─ B-T4.2 ─ B-T4.3 ─ B-T4.4 ─ [D-M3] ─ B-T4.5/6 ─ B-T4.7
                                                       │
                                                       └─ B-T5.1 ─ B-T5.2

B-T6.1 / B-T6.2 land alongside B-T1.3.
B-T6.3 / B-T6.4 land alongside B-T2.7.
B-T6.5 / B-T6.6 close the track.
```

## Cross-references

- Design spec — [`../docs/operator/benchmark-mode.md`](../docs/operator/benchmark-mode.md)
- Performance target — [`../Requirement.md`](../Requirement.md) §3
- Pipeline — [`../Architecture.md`](../Architecture.md) §5
- API — [`../docs/control-plane/enterprise/api.md`](../docs/control-plane/enterprise/api.md)
  §benchmark
- Dashboard panels —
  [`../docs/control-plane/enterprise/pages/tracking.md`](../docs/control-plane/enterprise/pages/tracking.md)
  and
  [`../docs/control-plane/enterprise/pages/analytics.md`](../docs/control-plane/enterprise/pages/analytics.md)
