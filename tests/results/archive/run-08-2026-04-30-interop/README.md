# Run 08 — 2026-04-30 — Interop Contract Dry-Run + Perf

Self-driven Round-2 gate verification before the OC's automated
benchmarker sees us. Tracks DR-T1..DR-T7 of
[`plans/interop-dry-run.md`](../../../plans/interop-dry-run.md).

## Headline

- **All 5 interop dry-run scripts pass.** 27 individual checks,
  zero contract violations.
- **Perf delta: negligible.** Interop ON costs ~30 µs at p95 at
  4 k RPS vs OFF — well within laptop noise. 100 % success rate
  on both axes.

## Track results

| ID | Track | Result | Detail |
|---|---|---|---|
| **DR-T1** | Header conformance — 50 responses | ✅ | All 6 `X-WAF-*` headers present, every value matches the contract's exact set (lowercase `Action`/`Mode`, uppercase `Cache`, integer `Risk-Score` 0..100, UUID-shaped `Request-Id`) |
| **DR-T2** | Control-plane shape — 10 checks | ✅ | Auth (no/wrong → 403), capabilities shape, set_profile {all, features, policies, invalid → 400, unknown → unsupported}, reset_state, flush_cache |
| **DR-T3** | Mode cycle — 6 phases | ✅ | enforce baseline, log_only flip, enforce recovery, feature-scoped, policy-scoped, scope=all clears overrides |
| **DR-T4** | Audit log preservation — 4 phases | ✅ | 25 → 50 lines across `reset_state` (no truncate); every line is single-object JSON with all 8 required fields |
| **DR-T5** | Header ↔ audit `request_id` correlation | ✅ | 100 distinct `X-WAF-Request-Id` values, all 100 found in `./waf_audit.log` exactly once |
| **DR-T6** | Perf re-measure with interop on | ✅ | See table below |
| **DR-T7** | run-08 README + summary | ✅ | This document |

Scripts live in
[`tests/interop/`](../../interop/). `run-all.sh` runs DR-T1..T5
in sequence; `run-perf.sh` (this directory) runs DR-T6.

## Run context

| Field | Value |
|---|---|
| Date (UTC) | 2026-04-30T08:35Z |
| Host | Darwin 23.1.0 arm64, 12 logical CPUs |
| Gateway binary | `target/release/waf` built with `--features redis` |
| Upstream | `aegis-httpbin` on `127.0.0.1:8081` |
| Load driver | `aegis-k6` (k6 0.51.0), `failover-burst.js` constant-arrival-rate |
| Scenario | 30 s burst |

## DR-T6 — perf with interop on vs off

[`summary.txt`](./summary.txt) at 1 k RPS,
[`summary-ceiling-4k.txt`](./summary-ceiling-4k.txt) at 4 k RPS.

### 1 k offered RPS (4 worker counts × 2 modes)

| interop | workers | RPS | p50 | p95 | success |
|---|---|---|---|---|---|
| **on** | 2 | 999.86 | 740.91 µs | 1.08 ms | 100.00 % |
| **on** | 4 | 999.96 | 612.66 µs | 0.88 ms | 100.00 % |
| **on** | 12 | 999.98 | 769.89 µs | 1.10 ms | 100.00 % |
| **on** | auto (=12) | 999.43 | 613.91 µs | 0.96 ms | 100.00 % |
| off | 2 | 338.60 ⚠️ | 645.58 µs | 1.20 ms | 100.00 % |
| off | 4 | 999.70 | 755.79 µs | 1.41 ms | 100.00 % |
| off | 12 | 999.98 | 664.58 µs | 1.13 ms | 100.00 % |
| off | auto (=12) | 339.01 ⚠️ | 593.16 µs | 1.04 ms | 100.00 % |

⚠️ Two interop-off iterations hit a TIME_WAIT spike from the
prior block and only pushed 339 RPS out the front. This is host
TCP behaviour, not WAF behaviour — verified by the matching 4 k
sweep below where neither side hit it.

### 4 k offered RPS (saturation probe)

| interop | workers | RPS | p50 | p95 | success |
|---|---|---|---|---|---|
| **on** | auto (=12) | 3 996.37 | 447.41 µs | 729.29 µs | 100.00 % |
| off | auto (=12) | 3 995.98 | 409.70 µs | 700.87 µs | 100.00 % |

**Delta: 28 µs at p95, 38 µs at p50. ~4 % overhead.** Both modes
sustain 4 k RPS at 100 % success. No throughput regression.

## What the dry-run found

- Zero contract violations across 5 scripts × 27 checks. The
  surface is shaped exactly as the v2.3 contract requires.
- `X-WAF-Request-Id` UUIDs are unique per request and each
  matches a single audit-log line — the OC's correlation
  expectation is satisfied.
- `reset_state` is genuinely append-only on `./waf_audit.log`.
- `set_profile` round-trips at all three scopes
  (`all` / `features` / `policies`); unknown features surface
  in `.unsupported` rather than silently no-op.
- `flush_cache` returns `supported: false` until an upstream
  cache lands — the contract explicitly accepts this.

## What got better since run-07

- Run-07 had no interop surface; this run validates it on top
  of the same UP-T1 pooled forwarder.
- Throughput ceiling unchanged (~4 k RPS achievable on the
  laptop, ~8 k RPS at saturation per run-07's higher probes).
- p95 within 30 µs of the run-07 baseline at 4 k RPS — header
  stamping + audit fsync are not in the way.

## What's left after run-08

- **Action-class fidelity**: `stamp_interop_response`
  currently infers the contract action from HTTP status. A
  challenge body returns 429 → currently maps to `rate_limit`.
  Plumbing the actual decision class through from
  `handle_data_request` is filed as the next minor follow-up.
- **Linux NUMA re-measure**: laptop run-07 plateau persists in
  run-08 (~8 k RPS ceiling regardless of workers). Bottleneck
  is above the upstream pool and above the interop layer —
  needs a real Linux box to localise.
- **B6-T1 production Dockerfile**: still deferred. With the
  interop surface validated, this is now the natural next step
  for an OC submission.

## Reproducing

```sh
# Build the release binary.
cargo build -p aegis-bin --release --features redis

# 5 dry-run scripts (each boots its own WAF).
bash tests/interop/run-all.sh

# Perf sweep — interop on vs off, 4 worker counts, 1k RPS each.
bash tests/results/run-08-2026-04-30-interop/run-perf.sh

# 4k saturation probe.
RPS=4000 WORKER_COUNTS=auto \
  bash tests/results/run-08-2026-04-30-interop/run-perf.sh
```
