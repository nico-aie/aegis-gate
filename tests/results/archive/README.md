# `tests/results/archive/` — historical run timeline

These runs are kept for historical context. None of them are
referenced as a current baseline — go to
[`../README.md`](../README.md) for those. Use this directory
when you need to answer "when did HA cluster perf land" or
"what did the v2 of the 15-min run look like before the
detector-coverage sprint".

Newest at the top.

| # | Dir | Date | Focus |
|---|---|---|---|
| sweep | `run-soc-sweep-202605030550/` | 2026-05-03 | Earlier SOC-walkthrough sweep, superseded by 0612 |
| sweep | `run-soc-sweep-202605030539/` | 2026-05-03 | Earlier SOC-walkthrough sweep, superseded by 0612 |
| sweep | `run-soc-sweep-202605022020/` | 2026-05-02 | First-day SOC sweep, post DD-T8 |
| sweep | `run-soc-sweep-202605022017/` | 2026-05-02 | First-day SOC sweep |
| sweep | `run-profile-sweep-20260502/` | 2026-05-02 | Profile decision-tree sweep (balanced / strict / throughput) |
| perf | `run-perf-5krps-prod-balanced-2026-05-02-v2/` | 2026-05-02 | 5 k RPS perf v2 — superseded by v3 (current baseline) |
| perf | `run-perf-5krps-prod-balanced-2026-05-02-v1/` | 2026-05-02 | First 5 k RPS attempt; surfaced 7 improvements |
| perf | `run-perf-15min-2026-05-02/` | 2026-05-02 | 15-min mixed-traffic v1 — 33 % detection (pre detector-coverage sprint) |
| cqa | `run-cqa-round2-20260502/` | 2026-05-02 | Console QA round 2 — superseded by round 3 |
| cqa | `run-cqa-20260502-api/` | 2026-05-02 | API-only Console QA pass |
| cqa | `run-cqa-20260502/` | 2026-05-02 | Initial Console QA round |
| 17 | `run-17-2026-05-02-hackt5/` | 2026-05-02 | HACK-T5 — Tier B + C bonuses |
| 16 | `run-16-2026-05-01-hackt4/` | 2026-05-01 | HACK-T4 — rollback for mode changes |
| 15 | `run-15-2026-05-01-hackt2-t3/` | 2026-05-01 | HACK-T2/T3 — observability pass + rule simulator |
| 14 | `run-14-2026-05-01-hackt1/` | 2026-05-01 | HACK-T1 — closed mock-data risk; aggregator endpoints landed |
| 13 | `run-13-2026-05-01-sct1-sct2/` | 2026-05-01 | SC-T1 + SC-T2 — Scaling page (L1 + L2 + L3) |
| 12 | `run-12-2026-05-01-mtls-pre-refactor/` | 2026-05-01 | mTLS pre-proxy-refactor smoke |
| 11 | `run-11-2026-04-30-control-panel-acceptance/` | 2026-04-30 | Full control-panel acceptance — 22/22 endpoints, 25/25 OpenAPI, 8/8 contract |
| 10 | `run-10-2026-04-30-dashboard-redesign/` | 2026-04-30 | Dashboard redesign DD-T0..T7 — Aegis WAF Console pre-compiled SPA |
| 9 | `run-09-2026-04-30-tls-recheck/` | 2026-04-30 | TLS-T1 clean-host re-measure (closes run-05 carry-over) |
| 8 | `run-08-2026-04-30-interop/` | 2026-04-30 | Interop contract self-driven dry-run — 27/27 contract checks |
| 7 | `run-07-2026-04-30-upstream-pool/` | 2026-04-30 | UP-T1 pooled keep-alive — 525 → 7 964 RPS (15×) |
| 6 | `run-06-2026-04-30-workers-perf/` | 2026-04-30 | Single-node sweep across `runtime.workers` ∈ {2, 4, 8, 12, auto} |
| 5 | `run-05-2026-04-30-ha-implementation/` | 2026-04-30 | HA-T1..T5 — HAProxy + 9.5 k RPS via VIP, 99.93 % failover |
| 4 | `run-04-2026-04-29-cluster-https/` | 2026-04-29 | Cluster smoke + HTTPS data-plane — 31.7 k RPS plain, 31.8 k RPS over TLS |
| 3 | `run-03-2026-04-29-carryovers/` | 2026-04-29 | Carry-over A + B closures + first cluster smoke |
| 2 | `run-02-2026-04-29-phase-b/` | 2026-04-29 | First whole-system run after Phase B B3 + B4 + B5 closed |
| 1 | `run-01-2026-04-28-baseline/` | 2026-04-28 | Baseline after F-T1..F-T10 + dashboard track |
