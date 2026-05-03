# Interop Contract — Self-Driven Dry-Run

> **Status:** Closed — DR-T1..T7 shipped in run-08 (27/27 contract
> checks green, ~30 µs p95 overhead at 4 k RPS, 100 % success in
> both modes). Reference only. See [`README.md`](./README.md).

Round-2 gate verification before the OC's automated benchmarker
sees us. The goal is to catch contract-shape bugs (wrong header
case, wrong JSON field, premature `reset_state` success, etc.)
under our own control rather than burning a real benchmark slot.

## Tracks

| ID | Track | Effort | What it proves |
|---|---|---|---|
| **DR-T1** | Header conformance script | 30 min | Every response has all 6 `X-WAF-*` headers with values from the spec's exact value sets |
| **DR-T2** | Control-plane shape script | 30 min | All four `/__waf_control/*` endpoints reply with the contract JSON shape; auth is enforced |
| **DR-T3** | Mode-cycle behaviour test | 1 hr | `enforce` blocks malicious input, `log_only` lets it through with headers/audit, switching back restores enforcement |
| **DR-T4** | `reset_state` audit preservation | 30 min | `./waf_audit.log` line count strictly increases through reset |
| **DR-T5** | Audit ↔ header request_id correlation | 30 min | Every `X-WAF-Request-Id` from a sample of 1k responses matches a unique audit line |
| **DR-T6** | Perf re-measure with interop on | 1 hr | UP-T1's 7 964 RPS / sub-1 ms p95 holds with header stamping + audit write in the hot path |
| **DR-T7** | run-08 README + summary | 30 min | Per-track pass/fail + perf delta table vs run-07 |

**Total: ~4.5 hr.** Outputs land in
[`tests/interop/`](../tests/interop/) (the scripts) and
[`tests/results/run-08-2026-04-30-interop/`](../tests/results/run-08-2026-04-30-interop/)
(the proof).

## Risks

| Severity | Risk | Mitigation |
|---|---|---|
| HIGH | DR-T6 shows a regression vs run-07 (audit fsync on hot path) | If > 10 % slowdown, switch the sink to a `BufWriter` + periodic flush; defer to follow-up |
| MEDIUM | The action-class inference (HTTP status → `Action`) maps the challenge body to `rate_limit` | Already filed as smaller follow-up #4. DR-T3 will surface it; record but don't block |
| LOW | Loopback aliases on macOS need explicit `lo0` setup for distinct-IP tests | Skip the multi-IP tests on macOS; document |

## Done

- All 7 tracks green.
- `Implement-Progress.md` Last Completed updated.
- `plans/interop-contract.md` compliance table cross-references DR-T results.
