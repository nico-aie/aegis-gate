# Plans

Living plans for **active** and **recently-shipped** tracks. Closed
reference-only plans live in [`archive/`](./archive/) — readable
but no longer guiding new work.

## Active

| Track | Plan | Status |
|---|---|---|
| **Hackathon Round-1 stress test** | [`hackathon-stress-test.md`](./hackathon-stress-test.md) | Harness + mock upstream + 15-min k6 mixed-traffic shipped. Awaiting benchmark team's source-IP fan-out + latency target. |
| **AI-assistant sweep tooling** | [`ai-assistant-testing-kickoff.md`](./ai-assistant-testing-kickoff.md) | Tooling shipped 2026-05-03 (`tests/sweeps/` + `make sweep-validate`). Awaiting sweep #1 schedule. |
| **Multi-node deployment** | [`multi-node-deployment/`](./multi-node-deployment/) | Proposal drafted 2026-05-08. Active-Active behind L4 LB + Redis cluster. Awaiting SA Team answers on machine count, network model, Redis availability. |
| **2026-05-07 QA fixes (tester-n)** | [`issue-fix/tester-n-2026-05-07/`](./issue-fix/tester-n-2026-05-07/) | C001+C002+H001+H002+H003 + M001+M002+M003+M004(read-only)+M005+M006+M007+M008 + L001-L004 shipped on `develop` 2026-05-08. Awaiting Test/UI re-check + M004 mutation backend follow-up + M009 operator action. |
| **2026-05-07 QA regression (tester-n rerun)** | [`issue-fix/tester-n-2026-05-07-regression/`](./issue-fix/tester-n-2026-05-07-regression/) | Run-2 closed 15/18 of Run-1 + opened 5 new findings (NEW-1..NEW-5). Plan drafted 2026-05-08. Phase 1 (NEW-1 + C002 follow-up) starts first; Phase 2 NEW-2 PoW challenge body is the largest item. |
| **2026-05-08 QA Run-3 (tester-n)** | [`issue-fix/tester-n-2026-05-08-run3/`](./issue-fix/tester-n-2026-05-08-run3/) | Run-3 closed all 5 Run-2 findings + opened 3 new (RUN3-NEW-1 HIGH bench-dev waf.yaml drift, RUN3-NEW-2 MEDIUM /__waf_control/healthz, RUN3-NEW-3 LOW SPA login redirect after reset_state). Plan drafted 2026-05-08. ~1.5h, 3 small PRs. |

## Recently shipped (kept for fix-lookup)

| Track | Plan | Notes |
|---|---|---|
| **AI detector** integration | [`ai-detector.md`](./ai-detector.md) · [per-detector doc](../docs/security/detectors/ai-detector.md) | **Shipped 2026-05-03** — T1..T9 all live. `ort` 2.0-rc.12, 26-feature extractor, binary attack/normal verdict. Treated like any other detector: `enabled`/`disabled` via the Detectors page (audit-mutated `PUT /api/ai/enabled`). Mean inference 694 µs, +1.1 ms p95 / +2.3 ms p99 chained behind regex (laptop hardware). Perf comparison + p99 vs 5 ms target: `tests/results/run-ai-compare-2026-05-03/REPORT.md`. Config simplified 2026-05-04 (dropped dead `mode`/`tiers`/`timeout`/`explain` knobs). |
| TCP CONNECT tunneling (Phase 4) | [`tcp-forwarder-phase-4.md`](./tcp-forwarder-phase-4.md) | TCP-T1..T6 shipped 2026-05-03. |
| Binary handover (fd-pass) | [`binary-handover-fd-pass.md`](./binary-handover-fd-pass.md) | FDP-T1..T6 library + accept-loop drain refactor shipped 2026-05-03. |
| WebSocket bridge | [`websocket-bridge.md`](./websocket-bridge.md) | WS-T1..T6 shipped 2026-05-03 (T5 e2e test, T6 metrics + Live-Feed pill). |

## Phase B production-packaging

[`phase-b/`](./phase-b/) — B1..B5 closed; B6-T1..T3 closed (Dockerfile +
Helm + CI v2.3 contract gate). **B6-T4** (HSM) deferred — no design
pass. **B6-T5** (binary handover) ✅ closed via FDP-T1..T6.

## Reference

- [`plan.md`](./plan.md) — AI assistant guide + protocol for this repo
- [`implementation-matrix.md`](./implementation-matrix.md) — doc-by-doc Implemented / Partial / Designed status

## Archive

[`archive/`](./archive/) — closed plans kept for history. Recent
archivals (2026-05-03):

- `benchmark-mode.md` (folded into B5-T2)
- `cluster-ingress-lb.md` (HA-T1..T5 shipped run-05)
- `console-api-integration.md` (CI-T1..T12 shipped)
- `console-config-pages.md` (CC-T\* shipped)
- `console-fixups.md` (CQF-T1..T16 shipped)
- `console-qa.md` (closed)
- `console-soc-refactor.md` (folded into the SOC-UX pass)
- `control.md` (M3 shipped)
- `dashboard-redesign.md` (DD-T0..T8 shipped)
- `dashboard-enterprise/` (D-M1..D-M6 superseded by DD-T\*)
- `followups-rollback-and-sans.md` (HACK-T4 + MTLS-T7 shipped)
- `hackathon-readiness.md` (HACK-T1..T5 + follow-ups shipped)
- `interop-contract.md` / `interop-dry-run.md` (IT-T + DR-T shipped)
- `mtls.md` (T1..T11 shipped)
- `post-k6-followup.md` (P1..P8 + F-T1..F-T10 shipped)
- `post-run-08.md` (AF-T1 / HP-T1 / TLS-T1 shipped)
- `proxy.md` (M1 shipped)
- `proxy-refactor.md` (PRE-T1..T8 shipped)
- `scaling-config.md` (SC-T1..T5 shipped)
- `security.md` (M2 shipped)

For a full implementation log of what's shipped where, see
[`../Implement-Progress.md`](../Implement-Progress.md).
