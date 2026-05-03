# Plans

Living plans for **active** and **recently-shipped** tracks. Closed
reference-only plans live in [`archive/`](./archive/) — readable
but no longer guiding new work.

## Active

| Track | Plan | Status |
|---|---|---|
| **Hackathon Round-1 stress test** | [`hackathon-stress-test.md`](./hackathon-stress-test.md) | Harness + mock upstream + 15-min k6 mixed-traffic shipped. Awaiting benchmark team's source-IP fan-out + latency target. |
| **AI-assistant sweep tooling** | [`ai-assistant-testing-kickoff.md`](./ai-assistant-testing-kickoff.md) | Tooling shipped 2026-05-03 (`tests/sweeps/` + `make sweep-validate`). Awaiting sweep #1 schedule. |

## Recently shipped (kept for fix-lookup)

| Track | Plan | Notes |
|---|---|---|
| **AI detector** integration | [`ai-detector.md`](./ai-detector.md) · [per-detector doc](../docs/security/detectors/ai-detector.md) | **Shipped 2026-05-03** — T1..T9 all live. `ort` 2.0-rc.12, 26-feature extractor, binary attack/normal verdict, hybrid `mode: observe \| enforce`. Mean inference 357 µs, +0.1 ms p95 chained behind regex. Perf comparison: `tests/perf/results/ai-compare-20260503T185335Z/REPORT.md`. |
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
