# PLAN — Validation under realistic operating conditions

> **Type:** PLAN (committee round-2 🟡5) · **Status:** ☐ Not started — planned 2026-07-04
> **Track ID prefix:** `OV-<1–3>` · Deliverable is **evidence** (runbook + drill transcripts),
> not features. Schedule before round 3.

**Objective (intent, not letter):** prove the system holds up outside isolated functional tests —
production-like load, real admin workflows, and failure/recovery — with reproducible drill scripts
and captured evidence.

---

## 1. Known debt this plan pays down

- **SLO/alerting manual smoke was never run** — the enforcement-excluded path has never been
  exercised end-to-end; first real attack wave would be the first test. This is the single most
  important drill.
- Watcher/deploy path only recently fixed (atomic-rename hot-reload) — worth a drill to prove in
  a running fleet, not just unit tests.
- Bench harness gotchas are documented but scattered: `WAF_CONFIG` env kills boot silently
  (`[[project_waf_config_env_footgun]]`), SIGTERM drain holds ports ~5s, orphaned Redis exec
  clients (`[[feedback_e2e_docker_cleanup]]`), dev XFF single-IP risk poisoning
  (`[[feedback_dev_xff_single_ip_gates]]`). The runbook consolidates these.

## 2. Staging

### OV-1 — load & attack-mix validation · **M** · START HERE
- Release-profile (LT-P1) fleet (≥2 nodes + Redis) under sustained production-like mix:
  benign baseline + attack waves (l-tester vectors, replayed raw), DDoS spike (exercises
  fleet-RPS aggregation), slow-drip enumeration.
- Capture: p50/p99 latency, error rate, block/allow correctness sampling, memory/fd stability
  over ≥1 h soak, SLO burn behavior during the attack window (the never-run smoke — verify
  blocks≠outage, origin-5xx=bad classification holds live).
- Pass/fail thresholds written down *before* the run.

### OV-2 — real administrative workflows · **S–M**
Scripted operator drills against the live fleet (each = steps + expected observations):
1. Attack triage: live feed → investigate IP → risk reset → verify clean allow.
2. Rule lifecycle: create (simulator) → enforce → observe attribution header → rollback.
3. Mode flip dry-run↔enforce → verify **fleet-wide** convergence (the `/api/mode` publish fix).
4. Config deploy via atomic rename → hot-reload observed on all nodes (watcher fix).
5. Incident ack/resolve across nodes (federation overlay convergence).
6. Credential rotation + (once shipped) TOTP enrollment / mTLS cert swap.
- Each drill doubles as the round-3 demo script.

### OV-3 — failure & recovery drills · **M**
- **Redis outage** mid-traffic: degraded-not-fail-closed posture holds
  (`[[project_health_signals_reported_not_gating]]`); risk/session behavior during + after;
  TelemetryAbsent watchdog fires.
- **Origin failure**: kill upstream members → passive health marks down → half-open recovery;
  zone failover with locality gate.
- **Node kill/restart**: SIGKILL a WAF node → peer continuity, hot-bind rebind, session survival
  (Redis-backed), incident resurrection behavior.
- **Config rollback under pressure**: bad config push → rollback → fleet converges.
- **Cert expiry** (zero_trust): expired upstream identity → alert fires, honest degraded state.
- Capture recovery-time observations against SLO expectations.

## 3. Deliverables

- [ ] `docs/ops/validation-runbook.md` — consolidated drill scripts + env footguns.
- [ ] Evidence pack per drill (transcripts, metrics screenshots, SLO panel captures) under
      `plans/future/` or `docs/ops/evidence/` — committee-facing.
- [ ] Defect list from drills triaged into issues (the real output — expect to find some).
- [ ] OV-1 thresholds met or regressions filed.

## 4. Risks

| Sev | Risk | Mitigation |
|---|---|---|
| MEDIUM | Drills find real bugs late | that's the point — schedule buffer before round 3 |
| LOW | Bench-env footguns burn drill time | runbook consolidates them up front (§1) |
| LOW | Single-machine limits (1 Redis, local fleet) | document env honestly in the evidence pack |
