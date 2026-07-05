# Validation runbook — realistic operating conditions

> **OV** deliverable of [PLAN-ops-validation-realistic](../../plans/issues/PLAN-ops-validation-realistic-2026-07.md)
> (committee round-2 🟡5). This is the drill script + environment cheat-sheet.
> Executing the drills needs a live ≥2-node fleet and produces an evidence pack;
> that run is scheduled separately (team plan week 4). Authored 2026-07-05.

**Objective:** prove the system holds up outside isolated functional tests —
production-like load, real admin workflows, and failure/recovery — with
reproducible scripts and captured evidence. The single most important gap this
pays down: **the SLO/alerting enforcement-excluded path has never been run
end-to-end** — the first real attack wave would otherwise be its first test.

---

## 0. Environment footguns (read before every drill)

These have each burned real time. Consolidated here so a drill doesn't
rediscover them.

| Footgun | Symptom | Avoid |
|---|---|---|
| **`WAF_CONFIG` env set** | `waf run` dies at boot, **rc=1 with an empty log** (the tracing subscriber inits after config load, so the figment `WAF_`-overlay error — unknown key `config` — is never printed) | `unset WAF_CONFIG` in any shell that runs `waf`; the documented bench flow is affected |
| **SIGTERM drain holds ports ~5 s** | Next boot fails to bind `:443`/`:9443` for a few seconds after stop | Wait out the drain, or `--force` a fresh port; don't assume instant rebind |
| **Orphaned `docker exec aegis-redis` clients** | Redis daemon wedges; connections hang | Full restart recipe in `[[feedback_e2e_docker_cleanup]]`; `make bench-dev` is a **foreground** server, not a hang |
| **Dev doesn't trust XFF** | All traffic attributes to `127.0.0.1`; after any attack the per-IP risk gate poisons the single IP and later "clean" requests still gate | Reset via `PUT /api/risk/<ip>/reset` (CSRF); use a real UA and space requests for a clean `allow` |
| **`X-WAF-Action` ≠ actual outcome** | Header shows the would-be decision even in log-only | Check HTTP status + `X-WAF-Mode` for the enforced-vs-logged truth |
| **No `challenge` actions seen** | `challenges_enabled` off ⇒ challenge band collapses to allow | Expected, not a bug; enable per-tier to exercise |
| **Two score models** | `/api/risk` cumulative (max-per-request + decay) vs per-request detector SUM differ (e.g. 100 vs 70) | Not a bug — they measure different things |

Boot cheats: `make run-dev` (single node + Redis + mock upstream, `config/dev.yaml`),
`make bench-dev` (v2.3 benchmark-contract binary, foreground). A ≥2-node fleet
needs Redis + `node.id`/`AEGIS_ZONE` per node — see `deploy/HACKATHON-FLEET.md`.

---

## OV-1 — load & attack-mix validation · START HERE

Release-profile (LT-P1) fleet, ≥2 nodes + Redis, under a sustained
production-like mix. **Write pass/fail thresholds down before the run.**

**Traffic:** benign baseline (real UAs, spaced) + attack waves (l-tester
vectors replayed raw — remember the data plane feeds detectors the RAW
percent-encoded path, so validate against raw forms) + a DDoS spike (exercises
fleet-RPS aggregation) + slow-drip enumeration.

**Capture:** p50/p99 latency, error rate, block/allow correctness sampling,
memory + fd stability over a ≥1 h soak, and — the never-run part — **SLO burn
behavior during the attack window**: verify blocks ≠ outage and origin-5xx =
bad classification hold live, that the multi-burn alert fires on a real budget
drain, and that silence ≠ recovery + the TelemetryAbsent watchdog behave.

**Suggested thresholds (adjust to hardware, record actual):** p99 added
latency < 5 ms benign; zero fd/memory growth trend over the soak; block-decision
sampling ≥ 99 % correct against a labeled subset; no alert on a benign-only hour;
page-severity alert within its short-window on the attack hour.

---

## OV-2 — real administrative workflows

Scripted operator drills against the live fleet. Each = steps + expected
observation; each doubles as a round-3 demo script.

1. **Attack triage:** live feed → click an attacker → investigate IP → risk
   reset (`PUT /api/risk/<ip>/reset`, CSRF) → verify next request `allow`.
2. **Rule lifecycle:** create in the simulator → enforce → observe the
   attribution header on a matching request → rollback (`POST /api/config/rollback`).
3. **Mode flip:** dry-run ↔ enforce → verify **fleet-wide** convergence (this
   is the `/api/mode` publish path — confirm peers converge, not just the local
   node).
4. **Config deploy:** atomic-rename a new `waf.yaml` → hot-reload observed on
   **all** nodes (the watcher-watches-the-dir fix; prove in a running fleet).
5. **Incident lifecycle:** ack/snooze/resolve across nodes → federation overlay
   converges (LWW), resolve doesn't auto-resurrect.
6. **Credential rotation** + (once shipped) TOTP enrollment / mTLS cert swap.
   Confirm each leaves an audit event (AU-1): login events, `config_activate`
   for the rotation.

---

## OV-3 — failure & recovery drills

Capture recovery-time observations against SLO expectations for each.

- **Redis outage mid-traffic:** degraded-not-fail-closed holds (data plane keeps
  serving on in-memory fallback; `/healthz/ready` → `degraded` HTTP 200, never
  503); risk/session behavior during + after; TelemetryAbsent watchdog fires;
  `state_backend_up`/`state_backend_writable` flip on the wire.
- **Origin failure:** kill upstream members → passive health marks them down →
  half-open recovery; zone failover honors the locality gate.
- **Node kill/restart:** SIGKILL a WAF node → peer continuity, hot-bind rebind
  (mind the ~5 s drain footgun on graceful stop), Redis-backed session
  survival, incident resurrection behavior.
- **Config rollback under pressure:** push a bad config → rollback → fleet
  reconverges on the good version.
- **Cert expiry (zero_trust):** expired upstream identity → alert fires, honest
  degraded state (not a silent all-fail).
- **Risk-tracker saturation (new, AU-3B):** drive distinct-key cardinality past
  `MAX_TRACKED_KEYS` → `waf_risk_tracker_saturated` gauge → 1,
  `saturation_rejects` climbs, `/api/risk` shows `saturated: true`. Proves the
  fail-open is now observable.

---

## Deliverables (the actual output of the scheduled run)

- [ ] This runbook (done) — drill scripts + footguns.
- [ ] Evidence pack per drill (transcripts, metric screenshots, SLO panel
      captures) under `docs/ops/evidence/` — committee-facing.
- [ ] Defect list from the drills triaged into issues (expect to find some —
      that's the point; schedule buffer before round 3).
- [ ] OV-1 thresholds met, or regressions filed.
- [ ] Single-machine limits (1 Redis, local fleet) documented honestly in the
      evidence pack.
