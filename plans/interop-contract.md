# Hackathon 2026 — Compliance Plan

This plan tracks what must change in Aegis-Gate to comply with
the WAF Hackathon 2026 v2.3 contract
([`Hackathon_Doc/EN_waf_interop_contract_v2.3.md`](../Hackathon_Doc/EN_waf_interop_contract_v2.3.md))
and pass Round 1 / score in Round 2 / compete in Round 3.

The contract was published *after* the bulk of Aegis-Gate
landed, so a lot of what we've already built (HA cluster,
worker tuning, upstream pool, dashboard, audit chain, GitOps,
SLO, …) is **bonus territory**. The gap below is the strict
contract surface; everything else is already a Tier-A/B/C win.

## 1. Round mapping

| Round | Weight | What it tests | Where we stand |
|---|---|---|---|
| 1 — Functional review (Pass/Fail) | gate | Rust core, single binary, reverse proxy works, basic OWASP block, dashboard with hot-reload + audit viewer | **Mostly there.** Binary runs, proxy works, dashboard exists. Gaps below are **mandatory** for Round 1 too because the OC verifies UI ↔ proxy parity. |
| 2 — Automated benchmark | 65 % (≥ 70 % gate) | Strict interop contract: control plane, observability headers, audit log JSONL at `./waf_audit.log`, decision semantics, log-only mode | **Big gap.** None of the contract surface exists today (different header prefix, no control plane, audit log at wrong path). |
| 3 — Performance & resilience | 35 % + bonus | Throughput, latency, resilience, graceful degradation, Tier A/B/C bonus features | **Strong.** UP-T1 took us 525 → 7 964 RPS; HA cluster + drain + load-mode degradation already shipped. Bonus features (A: detection breadth; B: ops surface; C: SIEM/metrics) cover most of what the contract lists. |

## 2. Gap analysis vs the v2.3 interop contract

### 2.1 Control plane (§2 of contract) — **MISSING**

| Endpoint | Required | Status |
|---|---|---|
| `GET  /__waf_control/capabilities` | yes | not implemented |
| `POST /__waf_control/reset_state` | yes | not implemented |
| `POST /__waf_control/set_profile` | yes | not implemented |
| `POST /__waf_control/flush_cache` | if cache exists | n/a today (no upstream-response cache) |
| Auth via `X-Benchmark-Secret` header | yes | not implemented |

Notes:

- We have `/api/loadmode`, `/api/detectors`, etc. — *similar
  shape* but at different paths and without the secret header.
  Don't try to refactor the existing dashboard-facing API to
  match the contract. The contract endpoints are an **adapter**
  layer that wraps existing internals.
- `reset_state` MUST clear runtime state (rate-limit counters,
  risk scores, challenge sessions, cache) but MUST NOT touch
  `./waf_audit.log`. Map onto: `RiskTracker::reset_all`,
  `IpRateLimiter::reset_all`, `RedisBackend::flush` (if
  cluster), session store reset.
- `set_profile` toggles `enforce` / `log_only` per
  feature/policy. We have `LoadGauge` / `DetectorMask` /
  load-mode plumbing — extend to a per-policy mode override
  table.

### 2.2 Observability headers (§5) — **WRONG PREFIX**

| Required header | Today | Action |
|---|---|---|
| `X-WAF-Request-Id` | (we set internal `request_id`, never headered) | emit on every response |
| `X-WAF-Risk-Score` | n/a | thread the risk-score through to the response builder |
| `X-WAF-Action` | n/a | translate the WAF decision (block/allow/challenge/rate_limit/timeout/circuit_breaker) to this header |
| `X-WAF-Rule-Id` | n/a | propagate the responsible rule/detector ID |
| `X-WAF-Cache` | n/a | always emit `BYPASS` until upstream cache lands |
| `X-WAF-Mode` | n/a | reflect enforce/log_only of the policy that produced the action |

We have `X-Aegis-*` benchmark-mode headers
([`crates/aegis-proxy/src/benchmark.rs`](../crates/aegis-proxy/src/benchmark.rs))
but those are gated and use a different prefix. Required
`X-WAF-*` headers are **always-on**, not gated.

### 2.3 Audit log (§6) — **PATH + SHAPE MISMATCH**

Default path today: `/var/log/aegis/audit.jsonl` (configurable).
Hackathon contract: `./waf_audit.log` (default, configurable).

Schema today (rich, includes lots of extra fields). Schema
required: 8 fields minimum (`request_id`, `ts_ms`, `ip`,
`method`, `path`, `action`, `risk_score`, `mode`). We can add
more fields freely (it's a Dashboard-tier bonus).

Critical: `ip` MUST be the TCP peer address, not from XFF.
Today our access log writes `peer_addr` already, but the
audit chain may use the parsed forwarded IP — needs verifying.

### 2.4 Decision class semantics (§3) — **PARTIAL**

The 6 classes (`allow`, `block`, `challenge`, `rate_limit`,
`timeout`, `circuit_breaker`) are conceptually present. We
need to make sure every code path that produces a final
response stamps the right `X-WAF-Action`. Mapping:

- Allow → `allow` (after `forward::forward()` returns 2xx).
- Detector / rule deny → `block` (HTTP 403).
- Risk strikes block → `block`.
- Rate-limit fire → `rate_limit` (HTTP 429).
- Challenge ladder → `challenge` (HTTP 429 + challenge body).
- Upstream connect-timeout → `timeout` (HTTP 504).
- Circuit-breaker open → `circuit_breaker` (HTTP 503).

### 2.5 Log-only mode (§5.3, §7) — **NOT WIRED**

Each feature/policy needs an explicit `enforce` vs `log_only`
mode. In `log_only`, detectors run + emit headers + write
audit, but enforcement (block/challenge/rate_limit/etc.) is
suppressed.

We have a global `LoadMode` (NormalMode / DegradedMode etc.)
but no per-policy override. Need a new `PolicyModeMap`
(`Arc<DashMap<PolicyId, Mode>>`) that the security pipeline
consults before applying enforcement.

### 2.6 Startup contract (§8) — **PATH MISMATCH**

- Binary: contract says `./waf`. Ours is `target/release/waf`
  — fine, the OC will copy it to `./waf` per their build.
- Config: contract default `./waf.yaml`. We default to
  `config/waf.yaml`. Ship a `./waf.yaml` symlink/copy at the
  repo root for the OC build, or document the override.
- Audit log: contract default `./waf_audit.log`. Today's
  default is wrong. Add a hackathon profile / override.
- `./waf run` — already works.
- Health endpoint — already exists at `/healthz/ready`.
  Contract doesn't fix the path; document ours.

### 2.7 Source IP trust (§10) — **VERIFY**

In the sandbox, traffic arrives from `127.0.0.x` loopback
aliases. The WAF MUST treat each as a distinct client for
rate-limit / risk. We already do this for `peer_addr`-keyed
limiters; need to verify `IpRateLimiter` doesn't fold
loopback traffic.

## 3. Plan of work — six tracks

| ID | Track | Effort | Round |
|---|---|---|---|
| **HK-T1** | Audit log path + minimal schema profile | 1 hr | R1 + R2 |
| **HK-T2** | `X-WAF-*` mandatory header set on every response | 2 hr | R1 + R2 |
| **HK-T3** | `/__waf_control` endpoints + `X-Benchmark-Secret` | 4 hr | R2 |
| **HK-T4** | Per-policy `enforce` / `log_only` mode map + pipeline gate | 3 hr | R2 |
| **HK-T5** | Decision class → `X-WAF-Action` mapping audit + tests | 2 hr | R2 |
| **HK-T6** | Hackathon profile + `./waf.yaml` + smoke-test against contract | 1 hr | R1 + R2 |

**Total effort: ~13 hr**, ordered by dependency.

## 4. Scoring posture

- **Round 1 (gate)**: HK-T1, HK-T2, HK-T6 are mandatory. HK-T5
  + HK-T6 prove "UI ↔ proxy parity" by ensuring the dashboard
  reflects real state.
- **Round 2 (65 %, ≥ 70 % gate)**: HK-T3, HK-T4, HK-T5 are
  mandatory. The OC's automated benchmark **fails the run** if
  any required header / control endpoint format is wrong.
- **Round 3 (35 % head-to-head)**: most existing features
  already line up against the bonus tiers:
  - **Tier A — security & detection**: 7 OWASP detectors,
    JA4 fingerprint, risk + decay, threat intel feeds, DLP,
    OpenAPI guard.
  - **Tier B — advanced ops**: snapshot/restore CLI, GitOps
    loader, audit chain + verification CLI, hot-reload + ack
    (already meets the ≤ 10 s contract).
  - **Tier C — system integration**: 8 SIEM sinks (JSONL,
    syslog, CEF, LEEF, OCSF, HEC, ECS, Kafka), SLO alerts
    with multi-burn, Prometheus + OTLP exporters.
- HA cluster + UP-T1 + worker scaling already cover the
  performance / resilience axis: ~8 k RPS proxied, 100 %
  graceful failover, sub-1 ms p95 at 1 k RPS.

## 5. What we deliberately **don't** do

- Don't rename `X-Aegis-*` headers to `X-WAF-*`. The benchmark
  headers stay scoped under their gated mode; the new `X-WAF-*`
  set is always-on and serves a different purpose.
- Don't break existing `/api/*` dashboard endpoints. The new
  control plane lives at `/__waf_control/*`.
- Don't rebuild the audit chain. Add a thin "minimal-schema"
  JSONL sink that tees into `./waf_audit.log` while the
  existing tamper-evident SHA-256 chain keeps writing to its
  configured path.
- Don't pre-tune for hidden benchmark cases. The contract
  warns about hard-coded benchmark behavior.

## 6. Done definition

- Round 1 OC dry-run boots the binary, hits /health, fires a
  basic SQLi payload — sees `X-WAF-Action: block`, `403`,
  audit entry in `./waf_audit.log`.
- Round 2 OC's automated benchmark issues every
  `/__waf_control/*` call, gets the right shape, can flip
  log-only mode and observe headers update without enforcement.
- All three legitimate-credentials login flows from the public
  OpenAPI succeed without false positives in `enforce` mode.
- Workspace test count up by HK-T tests' worth, clippy clean.
- Run-08 perf re-run with the new always-on `X-WAF-*` headers
  shows no regression vs run-07's 7 964 RPS baseline.
