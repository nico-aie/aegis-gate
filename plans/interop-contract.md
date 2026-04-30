# External Interop Contract — Implementation Status

This plan tracks Aegis-Gate's compliance with the WAF Interop
Contract v2.3
([`Hackathon_Doc/EN_waf_interop_contract_v2.3.md`](../Hackathon_Doc/EN_waf_interop_contract_v2.3.md)).
The contract is a generic external-tooling protocol — benchmark
harnesses, SIEMs, and operations dashboards all benefit from it,
not just the OC's automated benchmarker. We treat the surface as
an always-on operational feature, not a benchmark profile.

## Compliance status (after IT-T1..IT-T6)

| Contract clause | Status | Where |
|---|---|---|
| §2.1 — `GET /__waf_control/capabilities` | ✅ | `aegis-control::interop::control::ControlContext::capabilities` |
| §2.1 — `POST /__waf_control/reset_state` | ✅ | `ControlContext::reset_state` (clears risk + rate-limit; preserves audit log) |
| §2.1 — `POST /__waf_control/set_profile` | ✅ | `ControlContext::set_profile` (scope ∈ all / features / policies) |
| §2.1 — `POST /__waf_control/flush_cache` | ✅ | `ControlContext::flush_cache` returns `supported: false` until upstream cache lands |
| §2.2 — `X-Benchmark-Secret` auth | ✅ | configurable via `interop.control_secret`; default `waf-hackathon-2026-ctrl` |
| §2.3 — capability schema | ✅ | features pre-populated: `access_control`, `rules_engine`, `rate_limit`, `risk_engine` |
| §2.4 — atomic `reset_state`, audit-log preserved | ✅ | `MinimalJsonlSink` is append-only; reset chain runs synchronously before success |
| §2.5 — `enforce` / `log_only` per scope | ✅ | `ModeStore` lock-free read, `set_all` / `set_feature` / `set_policy` writes |
| §3 — six decision classes | ✅ | `Action::{Allow, Block, Challenge, RateLimit, Timeout, CircuitBreaker}` |
| §5.1 — six required `X-WAF-*` headers always-on | ✅ | `Decision::stamp` runs on every data-plane response |
| §5.3 — header consistency (mode reflects policy) | ✅ | `stamp_interop_response` resolves mode via `ModeStore` |
| §6 — minimal-schema JSONL audit at `./waf_audit.log` | ✅ | `MinimalJsonlSink` writes 8 fields + optional `rule_id` |
| §6 — `ip` is TCP peer, not XFF | ✅ | sink writes `peer.ip()` directly |
| §8 — startup contract | ✅ | `./waf run` already starts; default config now ships `interop.enabled: true` |
| §10 — source IP trust (loopback aliases distinct) | ✅ | `IpRateLimiter` keys on `peer_addr` |

## Implementation tracks

All six tracks landed in one working day.

| ID | Track | Outcome |
|---|---|---|
| **IT-T1** | Audit log path + minimal schema | `aegis-control::interop::audit` — `MinimalJsonlSink` + `MinimalAuditEntry`, default path `./waf_audit.log`, append-only |
| **IT-T2** | `X-WAF-*` mandatory headers | `aegis-control::interop::headers` — `Decision::stamp` puts six headers on every data-plane response |
| **IT-T3** | `/__waf_control/*` endpoints | `aegis-control::interop::control::ControlContext` — auth + capabilities + reset + set_profile + flush_cache; dispatched in `aegis-proxy::lib::handle_interop_control` |
| **IT-T4** | Per-policy `enforce` / `log_only` | `aegis-control::interop::mode::ModeStore` — `ArcSwap` snapshot, lock-free read, ordered resolution (policy → feature → default) |
| **IT-T5** | Decision class → `X-WAF-Action` mapping | `stamp_interop_response` in `aegis-proxy::lib`; HTTP status → `Action` mapping inline |
| **IT-T6** | Always-on by default + audit-log path | `InteropConfig::enabled` defaults to `true`; default audit path `./waf_audit.log`; `interop.control_secret` configurable |

## Code map

```
crates/aegis-control/src/interop/
  mod.rs          — InteropRuntime aggregate + DEFAULT_CONTROL_SECRET / CONTROL_SECRET_HEADER / DEFAULT_AUDIT_PATH
  audit.rs        — MinimalJsonlSink + MinimalAuditEntry + format_line
  headers.rs      — Action / Mode / CacheState / Decision::stamp
  mode.rs         — ModeStore + ModeSnapshot + resolution rules
  control.rs      — ControlContext + capabilities/reset_state/set_profile/flush_cache + SetProfileRequest

crates/aegis-proxy/src/lib.rs
  build_interop_runtime         — assembles InteropRuntime from config + risk + rate-limiter
  stamp_interop_response        — post-process every data-plane response: stamp X-WAF-*, write audit
  handle_interop_control        — dispatch /__waf_control/*

crates/aegis-core/src/config.rs
  InteropConfig                 — enabled, audit_path, control_secret
```

## Test surface

- 39 unit tests in `aegis-control::interop::*` cover the wire
  shape (action / mode strings exact, cache values uppercase,
  required headers stamped, set_profile validation, mode
  resolution order, audit log JSONL one-per-line + append-only).
- Workspace test count after IT-T1..T6: **2,273** (was 2,234;
  +39 interop tests).
- Clippy clean across `--workspace --features aegis-proxy/redis`.
- Live end-to-end smoke: 4/4 control endpoints respond with the
  contract shape; 6/6 `X-WAF-*` headers present on a `HEAD /get`
  response; minimal-schema audit entry written to
  `./waf_audit.log` with `request_id` matching the response.

## Round mapping

| Round | Weight | What it tests | Where we stand |
|---|---|---|---|
| 1 — Functional review (Pass/Fail) | gate | Rust core, single binary, reverse proxy works, basic OWASP block, dashboard with hot-reload | ✅ Binary runs (`./waf run`); reverse proxy fully wired (B4-T3 + UP-T1); 7 OWASP detectors active; dashboard real-time SSE ≤ 5 s; hot-reload ≤ 10 s. |
| 2 — Automated benchmark | 65 % (≥ 70 % gate) | Strict interop contract | ✅ All §2 / §3 / §5 / §6 / §10 clauses implemented; live smoke green. |
| 3 — Performance & resilience | 35 % + bonus | Throughput, latency, resilience, graceful degradation | ✅ UP-T1: 525 → 7 964 RPS (15× lift); HA cluster + drain; load-mode degradation; runtime worker tuning (Layer-1). |

## What we deliberately don't do

- Don't hardcode against the public OpenAPI surface. The contract
  itself warns about benchmark-specific shortcuts; per the
  external feedback the WAF must operate independently of the
  underlying source code or specific endpoint structures.
- Don't gate the interop surface behind a benchmark-only profile.
  The features (observability headers, control plane,
  minimal-schema audit log, mode toggle) are universally useful;
  any operator running a WAF wants them.
- Don't rebuild the existing tamper-evident audit chain. The new
  `MinimalJsonlSink` runs in parallel with the SHA-256 chain and
  the SIEM sinks (8 backends) — distinct purposes.
- Don't rename `X-Aegis-*` benchmark-mode headers. Those remain
  gated diagnostics; `X-WAF-*` is always-on operational metadata.

## Round 3 bonus alignment (Tier A/B/C)

The bonus rubric asks for advanced features. Most of what we've
built already lines up:

- **Tier A — security & detection**: 7 OWASP detectors, JA4
  fingerprint, risk engine with decay + strikes, threat intel
  feeds (TAXII), DLP (patterns + FPE), OpenAPI guard, GraphQL
  guard, JWT/OAuth validation.
- **Tier B — advanced operations**: snapshot/restore CLI,
  GitOps loader (B3-T1), audit chain + verification CLI,
  hot-reload + ack, runtime sizing knobs (Layer-1), worker
  affinity feature.
- **Tier C — system integration**: 8 SIEM sinks (JSONL,
  syslog, CEF, LEEF, OCSF, Splunk HEC, ECS, Kafka), SLO alerts
  with multi-burn rates, Prometheus + OTLP exporters, witness
  exporter, alertmanager+VipTalk dispatch.
