# Aegis-Gate — Implementation Plan

One-stop reference for building Aegis-Gate in Rust.

---

## 0. AI Assistant Guide

### 0.1 Starting a Session — Read in This Order

1. **`README.md`** (root of repo) — project overview, crate responsibilities, repo layout.
2. **`Implement-Progress.md`** (root) — last completed task, next task, full log.
3. **This file (`plans/plan.md`)** — shared types (§2), traits (§3), boot (§4), conventions (§5).
4. **The crate sub-plan** that matches your task:
   - Proxy tasks (M1-*) → [`plans/proxy.md`](proxy.md)
   - Security tasks (M2-*) → [`plans/security.md`](security.md)
   - Control tasks (M3-*) → [`plans/control.md`](control.md)

### 0.2 Standard Prompt Template

Copy-paste this to kick off any implementation task:

```
Context files to read first (in order):
  1. README.md
  2. Implement-Progress.md
  3. plans/plan.md  (shared types §2, traits §3)
  4. plans/<proxy|security|control>.md  (find task by code)

Task: <task code + title>   e.g. "M1-T2.3 RouteTable::build"
File: <target file(s) from sub-plan crate layout>
Signature: <copy exact signature from sub-plan>
Behavior: <copy "Behavior:" or description from sub-plan>

Constraints:
- Use only deps already in the target crate's Cargo.toml.
  If a new dep is needed: list it and wait for confirmation.
- Do not modify files outside the target crate except aegis-core (flag it).
- Write the unit + integration tests from "Test:" in the same commit.
- Run `cargo test -p <crate> && cargo clippy -p <crate> -- -D warnings` before finishing.
- After all tests pass, overwrite Implement-Progress.md per §0.3 below.
```

### 0.3 Implement-Progress.md Update Protocol

After every task, **overwrite the entire file** (do not append) with:

```markdown
# Aegis-Gate Implementation Progress

## Last Completed
- Task: <code + title>
- Crate: <aegis-proxy | aegis-security | aegis-control | aegis-core | aegis-bin>
- Files changed: <comma-separated>
- Status: DONE
- Date: <YYYY-MM-DD>

## Next Task
- Task: <next code + title>
- Plan: plans/<proxy|security|control>.md  (W<N> section)
- Notes: <blockers or context for the next session>

## Completed Tasks Log
| Task | Crate | Date |
|------|-------|------|
| <one row per previously completed task> |
```

### 0.4 Global Task Order

Integration checkpoints (§7) gate the transition to the next week.

| Week | Tasks (can be done in parallel) | Gate |
|------|----------------------------------|------|
| W1 | M1-T1.1–T1.5, M2-T1.1–T1.5, M3-T1.1–T1.5 | `./waf run` boots; `/healthz/live` 200 |
| W2 | M1-T2.1–T2.7, M2-T2.1–T2.4, M3-T2.1–T2.4 | SQLi blocks; event visible on dashboard SSE |
| W3 | M1-T3.1–T3.8, M2-T3.1–T3.9, M3-T3.1–T3.6 | TLS + JWT + Prometheus green |
| W4 | M1-T4.1–T4.9, M2-T4.1–T4.4, M3-T4.1–T4.7 | Dashboard auth fully green |
| W5 | M1-T5.1–T5.7, M2-T5.1–T5.14, M3-T5.1–T5.5 | Redis cluster + red-team suite + 5k RPS |

---

## 1. Workspace Layout

```
aegis-gate/
├── Cargo.toml          # workspace (members: aegis-core, proxy, security, control, bin)
├── crates/
│   ├── aegis-core/     # shared types, traits — PR-reviewed by all
│   ├── aegis-proxy/    # data plane: TLS, routing, upstreams, state
│   ├── aegis-security/ # security pipeline: rules, detectors, risk
│   ├── aegis-control/  # control plane: dashboard, audit, observability
│   └── aegis-bin/      # ./waf binary
└── config/waf.yaml, rules/
```

---

## 2. Shared Types (`aegis-core`)

> Full type definitions are in the original `shared-contract.md` until this file reaches parity.
> All task implementations must match those exact signatures.

Key modules: `config`, `context`, `decision`, `audit`, `tier`, `risk`, `error`.

| Type | Purpose |
|------|---------|
| `Tier` | Critical / High / Medium / CatchAll |
| `FailureMode` | FailClose (Critical default) / FailOpen |
| `Decision { action, reason, rule_id, risk_score }` | Pipeline verdict |
| `Action` | Allow / Block{status} / Challenge{level} / RateLimited{retry_after_s} |
| `RequestCtx` | Per-request state; `fields` BTreeMap carries JWT claims, risk score, bot label |
| `RouteCtx` | Route id, tier, failure mode, upstream pool name |
| `AuditEvent` | Serialisable event; `AuditBus` broadcasts to control |
| `RiskKey` | ip + device_fp + session (tenant_id always None in v1) |
| `WafConfig` | Top-level config; sub-structs owned by respective crates |

Config sub-structs: `StateConfig` (proxy), `RulesConfig` (security), `RateLimitConfig` (security), `RiskConfig` (security), `DetectorsConfig` (security), `DlpConfig` (security), `ObservabilityConfig` (control), `AuditConfig` (control), `AdminConfig` (control), `ComplianceProfile` (control).

Multi-tenancy and OIDC/RBAC are **DEFERRED** (see `docs/deferred/`). `tenant_id` is always `None` in v1.

---

## 3. Cross-Crate Traits (`aegis-core`)

| Trait | Direction | Location |
|-------|-----------|----------|
| `SecurityPipeline` (inbound + on_response_start + on_body_frame) | proxy calls → security implements | `core/src/pipeline.rs` |
| `StateBackend` (K/V, sliding window, token bucket, risk, nonces) | proxy provides → security consumes | `core/src/state.rs` |
| `SecretProvider` (resolve + watch) | proxy provides env/file; control provides vault/cloud | `core/src/secrets.rs` |
| `ServiceDiscovery` (subscribe per pool) | proxy provides | `core/src/sd.rs` |
| `CacheProvider` (get/put/invalidate) | proxy provides; CRITICAL never cached | `core/src/cache.rs` |
| `ClusterMembership` (peers + acquire_lease) | proxy provides gossip; control surfaces view | `core/src/cluster.rs` |
| `AuditBus` (emit + subscribe broadcast) | proxy/security emit; control fans out to sinks | `core/src/audit.rs` |
| `MetricsRegistry` (Arc<prometheus::Registry>) | control creates; proxy/security register into it | `core/src/metrics.rs` |
| `ReadinessSignal` (5 AtomicBools) | proxy flips; control reads for /healthz/ready | `core/src/health.rs` |
| `ConfigBroadcast` (broadcast::Sender<ConfigEvent>) | anyone can fire; all caches subscribe | `core/src/config.rs` |
| `NoopPipeline` | always Allow; used in W1 before security is wired | `core/src/pipeline.rs` |

---

## 4. Boot Sequence (`aegis-bin`)

Order: secrets → config load → metrics init → audit bus → state → cluster → cache → SD → security build → control start → proxy run.

See `crates/aegis-bin/src/main.rs` for the wiring. Control starts before proxy so `/healthz/startup` is observable from boot.

---

## 5. Conventions & Feature Flags

- `cargo fmt` + `cargo clippy -- -D warnings` enforced in CI.
- `cargo test --workspace` green on `main`.
- Commit prefixes: `proxy:`, `security:`, `control:`, `core:`.
- MSRV: Rust 1.82.
- Feature flags: `tls`, `redis`, `otel`, `acme`, `http3`, `fips`, `consul`, `etcd`, `k8s`, `kafka`, `hsm`, `opa`, `bot_ml`.

---

## 6. Requirement → Coverage Matrix

| Req | Topic | Tasks |
|-----|-------|-------|
| §3 | Binary, dual listener, hot reload | M1-T1.1–1.4 |
| §4–5 | Routing, upstreams, LB, health, CB | M1-T2.1–2.7 |
| §6 | Canary, retry, shadow | M1-T4.3–4.5 |
| §7 | TLS, ACME, OCSP, mTLS, FIPS | M1-T3.1–3.7 |
| §8 | h1/h2/WS/gRPC/h3 | M1-T3.2–3.4, 3.8 |
| §9–10 | Tier policy, rule engine, rate-limit, DDoS, OWASP, risk, fingerprint | M2-T1–T3 |
| §10.7–10.8 | IP rep, response filter | M2-T4.1–4.2, T5.1 |
| §11 | JWT, ForwardAuth, Basic, CIDR, OPA | M2-T5.5–5.6, 5.12–5.14 |
| §12–14 | Transforms, quotas, session affinity | M1-T4.1–4.2, 4.6 |
| §15–16 | Observability, audit chain, SIEM | M3-T1–3 |
| §17–19 | Drain, hot reload, SD, clustering | M1-T4.7–4.8, T5.1–5.7 |
| §20–21 | Compliance, dashboard auth | M3-T4–5 |
| §21 SSO/RBAC | — | **DEFERRED** |
| §22–23 | Secrets, multi-tenancy | M1-T5.4; multi-tenancy **DEFERRED** |
| §24–28 | Threat intel, DLP, API sec, bots, ICAP | M2-T4.3–4.4, T5.2–5.11 |
| §29–33 | Shedding, DR, residency, GitOps, SLO | M1-T5.3–5.5, M3-T5.2–5.5 |

---

## 7. Integration Checkpoints

| End of | Checkpoint |
|--------|-----------|
| W1 | `./waf run` boots; NoopPipeline allows; `/healthz/live` 200 |
| W2 | SQLi rule blocks; block on dashboard SSE |
| W3 | TLS + JWT + Prometheus green |
| W4 | Dashboard auth: login + session + CSRF + lockout + IP allowlist |
| W5 | 2-node Redis + red-team suite + 5k RPS load test |

---

## 8. Definition of Done

- [ ] `cargo test --workspace` green; `cargo clippy -- -D warnings` clean.
- [ ] Load test: ≥ 5 000 RPS, p99 WAF overhead ≤ 5 ms.
- [ ] Graceful drain: 0 dropped in-flight under SIGTERM + `wrk`.
- [ ] 2-node Redis cluster shares rate-limit + risk counters.
- [ ] Red-team suite (SQLi/XSS/SSRF/path-traversal/brute-force) fully blocked.
- [ ] FP rate < 1% on benign corpus.
- [ ] Dashboard auth: argon2id + HMAC session + CSRF + lockout + IP allowlist green.
- [ ] Hash chain verifies clean; tampered log detected by CLI.
- [ ] SIEM forwarder delivers to ≥ 3 sinks in integration test.
- [ ] SLO burn alert fires on synthetic regression.
- [ ] FIPS profile boots; non-FIPS algs refused at load.

---

## 9. Sub-Plan Index

Task-level breakdowns live in separate files to keep each document focused.
An AI assistant should open only the file relevant to the current task.

| Sub-plan | Crate | Contents |
|----------|-------|----------|
| [`plans/proxy.md`](proxy.md) | `aegis-proxy` | Crate layout, metrics, W1–W5 tasks (M1-T1.1 → M1-T5.7), DoD |
| [`plans/security.md`](security.md) | `aegis-security` | Crate layout, pipeline order, metrics, W1–W5 tasks (M2-T1.1 → M2-T5.14), DoD |
| [`plans/control.md`](control.md) | `aegis-control` | Crate layout, REST API surface, metrics, W1–W5 tasks (M3-T1.1 → M3-T5.5), DoD |

---

<!-- Task-level content has moved to the sub-plan files above. -->

