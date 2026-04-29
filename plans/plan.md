# 0. AI Assistant Guide (Reusable)

## 0.1 Session Startup (Always Do This First)

Before implementing anything, load context in this exact order:

1. README.md — architecture + crate responsibilities  
2. Implement-Progress.md — last state + next task  
3. plans/plan.md — this assistant guide (rules + protocol)  
4. Relevant sub-plan:
   - plans/proxy.md — `aegis-proxy` track (M1/M2/… task IDs)
   - plans/security.md — `aegis-security` track
   - plans/control.md — `aegis-control` track
   - plans/dashboard-enterprise/README.md — enterprise dashboard
     track (D-M1/D-M2/… task IDs); design spec lives at
     `docs/control-plane/enterprise/`

Do not start coding without reading these.

---

## 0.2 Universal Implementation Prompt (Copy-Paste)

Use this template every time you start or resume work. Copy the
fenced block below verbatim — the code fence preserves the
`<placeholder>` markers so they survive markdown rendering.

```text
Context files to read first (in order):
1. README.md
2. Implement-Progress.md
3. plans/plan.md (this assistant guide)
4. Track-specific plan:
   - Proxy:    plans/proxy.md
   - Security: plans/security.md
   - Control:  plans/control.md
   - Dashboard:
       plans/dashboard-enterprise/README.md
       + plans/dashboard-enterprise/milestone-<N>-*.md
       + docs/control-plane/enterprise/README.md   (design spec)

Task:
<copy NEXT TASK from Implement-Progress.md, e.g. "D-M1-T1.1 Asset embedder">

Target crate:
<aegis-proxy | aegis-security | aegis-control | aegis-core | aegis-bin>
(dashboard-enterprise track is aegis-control only)

Requirements:
- Follow exact types and traits from aegis-core
- Do not invent new interfaces unless necessary
- Use only dependencies already in Cargo.toml
- If a new dependency is needed -> list it, do not add it

Implementation rules:
- Modify only the target crate (except aegis-core if required)
- Keep code idiomatic and production-ready
- Handle errors explicitly (no unwrap in core paths)
- Respect tier + failure mode semantics

Testing:
- Add unit + integration tests where applicable
- Ensure (replace CRATE with the target crate name):
    cargo test -p CRATE
    cargo clippy -p CRATE -- -D warnings

Completion:
- All tests pass
- No clippy warnings
- Update Implement-Progress.md (overwrite fully)
```

---

## 0.3 Progress File Protocol (Strict)

`Implement-Progress.md` is a **living snapshot**, not a changelog.
The Completed Tasks Log at the bottom is the only append-only
section. Every other section is overwritten in place.

The file ships with a header that documents this protocol — keep
that header intact.

### Section rules

| Section | What it holds | Update cadence |
|---|---|---|
| **Status (snapshot)** | Date + test count + clippy state + one-line "latest activity" | Every closed task |
| **Last Completed** | Current task in full detail (outcome + files + verification) | Every closed task — overwrite |
| **Recent History** | Previous **5** tasks, **1–2 lines each**, table form | Push the old "Last Completed" down to the top of this table |
| **Next Task** | The immediate next item, or a list of open tracks if no task is in flight | Every closed task — overwrite |
| **Tracks in flight** | Long-running tracks + their open/closed state | Only when a track opens or closes |
| **Carry-overs / known limitations** | Durable list of things that work but aren't fully shipped | Only when a carry-over graduates to "shipped" |
| **Future phases** | Pointers to `plans/dashboard-redesign/` + `docs/future/advanced-features.md` | Rarely |
| **Verification (last full run)** | `cargo test` count + clippy state | Every closed task |
| **Completed Tasks Log** | One row per closed task | **Append only** — never edit older rows |

### After completing a task

1. **Move** the current "Last Completed" → top row of "Recent
   History" table, compressed to 1–2 lines.
2. **Overwrite** "Last Completed" with the new task's full detail.
3. **Overwrite** "Next Task" with what to do next (or list open
   tracks if you don't know).
4. **Update** "Status (snapshot)" with the new date / test count.
5. **Append** one row to "Completed Tasks Log".
6. **Update** "Verification" with the latest `cargo test --workspace`
   count.
7. Touch "Tracks", "Carry-overs", or "Future phases" **only** if
   the closed task changes their state.

Do NOT add per-task "Earlier Completed" or "Previous (X) — for
context" sections. That pattern bloated the file before this
template existed; the Recent History table replaces it.

### Last Completed entry format

```markdown
## Last Completed

**Task:** <code + title>

**Outcome.** <2–4 sentences: what now works, observable from the
outside.>

**Files changed.**
- <path> — <one-line note>
- ...

**Verification.** <commands run + their results>
```

---

## 0.4 Execution Rules (Always Enforced)

- Never skip reading context files  
- Never guess missing types — check aegis-core  
- Never modify unrelated crates  
- Never introduce hidden coupling between crates  
- Prefer simple, testable implementations first  
- Keep performance in mind (this is a data-plane system)  

---

## 0.5 Mental Model for the Assistant

When implementing, always think:

- Proxy = execution engine (data plane)  
- Security = decision engine  
- Control = visibility + management  
- Core = contract (source of truth)  

If something feels unclear → it likely belongs in aegis-core.

### Tracks currently in flight

| Track | Plan root | Task ID prefix | Crates touched |
|-------|-----------|----------------|----------------|
| Proxy core | `plans/proxy.md` | `M{n}-T{x}.{y}` | aegis-proxy (+ aegis-core) |
| Security pipeline | `plans/security.md` | `M{n}-T{x}.{y}` | aegis-security |
| Control plane | `plans/control.md` | `M{n}-T{x}.{y}` | aegis-control |
| Enterprise dashboard | `plans/dashboard-enterprise/` | `D-M{n}-T{x}.{y}` | aegis-control only |
| Benchmark mode | `plans/benchmark-mode.md` | `B-T{n}.{y}` | aegis-core, aegis-proxy, aegis-security, aegis-control, aegis-bin |

The `D-` and `B-` prefixes keep dashboard and benchmark task IDs
disjoint from the original M1/M2/M3 IDs already in the Completed
Tasks Log. The dashboard and benchmark tracks are parallel — B-T1..B-T3
can land before D-M1 finishes; B-T4.5 / B-T4.6 (dashboard panels)
are the only B- tasks gated on dashboard milestones.

---

## 0.6 When Resuming Work

Do NOT ask what to do next.

Instead:

1. Read Implement-Progress.md  
2. Take the Next Task  
3. Continue implementation immediately  

---

# 1. Doc-by-doc Implementation Status

This matrix is the source of truth for "what's actually shipped"
vs "what's specified in docs/". Each doc carries a one-line
`> **Status:** ...` banner that mirrors a row in this table; the
banner is generated from this table — keep them in sync.

**Status legend.**

| Status | Meaning |
|---|---|
| **Implemented** | Production-ready code wired into the runtime, with unit + integration tests. |
| **Partial** | Core path is in code; specific advertised pieces (a backend, a feature gate, a sub-mode) are missing. The doc calls out which parts are stubs. |
| **Designed only** | The doc has a full spec but no production code (or only types/traits with no concrete impl). |
| **Deferred** | Explicitly deferred — design preserved for future work, not on any current track. |

**As of 2026-04-29.** Verify before relying on a row by checking the
named module path. When status changes, update the doc banner and
this table together.

## 1.1 Operator

| Doc | Status | Notes / module path |
|---|---|---|
| [`docs/operator/usage.md`](../docs/operator/usage.md) | **Implemented** | Operator runbook is current; references real subcommands. |
| [`docs/operator/cli.md`](../docs/operator/cli.md) | **Implemented** | Every subcommand exists in `aegis-bin/src/main.rs`. |
| [`docs/operator/benchmark-mode.md`](../docs/operator/benchmark-mode.md) | **Designed only** | `plans/benchmark-mode.md` track (B-T1..B-T6) is open; no `benchmark/` module yet. `X-Aegis-*` headers + dashboard panels are not wired. |

## 1.2 Architecture

| Doc | Status | Notes / module path |
|---|---|---|
| [`docs/architecture/protocols.md`](../docs/architecture/protocols.md) | **Partial** | HTTP/1.1 + HTTP/2 + WebSocket + gRPC: `aegis-proxy/src/proto/{h2,ws,grpc}.rs`. **HTTP/3 not implemented** (no `quinn`/`h3`/`s2n-quic` dependency). |

## 1.3 Data plane (M1 / aegis-proxy)

| Doc | Status | Notes / module path |
|---|---|---|
| [`reverse-proxy.md`](../docs/data-plane/reverse-proxy.md) | **Implemented** | `aegis-proxy/src/{lib,proxy,supervisor}.rs`. |
| [`routing-ingress.md`](../docs/data-plane/routing-ingress.md) | **Implemented** | `aegis-proxy/src/route/{host,path,mod}.rs`. |
| [`upstream-pools.md`](../docs/data-plane/upstream-pools.md) | **Implemented** | `aegis-proxy/src/upstream/{lb,health,circuit,tls,mod}.rs`. 5 LB strategies, health checks, circuit breaker. |
| [`traffic-management.md`](../docs/data-plane/traffic-management.md) | **Implemented** | `aegis-proxy/src/traffic.rs` — canary, steering, shadow mirror, retries. |
| [`tls-termination.md`](../docs/data-plane/tls-termination.md) | **Implemented** | `listener/{tls,tls_policy}.rs` + `acme.rs` + `acme_instant.rs` + `ocsp.rs`. P4 hardening + P5 ACME via Pebble (F-T7/F-T8). |
| [`session-affinity.md`](../docs/data-plane/session-affinity.md) | **Implemented** | `aegis-proxy/src/session.rs`. |
| [`per-route-quotas.md`](../docs/data-plane/per-route-quotas.md) | **Implemented** | `aegis-proxy/src/quota.rs`. |
| [`transformations-cors.md`](../docs/data-plane/transformations-cors.md) | **Implemented** | `aegis-proxy/src/transform/{cors,vars,mod}.rs`. |
| [`service-discovery.md`](../docs/data-plane/service-discovery.md) | **Partial** | `sd/mod.rs` ships file watcher + diff helpers + churn safety limits. **`consul` / `etcd` / `k8s` adapters NOT implemented** (only mentioned in module doc). |
| [`smart-caching.md`](../docs/data-plane/smart-caching.md) | **Implemented** | `aegis-proxy/src/cache/mod.rs` — `TierCache`, vary-aware, max-age honored. |
| [`adaptive-load-shedding.md`](../docs/data-plane/adaptive-load-shedding.md) | **Implemented** | `aegis-proxy/src/shed.rs` + `aegis-core/src/load_mode.rs` (P7). |
| [`graceful-degradation.md`](../docs/data-plane/graceful-degradation.md) | **Implemented** | Circuit breaker (`upstream/circuit.rs`) + load shedder (`shed.rs`) + cache fallback. |

## 1.4 Security pipeline (M2 / aegis-security)

| Doc | Status | Notes / module path |
|---|---|---|
| [`rule-engine.md`](../docs/security/rule-engine.md) | **Implemented** | `aegis-security/src/rules/{ast,eval,parser,linter,mod}.rs`. |
| [`tiered-protection.md`](../docs/security/tiered-protection.md) | **Implemented** | `aegis-core/src/tier.rs` + per-tier detector mask overrides (P2/P3). |
| [`rate-limiting.md`](../docs/security/rate-limiting.md) | **Implemented** | `rate_limit/{bucket,sliding,ip_limiter,mod}.rs`. |
| [`ddos-protection.md`](../docs/security/ddos-protection.md) | **Implemented** | `aegis-security/src/ddos.rs`. |
| [`ip-reputation.md`](../docs/security/ip-reputation.md) | **Partial** | `ip_rep/{asn,xff,mod}.rs` — XFF validation + ASN matching. **No live threat-intel feed fetcher** (see threat-intelligence row). |
| [`geoip-filtering.md`](../docs/security/geoip-filtering.md) | **Designed only** | No `maxmind` / `country_code` code anywhere. |
| [`device-fingerprinting.md`](../docs/security/device-fingerprinting.md) | **Implemented** | `fingerprint/{ja3,ja4,h2,mod}.rs`. |
| [`risk-scoring.md`](../docs/security/risk-scoring.md) | **Implemented** | `risk/{tracker,mod}.rs` + `aegis-core::RiskKey`. P6 strikes + trust recovery. |
| [`challenge-engine.md`](../docs/security/challenge-engine.md) | **Implemented** | `challenge/{ladder,captcha,token,mod}.rs`. |
| [`bot-management.md`](../docs/security/bot-management.md) | **Implemented** | `aegis-security/src/bots.rs`. |
| [`behavioral-analysis.md`](../docs/security/behavioral-analysis.md) | **Implemented** | `aegis-security/src/behavior.rs`. |
| [`transaction-velocity.md`](../docs/security/transaction-velocity.md) | **Implemented** | `aegis-security/src/velocity.rs`. |
| [`threat-intelligence.md`](../docs/security/threat-intelligence.md) | **Partial** | `threat_intel.rs` ships an in-memory `ThreatIntelStore` + indicator types. **No STIX/TAXII fetch loop** — feeds must be loaded by external code. |
| [`api-security.md`](../docs/security/api-security.md) | **Implemented** | `api_security/{api_keys,graphql,hmac_sign,mod}.rs`. |
| [`content-scanning.md`](../docs/security/content-scanning.md) | **Partial** | `content/{archive,icap,mod}.rs` — archive-bomb guard real, **ICAP client is a trait + types stub** (no concrete TCP client). |
| [`dlp.md`](../docs/security/dlp.md) | **Implemented** | `dlp/{fpe,mod}.rs` — pattern matching + AES-FF1 FPE. |
| [`response-filtering.md`](../docs/security/response-filtering.md) | **Implemented** | `aegis-security/src/response_filter.rs`. |
| [`external-auth.md`](../docs/security/external-auth.md) | **Implemented** | `auth/{basic,forward,jwt,opa,mod}.rs`. |

### Detectors

| Doc | Status | Notes |
|---|---|---|
| [`detectors/sqli.md`](../docs/security/detectors/sqli.md) | **Implemented** | `detectors/sqli.rs`. |
| [`detectors/xss.md`](../docs/security/detectors/xss.md) | **Implemented** | `detectors/xss.rs`. |
| [`detectors/path-traversal.md`](../docs/security/detectors/path-traversal.md) | **Implemented** | `detectors/path_traversal.rs`. |
| [`detectors/ssrf.md`](../docs/security/detectors/ssrf.md) | **Implemented** | `detectors/ssrf.rs`. |
| [`detectors/header-injection.md`](../docs/security/detectors/header-injection.md) | **Implemented** | `detectors/header_injection.rs`. |
| [`detectors/recon.md`](../docs/security/detectors/recon.md) | **Implemented** | `detectors/recon.rs`. |
| [`detectors/body-abuse.md`](../docs/security/detectors/body-abuse.md) | **Implemented** | `detectors/body_abuse.rs`. |
| [`detectors/brute-force.md`](../docs/security/detectors/brute-force.md) | **Partial** | `BruteForce` is a `DetectorClass` enum variant + audit/api surface; the actual brute-force logic is delivered through `velocity.rs` (login-failure counter). No dedicated `detectors/brute_force.rs`. |

## 1.5 Control plane (M3 / aegis-control)

| Doc | Status | Notes / module path |
|---|---|---|
| [`dashboard.md`](../docs/control-plane/dashboard.md) | **Implemented** | `aegis-control/src/dashboard/{mod,assets,dispatch,sse,overview,security}.rs` + 27 read-only `/api/*` handlers + bundled SPA assets. |
| [`dashboard-auth.md`](../docs/control-plane/dashboard-auth.md) | **Implemented** | `admin_auth/{password,session,csrf,mtls,rate_limit,totp,mod}.rs`. |
| [`config-hot-reload.md`](../docs/control-plane/config-hot-reload.md) | **Implemented** | `gitops::dry_run_validate` + `secrets.rs` resolver + reload signal. |
| [`gitops-change-management.md`](../docs/control-plane/gitops-change-management.md) | **Partial** | `gitops.rs` ships `GitClient` trait + signature verification (PGP/SSH) + dry-run validate + `GitOpsLoader`. **No concrete git poll-and-pull driver** wired into the runtime — `GitClient` is a trait without a built-in implementation. |
| [`secrets-management.md`](../docs/control-plane/secrets-management.md) | **Partial** | `aegis-proxy/src/secrets.rs` — `env` and `file` providers work. **Vault / AWS SM / GCP SM / Azure KV / HSM return `NotImplemented`.** |
| [`zero-downtime-ops.md`](../docs/control-plane/zero-downtime-ops.md) | **Partial** | `supervisor.rs` + `hotbin.rs` + drain logic in `lib.rs`; SO_REUSEPORT exists in the listener layer. **No live binary-handover via fd-passing** — restart is via supervised re-exec only. |
| [`enterprise/`](../docs/control-plane/enterprise/) | **Implemented** | D-M1..D-M6 closed; SPA bundled into the binary, served from `/dashboard/`. Re-design track (`plans/dashboard-redesign/`) is the next phase. |

## 1.6 Observability

| Doc | Status | Notes / module path |
|---|---|---|
| [`prometheus-otel.md`](../docs/observability/prometheus-otel.md) | **Implemented** | `metrics/{exporter,request_duration,mod}.rs` + `tracing_init.rs` + `access_log.rs`. Per-stage WAF latency histogram landed F-T10. |
| [`audit-logging.md`](../docs/observability/audit-logging.md) | **Implemented** | `audit/{chain,verify,witness,state_snapshot,mod}.rs`. SHA-256 hash chain + `audit verify` CLI + verbosity gating (P8). |
| [`siem-log-forwarding.md`](../docs/observability/siem-log-forwarding.md) | **Implemented** | All 8 sinks present: `audit/sinks/{cef,ecs,jsonl,kafka,leef,ocsf,splunk_hec,syslog}.rs`. Cold-tier surface @ `/api/cold-tier`. |
| [`slo-sli-alerting.md`](../docs/observability/slo-sli-alerting.md) | **Implemented** | `slo.rs` (674 lines) — 5 SLI kinds, multi-burn windows, 5 receiver kinds. |

## 1.7 Operations

| Doc | Status | Notes / module path |
|---|---|---|
| [`ha-clustering.md`](../docs/operations/ha-clustering.md) | **Partial** | `StateBackend` trait + `InMemoryBackend` shipped; `RedisBackendStub` carries config + Lua scripts only — **no `redis_cluster` / `raft` / `foca_swim` backends**, no cross-node leader lease, no rehydrate phase. `aegis-bin/src/main.rs:83-84` always wires `InMemoryBackend`. Fine for single node; "HA cluster" is not delivered. |
| [`compliance.md`](../docs/operations/compliance.md) | **Implemented** | `compliance/{fips,gdpr,hipaa,pci,soc2,mod}.rs` — full mode matrix. |
| [`data-residency-retention.md`](../docs/operations/data-residency-retention.md) | **Implemented** | `aegis-control/src/residency.rs` — `sweep`, `erase_subject`, `rechain`, region pin, retention policy. |
| [`dr-backup.md`](../docs/operations/dr-backup.md) | **Partial** | `aegis-proxy/src/dr.rs` ships `SnapshotMeta` + structure; the `waf snapshot` / `waf restore` CLI subcommands and the `.tar.zst` writer are **not** wired. |

## 1.8 Future

| Doc | Status | Notes |
|---|---|---|
| [`advanced-features.md`](../docs/future/advanced-features.md) | **Intake template** | Open process for Phase B candidates. |
| [`multi-tenancy.md`](../docs/future/multi-tenancy.md) | **Deferred** | No production code; design preserved. |
| [`rbac-sso.md`](../docs/future/rbac-sso.md) | **Deferred** | No production code; OIDC / SAML / RBAC retained as future reference. |

---

## 1.9 Phase B candidate seeds (suggested)

The audit above surfaces concrete gaps. Each is a candidate for the
[`advanced-features.md`](../docs/future/advanced-features.md) intake;
none are in flight today.

| # | Gap | Doc affected | Suggested track |
|---|---|---|---|
| 1 | Real Redis backend (replace `RedisBackendStub` with a `deadpool-redis` impl + Lua eval + reconnect) | `operations/ha-clustering.md` | `aegis-proxy` |
| 2 | Cross-node leader lease (Redis SET NX EX) + gate ACME + GitOps + threat-intel + witness export on lease | `operations/ha-clustering.md` | `aegis-proxy` |
| 3 | Service-discovery adapters: Consul, etcd, k8s | `data-plane/service-discovery.md` | `aegis-proxy` |
| 4 | GeoIP filter — MaxMind reader + country/ASN match in rule engine | `security/geoip-filtering.md` | `aegis-security` |
| 5 | STIX/TAXII fetch loop into `ThreatIntelStore` | `security/threat-intelligence.md` | `aegis-security` |
| 6 | Concrete ICAP TCP client implementing `IcapClient` | `security/content-scanning.md` | `aegis-security` |
| 7 | Vault / AWS SM / GCP SM / Azure KV / HSM secret resolvers | `control-plane/secrets-management.md` | `aegis-proxy` |
| 8 | `waf snapshot` / `waf restore` CLI + `.tar.zst` (de)serializer | `operations/dr-backup.md` | `aegis-bin` + `aegis-proxy` |
| 9 | HTTP/3 support (quinn / h3) | `architecture/protocols.md` | `aegis-proxy` |
| 10 | Built-in git poll driver implementing `GitClient` | `control-plane/gitops-change-management.md` | `aegis-control` |
| 11 | Benchmark mode (`X-Aegis-*` headers + dashboard panels) — `plans/benchmark-mode.md` is the live track | `operator/benchmark-mode.md` | cross-crate |

These are the eleven most-referenced "deferred but useful" gaps the
matrix above produces. When one is accepted into Phase B, move its
row out of this list and into the appropriate doc + track.

