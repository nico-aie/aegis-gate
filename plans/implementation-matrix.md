# Implementation Matrix

> **Status:** Living matrix — update whenever a feature graduates
> from Partial / Designed-only to Implemented (or vice-versa).

The single source of truth for "what's actually shipped" vs "what's
specified in `docs/`". Each doc carries a one-line `> **Status:**`
banner that mirrors a row here; the banner is generated from this
table — keep them in sync.

**As of:** 2026-05-03 (post HACK-T1..T5 + rollback v6 + MTLS-T7..T11 + TCP-T1..T6 CONNECT tunneling + FDP-T1..T6 binary-handover primitives + SWEEP-T tooling + AI-T design lock-in + geoip XFF + dashboard 3-state pill).

> **Verify before relying on a row.** Codebase moves; before acting
> on any "Implemented" claim, check the named module path. When
> status changes, update the doc banner *and* this table together.

## Status legend

| Status | Meaning |
|---|---|
| **Implemented** | Production-ready code wired into the runtime, with unit + integration tests. |
| **Partial** | Core path is in code; specific advertised pieces (a backend, a feature gate, a sub-mode) are missing. The doc calls out which parts are stubs. |
| **Designed only** | The doc has a full spec but no production code (or only types/traits with no concrete impl). |
| **Deferred** | Explicitly deferred — design preserved for future work, not on any current track. |

---

## 1. Operator

| Doc | Status | Notes / module path |
|---|---|---|
| [`docs/operator/usage.md`](../docs/operator/usage.md) | **Implemented** | Operator runbook is current; references real subcommands. |
| [`docs/operator/cli.md`](../docs/operator/cli.md) | **Implemented** | Every subcommand exists in `aegis-bin/src/main.rs`. |
| [`docs/operator/benchmark-mode.md`](../docs/operator/benchmark-mode.md) | **Implemented** (core slice) | `aegis-proxy::benchmark`: `BenchmarkConfig` + `StageTimings` + `X-Aegis-*` header serialiser; wired into `proxy::handle_request`. IP allowlist / HMAC tokens / dashboard panel deferred. |

## 2. Architecture

| Doc | Status | Notes / module path |
|---|---|---|
| [`docs/architecture/protocols.md`](../docs/architecture/protocols.md) | **Implemented** | HTTP/1.1 + HTTP/2 + WebSocket + gRPC: `aegis-proxy/src/proto/{h2,ws,grpc}.rs`; HTTP/3: `listener/http3.rs` (gated by `aegis-proxy/http3` — quinn 0.11 + h3 0.0.8 + h3-quinn 0.0.10). |

## 3. Data plane (M1 / aegis-proxy)

| Doc | Status | Notes / module path |
|---|---|---|
| [`reverse-proxy.md`](../docs/data-plane/reverse-proxy.md) | **Implemented** | `aegis-proxy/src/{lib,proxy,supervisor}.rs`. Multi-protocol upstream complete 2026-05-03 (HTTP/HTTPS/H2c/gRPC/CONNECT-tunneling-via-`scheme:tcp`); see plan [`tcp-forwarder-phase-4.md`](./tcp-forwarder-phase-4.md). |
| [`routing-ingress.md`](../docs/data-plane/routing-ingress.md) | **Implemented** | `aegis-proxy/src/route/{host,path,mod}.rs`. |
| [`upstream-pools.md`](../docs/data-plane/upstream-pools.md) | **Implemented** | `aegis-proxy/src/upstream/{lb,health,circuit,tls,mod}.rs`. 5 LB strategies, health checks, circuit breaker. |
| [`traffic-management.md`](../docs/data-plane/traffic-management.md) | **Implemented** | `aegis-proxy/src/traffic.rs` — canary, steering, shadow mirror, retries. |
| [`tls-termination.md`](../docs/data-plane/tls-termination.md) | **Implemented** | `listener/{tls,tls_policy}.rs` + `acme.rs` + `acme_instant.rs` + `ocsp.rs`. P4 hardening + P5 ACME via Pebble (F-T7/F-T8). |
| [`session-affinity.md`](../docs/data-plane/session-affinity.md) | **Implemented** | `aegis-proxy/src/session.rs`. |
| [`per-route-quotas.md`](../docs/data-plane/per-route-quotas.md) | **Implemented** | `aegis-proxy/src/quota.rs`. |
| [`transformations-cors.md`](../docs/data-plane/transformations-cors.md) | **Implemented** | `aegis-proxy/src/transform/{cors,vars,mod}.rs`. |
| [`service-discovery.md`](../docs/data-plane/service-discovery.md) | **Implemented** | B2 closed (T5..T7): `sd/mod.rs` (file + diff + churn) + feature-gated `consul` / `etcd` / `k8s` watchers. DNS SRV remains designed-only. |
| [`smart-caching.md`](../docs/data-plane/smart-caching.md) | **Implemented** | `aegis-proxy/src/cache/mod.rs` — `TierCache`, vary-aware, max-age honored. |
| [`adaptive-load-shedding.md`](../docs/data-plane/adaptive-load-shedding.md) | **Implemented** | `aegis-proxy/src/shed.rs` + `aegis-core/src/load_mode.rs` (P7). |
| [`graceful-degradation.md`](../docs/data-plane/graceful-degradation.md) | **Implemented** | Circuit breaker (`upstream/circuit.rs`) + load shedder (`shed.rs`) + cache fallback. |

## 4. Security pipeline (M2 / aegis-security)

| Doc | Status | Notes / module path |
|---|---|---|
| [`rule-engine.md`](../docs/security/rule-engine.md) | **Implemented** | `aegis-security/src/rules/{ast,eval,parser,linter,mod}.rs`. |
| [`tiered-protection.md`](../docs/security/tiered-protection.md) | **Implemented** | `aegis-core/src/tier.rs` + per-tier detector mask overrides (P2/P3). |
| [`rate-limiting.md`](../docs/security/rate-limiting.md) | **Implemented** | `rate_limit/{bucket,sliding,ip_limiter,mod}.rs`. |
| [`ddos-protection.md`](../docs/security/ddos-protection.md) | **Implemented** | `aegis-security/src/ddos.rs`. |
| [`ip-reputation.md`](../docs/security/ip-reputation.md) | **Partial** | `ip_rep/{asn,xff,mod}.rs` — XFF validation + ASN matching. **No live threat-intel feed fetcher** — Phase B **B3-T2**. |
| [`geoip-filtering.md`](../docs/security/geoip-filtering.md) | **Implemented** | `geoip/{mod,reader}.rs` (gated by `aegis-security/geoip`) + rule-engine `country` / `asn` conditions with hot-reload. |
| [`device-fingerprinting.md`](../docs/security/device-fingerprinting.md) | **Implemented** | `fingerprint/{ja3,ja4,h2,mod}.rs`. |
| [`risk-scoring.md`](../docs/security/risk-scoring.md) | **Implemented** | `risk/{tracker,mod}.rs` + `aegis-core::RiskKey`. P6 strikes + trust recovery. |
| [`challenge-engine.md`](../docs/security/challenge-engine.md) | **Implemented** | `challenge/{ladder,captcha,token,mod}.rs`. |
| [`bot-management.md`](../docs/security/bot-management.md) | **Implemented** | `aegis-security/src/bots.rs`. |
| [`behavioral-analysis.md`](../docs/security/behavioral-analysis.md) | **Implemented** | `aegis-security/src/behavior.rs`. |
| [`transaction-velocity.md`](../docs/security/transaction-velocity.md) | **Implemented** | `aegis-security/src/velocity.rs`. |
| [`threat-intelligence.md`](../docs/security/threat-intelligence.md) | **Implemented** | `threat_intel/mod.rs` (store) + `threat_intel/taxii.rs` (TAXII 2.1 client + fetcher loop, gated by `aegis-security/taxii`). |
| [`api-security.md`](../docs/security/api-security.md) | **Implemented** | `api_security/{api_keys,graphql,hmac_sign,mod}.rs`. |
| [`content-scanning.md`](../docs/security/content-scanning.md) | **Implemented** | `content/icap/{mod,codec,tcp}.rs` — RFC 3507 TCP client + pure framing helpers + decision table covering 5 vendor infection-header forms. |
| [`dlp.md`](../docs/security/dlp.md) | **Implemented** | `dlp/{fpe,mod}.rs` — pattern matching + AES-FF1 FPE. |
| [`response-filtering.md`](../docs/security/response-filtering.md) | **Implemented** | `aegis-security/src/response_filter.rs`. |
| [`external-auth.md`](../docs/security/external-auth.md) | **Implemented** | `auth/{basic,forward,jwt,opa,mod}.rs`. |

### Detectors

| Doc | Status | Notes |
|---|---|---|
| [`detectors/sqli.md`](../docs/security/detectors/sqli.md) | **Implemented** | `detectors/sqli.rs`. |
| [`detectors/xss.md`](../docs/security/detectors/xss.md) | **Implemented** | `detectors/xss.rs`. |
| [`detectors/path-traversal.md`](../docs/security/detectors/path-traversal.md) | **Implemented** | `detectors/path_traversal.rs` — Run-5 GAP-002 added overlong UTF-8 (`%c0%ae{2,}`, `%c0%af`, `%c0%5c`, `%c1%9c`) + Docker socket path (`/var/run/docker.sock`). |
| [`detectors/ssrf.md`](../docs/security/detectors/ssrf.md) | **Implemented** | `detectors/ssrf.rs` — Run-5 GAP-004 added URL-userinfo pattern (`https?://[^@/\s]+@`) for parser-split bypass attacks. |
| [`detectors/header-injection.md`](../docs/security/detectors/header-injection.md) | **Implemented** | `detectors/header_injection.rs` — Run-4 SEC-L002 X-Forwarded-Host keyword detection + Run-5 GAP-005 internal-IP literal detection (RFC 1918 / loopback / link-local IPv4 + IPv6 loopback / link-local). |
| [`detectors/recon.md`](../docs/security/detectors/recon.md) | **Implemented** | `detectors/recon.rs` — Run-4 SEC-L001 Docker REST + Run-5 GAP-001 framework recon (Spring actuator dangers / Laravel Ignition / Swagger / GraphQL / K8s API / Kibana / Jenkins / CGI / Prometheus federation). Path scan now uses `path_and_query()` so query-shaped probes (`/metrics?format=…`) match. |
| [`detectors/body-abuse.md`](../docs/security/detectors/body-abuse.md) | **Implemented** | `detectors/body_abuse.rs` — Run-5 GAP-010 prototype pollution (`__proto__`, `constructor.prototype`) sub-tag `proto_pollution` at score 45 alongside existing oversize / deep-nesting / mass-assign / XXE. |
| [`detectors/brute-force.md`](../docs/security/detectors/brute-force.md) | **Partial** | `BruteForce` is a `DetectorClass` enum variant; the actual detection is via `velocity.rs` (login-failure counter). No dedicated `detectors/brute_force.rs`. |
| [`detectors/command-injection.md`](../docs/security/detectors/command-injection.md) | **Implemented** | `detectors/command_injection.rs` (2026-05-08 SEC-M002 + Run-5 GAP-008 Log4Shell). Regex-only — `$()`, backticks, `\|cmd`, `;cmd`, `/bin/sh`, reverse-shell shapes, plus `${jndi:...}` at score 60 (CVE-2021-44228). Headers (UA / Referer / Authorization / etc.) scanned for Log4Shell. |
| [`detectors/template-injection.md`](../docs/security/detectors/template-injection.md) | **Implemented** | `detectors/template_injection.rs` (2026-05-08 Run-5 GAP-006). Regex-only — Jinja2 `{{config}}` / Twig / Mako / Freemarker `<#assign>` / Velocity `#set()` / SpEL `${T(...)}` / Handlebars `{{#with}}`. Score 50. |
| [`detectors/nosql-injection.md`](../docs/security/detectors/nosql-injection.md) | **Implemented** | `detectors/nosql_injection.rs` (2026-05-08 Run-5 GAP-007). Regex-only — MongoDB operator allowlist (`$ne`, `$gt`, `$where`, etc.) in query strings (`?param[$ne]=x`) and JSON bodies (`{"$where":"..."}`). Score 50. |
| [`detectors/open-redirect.md`](../docs/security/detectors/open-redirect.md) | **Implemented** | `detectors/open_redirect.rs` (2026-05-09 Run-5 GAP-009). Closed-list redirect-param names + URL-shape regex set; `cfg.detectors.open_redirect.allowed_domains` allowlist (literal or `*.glob`). Score 30 (phishing tier). |

## 5. Control plane (M3 / aegis-control)

| Doc | Status | Notes / module path |
|---|---|---|
| [`dashboard.md`](../docs/control-plane/dashboard.md) | **Implemented** | `dashboard/{mod,assets,dispatch,sse,overview,security}.rs` + 27 read-only `/api/*` handlers + bundled SPA. |
| [`dashboard-auth.md`](../docs/control-plane/dashboard-auth.md) | **Implemented** | `admin_auth/{password,session,csrf,mtls,rate_limit,totp,mod}.rs`. |
| [`config-hot-reload.md`](../docs/control-plane/config-hot-reload.md) | **Implemented** | `gitops::dry_run_validate` + `secrets.rs` resolver + reload signal. |
| [`gitops-change-management.md`](../docs/control-plane/gitops-change-management.md) | **Partial** | `GitClient` trait + signature verify + dry-run + `GitOpsLoader`. **No concrete git poll-and-pull driver** — Phase B **B3-T1**. |
| [`secrets-management.md`](../docs/control-plane/secrets-management.md) | **Implemented** (cloud quartet) | B2-T1..T4 closed: `env` + `file` (sync) + feature-gated `vault` / `aws` / `gcp` / `azure` resolvers. **HSM** still returns `NotImplemented` — B6-T4. |
| [`zero-downtime-ops.md`](../docs/control-plane/zero-downtime-ops.md) | **Partial** | `supervisor.rs` + `hotbin.rs` + drain. **B6-T5 fd-pass library shipped 2026-05-03** (FDP-T1..T6: `adopt_inherited_listeners` / `spawn_successor` / `bridge_tunnel` / `InFlightCounter` / `perform_handover` / `ReadinessPipe` / SIGUSR2 listener / systemd `LISTEN_FDS` compat — 26 new tests). One gap: accept-loop drain refactor that lets SIGUSR2 actually invoke `perform_handover` — see [`binary-handover-fd-pass.md`](./binary-handover-fd-pass.md) §11. |
| [`enterprise/`](../docs/control-plane/enterprise/) | **Implemented** | D-M1..D-M6 closed; SPA bundled into the binary, served from `/dashboard/`. Dashboard-redesign track is queued behind Phase B. |

## 6. Observability

| Doc | Status | Notes / module path |
|---|---|---|
| [`prometheus-otel.md`](../docs/observability/prometheus-otel.md) | **Implemented** | `metrics/{exporter,request_duration,mod}.rs` + `tracing_init.rs` + `access_log.rs`. Per-stage WAF latency landed F-T10. |
| [`audit-logging.md`](../docs/observability/audit-logging.md) | **Implemented** | `audit/{chain,verify,witness,state_snapshot,mod}.rs`. SHA-256 hash chain + `audit verify` CLI + verbosity gating (P8). |
| [`siem-log-forwarding.md`](../docs/observability/siem-log-forwarding.md) | **Implemented** | All 8 sinks: `audit/sinks/{cef,ecs,jsonl,kafka,leef,ocsf,splunk_hec,syslog}.rs`. Cold-tier surface @ `/api/cold-tier`. |
| [`slo-sli-alerting.md`](../docs/observability/slo-sli-alerting.md) | **Implemented** | `slo.rs` (674 lines) — 5 SLI kinds, multi-burn windows, 5 receiver kinds. |

## 7. Operations

| Doc | Status | Notes / module path |
|---|---|---|
| [`ha-clustering.md`](../docs/operations/ha-clustering.md) | **Implemented** | B1 closed (T1..T6): `RedisBackend` (deadpool-redis + Lua) + `LeaseStore` trait with Redis impl + heartbeat + `run_with_lease` (ACME gated), `rehydrate` warm-up gating `/healthz/ready`, `ReconcilingBackend` (block-list union + fallback on partition). `redis_cluster` / `raft` / `foca_swim` remain Phase B candidates beyond B1. |
| [`compliance.md`](../docs/operations/compliance.md) | **Implemented** | `compliance/{fips,gdpr,hipaa,pci,soc2,mod}.rs` — full mode matrix. |
| [`data-residency-retention.md`](../docs/operations/data-residency-retention.md) | **Implemented** | `aegis-control/src/residency.rs` — sweep, erase_subject, rechain, region pin, retention policy. |
| [`dr-backup.md`](../docs/operations/dr-backup.md) | **Implemented** (config + rules) | `aegis-bin::snapshot` ships `waf snapshot` + `waf restore`; JSON envelope with blake3 hash + schema versioning + dry-run validation on restore. State-backend / audit-log restore remain external-system flows. |

## 8. Future

| Doc | Status | Notes |
|---|---|---|
| [`advanced-features.md`](../docs/future/advanced-features.md) | **Intake template** | Open process for proposals NOT covered by Phase B. |
| [`multi-tenancy.md`](../docs/future/multi-tenancy.md) | **Deferred** | No production code; design preserved. |
| [`rbac-sso.md`](../docs/future/rbac-sso.md) | **Deferred** | No production code; OIDC / SAML / RBAC retained as future reference. |

---

## Phase B mapping

Every **Partial** / **Designed-only** row above maps to a Phase B
task in [`phase-b/README.md`](./phase-b/README.md). Closing a Phase
B milestone graduates the corresponding rows here to **Implemented**
in lockstep — keep the table and the milestone status in sync.

| Milestone | Theme | Closes these matrix rows |
|---|---|---|
| ~~**B1**~~ ✅ | HA & multi-node — **closed 2026-04-29** | ~~`ha-clustering.md`~~ flipped to Implemented |
| ~~**B2**~~ ✅ | Operational integrations — **closed 2026-04-29** (HSM deferred to B6-T4) | ~~`secrets-management.md` (most), `service-discovery.md`~~ both flipped to Implemented |
| ~~**B3**~~ ✅ | Data feeds + filtering — **closed 2026-04-29** (B3-T1..T4) | ~~`threat-intelligence.md`, `geoip-filtering.md`, `content-scanning.md`~~ all flipped to Implemented; `gitops-change-management.md` driver lands but banner stays Partial pending boot-site lease wrap |
| ~~**B4**~~ ✅ | Operator tooling — **closed 2026-04-29** (B4-T1..T4) | ~~`dr-backup.md`~~ flipped Implemented; upstream-proxy + SSE carry-overs removed |
| ~~**B5**~~ ✅ | Protocols + benchmark — **closed 2026-04-29** (B5-T1 + B5-T2) | ~~`protocols.md`, `benchmark-mode.md`~~ both flipped Implemented |
| **B6** | Production packaging | `secrets-management.md` (HSM), `zero-downtime-ops.md` |
