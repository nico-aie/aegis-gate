# Member 3 — Control Plane & Ops

**Read [`shared-contract.md`](./shared-contract.md) first.**

**Mission:** operators can *see, audit, and govern* the WAF. You own the
admin listener, dashboard, RBAC/SSO, Prometheus/OTEL, audit hash-chain,
SIEM forwarding, multi-tenancy surfaces, compliance profiles, GitOps
loader, and SLO alerts.

**Crate:** `crates/aegis-control/`

---

## 1. Crate Layout

```
crates/aegis-control/
├── Cargo.toml
└── src/
    ├── lib.rs                # pub async fn start(cfg, bus, metrics)
    ├── server.rs             # axum router mount on admin listener
    ├── health.rs             # /healthz/{live,ready,startup}
    ├── metrics/
    │   ├── mod.rs            # pub fn init() -> MetricsRegistry
    │   └── exporter.rs       # /metrics handler
    ├── tracing_init.rs       # tracing-subscriber + OTLP (feature = "otel")
    ├── access_log.rs         # combined / json / template writer
    ├── dashboard/
    │   ├── mod.rs
    │   ├── routes.rs         # /dashboard/* pages
    │   └── sse.rs            # live event feed (subscribes to AuditBus)
    ├── api/
    │   ├── mod.rs            # REST admin API
    │   ├── config.rs         # GET/PUT /api/config (secrets masked)
    │   ├── rules.rs          # CRUD rules
    │   ├── routes_api.rs     # CRUD routes + upstreams
    │   ├── tenants.rs        # CRUD tenants
    │   ├── tokens.rs         # API token management
    │   └── audit.rs          # GET /api/audit, /api/audit/verify
    ├── auth/
    │   ├── mod.rs            # role check middleware
    │   ├── oidc.rs           # OIDC relying party
    │   ├── rbac.rs           # require_role! macro
    │   ├── tokens.rs         # argon2 API tokens
    │   └── mtls.rs           # admin mTLS acceptor
    ├── audit/
    │   ├── mod.rs            # chain writer
    │   ├── chain.rs          # SHA-256 hash chain
    │   ├── verify.rs         # `waf audit verify` CLI
    │   ├── witness.rs        # S3 / append-only export
    │   └── sinks/
    │       ├── jsonl.rs
    │       ├── syslog.rs     # RFC 5424
    │       ├── cef.rs
    │       ├── leef.rs
    │       ├── ocsf.rs
    │       ├── splunk_hec.rs
    │       ├── ecs.rs        # Elastic ECS
    │       └── kafka.rs
    ├── tenant.rs             # isolation boundary helpers
    ├── compliance/
    │   ├── mod.rs            # profile stacking
    │   ├── fips.rs
    │   ├── pci.rs
    │   ├── soc2.rs
    │   ├── gdpr.rs
    │   └── hipaa.rs
    ├── residency.rs          # region pins + retention + right-to-erasure
    ├── gitops.rs             # signed-commit loader + dry-run swap
    └── slo.rs                # multi-window multi-burn-rate alerts
```

---

## 2. Weekly Task Breakdown

### Week 1 — Admin Listener, Health, Dashboard Skeleton

**T1.1** — `MetricsRegistry` init
- File: `src/metrics/mod.rs`
- `pub fn init() -> MetricsRegistry { MetricsRegistry(Arc::new(prometheus::Registry::new())) }`
- Expose this before M1/M2 boot so they can register families.

**T1.2** — Admin listener + axum router
- File: `src/server.rs`, `src/lib.rs`
- `pub async fn start(cfg: Arc<ArcSwap<WafConfig>>, bus: AuditBus, metrics: MetricsRegistry) -> Result<()>`
- Binds `cfg.admin.listen` (e.g. `127.0.0.1:9443`), mounts:
  - `GET /healthz/{live,ready,startup}`
  - `GET /metrics`
  - `GET /dashboard/*`
  - `GET /dashboard/sse`
  - `GET|PUT /api/*`
- Test: `curl localhost:9443/healthz/live` returns 200.

**T1.3** — Health endpoints
- File: `src/health.rs`
- `/live` = process up. `/ready` = state backend reachable + certs loaded + ≥1 healthy member per pool (queried via signal channel from M1). `/startup` = first config load complete.
- Test: flip readiness via signal, assert 503 → 200 transition.

**T1.4** — Dashboard shell + SSE
- Files: `src/dashboard/mod.rs`, `src/dashboard/sse.rs`
- Static HTML/JS shell (vendored, no build step). SSE endpoint subscribes to `AuditBus`, streams events filtered by user role + tenant.
- Test: subscribe, emit event via bus, assert delivered.

**T1.5** — `GET /api/config` (secrets masked)
- File: `src/api/config.rs`
- Return effective `WafConfig` as JSON; `${secret:*}` references never resolved in response.
- Test: fixture with `${secret:env:FOO}` — response contains the reference string.

**Week 1 exit:** healthz green, dashboard shell loads, SSE ticks an event when M1 reloads config.

---

### Week 2 — Observability

**T2.1** — Prometheus exporter
- File: `src/metrics/exporter.rs`
- `GET /metrics` returns text format from shared registry. Histogram buckets tuned for ms-range latencies.
- Test: scrape via `reqwest`, parse via `prometheus-parse`, assert expected families.

**T2.2** — Tracing init + OTLP
- File: `src/tracing_init.rs`
- `tracing-subscriber` with JSON layer to stdout. Feature `otel`: add `opentelemetry-otlp` batch exporter. Root span `waf.request` with child spans for pipeline stages + upstream.
- Test: feature-gated integration test asserts OTLP endpoint receives spans (wiremock).

**T2.3** — W3C Trace Context middleware
- Provide a helper `pub fn ensure_trace_context(headers: &mut HeaderMap) -> String` used by M1. Accept `traceparent`/`tracestate`; generate when missing.
- Test: round-trip.

**T2.4** — Access log writer
- File: `src/access_log.rs`
- Formats: `combined`, `json` (ECS-compatible), template (`%{var}` placeholders). Output: stdout or rotating file via `tracing-appender`.
- Consumes a bounded channel M1 writes into; backpressure drops with metric increment.
- Test: one golden line per format.

---

### Week 3 — Audit Hash Chain + SIEM Sinks

**T3.1** — Chain writer
- File: `src/audit/chain.rs`
- `pub struct Chain { prev_hash: [u8;32] }`
- For each event: `canonical = serde_json::to_vec(&event_canonical)`; `hash = sha256(prev_hash || canonical)`; persist `(hash, event)` to on-disk spool.
- Test: tamper with a line in the spool, assert verifier detects break.

**T3.2** — `waf audit verify` CLI
- File: `src/audit/verify.rs`
- Walk spool, recompute chain, report first break. Exit non-zero on break.
- Test: round-trip OK; tampered line fails.

**T3.3** — Sinks (one file each)
- Files under `src/audit/sinks/`
- Each sink: `pub trait AuditSink { async fn write(&self, ev: &AuditEvent) -> Result<()>; }`
- Bounded channel per sink; on-disk spool for backpressure; priority drop (lowest severity first; `Admin` + `Critical` never dropped silently — increment a paging metric).
- Test per sink: wiremock (HEC, Kafka via embedded broker, syslog UDP listener).

**T3.4** — Admin change log (separate chain)
- File: `src/audit/mod.rs`
- Distinct chain for `AuditClass::Admin`. Every admin mutation records actor, target, JSON diff, reason, approver.
- Test: mutate config via API, assert admin chain records diff.

**T3.5** — Witness export
- File: `src/audit/witness.rs`
- Periodic task signs chain head and exports to S3 Object Lock / append-only log. Feature-gated.

---

### Week 4 — RBAC, OIDC, Multi-Tenancy

**T4.1** — Roles + `require_role!`
- File: `src/auth/rbac.rs`
- `enum Role { Viewer, Operator, Admin, Auditor, BreakGlass }`
- `macro_rules! require_role { ($req:expr, $min:expr) => { ... } }` — extracts role from request extensions, returns 403 if insufficient.
- Test: viewer hits `PUT /api/rules` → 403; admin → 200.

**T4.2** — OIDC relying party
- File: `src/auth/oidc.rs`
- Providers: Okta, Azure AD, Google Workspace, Keycloak. Group claim → role mapping from config.
- Session cookie is PASETO v4 local; absolute lifetime + idle TTL.
- Test: mock IdP (wiremock), simulate auth code flow, assert session cookie + role.

**T4.3** — API tokens
- File: `src/auth/tokens.rs`
- Stored as `argon2id` hashes; scoped permissions, IP allowlist, TTL. Admin IP allowlist enforced in addition to auth.
- Test: rotate token, old token rejected.

**T4.4** — Admin mTLS listener
- File: `src/auth/mtls.rs`
- Rustls with client cert required; chain verified against configured CA bundle. Admin plane refuses non-mTLS connections.
- Test: openssl client with valid cert → 200; without → handshake refused.

**T4.5** — Multi-tenancy boundaries
- File: `src/tenant.rs`
- Tenant as first-class config entity (id, name, quotas, allowed hosts, tier overrides, rule namespace, audit sinks, residency).
- State keyspace: every key passes through `tenant_key(tenant_id, key) -> String`.
- Dashboard + metrics projected through token's tenant claim.
- Test: 2-tenant fixture — tenant A viewer cannot see tenant B traffic in dashboard or `/api/audit`.

**T4.6** — Per-tenant quotas
- Enforce: RPS, concurrent conns, log volume, risk-store entries, rule count, route count, body size. Exceeding quota load-sheds that tenant only (coordinate with M1's shedder via a shared `TenantPressure` struct).
- Test: saturate tenant A, assert tenant B unaffected.

---

### Week 5 — Compliance, GitOps, SLO Alerts

**T5.1** — Compliance profiles stacking
- File: `src/compliance/mod.rs`
- `pub fn apply(profiles: &[ComplianceProfile], cfg: &mut WafConfig) -> Result<()>`
- Profiles: FIPS, PCI, SOC2, GDPR, HIPAA. Strictest setting wins; conflicts refused at load.
- Concrete enforcement:
  - FIPS: only `aws-lc-rs` FIPS provider — coordinate with M1 to pick provider at boot.
  - PCI: TLS ≥ 1.2 on PCI-scope listeners; PAN masking enforced (DLP pattern enabled); audit retention ≥ 90d.
  - SOC2: tamper-evident chain active; admin change trail mandatory; SLO alerts enabled.
  - GDPR: PII redaction before egress; residency pinning `strict`; retention ceilings applied.
  - HIPAA: PHI-safe log mode (drop request bodies + flagged headers on PHI routes).
- Test: per-profile fixture — boot, assert enforced settings; conflicting combo rejected.

**T5.2** — Data residency + retention + right-to-erasure
- File: `src/residency.rs`
- Region pin per tenant; audit sinks / state writes / metric exports respect pin. `strict` refuses non-compliant sinks; `preferred` warns.
- Retention per event class. Pseudonymization job after N days (salted hash of IP/UA/JWT sub).
- Right-to-erasure: `POST /api/gdpr/erase` purges operational state; audit entries pseudonymized in place so hash chain stays valid. Dual-control required.
- Data export: `GET /api/gdpr/export?subject=...` streams JSONL.
- Test: erase flow, verify chain still verifies after pseudonymization.

**T5.3** — GitOps loader
- File: `src/gitops.rs`
- Poll (or webhook) a Git repo; verify commit signatures (GPG/SSH) against `allowed_signers` on every pull. Run same validator as runtime (dry-run) before `ArcSwap` swap.
- Break-glass: direct API edits allowed but auto-round-tripped as a branch + PR against the repo. Dashboard banner until merged.
- Test: push signed commit → applied; push unsigned → rejected; API edit → PR created (mock Git).

**T5.4** — Change approval workflow
- For mutations to `scope = Critical` config (rules touching Critical tier, tenants, compliance profile): require second admin approval before activation. Store pending changes in state backend with TTL.
- Test: admin A proposes → status pending; admin B approves → applied; TTL expires → dropped.

**T5.5** — SLO / SLI + alerts
- File: `src/slo.rs`
- SLIs: availability (non-5xx / total), WAF-overhead latency p50/p95/p99 (histogram provided by M1), upstream availability, admin API availability, audit delivery rate, config freshness, cert freshness.
- SLOs: data-plane availability 99.99% / 30d; p99 overhead ≤ 5 ms in 99% of 1-min windows; audit delivery 99.999%; cert freshness ≥ 7d.
- Multi-window multi-burn-rate (Google SRE): fast (1h/2%), slow (6h/5%), trickle (3d/10%).
- Alert routing: Alertmanager webhook compatible + direct Slack/PagerDuty/ServiceNow/Jira receivers. Each alert carries a runbook URL.
- Test: synthetic regression → fast-burn fires within 5 min; recover → clear.

---

## 3. Interfaces Consumed

- From M1: config reload events (via `AuditBus` + a `ReadinessSignal` channel), cert freshness signal, pool health state (read via a `SharedStatus` handle).
- From M2: `AuditEvent` stream on the bus, metric families in the shared registry.
- Provides to M1+M2: `MetricsRegistry` at boot, `TenantPressure` for the shedder.

## 4. Metrics You Own

```
waf_audit_events_total{class,sink,outcome}
waf_audit_spool_bytes{sink}
waf_audit_dropped_total{sink,severity}
waf_admin_requests_total{endpoint,role,status}
waf_admin_auth_failures_total{mechanism}
waf_config_reload_outcomes_total{source,outcome}
waf_slo_budget_remaining{sli}
waf_cert_expires_in_seconds{host}          (gauge)
waf_tenant_quota_usage_ratio{tenant,quota} (gauge)
```

## 5. API Surface (REST, all JSON)

```
GET    /healthz/{live,ready,startup}
GET    /metrics
GET    /api/config
PUT    /api/config                     (admin, dry-run validated)
GET    /api/rules
POST   /api/rules                      (operator+)
DELETE /api/rules/:id                  (admin)
GET    /api/routes, /api/upstreams
GET    /api/tenants
POST   /api/tenants                    (admin)
GET    /api/audit?since=&class=&tenant=
GET    /api/audit/verify
POST   /api/gdpr/erase                 (admin, dual-control)
GET    /api/gdpr/export?subject=
POST   /api/tokens                     (admin)
GET    /dashboard/*
GET    /dashboard/sse
```

## 6. Definition of Done (M3 exit criteria)

- [ ] `Requirement.md` §34 items: 9, 10, 14, 15, 17, 18, 19, 25, 28.
- [ ] OIDC login works against a mock IdP; viewer cannot mutate.
- [ ] 2-tenant isolation test: A cannot see B's traffic / audit / metrics.
- [ ] Hash chain verifies clean; tampered log is detected by CLI.
- [ ] SIEM forwarder delivers to at least 3 sinks in an integration test.
- [ ] SLO burn alert fires via Alertmanager webhook on synthetic regression.
- [ ] FIPS profile boots; non-FIPS algs refused at load.
- [ ] All W1–W5 tests green; `cargo clippy -p aegis-control -- -D warnings` clean.

## 7. Working with an AI Assistant

```
Read: plans/shared-contract.md and plans/member-3-control-plane.md

Task: <T-number and title>
File: <path>
Signature: <copy>
Behavior: <copy>

Constraints:
- Depend only on aegis-core.
- Never import aegis-proxy or aegis-security directly — interact via
  AuditBus, MetricsRegistry, and the ReadinessSignal channel.
- Every admin mutation must emit an AuditClass::Admin event with
  actor, target, diff, reason.
- Secrets must never appear in any response body.
- Run `cargo test -p aegis-control` before finishing.
```
