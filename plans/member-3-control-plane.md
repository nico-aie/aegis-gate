# Member 3 — Control Plane & Ops

**Read [`shared-contract.md`](./shared-contract.md) first.**

**Mission:** operators can *see, audit, and govern* the WAF. You own the
admin listener, dashboard, local dashboard authentication (argon2id +
HMAC session + CSRF + IP allowlist + optional TOTP/mTLS), Prometheus/OTEL,
audit hash-chain, SIEM forwarding, compliance profiles, GitOps loader,
and SLO alerts.

> **Scope notes (v1).** OIDC/SSO, RBAC roles, and multi-tenancy are
> deferred — see `docs/deferred/rbac-sso.md` and
> `docs/deferred/multi-tenancy.md`. v1 ships one admin principal with
> full privileges; dashboard auth is specified in
> `docs/dashboard-auth.md`.

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
    │   ├── overview.rs       # cluster + SLO overview page
    │   ├── routes_page.rs    # /dashboard/routes
    │   ├── pools_page.rs     # /dashboard/upstreams
    │   ├── rules_page.rs     # /dashboard/rules (editor + dry-run)
    │   ├── audit_page.rs     # /dashboard/audit search + verify
    │   ├── cluster_page.rs   # /dashboard/cluster (ClusterMembership.peers)
    │   └── sse.rs            # live event feed (subscribes to AuditBus)
    ├── api/
    │   ├── mod.rs            # REST admin API
    │   ├── config.rs         # GET/PUT /api/config (secrets masked)
    │   ├── rules.rs          # CRUD rules
    │   ├── routes_api.rs     # CRUD routes + upstreams
    │   └── audit.rs          # GET /api/audit, /api/audit/verify
    ├── admin_auth/
    │   ├── mod.rs            # axum tower middleware (session + CSRF + IP allowlist)
    │   ├── password.rs       # argon2id verify + hash (PHC)
    │   ├── session.rs        # HMAC cookie + SessionRecord store (etcd-backed)
    │   ├── csrf.rs           # double-submit token
    │   ├── rate_limit.rs     # per-IP + per-user login limits + lockout
    │   ├── totp.rs           # optional RFC 6238
    │   └── mtls.rs           # optional admin mTLS acceptor
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
- Static HTML/JS shell (vendored, no build step). SSE endpoint subscribes to `AuditBus` and streams events to any authenticated admin session.
- Test: subscribe, emit event via bus, assert delivered.

**T1.4b** — Dashboard pages (shipped incrementally)
- Files under `src/dashboard/*_page.rs`.
- Pages:
  - **Overview**: request rate, block rate, SLO burn, cluster peers.
  - **Routes**: list routes, show host/path/tier/upstream/policy, link to traffic.
  - **Upstreams**: pool members, health, CB state, inflight, p99.
  - **Rules**: browse + filter by id/scope/priority; inline editor with dry-run validate before save.
  - **Audit**: search by time/class/rule; one-click `verify` runs hash-chain verifier. Admin audit tab surfaces login/logout/lockout events from the separate admin chain.
  - **Cluster**: `ClusterMembership.peers()` view with load + version.
- Test: snapshot HTML render for each page; unauthenticated request → 302 to `/admin/login`.

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
- Periodic task signs chain head and exports to S3 Object Lock / append-only log. Leader-only via `ClusterMembership::acquire_lease("witness")`. Feature-gated.

**T3.6** — State backend snapshot exporter
- File: `src/audit/state_snapshot.rs`
- Hourly leader-only task triggers a state-backend snapshot (Redis `BGSAVE` hook or Raft snapshot) and ships it to the configured archive target (file / S3 / GCS). Surfaces RPO in `waf_state_snapshot_lag_seconds` metric.
- Test: mocked backend — snapshot task writes an archive and the metric reflects freshness.

---

### Week 4 — Dashboard Authentication

Spec: [`docs/dashboard-auth.md`](../docs/dashboard-auth.md). Contract
types: `DashboardAuthConfig`, `LoginRateLimitConfig`, `LockoutConfig`,
`MtlsAdminConfig` in `plans/shared-contract.md` §2.6.11.

**T4.1** — Password verify + PHC storage
- File: `src/admin_auth/password.rs`
- `pub async fn verify(hash_ref: &str, candidate: &str) -> Result<bool>` — resolves `password_hash_ref` via secret provider; `argon2id` verify with constant-time compare. Unknown-user path hashes against a fixed dummy PHC string to equalize timing.
- `pub fn hash(password: &str, params: Argon2Params) -> Result<String>` for `waf admin set-password`.
- Test: correct password → true; wrong → false; unknown-user path runs full work (measure timing within noise band).

**T4.2** — HMAC session cookie + SessionRecord store
- File: `src/admin_auth/session.rs`
- Cookie: `aegis_session = base64url(HMAC_SHA256(csrf_secret, session_id || issued_at || client_ip || ua_hash))`. Flags: `HttpOnly; Secure; SameSite=Strict; Path=/`.
- `SessionRecord { id, issued_at, last_seen, client_ip, ua_hash, totp_verified, revoked }` stored under `/aegis/sessions/<id>` in etcd. Idle TTL 30m (sliding), absolute 8h (hard).
- Revocation: `POST /admin/logout` sets `revoked = true`; etcd watch on `/aegis/sessions/` propagates to every replica.
- Binding: request whose `client_ip || ua_hash` does not match → 401 + audit.
- Test: issue session, mutate cookie byte → 401; revoke via other replica → next request 401.

**T4.3** — CSRF double-submit token
- File: `src/admin_auth/csrf.rs`
- On login, set `aegis_csrf = random 128-bit` (not HttpOnly). Every mutating method (`POST|PUT|PATCH|DELETE`) must present `X-CSRF-Token` header matching the cookie. Safe methods exempt.
- Test: `POST /api/rules` without header → 403; with matching header → 200.

**T4.4** — Login rate limit + lockout
- File: `src/admin_auth/rate_limit.rs`
- Per-IP 5/min (sliding window via `CounterStore::incr_window`); per-user 10/15min. Exponential backoff on attempts 6/7/8 (1s/2s/4s). Lockout for 15 min after threshold; attempts during lockout still fail and audit as `LoginDuringLockout`.
- Test: 11 wrong passwords → lockout; valid password during lockout → still 401; after TTL expires → success.

**T4.5** — IP allowlist (accept-time)
- File: `src/admin_auth/mod.rs`
- Reject any TCP peer whose address is not in `dashboard_auth.ip_allowlist` (default `127.0.0.1/32`, `::1/128`) **before** the HTTP layer runs. Audit rejection as `LoginFailure { reason: ip_denied }`.
- Test: bind on wildcard, connect from disallowed CIDR → connection refused + audit event.

**T4.6** — Optional TOTP (RFC 6238)
- File: `src/admin_auth/totp.rs`
- 6-digit, 30s step, SHA-1 HMAC. Shared secret at `/aegis/secrets/admin_totp`. Enrollment CLI (`waf admin enroll-totp`) emits provisioning URI + 10 recovery codes (argon2 hashes stored).
- Session is not fully authenticated until `totp_verified = true`.
- Test: correct TOTP → verified; skewed by ±1 step → accepted; ±2 → rejected.

**T4.7** — Optional admin mTLS
- File: `src/admin_auth/mtls.rs`
- Rustls client-auth with CA from `mtls.ca_ref`; required SAN from config. Valid cert bypasses password flow; session issued with `auth_method="mtls"`. Still subject to IP allowlist. Still audited.
- Test: openssl client with valid cert → 200; wrong SAN → 401 + `MtlsAuthRejected` event.

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
- Cluster-wide region pin; audit sinks / state writes / metric exports respect pin. `strict` refuses non-compliant sinks; `preferred` warns.
- Retention per event class. Pseudonymization job after N days (salted hash of IP/UA/JWT sub).
- Right-to-erasure: `POST /api/gdpr/erase` purges operational state; audit entries pseudonymized in place so hash chain stays valid. Dual-control required.
- Data export: `GET /api/gdpr/export?subject=...` streams JSONL.
- Test: erase flow, verify chain still verifies after pseudonymization.

**T5.3** — GitOps loader
- File: `src/gitops.rs`
- Poll (or webhook) a Git repo; verify commit signatures (GPG/SSH) against `allowed_signers` on every pull. Run same validator as runtime (dry-run) before `ArcSwap` swap.
- Break-glass: direct API edits allowed but auto-round-tripped as a branch + PR against the repo. Dashboard banner until merged.
- Test: push signed commit → applied; push unsigned → rejected; API edit → PR created (mock Git).

**T5.4** — *(deferred)* Change approval workflow
- Four-eyes approval for Critical-scope mutations is deferred with the
  RBAC work. v1 has a single admin principal; critical changes are
  audited but not gated by a second approver. See
  `docs/deferred/rbac-sso.md`.

**T5.5** — SLO / SLI + alerts
- File: `src/slo.rs`
- SLIs: availability (non-5xx / total), WAF-overhead latency p50/p95/p99 (histogram provided by M1), upstream availability, admin API availability, audit delivery rate, config freshness, cert freshness.
- SLOs: data-plane availability 99.99% / 30d; p99 overhead ≤ 5 ms in 99% of 1-min windows; audit delivery 99.999%; cert freshness ≥ 7d.
- Multi-window multi-burn-rate (Google SRE): fast (1h/2%), slow (6h/5%), trickle (3d/10%).
- Alert routing: Alertmanager webhook compatible + direct Slack/PagerDuty/ServiceNow/Jira receivers. Each alert carries a runbook URL.
- Test: synthetic regression → fast-burn fires within 5 min; recover → clear.

---

## 3. Interfaces Consumed

- From M1: `ReadinessSignal`, `ClusterMembership` impl, cert freshness signal, pool health state, `ConfigBroadcast` subscription, `CacheProvider` stats, `CounterStore` handle (for login rate-limit / lockout).
- From M2: `AuditEvent` stream on the bus, metric families in the shared registry.
- Provides to M1+M2: `MetricsRegistry` at boot, `ConfigBroadcast` sender.

## 4. Metrics You Own

```
waf_audit_events_total{class,sink,outcome}
waf_audit_spool_bytes{sink}
waf_audit_dropped_total{sink,severity}
waf_admin_requests_total{endpoint,status}
waf_admin_login_total{outcome}              # success|bad_password|unknown_user|rate_limited|locked|ip_denied|bad_totp
waf_admin_sessions_active                   (gauge)
waf_admin_lockouts_total
waf_config_reload_outcomes_total{source,outcome}
waf_slo_budget_remaining{sli}
waf_cert_expires_in_seconds{host}           (gauge)
```

## 5. API Surface (REST, all JSON)

```
GET    /healthz/{live,ready,startup}
GET    /metrics
POST   /admin/login                    (rate-limited; sets session + CSRF cookies)
POST   /admin/logout                   (revokes current session)
GET    /api/config
PUT    /api/config                     (session + CSRF; dry-run validated)
GET    /api/rules
POST   /api/rules                      (session + CSRF)
DELETE /api/rules/:id                  (session + CSRF)
GET    /api/routes, /api/upstreams
GET    /api/audit?since=&class=
GET    /api/audit/verify
POST   /api/gdpr/erase                 (session + CSRF)
GET    /api/gdpr/export?subject=
GET    /dashboard/*
GET    /dashboard/sse
```

## 6. Definition of Done (M3 exit criteria)

- [ ] `Requirement.md` §34 items: 9, 10, 14, 15, 17, 18, 19, 25, 28.
- [ ] Dashboard auth green: login (argon2id), HMAC session, CSRF enforced on mutations, per-IP + per-user rate limit + lockout, IP allowlist enforced at accept time; every event audited on the admin chain.
- [ ] Optional TOTP + optional admin mTLS paths pass integration tests behind feature flags.
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
