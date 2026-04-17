# Control Plane — `aegis-control` Task Plan

> **Before reading this:** Read `README.md`, then `Implement-Progress.md`,
> then `plans/plan.md` (shared types §2, traits §3, boot §4, conventions §5).
> This file contains only the per-task breakdown for `aegis-control`.

**Crate mission:** operators can see, audit, and govern the WAF. Owns the admin
listener, dashboard, authentication, Prometheus/OTEL, audit hash-chain, SIEM sinks,
compliance enforcement, GitOps, and SLO alerts.

> **v1 scope reminder:** OIDC/SSO, RBAC roles, API tokens, and multi-tenancy are
> **DEFERRED**. v1 ships one admin principal with full privileges via
> argon2id password + HMAC session + CSRF + TOTP + mTLS. See `docs/deferred/`.

**Entry point:** `pub async fn start(cfg, bus, metrics, readiness, cluster, cfg_bcast) -> Result<()>`

**Verification:** `cargo test -p aegis-control && cargo clippy -p aegis-control -- -D warnings`

---

## Crate Layout

```
crates/aegis-control/src/
  lib.rs, server.rs, health.rs
  metrics/
    mod.rs           # pub fn init() -> MetricsRegistry — MUST be called before proxy/security boot
    exporter.rs      # GET /metrics text scrape
  tracing_init.rs    # tracing-subscriber JSON + OTLP (feature = "otel")
  access_log.rs      # access log writer (combined, JSON/ECS, template)
  dashboard/
    mod.rs           # route registration
    overview.rs      # rate, block counts, SLO burn, peer list
    routes_page.rs   # route table + live hit counters
    pools_page.rs    # health, CB state, inflight, p99 per pool
    rules_page.rs    # rule list + editor + dry-run
    audit_page.rs    # searchable event stream + chain verify
    cluster_page.rs  # node list, leases, version skew
    sse.rs           # Server-Sent Events from AuditBus
  api/
    mod.rs, config.rs, rules.rs, routes_api.rs, audit.rs
  admin_auth/
    mod.rs, password.rs, session.rs, csrf.rs, rate_limit.rs, totp.rs, mtls.rs
  audit/
    mod.rs, chain.rs, verify.rs, witness.rs, state_snapshot.rs
    sinks/
      jsonl.rs, syslog.rs, cef.rs, leef.rs, ocsf.rs
      splunk_hec.rs, ecs.rs, kafka.rs
  compliance/
    mod.rs, fips.rs, pci.rs, soc2.rs, gdpr.rs, hipaa.rs
  residency.rs, gitops.rs, slo.rs
```

---

## REST API Surface

```
GET    /healthz/{live,ready,startup}
GET    /metrics
POST   /admin/login           (rate-limited; sets aegis_session + aegis_csrf cookies)
POST   /admin/logout
GET    /api/config            (returns WafConfig; secret refs NOT resolved)
PUT    /api/config            (session + CSRF; dry-run validated before apply)
GET    /api/rules
POST   /api/rules             (session + CSRF)
DELETE /api/rules/{id}        (session + CSRF)
GET    /api/routes
GET    /api/upstreams
GET    /api/audit?since=&class=
GET    /api/audit/verify
POST   /api/gdpr/erase        (session + CSRF)
GET    /api/gdpr/export?subject=
GET    /dashboard/*           (served as static SPA; login redirect for unauthed)
GET    /dashboard/sse         (session required; SSE stream of AuditEvent)
```

---

## Prometheus Metrics

```
waf_audit_events_total{class,sink,outcome}
waf_audit_spool_bytes{sink}
waf_audit_dropped_total{sink,severity}
waf_admin_requests_total{endpoint,status}
waf_admin_login_total{outcome}              # success|bad_password|rate_limited|locked|ip_denied|bad_totp
waf_admin_sessions_active                   (gauge)
waf_admin_lockouts_total
waf_config_reload_outcomes_total{source,outcome}
waf_slo_budget_remaining{sli}
waf_cert_expires_in_seconds{host}           (gauge)
waf_state_snapshot_lag_seconds              (gauge)
```

---

## W1 — Admin Listener, Health, Dashboard Skeleton

**M3-T1.1** `MetricsRegistry` init
- File: `src/metrics/mod.rs`
- `pub fn init() -> MetricsRegistry { MetricsRegistry(Arc::new(prometheus::Registry::new())) }`
- **Must be called before proxy/security boot** so they can register their metric families into it.
- Test: registry created; proxy + security can register counters without panic.

**M3-T1.2** Admin listener + axum router
- File: `src/server.rs`
- `pub async fn start(cfg, bus, metrics, readiness, cluster, cfg_bcast)` — binds `cfg.admin.bind`; mounts all routes.
- Test: `GET /healthz/live` → 200.

**M3-T1.3** Health endpoints
- File: `src/health.rs`
- `/live` — 200 if process is running, 503 otherwise.
- `/ready` — 200 only when `state_backend_up && certs_loaded && pool_has_healthy && !draining`.
- `/startup` — 200 after first config load completes.
- Test: flip individual `ReadinessSignal` booleans; assert 503 transitions to 200 and back.

**M3-T1.4** Dashboard shell + SSE
- Files: `src/dashboard/mod.rs`, `src/dashboard/sse.rs`
- Static HTML/JS shell served from embedded bytes. SSE endpoint subscribes to `AuditBus` broadcast, streams to authenticated sessions only; closes stream on session expiry.
- Test: emit audit event on bus; assert it arrives over SSE within 1s.

**M3-T1.4b** Dashboard pages
- Files: `src/dashboard/overview.rs`, `routes_page.rs`, `pools_page.rs`, `rules_page.rs`, `audit_page.rs`, `cluster_page.rs`
- Shipped incrementally. Overview: request rate, block counts, SLO burn rate, peer list. Others: see crate layout.
- Test: unauthenticated GET `/dashboard/` → 302 to `/admin/login?next=…`.

**M3-T1.5** `GET /api/config`
- File: `src/api/config.rs`
- Return effective `WafConfig` as JSON; `${secret:*}` references **never resolved** in the response.
- Test: assert `${secret:env:FOO}` appears as-is in JSON body.

**W1 exit gate:** `./waf run` boots; `/healthz/live` 200; dashboard shell loads; SSE delivers events.

---

## W2 — Observability

**M3-T2.1** Prometheus exporter
- File: `src/metrics/exporter.rs`
- `GET /metrics` returns `prometheus::TextEncoder` output from the shared registry. Histogram buckets: `[0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]` seconds.
- Test: scrape, parse with `prometheus-parse`, assert `waf_requests_total` and `waf_upstream_latency_seconds` families present.

**M3-T2.2** Tracing init + OTLP (feature `otel`)
- File: `src/tracing_init.rs`
- `tracing-subscriber` JSON layer + `opentelemetry-otlp` batch exporter. Root span `waf.request`; child spans per pipeline stage annotated with `tier`, `route`, `decision`.
- Test: wiremock OTLP endpoint receives export request with a `waf.request` span.

**M3-T2.3** W3C Trace Context middleware
- File: `src/tracing_init.rs`
- `fn ensure_trace_context(headers: &HeaderMap) -> String` — accept `traceparent`/`tracestate` or generate a new trace id. Attach to span context.
- Test: round-trip; downstream receives the same `traceparent` header.

**M3-T2.4** Access log writer
- File: `src/access_log.rs`
- Formats: `combined` (Apache), `json` (ECS-compatible), `template` (custom). Bounded `tokio::sync::mpsc` channel from proxy; backpressure drops with `waf_access_log_dropped_total` increment.
- Test: one golden-file comparison per format.

**W2 exit gate:** Prometheus scrape returns all expected metric families; OTLP spans received.

---

## W3 — Audit Hash Chain + SIEM Sinks

**M3-T3.1** Chain writer
- File: `src/audit/chain.rs`
- `hash = sha256(prev_hash || canonical_json(event))`. Persist `{hash, event}` as NDJSON to spool file. First event: `prev_hash = sha256(b"genesis")`.
- Test: tamper any spool line → verifier detects the break.

**M3-T3.2** `waf audit verify` CLI subcommand
- File: `src/audit/verify.rs`
- Walk spool from start, recompute chain, report first broken line with line number + expected vs actual hash. Exit code 0 = clean, 1 = broken.
- Test: clean chain → exit 0; tampered line → exit 1 + diagnostic.

**M3-T3.3** Audit sinks
- Files: `src/audit/sinks/`
- Trait: `pub trait AuditSink: Send + Sync { async fn write(&self, ev: &AuditEvent) -> Result<()>; }`
- Per-sink bounded channel + on-disk spool for backpressure. Implementations: JSONL (file rotation), syslog RFC 5424 UDP/TLS, CEF, LEEF, OCSF, Splunk HEC, Elastic ECS, Kafka.
- Test: wiremock for HEC and syslog UDP; embedded Kafka for Kafka sink.

**M3-T3.4** Admin change log
- File: `src/audit/mod.rs`
- Every mutation via `/api/config`, `/api/rules`, `/api/gdpr/erase` writes a separate chain entry for `AuditClass::Admin`: actor, target resource, JSON diff, reason.
- Test: PUT /api/config → admin chain has one new entry with the diff.

**M3-T3.5** Witness export
- File: `src/audit/witness.rs`
- Periodic task (leader-only: `acquire_lease("witness")`). Signs chain head with the cluster key → S3 Object Lock / append-only log. Metric: `waf_witness_lag_seconds`.

**M3-T3.6** State backend snapshot exporter
- File: `src/audit/state_snapshot.rs`
- Hourly leader-only task triggers snapshot (`BGSAVE` on Redis or Raft snapshot), ships to configured archive target. Metric: `waf_state_snapshot_lag_seconds`.
- Test: mock backend; snapshot task writes archive; metric reflects freshness.

**W3 exit gate:** `waf audit verify` passes; SIEM sink integration test (HEC + syslog UDP + Kafka) all deliver events.

---

## W4 — Dashboard Authentication

Spec: `docs/dashboard-auth.md`. Config types live in `aegis-core::config` (§2.7 of `plans/plan.md`): `DashboardAuthConfig`, `LoginRateLimitConfig`, `LockoutConfig`, `MtlsAdminConfig`.

**M3-T4.1** Password verify + PHC
- File: `src/admin_auth/password.rs`
- `async fn verify(hash_ref: &str, candidate: &str, secrets: &dyn SecretProvider) -> Result<bool>`: resolve hash via `SecretProvider`, argon2id verify, constant-time compare. Unknown-user path runs full argon2id work to equalize timing (no user-enumeration).
- `fn hash(password: &str, params: Params) -> Result<String>` — used by `waf admin set-password` CLI.
- Test: correct → true; wrong → false; timing delta between known/unknown users within noise band.

**M3-T4.2** HMAC session cookie + `SessionRecord`
- File: `src/admin_auth/session.rs`
- Cookie: `aegis_session = base64url(HMAC_SHA256(session_key, id||issued_at||ip||ua_hash))`. Flags: `HttpOnly; Secure; SameSite=Strict`.
- `SessionRecord { id, issued_at, last_seen, ip, ua_hash, totp_verified }` stored in etcd/Redis with idle TTL 30m, absolute TTL 8h.
- Revocation via etcd key deletion; replicas watch for changes so concurrent sessions invalidate immediately.
- Test: mutate one cookie byte → 401; revoke on one replica → next request on any replica → 401.

**M3-T4.3** CSRF double-submit
- File: `src/admin_auth/csrf.rs`
- `aegis_csrf = random 128-bit` (not HttpOnly). Mutating methods (`POST|PUT|PATCH|DELETE`) require `X-CSRF-Token` matching the cookie value.
- Test: POST without header → 403; with matching header → 200.

**M3-T4.4** Login rate limit + lockout
- File: `src/admin_auth/rate_limit.rs`
- Per-IP: 5 attempts/1min. Per-user: 10 attempts/15min. Exponential backoff at attempts 6/7/8: wait 2s, 5s, 15s before responding. Lockout 15min after threshold. Attempts during lockout still fail and are audited as `LoginDuringLockout`.
- Test: 11 wrong passwords → lockout; valid password during lockout → 401; after TTL expires → success.

**M3-T4.5** IP allowlist
- File: `src/server.rs` or `src/admin_auth/mod.rs`
- Reject TCP connections from IPs not in `ip_allowlist` **before** any HTTP parsing. Audit as `LoginFailure{reason: ip_denied}`.
- Test: connect from a CIDR not in the allowlist → connection refused + audit event.

**M3-T4.6** TOTP (RFC 6238)
- File: `src/admin_auth/totp.rs`
- 6-digit, 30s step, SHA-1 HMAC. Shared secret at `${secret:file:/etc/aegis/admin_totp}`. `waf admin enroll-totp` emits a provisioning URI (otpauth://) and 10 recovery codes (stored as argon2id hashes). Session `SessionRecord.totp_verified` must be `true` for full auth.
- Test: correct TOTP → verified; step ±1 accepted; step ±2 rejected; recovery code consumed exactly once.

**M3-T4.7** Admin mTLS
- File: `src/admin_auth/mtls.rs`
- rustls client-auth with CA from `cfg.admin.dashboard_auth.mtls.ca_ref`. A valid client cert bypasses the password flow; session still issued and audited. Still subject to IP allowlist.
- Test: valid client cert + correct SAN → 200; wrong SAN → 401 + `MtlsAuthRejected` audit event.

**W4 exit gate:** full login flow green — argon2id verify, HMAC session, CSRF, lockout, IP allowlist, TOTP, mTLS.

---

## W5 — Compliance, GitOps, SLO

**M3-T5.1** Compliance profiles
- File: `src/compliance/mod.rs` + per-profile files
- `pub fn apply(profiles: &[ComplianceMode], cfg: &mut WafConfig) -> Result<()>` — strictest setting wins; conflicting combos refused at load.
  - **FIPS**: force `aws-lc-rs` TLS provider; reject non-FIPS algorithms at startup.
  - **PCI-DSS**: TLS ≥ 1.2; PAN masking in DLP; audit retention ≥ 90 days.
  - **SOC 2**: audit hash chain + admin trail + SLO alerts must be enabled.
  - **GDPR**: PII pseudonymization in audit logs; data residency pin required.
  - **HIPAA**: PHI-safe log mode (PHI fields masked before any sink write).
- Test: per-profile fixture boots with expected settings; conflicting combo rejected with clear error.

**M3-T5.2** Data residency + retention + right-to-erasure
- File: `src/residency.rs`
- Region pin (strict/preferred) enforced across state backend and audit spool writes. Per-event-class retention enforced by a background sweep. Right-to-erasure: pseudonymize all events matching `subject_id` without breaking the hash chain (replace PII field, recompute hash, stamp `erased_at`).
- `POST /api/gdpr/erase {subject_id, reason}` (session + CSRF). `GET /api/gdpr/export?subject=`.
- Test: erase flow completes; `waf audit verify` still exits 0 after erasure.

**M3-T5.3** GitOps loader
- File: `src/gitops.rs`
- Poll or webhook from a configured Git repository. Verify commit signatures (GPG/SSH) against `allowed_signers`. Dry-run validate before applying; swap via `ConfigBroadcast`. Break-glass: direct API edit creates a branch + PR automatically; dashboard shows a banner until merged.
- Test: signed commit → applied; unsigned commit → rejected with audit event; API edit → branch + PR created (mock Git).

**M3-T5.4** *(deferred)* Change approval workflow
- 4-eyes for Critical configuration mutations is deferred with RBAC. See `docs/deferred/rbac-sso.md`.

**M3-T5.5** SLO / SLI + multi-burn alerts
- File: `src/slo.rs`
- SLIs tracked:
  - Data-plane availability (1 - error_rate).
  - WAF overhead p50/p95/p99 latency.
  - Upstream availability per pool.
  - Audit delivery rate (events in vs events acknowledged by sinks).
  - Cert freshness (days to expiry).
- Multi-window multi-burn-rate alerting: fast burn (1h window, 2% budget) → page; slow burn (6h/5%, 3d/10%) → ticket.
- Alertmanager webhook + optional Slack/PagerDuty/ServiceNow/Jira receivers. Each alert carries a `runbook_url`.
- Test: inject synthetic errors to push SLI below threshold → fast-burn alert fires within 5min; errors clear → alert resolves.

**W5 exit gate:** compliance profile test suite green; `waf audit verify` passes after GDPR erase; SLO fast-burn alert fires and clears.

---

## Definition of Done (`aegis-control`)

- [ ] `cargo test -p aegis-control` green; `cargo clippy -p aegis-control -- -D warnings` clean.
- [ ] Full login flow: argon2id + HMAC session + CSRF + lockout + IP allowlist + TOTP + mTLS.
- [ ] `waf audit verify` exits 0 on a clean chain; exits 1 after tampering.
- [ ] SIEM forwarder delivers to ≥ 3 sinks in integration test.
- [ ] FIPS compliance profile forces `aws-lc-rs` provider; non-FIPS algo rejected at boot.
- [ ] SLO fast-burn alert fires on synthetic regression; clears on recovery.
