# Dashboard

> **v1 scope.** The dashboard is served by the **control-plane listener**
> (separate from data-plane traffic). Authentication is local
> (argon2id password + HMAC session + CSRF + IP allowlist, optional
> TOTP/mTLS) — see [`dashboard-auth.md`](./dashboard-auth.md). The WAF
> runs single-tenant in v1; OIDC/SSO, RBAC roles, and multi-tenant
> scoping are deferred (see
> [`deferred/rbac-sso.md`](./deferred/rbac-sso.md) and
> [`deferred/multi-tenancy.md`](./deferred/multi-tenancy.md)). The
> listener also exposes Prometheus `/metrics`,
> `/healthz/{live,ready,startup}`, and the full admin API. See
> [`observability-prometheus-otel.md`](./observability-prometheus-otel.md).

## Purpose

A single pane of glass for operators: live traffic, attack visualization,
config inspection and editing, rule management, audit log, and
operational health.

## Control plane vs data plane

Data-plane listener (public, :443) is never reachable from the dashboard
and vice versa. The dashboard binds its own listener (default :9443)
behind local authentication:

```
┌──────────────────────────┐   ┌───────────────────────────────┐
│  Data Plane (public)     │   │  Control Plane (admin)        │
│  Traffic + pipeline      │   │  Dashboard UI + Admin API     │
│  :80 / :443              │   │  :9443 (loopback by default)  │
└──────────────────────────┘   └───────────────────────────────┘
         │                                   │
         │                                   │
         ▼                                   ▼
   in-mem counters            etcd (config + secrets + session revocation)
   (+ optional Redis)
```

## Surfaces

Every non-`open` path is gated by the local auth middleware: valid
session cookie + matching CSRF token for mutating methods. See
[`dashboard-auth.md`](./dashboard-auth.md) for the full flow.

| Path | Purpose | Auth |
|------|---------|------|
| `/` | SPA entry | open (redirects to `/admin/login` if no session) |
| `/admin/login` | Login form / `POST` credentials | open (rate-limited) |
| `/admin/logout` | Revoke current session | session |
| `/dashboard/*` | UI views (traffic, rules, config, audit, health) | session |
| `/api/stats` | Point-in-time metrics snapshot | session |
| `/api/live` | SSE stream of audit events | session |
| `/api/config` | `GET` effective config; `PUT` proposed config | session + CSRF |
| `/api/rules` | CRUD rules | session + CSRF |
| `/api/secrets` | List secret references (never values) | session |
| `/api/audit` | Query audit log with filters + hash verification | session |
| `/metrics` | Prometheus scrape | network ACL + optional bearer |
| `/healthz/live` | Liveness | open |
| `/healthz/ready` | Readiness (etcd reachable, certs loaded, ≥1 healthy upstream) | open |
| `/healthz/startup` | Startup (first config load done) | open |

> **Deferred.** `/api/tenants` and `/api/tokens` are out of scope for
> v1. The single admin principal holds all privileges; per-user API
> tokens, tenant CRUD, and role separation reappear with the deferred
> OIDC/RBAC/multi-tenancy work.

## UI views

- **Overview** — requests/sec by tier, decisions histogram, top blocked
  IPs, upstream pool health summary (cluster-wide).
- **Live feed** — SSE-driven request stream with filtering (tier,
  decision, path, status).
- **Attacks** — detector breakdown, top rules firing, threat-intel feed
  hits, bot classification mix.
- **Routes** — route table, host + path matchers, linked upstream pool,
  health color.
- **Upstreams** — pool members, LB algorithm, active/passive health,
  circuit-breaker state.
- **Rules** — rule list with priority, scope, recent match counts,
  inline editor with diff view.
- **Config** — full effective config (secrets redacted), diff view,
  apply or GitOps PR flow.
- **Audit** — query by class/actor/time; hash-chain verification status.
  Includes a dedicated **Admin audit** tab sourced from the admin hash
  chain (login, logout, lockout, password change, session revocation).
- **Alerts** — SLO burn rate, backend health, pending admin approvals.

## Authorization model (v1)

One principal: `admin`. Every authenticated request is treated as fully
privileged. A future RBAC migration (see
[`deferred/rbac-sso.md`](./deferred/rbac-sso.md)) will slot in beside
this without breaking the handler signatures — the session-layer traits
are designed to carry roles later.

## Live feed transport

Server-Sent Events (SSE) over HTTPS. A `tokio::sync::broadcast` fed by
the audit bus supplies each connected client. Rate-limited per
connection to prevent dashboard overload from flooding the WAF itself.

Fallback: long-poll for environments that block SSE.

## Change-safety on edits

UI edits do **not** immediately apply in GitOps mode — they produce a
PR to the configured repo. In direct mode, they run through the
[`config-hot-reload.md`](./config-hot-reload.md) dry-run validator and
only apply if the validator passes. Either way, the edit is written
back to etcd via CAS, which distributes the change to every replica
through the etcd watcher.

## Configuration

The authoritative schema lives in
[`../plans/shared-contract.md`](../plans/shared-contract.md) §2.6.11
(`AdminConfig` + `DashboardAuthConfig`). Full field reference in
[`dashboard-auth.md`](./dashboard-auth.md).

```yaml
admin:
  bind: 127.0.0.1:9443
  tls:
    cert_ref: "${secret:etcd:/aegis/secrets/admin_cert}"
    key_ref:  "${secret:etcd:/aegis/secrets/admin_key}"
  dashboard_auth:
    password_hash_ref: "${secret:etcd:/aegis/secrets/admin_password}"
    csrf_secret_ref:   "${secret:etcd:/aegis/secrets/admin_csrf}"
    session_ttl_idle: 30m
    session_ttl_absolute: 8h
    ip_allowlist: ["127.0.0.1/32", "::1/128"]
    totp_enabled: false
    login_rate_limit:
      per_ip:   { limit: 5,  window: 1m }
      per_user: { limit: 10, window: 15m }
    lockout: { threshold: 10, window: 15m, duration: 15m }
    mtls:    { enabled: false }
```

## Implementation pointers

- `crates/aegis-control/src/admin/api.rs` — Axum router
- `crates/aegis-control/src/admin/middleware.rs` — auth + CSRF tower layer
- `crates/aegis-control/src/admin/ui/` — embedded SPA assets (via `include_bytes!`)
- `crates/aegis-control/src/admin/sse.rs` — live feed stream
- `crates/aegis-control/src/admin/handlers/{config,rules,audit,...}.rs`
- `crates/aegis-control/src/admin/metrics.rs` — Prometheus exporter
- `crates/aegis-control/src/admin/health.rs` — `/healthz/*`

## Performance notes

- Static assets embedded in the binary; no disk reads on the hot path.
- Metrics snapshot is a pure read of atomics.
- SSE per-connection channel is bounded; overflow disconnects rather
  than back-pressures the data plane.
- Login is the only argon2id hit (~150 ms) and is serialized per
  principal — see [`dashboard-auth.md`](./dashboard-auth.md) §Performance.
