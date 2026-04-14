# Dashboard (v2)

> **v1 → v2:** the dashboard is now behind the **control-plane listener**
> (separate from data-plane traffic), enforces **RBAC + OIDC SSO**, supports
> **multi-tenant scoping**, and exposes Prometheus `/metrics`,
> `/healthz/{live,ready,startup}`, and a full admin API. See
> [`rbac-sso.md`](./rbac-sso.md), [`multi-tenancy.md`](./multi-tenancy.md),
> and [`observability-prometheus-otel.md`](./observability-prometheus-otel.md).

## Purpose

A single pane of glass for operators: live traffic, attack visualization,
config inspection and editing, rule management, audit log, tenant views,
and operational health.

## Control plane vs data plane

Data-plane listener (public, :443) is never reachable from the dashboard
and vice versa. The dashboard binds its own listener (default :9443)
behind mTLS + OIDC:

```
┌──────────────────────────┐   ┌──────────────────────────┐
│  Data Plane (public)     │   │  Control Plane (admin)   │
│  Traffic + pipeline      │   │  Dashboard UI + Admin API│
│  :80 / :443              │   │  :9443 (mTLS + OIDC)     │
└──────────────────────────┘   └──────────────────────────┘
         │                                │
         └──── shared state backend ──────┘
```

## Surfaces

| Path | Purpose | Auth |
|------|---------|------|
| `/` | SPA entry | OIDC |
| `/dashboard/*` | UI views (traffic, rules, config, tenants, audit, health) | OIDC + role |
| `/api/stats` | Point-in-time metrics snapshot | `viewer` |
| `/api/live` | SSE stream of audit events | `viewer` |
| `/api/config` | GET effective config; PUT proposed config | `operator`+ for PUT |
| `/api/rules` | CRUD rules | `operator`+ for mutate |
| `/api/tenants` | CRUD tenants | `admin` |
| `/api/secrets` | List secret references (never values) | `admin` |
| `/api/audit` | Query audit log with filters + hash verification | `auditor` / `admin` |
| `/api/tokens` | Issue / revoke API tokens | `admin` |
| `/metrics` | Prometheus scrape | network ACL + optional bearer |
| `/healthz/live` | Liveness | open |
| `/healthz/ready` | Readiness (state backend reachable, certs loaded, ≥1 healthy upstream) | open |
| `/healthz/startup` | Startup (first config load done) | open |

## UI views

- **Overview** — requests/sec by tier, decisions histogram, top blocked IPs,
  upstream pool health summary, cluster-wide or tenant-scoped
- **Live feed** — SSE-driven request stream with filtering (tenant, tier,
  decision, path, status)
- **Attacks** — detector breakdown, top rules firing, threat-intel feed
  hits, bot classification mix
- **Routes** — route table, host + path matchers, linked upstream pool,
  health color
- **Upstreams** — pool members, LB algorithm, active/passive health,
  circuit-breaker state
- **Rules** — rule list with priority, scope, recent match counts,
  inline editor with diff view
- **Config** — full effective config (secrets redacted), diff view, apply
  or GitOps PR flow
- **Tenants** — list, quotas, per-tenant dashboards
- **Audit** — query by class/actor/time; hash-chain verification status
- **Alerts** — SLO burn rate, backend health, pending admin approvals

## RBAC

Roles (see [`rbac-sso.md`](./rbac-sso.md)):

- `viewer` — read-only
- `operator` — read + mutate non-security config
- `admin` — all mutations
- `auditor` — read-only access to audit log and change history

Every mutating handler is wrapped with `require_role!(...)`. Unauthorized
calls are rejected with 403 and logged as a security-relevant admin event.

## Multi-tenant scoping

Tokens issued to a tenant-scoped user carry a `tenant_id` claim. Every
query through the admin API is projected through that id so a tenant's
`viewer` cannot see another tenant's traffic. Cluster-wide operators have
a special scope.

## Live feed transport

Server-Sent Events (SSE) over HTTPS. A `tokio::sync::broadcast` fed by
the audit bus supplies each connected client. Rate-limited per connection
to prevent dashboard overload from flooding the WAF itself.

Fallback: long-poll for environments that block SSE.

## Change-safety on edits

UI edits do **not** immediately apply in GitOps mode — they produce a
PR to the configured repo. In direct mode, they run through the
[`config-hot-reload.md`](./config-hot-reload.md) dry-run validator and
only apply if the validator passes.

## Configuration

```yaml
admin:
  listen: "0.0.0.0:9443"
  tls:
    cert_file: "/etc/waf/certs/admin.pem"
    key_file:  "${secret:file:/etc/waf/keys/admin.key}"
    require_client_cert: true
    client_ca: "/etc/waf/certs/admin-ca.pem"
  oidc:
    issuer: "https://idp.example.com"
    client_id: "waf-admin"
    client_secret: "${secret:env:OIDC_SECRET}"
    redirect_uri: "https://waf.example.com:9443/auth/callback"
    groups_claim: "groups"
    role_mapping:
      "waf-admins": admin
      "waf-ops": operator
      "waf-view": viewer
      "waf-audit": auditor
  session_timeout_s: 3600
  ip_allowlist: ["10.0.0.0/8"]
```

## Implementation

- `src/dashboard/api.rs` — Axum router
- `src/dashboard/auth.rs` — OIDC + RBAC middleware
- `src/dashboard/ui/` — embedded SPA assets (via `include_bytes!`)
- `src/dashboard/sse.rs` — live feed stream
- `src/dashboard/handlers/{config,rules,tenants,audit,...}.rs`
- `src/dashboard/metrics.rs` — Prometheus exporter
- `src/dashboard/health.rs` — `/healthz/*`

## Performance notes

- Static assets embedded in the binary; no disk reads on hot path
- Metrics snapshot is a pure read of atomics
- SSE per-connection channel is bounded; overflow disconnects rather
  than back-pressures the data plane
