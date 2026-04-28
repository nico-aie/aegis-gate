# Control plane (M3)

The admin surface: dashboard, admin API, hot-reload, secrets, and the
audit/observability machinery that makes operator actions traceable.
Owner: **M3** —
[`../../plans/member-3-control-plane.md`](../../plans/member-3-control-plane.md).

## Core docs

| Doc | Summary |
|---|---|
| [dashboard.md](./dashboard.md) | Control-plane UI + admin API surface |
| [dashboard-auth.md](./dashboard-auth.md) | argon2id + HMAC session + CSRF + IP allowlist + optional TOTP/mTLS |
| [config-hot-reload.md](./config-hot-reload.md) | Dry-run validator + secret refs + GitOps |
| [gitops-change-management.md](./gitops-change-management.md) | Git source of truth, signed commits |
| [secrets-management.md](./secrets-management.md) | Vault / AWS SM / GCP SM / Azure KV / HSM |
| [zero-downtime-ops.md](./zero-downtime-ops.md) | SO_REUSEPORT, drain, hot reload |

## Enterprise dashboard

The full UI spec for the bundled SPA lives at [`enterprise/`](./enterprise/).
That folder defines the design system, component library, page-by-page
layouts, accessibility, security, and the REST/SSE contract the SPA
consumes from the admin listener.

The next phase of work is **Dashboard redesign** — see
[`../../plans/dashboard-redesign/`](../../plans/dashboard-redesign/).
Each milestone in that track lands implementation notes inside
[`enterprise/`](./enterprise/) as it completes.
