# Enterprise Dashboard — Design Spec

> **Status.** Design phase. No implementation yet — see
> [`../../plans/dashboard-enterprise/README.md`](../../plans/dashboard-enterprise/README.md)
> for the task breakdown that turns this spec into code.

> **Reference.** This work upgrades the existing v1 dashboard
> (single-page event tail at `/dashboard/`, see
> [`../dashboard.md`](../dashboard.md)) into a multi-page operator
> console comparable to Cloudflare / Imperva / F5 BIG-IP ASM consoles.
> The `dashboard.md` contract (control-plane listener, auth model,
> deferred RBAC/multi-tenancy) is **unchanged** — this work only
> reshapes the UI surface served from `crates/aegis-control/src/dashboard/`.

## Goals

1. **Operator-grade.** A single pane of glass: traffic, attacks,
   rules, configuration, audit, health — without a terminal.
2. **No external build step.** Vanilla HTML/CSS/JS embedded in the
   `aegis-control` crate via `include_bytes!`. Charts via Chart.js
   loaded from a pinned CDN (offline fallback documented in
   [`assets.md`](assets.md)).
3. **No regression.** Existing endpoints — `/dashboard/sse`,
   `/api/config`, `/healthz/*`, `/metrics` — keep their contracts.
   New endpoints sit alongside them.
4. **Auth unchanged.** Every non-`open` path stays behind the
   argon2id + HMAC session + CSRF + IP allowlist + optional TOTP/mTLS
   stack defined in [`../dashboard-auth.md`](../dashboard-auth.md).
5. **Single-tenant only.** RBAC, OIDC/SSO, multi-tenant scoping
   remain deferred — see [`../../future/rbac-sso.md`](../../future/rbac-sso.md)
   and [`../../future/multi-tenancy.md`](../../future/multi-tenancy.md).

## Non-goals

- Switching the front-end to React / Vue / Svelte. Decided against:
  adds a Node.js build to the Rust workflow, fights the existing
  `include_bytes!` embedding pattern, doubles asset surface area.
- Multi-tenant scoping in the UI. v1 ships one admin principal.
- Replacing Prometheus or Grafana. Operators retain those for
  long-term metrics; the dashboard is for live incident response.

## Document map

| File | Purpose |
|------|---------|
| [`overview.md`](overview.md) | Why this exists, design principles, what it replaces |
| [`layout.md`](layout.md) | Sidebar + header + content frame, breakpoints, navigation model |
| [`theme.md`](theme.md) | Design tokens — color, typography, spacing, motion |
| [`components.md`](components.md) | Reusable widgets (stat card, chart, table, badge, modal, toast) |
| [`pages/`](pages/) | One file per sidebar page: data shape, layout, interactions |
| [`api.md`](api.md) | New REST endpoints + SSE events the UI consumes |
| [`assets.md`](assets.md) | Embedding strategy, third-party deps, CSP, offline mode |
| [`accessibility.md`](accessibility.md) | Keyboard nav, ARIA, contrast, screen-reader expectations |
| [`security.md`](security.md) | CSP, CSRF, XSS hardening, supply-chain notes |

## Page inventory (sidebar order)

The example screenshot drives the sidebar. The ten pages below are
grouped into three sections in [`layout.md`](layout.md).

**Operator views (core)**

1. **Overview** — top-level KPIs + traffic/attack visualization
2. **Live Feed** — SSE-driven request stream with filters
3. **Attack Events** — detector breakdown, top rules, threat-intel hits
4. **Analytics** — historical trends, Prometheus-backed
5. **Audit Log** — searchable audit chain with verification status

**Configuration management**

6. **Rule Manager** — rule CRUD + diff editor + dry-run
7. **Tier Config** — tier definitions and pipeline assignment
8. **Blacklist** — IP / CIDR / ASN deny lists
9. **Whitelist** — IP / CIDR / ASN allow lists
10. **Settings** — admin password, TOTP, session policy, theme

**Tracking** (a single Tracking section consolidates the live operator
state that does not fit cleanly into the operator or config buckets)

11. **Tracking** — SLO burn rate, upstream pool health, cluster peer
    list, certificate freshness, GitOps sync status. See
    [`pages/tracking.md`](pages/tracking.md).

## Out-of-band reading

- [`../dashboard.md`](../dashboard.md) — control-plane contract
- [`../dashboard-auth.md`](../dashboard-auth.md) — auth flow
- [`../slo-sli-alerting.md`](../slo-sli-alerting.md) — SLO data source
- [`../audit-logging.md`](../audit-logging.md) — audit chain & sinks
- [`../rule-engine.md`](../rule-engine.md) — rule schema
- [`../../observability/prometheus-otel.md`](../../observability/prometheus-otel.md) — metrics surface
- [`../benchmark-mode.md`](../benchmark-mode.md) — benchmark mode
  spec (gates, headers, panels under Tracking + Analytics)

## Open questions to resolve before M1

- Charting library pin: Chart.js 4.x vs uPlot. Defer to
  [`assets.md`](assets.md).
- Whether to surface a `/api/stats` aggregate endpoint or have each
  page hit its own dedicated endpoint. Current lean: aggregate at
  `/api/stats` for the Overview page only; per-page endpoints
  elsewhere. See [`api.md`](api.md).
- CSP `script-src` hash list vs nonce — see
  [`security.md`](security.md).
