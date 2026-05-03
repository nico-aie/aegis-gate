# Aegis WAF Console — Dashboard Reference

> **Status.** Shipped — pre-compiled React 18 SPA, bundled into
> `crates/aegis-control/assets/dashboard/app.js` (~305 KB), served
> from `/dashboard/` on the admin listener.
>
> Live source — [`crates/aegis-control/assets/dashboard/src/`](../../../crates/aegis-control/assets/dashboard/src/).
> Auth + listener contract — [`../dashboard.md`](../dashboard.md) · [`../dashboard-auth.md`](../dashboard-auth.md).
> REST + SSE contract — [`./api.md`](./api.md).
> Front-end CSP / threat model — [`./security.md`](./security.md).

The earlier vanilla-HTML / Chart.js-CDN design (D-M1..D-M6, 11
pages) was superseded — the per-page specs and design-token docs
that lived alongside this README have been removed in favour of
the live React source as the single source of truth. The archived
milestone plan still lives at
[`../../../plans/archive/dashboard-enterprise/`](../../../plans/archive/dashboard-enterprise/)
for historical context.

## Page inventory (live)

The bundled SPA exposes the following pages — the inventory is
sourced from `crates/aegis-control/assets/dashboard/src/pages.jsx`:

| Section | Pages |
|---|---|
| **Operator views** | Overview · Live Feed · Investigation · Top Attackers · Threat Intel |
| **Configuration** | Rules · Detectors · Access Lists · Routing & Upstreams · Compliance |
| **Health & telemetry** | Performance · Health & SLOs · Audit Trail · Scaling |
| **Settings** | Settings · Reports · Help |

Each page is a React component wrapped in an `ErrorBoundary` so a
single component crash never blanks the shell.

## Architecture (one-line summary)

- **No build step in the runtime.** The pre-compiled bundle and
  asset map are checked in; `aegis-control` re-exports them via
  `include_bytes!` so the binary ships everything it needs.
- **No CDN.** All scripts and styles are first-party — `script-src
  'self'`. Charts use a vendored library, not a third-party CDN.
- **No new auth.** Every non-`open` route on the admin listener
  goes through the same argon2id + HMAC session + CSRF + IP
  allow-list stack documented in
  [`../dashboard-auth.md`](../dashboard-auth.md).
- **Read-mostly with audited mutations.** Every write hits an
  audit-mutated endpoint (`PUT /api/detectors`, `POST /api/rules`,
  `PUT /api/upstreams`, …) which records a `config_reload` audit
  entry before swapping the live config.

## REST + SSE contract

Endpoint inventory and request / response shapes:
[`api.md`](./api.md). Every mutating endpoint requires the session
cookie + the CSRF double-submit token; read-only endpoints just
need the session. SSE stream `/dashboard/sse` carries every audit
event and is the source for the Live Feed / Investigation pages.

## Security model

Front-end threat model + CSP + supply-chain notes:
[`security.md`](./security.md). The front-end is the most
privileged surface in the product — session cookies on the
admin's browser can mutate every WAF setting — and the bar for
shipping client-side code is correspondingly high.

## When to read what

| You're trying to … | Start here |
|---|---|
| Wire up a new page or change layout | `crates/aegis-control/assets/dashboard/src/pages.jsx` (and the per-page modules it imports) |
| Add a new admin endpoint | [`api.md`](./api.md) — pick the section, add the row, then implement in `crates/aegis-control/src/api/` |
| Adjust the auth or CSP | [`../dashboard-auth.md`](../dashboard-auth.md) · [`security.md`](./security.md) |
| Investigate a live incident from the UI | [`../../operator/soc-runbook.md`](../../operator/soc-runbook.md) |
