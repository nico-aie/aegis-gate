# Dashboard Redesign — Aegis WAF Console

Replaces the existing 11-page vanilla-JS SPA at
`crates/aegis-control/assets/dashboard/` with the
**Aegis WAF Console** design from
`Hackathon_Doc/.../qP2YNdKy5OaYBiZgh3mTiw` (extracted to
`/tmp/aegis-design/waf/`). The new design lands as React + Babel
inline (matching the design-bundle's shape) into the same
`aegis-control` embedded-assets registry — single binary, no new
deployment surface, no new HTTP service.

## Decision: stay embedded, do not split into a separate app

The handoff doc gave the choice (embedded SPA vs separate
API/DB/FE app). I'm staying embedded:

| Reason | Detail |
|---|---|
| Existing `/api/*` surface fits 1:1 | We already have 27 read-only endpoints, the `/dashboard/sse` stream, audit-mutated `PUT` endpoints, and admin auth. Splitting would force us to re-implement auth/CSRF/audit-mutation for a second deployment artifact. |
| Single binary is a Phase-B requirement | Round 1 grading verifies "Build as a single binary" — splitting would break that. |
| Design bundle already React | The prototype is React-shaped already; embedding it is mechanical. |
| Operational simplicity | One config file, one TLS cert, one healthcheck. |

The new design's mock-data layer (`data.jsx`) gets progressively
replaced with calls to the existing `/api/*` endpoints over the
course of this track.

## Mapping — new design ↔ existing endpoints

| Page | Existing endpoint (already serving real data) |
|---|---|
| Overview | `/api/stats`, `/api/stats/timeseries`, `/api/attacks/distribution`, `/api/attacks/top`, `/api/upstreams/summary` |
| Live Feed | `/dashboard/sse` (existing SSE stream) |
| Attack Events | `/api/attacks/distribution`, `/api/attacks/top` (window param) |
| Analytics | `/api/analytics`, `/api/stats/timeseries` |
| Audit Log | `/api/audit/since?cursor&limit` |
| Rule Manager | `/api/rules`, `PUT /api/detectors` (audit-mutated) |
| Tier Config | `/api/tiers`, `PUT /api/detectors` (per-tier mask) |
| Blacklist / Whitelist | `/api/blacklist`, `/api/whitelist` |
| Settings | `/api/about`, `/api/runtime`, `/api/integrations`, `PUT /api/loadmode`, `PUT /api/logging` |
| Tracking | `/api/slo`, `/api/cluster`, `/api/certs`, `/api/gitops/status`, `/api/alerts`, `/api/upstreams` |
| Help & Guide | static (no API calls) |

The new design also calls for: `Cmd-K palette` (no backend, runs
client-side over the existing data). `Tweaks panel` (dev-only;
gated off in prod via `cfg.admin.dashboard.tweaks_panel: false`).

## Hackathon WAF-FE compliance

The new dashboard MUST satisfy
[`Hackathon_Doc/EN_present_v2.3.md`](../Hackathon_Doc/EN_present_v2.3.md)
§2 (WAF-FE Dashboard & Administration). Mandatory items, mapped
against this track:

| Requirement | How we meet it | Track |
|---|---|---|
| **Real-time monitor ≤ 5 s** | Live Feed page subscribes to `/dashboard/sse`; tested by issuing a request and asserting it appears in < 5 s | DD-T2 + DD-T4 |
| **Rule Add / Edit / Delete / Enable / Disable via UI** | Rule Manager page wired to `POST/PUT/DELETE /api/rules/*` (existing `/api/rules` was read-only — extends in DD-T6) | DD-T6 |
| **Audit Log search/filter (time, IP, Rule ID, Request ID)** | Audit Log page reads `/api/audit/since` with new query params for filtering | DD-T2 |
| **Health/Status: uptime, current mode, active rules** | Status bar + Tracking page already reads `/api/about` (uptime), `/api/loadmode` (mode), `/api/rules` count | DD-T2 |
| **Hot-reload ≤ 10 s with visible UI indication** | After every mutating call, dashboard polls `/api/config/version` until the new version takes effect; shows "Applied in X.Xs" toast | DD-T7 |
| **Create new rule ≤ 5 clicks** | Rule Manager has a single "+ New Rule" button → modal with sane defaults → Save (3 clicks total: button, fill fields, save) | DD-T6 |
| **Find audit event ≤ 30 s** | Audit Log search input filters incrementally as you type; ⌘K palette also indexes recent audit entries | DD-T2 |
| **No mock-only features**: every UI control must have a real effect | DD-T2 wires every visible toggle/switch/button to a live endpoint; if the backend doesn't have one, we add the endpoint, not a mock | DD-T2 + DD-T6 |

## Tracks

| ID | Track | Effort | What lands |
|---|---|---|---|
| **DD-T1** | Drop in design files + asset registry update | 1 hr | `theme.css`, `app.jsx`, `data.jsx`, `widgets.jsx`, `pages.jsx`, `help.jsx`, `tweaks-panel.jsx`, new `index.html` replace the existing dashboard assets; registry updated; CSP allows `unpkg.com` + `unsafe-eval` for the dashboard route only. |
| **DD-T2** | Wire `data.jsx` → real `/api/*` endpoints | 3 hr | Each page's data loader calls the live endpoint. SSE stream consumed for Live Feed (real-time ≤ 5 s). Audit Log gets `?ip=`, `?rule_id=`, `?request_id=`, `?from=`, `?to=` filters. **No page may render mock data once the endpoint exists** — drop the mock fallback when wired. |
| **DD-T6** | Rule CRUD endpoints + UI | 2 hr | New `POST /api/rules`, `PUT /api/rules/{id}`, `DELETE /api/rules/{id}`, `PUT /api/rules/{id}/toggle`. All audit-mutated. Rule Manager modal: + New Rule (1 click) → form (1 click to type) → Save (1 click) = ≤ 3 clicks for create. |
| **DD-T7** | Hot-reload status + version toast | 1 hr | New `GET /api/config/version` returning `(version, applied_at_ms)`. Every mutating call returns the post-mutation version; dashboard polls until proxy reports it (max 10 s). Toast: "Applied in X.Xs · waf-a / waf-b". |
| **DD-T3** | Tweaks panel env-gate | 30 min | `cfg.admin.dashboard.tweaks_panel: bool` (default `false` in prod, `true` in dev). |
| **DD-T4** | Smoke + screenshots + ≤ 5 s real-time check | 1 hr | Live: navigate every page; fire a synthetic request and time how long it appears in Live Feed; create / edit / disable a rule via UI and verify the proxy actually changes behaviour within 10 s. Screenshots into `tests/results/run-10-2026-04-30-dashboard-redesign/`. |
| **DD-T5** | Doc + plan housekeeping | 30 min | Update `docs/control-plane/enterprise/README.md`; archive the old `dashboard-enterprise/` plan; add run-10 README; update `Implement-Progress.md`. |

**Total ~9 hr** (was 6; +2 for DD-T6, +1 for DD-T7).
Workspace tests grow with the new CRUD endpoints (~6 unit tests
estimated).

## Risks

| Severity | Risk | Mitigation |
|---|---|---|
| MEDIUM | CSP rejects `unpkg.com` React/Babel | Add `script-src 'self' https://unpkg.com 'unsafe-eval'` to the dashboard CSP (Babel needs `unsafe-eval`). Keep `'unsafe-eval'` scoped to the dashboard route only. Note: the proxy data plane keeps its strict CSP. |
| MEDIUM | Babel compile cost (~500 ms) on every page load | Acceptable for an admin console (loaded ~once per shift). Pre-compile JSX → JS in CI is a follow-up. |
| LOW | Existing dashboard component imports break | Replacing the whole asset set in one commit; no partial state. |
| LOW | `/api/*` shape mismatch with what `data.jsx` expects | We adapt `data.jsx` to map the live shape — the existing endpoints are stable and well-tested. |

## Out of scope

- **Pre-compile JSX → JS in CI** (deferred; follow-up).
- **Service-worker / offline mode** (deferred).
- **i18n** beyond the existing `en` strings (deferred).
- **Dark/light theme toggle** — design is dark-only by intent
  ("trading floor" mood); accent swap (yellow/cyan/violet) is
  the only customisation.
- **Rebuilding the design's mock data generators as a Rust
  type model** — the live `/api/*` endpoints already are the
  type model.
- **Replacing or rebuilding any existing `/api/*` endpoint**.

## Done definition

- Browser at `https://localhost:9443/dashboard/` shows the new
  Aegis WAF Console with the Binance-yellow accent + compact
  density.
- All 12 sidebar pages render without console errors.
- Live Feed streams from `/dashboard/sse` (real WAF traffic).
- Stats / charts / tables on every page show real data from
  `/api/*` endpoints.
- Cmd-K palette opens with ⌘K and navigates between pages.
- `Tweaks` panel hidden when `cfg.admin.dashboard.tweaks_panel`
  is false.
- Workspace tests + clippy + DR contract checks all still
  green (unchanged surface).
- run-10 README captures screenshots + verification.
- `Implement-Progress.md` updated.
