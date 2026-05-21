# Dashboard Redesign — Aegis WAF Console

> **Status:** Closed — DD-T0..T8 shipped in run-10. Reference only.
>
> See [`README.md`](../README.md) for the track status board and
> [`../tests/results/run-10-2026-04-30-dashboard-redesign/README.md`](../README.md)
> for the closing run.

Replaces the existing 11-page vanilla-JS SPA at
`crates/aegis-control/assets/dashboard/` with the
**Aegis WAF Console** design from
`Hackathon_Doc/.../qP2YNdKy5OaYBiZgh3mTiw`. Lands as
**pre-compiled** JS into the existing `aegis-control` embedded-assets
registry — single binary, no new deployment surface, no runtime CDN
dependency, no `'unsafe-eval'` in the dashboard CSP.

## Decision: stay embedded, do not split into a separate app

| Reason | Detail |
|---|---|
| Existing `/api/*` surface fits 1:1 | 27 read-only endpoints, `/dashboard/sse` stream, audit-mutated `PUT` endpoints, admin auth — all already wired |
| Single binary is a Round-1 grading requirement | Splitting would break "Build as a single binary" |
| Design bundle is React-shaped | Embedding is mechanical |
| Operational simplicity | One config file, one TLS cert, one healthcheck |

## Out of scope (explicit)

The redesign deliberately **excludes**:

- Multi-tenancy / per-tenant dashboard isolation.
- Full RBAC roles beyond the existing single-admin model.
- Dark / light theme toggle (design is dark-only by intent —
  "trading floor" mood; accent-swap deleted, see #2 below).
- Mobile-responsive layout (compact density assumes desktop).
- Full WCAG 2.2 audit (lite a11y pass: keyboard nav, focus
  rings, ARIA on interactive primitives — full audit is
  separate work).
- Service worker / offline mode.
- i18n beyond `en` (existing `en.json` keys preserved).
- Pre-compiled bundle minification / tree-shaking — the
  pre-compile step from #3 just transforms JSX to JS; size
  optimisation is a follow-up.
- Cmd-K palette and Tweaks panel — both removed (#2 below).
  Cmd-K can come back as a real feature when there's backend
  search; Tweaks was prototype-only.
- **Replacing or rebuilding any existing `/api/*` endpoint.**
  Confirmed explicit: this track only **adds** endpoints
  (`POST/PUT/DELETE /api/rules/*` in DD-T6, `GET
  /api/config/version` in DD-T7). Every existing `/api/*`
  endpoint is consumed as-is. If a page needs a shape the
  current endpoint doesn't return, the dashboard adapts on
  the client side; we don't reshape the server.

## Decisions applied to this plan

1. **Tighter page acceptance bar.** All 12 sidebar pages render
   with real data. **6 must work end-to-end for Round-1 sign-off**
   (Overview, Live Feed, Audit Log, Rule Manager, Settings,
   Tracking). The other 6 (Attack Events, Analytics, Tier Config,
   Blacklist, Whitelist, Help) render real data but get only
   "renders without errors" acceptance.
2. **Cmd-K palette + Tweaks panel removed.** The design's
   prototypes for both ship in the bundle but the actual UI
   elements stay hidden in the live build. Reduces asset
   surface and CSP complexity.
3. **No unpkg CDN. Pre-compile JSX → JS.** A new
   `crates/aegis-control/assets/dashboard/build.sh` script runs
   `npx esbuild --bundle --format=iife --target=es2020 …` once
   per change; the committed assets are plain `.js` files. CSP
   for the dashboard route stays `script-src 'self'` — no
   `'unsafe-eval'`.

## Mapping — design ↔ existing endpoints

| Page | Endpoint(s) | Round-1 must-work? |
|---|---|---|
| Overview | `/api/stats`, `/api/stats/timeseries`, `/api/attacks/distribution`, `/api/attacks/top`, `/api/upstreams/summary`, `/api/about` | ✅ |
| Live Feed | `/dashboard/sse` (real-time ≤ 5 s) | ✅ |
| Attack Events | `/api/attacks/distribution`, `/api/attacks/top` | renders only |
| Analytics | `/api/analytics`, `/api/stats/timeseries` | renders only |
| Audit Log | `/api/audit/since` (with new `?ip`, `?rule_id`, `?request_id`, `?from`, `?to` filter params from DD-T2) | ✅ |
| Rule Manager | `/api/rules` (read), new `POST/PUT/DELETE /api/rules/*` (DD-T6) | ✅ |
| Tier Config | `/api/tiers`, `PUT /api/detectors` | renders only |
| Blacklist / Whitelist | `/api/blacklist`, `/api/whitelist` | renders only |
| Settings | `/api/about`, `/api/runtime`, `/api/integrations`, `PUT /api/loadmode`, `PUT /api/logging` | ✅ |
| Tracking | `/api/slo`, `/api/cluster`, `/api/certs`, `/api/gitops/status`, `/api/alerts`, `/api/upstreams`, `/api/runtime` (uptime + mode + rule count) | ✅ |
| Help & Guide | static (no API calls) | renders only |

## Hackathon WAF-FE compliance

[`Hackathon_Doc/EN_present_v2.3.md`](../../Hackathon_Doc/EN_present_v2.3.md)
§2 acceptance bar:

| Requirement | How we meet it | Track |
|---|---|---|
| Real-time monitor ≤ 5 s | Live Feed → `/dashboard/sse`; smoke fires synthetic request, asserts arrival in < 5 s | DD-T2 + DD-T8 |
| Rule Add/Edit/Delete/Enable/Disable via UI | `POST/PUT/DELETE /api/rules/*` (audit-mutated); Rule Manager modal | DD-T6 |
| Audit Log search/filter (time, IP, Rule ID, Request ID) | `/api/audit/since?ip&rule_id&request_id&from&to` | DD-T2 |
| Health/Status: uptime, current mode, active rules | Overview + Tracking read `/api/about`, `/api/loadmode`, `/api/rules` count | DD-T2 |
| Hot-reload ≤ 10 s with visible UI indicator | New `GET /api/config/version`; mutations return post-version; dashboard polls; toast "Applied in X.Xs" | DD-T7 |
| Create rule ≤ 5 clicks | "+ New Rule" → form → Save = 3 clicks | DD-T6 + DD-T8 |
| Find audit event ≤ 30 s | Incremental search input on Audit Log | DD-T2 |
| **No mock-only features** | DD-T2 + DD-T6 wire every visible toggle/button to live endpoint | DD-T2 + DD-T6 |
| Auth on every dashboard route | Existing F-T1 (argon2id + HMAC session + CSRF + TOTP) covers the new pages without changes; verified in DD-T1 | DD-T1 |

## Tracks

| ID | Track | Effort | What lands |
|---|---|---|---|
| **DD-T0** | Clean removal of current dashboard | 30 min | Delete `index.html`, `app.js`, `aegis.css`, `theme.js`, `pages/*.js`, `components/*.js` from `crates/aegis-control/assets/dashboard/`. Update `assets.rs` registry — strip every removed entry. Workspace builds; tests stay green (the `dashboard::dispatch::dispatch` tests target the path layer, not the asset bytes). |
| **DD-T1** | Drop in design files + CSP + pre-compile pipeline | 2 hr | New `theme.css` + `index.html` + `src/app.jsx` + `src/data.jsx` + `src/widgets.jsx` + `src/pages.jsx` + `src/help.jsx` (Cmd-K and Tweaks panel sections deleted from the JSX). New `build.sh`: `npx --yes esbuild ... → app.js`. Asset registry serves `index.html`, `aegis.css`, `app.js`. CSP for `/dashboard/*` stays `script-src 'self'`. Verify existing F-T1 auth covers new pages (the path-prefix matcher already gates everything under `/dashboard/`). |
| **DD-T6** | Rule CRUD endpoints + UI | 2 hr | `POST /api/rules`, `PUT /api/rules/{id}`, `DELETE /api/rules/{id}`, `PUT /api/rules/{id}/toggle`. All audit-mutated. Rule Manager modal: + New Rule (1 click) → form (1 fill) → Save (1 click) = ≤ 3 clicks. **DD-T6 lands before DD-T2** so DD-T2's "no mock data" rule is satisfiable for Rule Manager. |
| **DD-T2** | Wire `data.jsx` → real `/api/*` endpoints | 3 hr | Each page's data loader calls live endpoints. Live Feed subscribes to `/dashboard/sse`. Audit Log gets filter query params. Mock generators removed once an endpoint exists; pages without endpoints either get one in DD-T6 (Rules) or stay rendering a one-line "no backend yet" notice (Help only). |
| **DD-T7** | Hot-reload status + version toast | 1 hr | `GET /api/config/version` returning `{version, applied_at_ms, applied_on_node}`. Every mutating call returns post-version. Dashboard polls every 500 ms (max 10 s) until proxy reports it; toast: "Applied in X.Xs · waf-a / waf-b". |
| **DD-T8** | Round-1 Pass/Fail acceptance script | 1 hr | New `tests/dashboard/round1-acceptance.sh`: (a) fires synthetic request, asserts Live Feed shows it in < 5 s; (b) opens Rule Manager via Playwright/headless, counts clicks for create-rule (must be ≤ 5); (c) issues mutation, polls `/api/config/version`, asserts hot-reload < 10 s. |
| **DD-T4** | Smoke + screenshot regression | 1 hr | Live: navigate every page; capture one screenshot per page into `tests/results/run-10-2026-04-30-dashboard-redesign/screenshots/`. Pin them as the visual regression reference for future PRs. |
| **DD-T5** | Doc + plan housekeeping | 30 min | Update `docs/control-plane/enterprise/README.md`; archive `plans/dashboard-enterprise/` → `plans/archive/dashboard-enterprise/`; add run-10 README; update `Implement-Progress.md`. ✅ Closed. |

**Total ~11 hr** (was 9; +30 min DD-T0, +1 hr DD-T8, ~+30 min for screenshot regression). Workspace tests grow by ~6 unit tests (Rule CRUD endpoints).

## Risks

| Severity | Risk | Mitigation |
|---|---|---|
| MEDIUM | esbuild not on the operator's machine | `build.sh` uses `npx --yes esbuild` (downloads on first run). Document in repo top-level README. |
| MEDIUM | Pre-compiled bundle gets out of sync with `*.jsx` source | CI hook + a `cargo make build-dashboard` shortcut. Initial commit ships both source and compiled output. |
| LOW | Existing dashboard routes hard-coded somewhere outside the asset registry | Grep before removing — covered in DD-T0. |
| LOW | F-T1 auth path matcher misses one of the new pages | The matcher already gates `/dashboard/*` as a prefix, not per-page; no per-page changes needed. Sanity-checked in DD-T1. |

## Done definition

- All **12** sidebar pages render with real data, no console
  errors, no mock-only data on the **6 must-work** pages.
- DD-T8 acceptance script runs end-to-end and reports
  `PASS` on every WAF-FE Round-1 criterion.
- DD-T4 captures one screenshot per page into
  `tests/results/run-10-…/screenshots/` as the visual
  regression baseline.
- Workspace tests, clippy, and the 27 interop dry-run checks
  all still green.
- `Implement-Progress.md` + `docs/control-plane/enterprise/README.md`
  + run-10 README updated.
