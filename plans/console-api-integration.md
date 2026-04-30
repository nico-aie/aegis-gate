# Console API Integration Plan (CI-T1..T6)

> **Status:** Active — picked up after the dashboard redesign
> (DD-T0..T8) closed. Bridges the gap between the UI shell shipped
> in run-10 and the real backend data the WAF already produces.
>
> See [`README.md`](./README.md) for the track status board.

---

## Problem statement

The Aegis WAF Console (DD-T0..T8) ships 12 visually complete pages.
**Only one of them — Rule Manager — actually calls the live API.**
Every other page renders from `window.RULES` / `window.BLACKLIST` /
`window.ATTACKER_GEO` etc. — JavaScript mock constants that haven't
moved since the design was extracted. The Live Feed page calls
`window.useLiveFeed()`, a fake-event generator, instead of
subscribing to `/dashboard/sse` (which does broadcast real audit
events).

Five backend endpoints (`/api/slo`, `/api/certs`, `/api/gitops/status`,
`/api/alerts`, and the Settings mutation surface) return
`*::placeholder()` shapes — the route exists but the data is stubbed.

This track closes both gaps so the dashboard reflects the running
WAF, not the design fixture.

## What's already wired (no work)

| Surface | Hook | Endpoint | State |
|---|---|---|---|
| Rule Manager (CRUD) | `useRulesApi` + `rulesPost/Put/Delete/Toggle` | `/api/rules` + `/api/rules/{id}*` | ✅ live (DD-T6 + DD-T7) |
| Hot-reload toast | `waitForVersion` | `/api/config/version` | ✅ live (DD-T7) |
| Audit-mutation pipeline | (server-side) | every `/api/*` write | ✅ live (M3) |

## What works on the backend already (frontend just needs to consume it)

| Endpoint | Returns | Currently consumed by |
|---|---|---|
| `/api/about` | uptime, version, mode | nobody |
| `/api/stats` | request rate, error rate, RPS | nobody |
| `/api/stats/timeseries` | windowed rate timeseries | nobody |
| `/api/attacks/distribution` | OWASP class breakdown | nobody |
| `/api/attacks/top` | top attackers (IP / ASN / fingerprint) | nobody |
| `/api/audit/since` | filtered audit chain rows | nobody |
| `/api/blacklist`, `/api/whitelist` | block/allow lists | nobody |
| `/api/upstreams` | upstream pool health | nobody |
| `/api/cluster` | peers + leader (HA mode) | nobody |
| `/api/tiers` | tier config | nobody |
| `/api/runtime` | tokio worker config | nobody |
| `/api/loadmode` | current mode (normal / elevated / critical) | nobody |
| `/dashboard/sse` | live audit-event stream | nobody (PageLiveFeed uses fake generator) |

Hooks for every one of these already exist in `data.jsx` and are
exported on `window`. The integration work is just **swap the page
components from mock constants to the live hooks**.

## What needs backend implementation first (placeholder → real)

| Endpoint | Current | Real data source |
|---|---|---|
| `/api/slo` | `SloResponse::placeholder()` | wire `services.slo.snapshot()` (engine already exists; just not surfaced) |
| `/api/certs` | `CertsResponse::placeholder()` | enumerate TLS cert resolver → `(host, expires_at, issuer, fingerprint)` |
| `/api/gitops/status` | `GitopsStatusResponse::placeholder()` | read `services.gitops.last_apply()` |
| `/api/alerts` | `AlertsResponse::placeholder()` | read `services.slo.firing()` + ack/silence state |

## What needs new endpoints

| Need | Used by | Proposed endpoint |
|---|---|---|
| Geo blip data (attacker IP → country / city) | Overview map | derive from `/api/attacks/top` + GeoIP join (server-side) |
| Route table (host + path → upstream) | Tier Config | new `GET /api/routes` (read-only — config-derived) |
| Settings mutation (mode toggles, detector enable/disable) | Settings | new `PUT /api/loadmode/mode`, `PUT /api/detectors/{name}/toggle` (audit-mutated) |

## Tasks

### CI-T1 — Wire Overview to live data (≈ 2 hr)

| Sub-task | Replace | With |
|---|---|---|
| traffic timeseries | `window.useTrafficSeries(60)` | `window.useTimeseriesApi(900, 5)` (already exists) |
| KPI counters | derived from mock series | `window.useStatsApi()` |
| attack distribution | hardcoded `window.ATTACK_CATS` slice | `window.useAttacksDistributionApi(900)` |
| top attackers list | `window.ATTACKER_GEO.slice(0,5)` | `window.useAttacksTopApi(900, 5)` |
| live attacker globe | `window.ATTACKER_GEO` | derive blips from `useAttacksTopApi`'s response |
| status badge | static "Healthy" | derive from `window.useStatusApi()` (mode + healthy peers) |

Also: PageOverview's drawer currently inspects a mock event shape;
adapt to the real `AuditEvent` shape (already mapped by `useRealLiveFeed`).

**Done:** Overview reflects live RPS, real OWASP-class blocks, real
top attackers — confirmed by injecting traffic + watching the values
change.

### CI-T2 — Wire Live Feed to /dashboard/sse (≈ 30 min)

Replace `window.useLiveFeed(80, paused, 8)` with
`window.useRealLiveFeed(80, paused)` (already in `data.jsx`).

The mapping is already in `useRealLiveFeed`:
```js
{ t, ip, method, path, status, latency, risk, action, rules, cat }
```
matches what `PageLiveFeed`'s row renderer expects, so this is a
one-line replacement plus removing the mock generator imports.

**Done:** issuing a request through the data plane shows up in the
Live Feed within 1 s; pause / filter still work.

### CI-T3 — Wire Audit Log + Blacklist + Whitelist + Upstreams + Tracking (≈ 3 hr)

Five independent page swaps, all the same shape: replace the mock
constant lookup with the matching `useXxxApi()` hook.

| Page | Replace | With |
|---|---|---|
| `PageAuditLog` | `window.ADMIN_LOG` | `window.useAuditLogApi({ limit: 200, ip, ruleId, requestId, from, to })` (already wired) — also wire the filter inputs to the hook params |
| `ListPage` (blacklist) | `window.BLACKLIST` | `window.useBlacklistApi()` |
| `ListPage` (whitelist) | `window.WHITELIST` | `window.useWhitelistApi()` |
| `PageTracking` upstream | `window.UPSTREAMS` | `window.useUpstreamsApi()` |
| `PageTracking` cluster | `window.CLUSTER` | `window.useClusterApi()` |
| `PageTierConfig` | `window.TIERS` + `window.ROUTES` | `window.useTiersApi()` + new `useRoutesApi()` (T5 dep) |

**Done:** every page lists what's actually in the running WAF; mock
constants in `data.jsx` shrink to design-time-only.

### CI-T4 — Implement real /api/slo, /api/certs, /api/gitops/status, /api/alerts (≈ 4 hr)

Backend work — the SLO engine, GitOps poller, and alert dispatcher
all exist; they just don't surface their snapshot through the API.

| Endpoint | Wiring |
|---|---|
| `/api/slo` | replace `SloResponse::placeholder()` with `services.slo.snapshot()` shape: per-SLO `{name, target, current, fast_burn_rate, slow_burn_rate, error_budget_remaining}` |
| `/api/certs` | new `services.tls_inspector` (or read from `acme::manager`) → list of `{host, issuer, not_before, not_after, fingerprint_sha256}` |
| `/api/gitops/status` | replace placeholder with `services.gitops.snapshot()` (commit hash, applied_at, last_error, in_sync flag) |
| `/api/alerts` | replace placeholder with `services.slo.firing()` + ack list — also expose `POST /api/alerts/{id}/ack` (audit-mutated) for the Tracking page's ack button |

**Done:** Tracking page's SLO panel shows real burn rates; cert
freshness panel shows real expiry; "Alerts" panel shows what's
actually firing.

### CI-T5 — New endpoints: /api/routes (≈ 1 hr)

| Endpoint | Purpose |
|---|---|
| `GET /api/routes` | read-only view of the routing trie: `[{id, host, path, match_type, upstream, tier_override}]`. PageTierConfig uses this to show which routes hit which tier. Cached 30 s — config is hot-reloadable but doesn't change on every request. |

**Done:** Tier Config page lists real routes from `prod.yaml` (or
the live hot-reloaded config), not the seven hardcoded mock entries.

### CI-T6 — Settings page mutations (≈ 3 hr)

PageSettings is currently a static visual stub. Make it functional.

| Action | New endpoint | Audit-mutated |
|---|---|---|
| Switch mode (`enforce` ↔ `log_only` ↔ `simulate`) | `PUT /api/loadmode/mode` body `{mode}` | ✅ |
| Toggle individual detector | `PUT /api/detectors/{name}/toggle` | ✅ |
| Toggle DDoS auto-mode | `PUT /api/loadmode/auto` body `{armed: bool}` | ✅ |
| Adjust risk thresholds | `PUT /api/risk/thresholds` body `{challenge_at, block_at, max}` | ✅ |
| Acknowledge / silence alert | `POST /api/alerts/{id}/ack` (already in T4) | ✅ |

All mutations route through `services.mutate.apply()` (CSRF-gated,
audit-chain-emitted, hot-reload-published). Frontend wires the
corresponding `window.settingsXxx()` helpers in `data.jsx` mirroring
the rule CRUD pattern.

**Done:** an operator can flip the WAF into `log_only` from the
Settings page, watch the toast confirm "Applied in X.X s", and see
subsequent attacks pass through unblocked.

## Total effort

| Track | Effort | Blocking? |
|---|---|---|
| CI-T1 Overview | 2 hr | independent |
| CI-T2 Live Feed | 30 min | independent |
| CI-T3 5-page swap | 3 hr | partly blocks on CI-T5 (routes) |
| CI-T4 Tracking-page real data | 4 hr | independent |
| CI-T5 /api/routes | 1 hr | unblocks CI-T3 tier config |
| CI-T6 Settings mutations | 3 hr | independent |
| **Total** | **~13 hr** | |

Recommended order: **T2 → T1 → T5 → T3 → T4 → T6** (fastest visible
wins first; backend-heavy work last).

## Acceptance per track

Each task closes when:

1. The page renders correctly against `make run` with the dev config
   (no console errors, real data visible).
2. The mock-constant fallback in `data.jsx` still renders when the
   endpoint is unreachable (degrades gracefully).
3. `cargo test --workspace` stays green; new endpoints have at least
   one shape test in their `crates/aegis-control/src/api/*.rs`.
4. `bash tests/dashboard/round1-acceptance.sh` still passes.
5. New endpoints are reachable from the SOC runbook's
   `make smoke` verification (extend `make smoke` if needed).

## Test plan

- **Unit:** new endpoints get a `render_*_response_has_expected_shape`
  test mirroring the existing pattern in `crates/aegis-control/src/api/*`.
- **Integration:** `tests/api/dashboard-integration.sh` (new) — boots
  `make run`, calls every endpoint the dashboard consumes, asserts
  non-empty / well-formed JSON. Extends `tests/dashboard/round1-acceptance.sh`.
- **Live:** for each page, capture a fresh screenshot under
  `tests/results/run-NN-…/screenshots/` after the wiring lands;
  diff against the run-10 baseline so regressions surface visually.

## Out of scope

- **Multi-tenant filters** (per-tenant rule sets, per-tenant audit
  chains) — deferred under [`docs/future/rbac-sso.md`](../docs/future/rbac-sso.md).
- **WebSocket real-time push** beyond the existing SSE — current
  SSE bus carries everything the dashboard needs.
- **Settings full RBAC** — the Settings page assumes the single
  admin principal model. Per-action permissions land with the SSO
  track.
