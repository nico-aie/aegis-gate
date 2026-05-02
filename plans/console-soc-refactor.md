# Plan — SOC-grade console refactor

> **Status:** Plan-only — awaiting user approval. Do not execute
> code changes from this doc until each phase is signed off.
> **As of:** 2026-05-02 — drafted in response to user audit feedback
> on console UX (CSRF residual, GeoDB unloaded, upstream UI bugs,
> Live Feed thin, Audit Log/Live Feed duplication, Analytics gaps,
> upstream protocol picker, missing SOC workflows).

## Problem statement

The current console has 13 pages and ~70% feature completeness for
basic WAF operations. It was built incrementally — most pages map
1:1 to a single backend API surface. The gap, surfaced by user
SOC-team test:

1. **Operational bugs**: CSRF cookie still rejected on dev
   (browser-side session staleness + UX gap), upstream pool shows
   `undefined / NaN members up`, Live Feed lacks request context,
   Live Attack Origins map empty (GeoDB not loaded — silent),
   Analytics latency p50/p95/p99 unwired, error rate by route
   unwired, upstream config supports HTTP/HTTPS only.
2. **Workflow gaps**: no Incident triage, no drill-down /
   investigation pivot from "Top Attacker" → "all requests from
   this IP", no threat-intel feed UI (TAXII config exists but
   not surfaced), no scheduled reports, no bulk import for
   blacklist, no alert-rule builder, no risk trending chart.
3. **Information architecture**: Audit Log + Live Feed
   look duplicative (different signal sources, same surface
   shape — Live = request stream, Audit = config + request
   trail). Tracking + Scaling are nearly identical pages.
   Configuration spread thin (Blacklist + Whitelist could merge
   into Access Lists; Tier Config + Detector mask blur).
4. **Enterprise polish**: no role-based access (single admin
   user), no exec rollups, no MTTR / SLA tracking, no
   compliance summary view, no forensics evidence preservation.

## Target end-state — SOC-team console

**Design principle**: every SOC analyst landing on the console
should answer three questions in 30 seconds — *what's wrong now*,
*what changed*, *what should I do*. Then they need to drill from
any signal into full context within two clicks.

### Sidebar information architecture (proposed)

```
SECURITY OPERATIONS  ← SOC default landing zone
├─ Overview             (executive dashboard, no change in concept)
├─ Live Feed            (real-time request stream — enriched)
├─ Incidents            [NEW]   open + ack'd alert queue, MTTR clock
├─ Investigation        [NEW]   pivot from IP / request_id / rule_id
├─ Attack Analytics     (RENAMED from "Attack Events" — top attacks, geo, attacker IPs)
├─ Threat Intel         [NEW]   TAXII / MISP / GeoIP feed status + config

POLICY            ← was "Configuration"
├─ Rules                (rule manager + simulator — keep)
├─ Detectors            (RENAMED from "Tier Config" — per-class enable, per-tier override)
├─ Access Lists         (MERGED Blacklist + Whitelist)
├─ Routing & Upstreams  (RENAMED from "Upstreams" — multi-protocol picker added)
├─ Compliance Profile   [NEW]   PCI / HIPAA / SOC2 / GDPR / FIPS clamp configurator

OBSERVABILITY     ← was "Tracking"
├─ Performance          [NEW]   latency p50/p95/p99 by route, error rate by route, throughput by tier
├─ Health & SLOs        (was "Tracking" — system health, SLO burn, alert receivers)
├─ Audit Trail          (RENAMED from "Audit Log" — chain integrity verification UI added)
├─ Scaling              (keep — L1/L2/L3 in one stack)

ADMIN
├─ Settings             (mTLS SANs, sessions, password, mode toggle, risk thresholds)
├─ Reports              [NEW]   exec rollups, compliance, MTTR, daily/weekly digests, CSV/PDF export
├─ Help & Guide         (keep)
```

**Net change**: 4 NEW pages (Incidents, Investigation, Threat Intel, Compliance Profile, Reports — actually 5), 2 RENAMED, 1 MERGED (Blacklist+Whitelist → Access Lists), 1 redundant page collapsed (Scaling stays — Tracking renamed to Health & SLOs since they truly serve different purposes once Performance splits out).

Total: 17 pages (vs 13 today). +4 new SOC workflows, -1 duplicate (Tracking/Scaling overlap resolved), +0 removed.

### What each page does — SOC analyst view

#### SECURITY OPERATIONS

- **Overview** — top-of-funnel rollup. RPS / block %% / active threats / upstream health / SLO burn / cluster status / "what changed in the last 1h". Single-screen; no scrolling. The 30-second answer to "is anything on fire?"
- **Live Feed** — real-time SSE stream of every request the WAF
  decided on. Filter by action / tier / IP / path / detector. Each
  row drills into a Request Detail panel with: full URL, method,
  headers (sanitised), peer IP + ASN + country, TLS + JA4
  fingerprint, detector signals, rule matches, response code,
  latency. *Today's gap*: Live Feed has thin RequestDetail and no
  drill-down to "all requests from this IP".
- **Incidents** [NEW] — alerts that fired (from `/api/alerts` +
  `/api/alert-receivers`). Status column: firing / acknowledged /
  resolved. SLA clock per row. Operator can ack, snooze, escalate,
  add notes. Alert-rule builder lives here too (currently rules
  are hardcoded in `waf.yaml`).
- **Investigation** [NEW] — single-input pivot field: paste
  IP / CIDR / request_id / rule_id / SAN / session ID. The page
  computes everything we know about that signal across the audit
  ring, attacker tables, threat-intel hits, recent rule hits,
  related sessions. SOC's universal "tell me about X" tool.
- **Attack Analytics** — current "Attack Events" page renamed.
  Top attackers (table + geo map), detector breakdown, bot mix,
  threat-intel hits. Plus new: risk trend over time, top new
  attackers in last 24h, week-over-week delta.
- **Threat Intel** [NEW] — surfaces what's currently config-only:
  TAXII feed status (last fetch, indicator count, errors), GeoIP
  DB status (file path, version, age — GeoDB-not-loaded warning
  links here), STIX bundle preview, MISP feed health. Config UI
  to add/remove feeds without YAML edit + restart.

#### POLICY

- **Rules** — keep current Rule Manager + simulator. Add: bulk
  enable/disable, "show requests matching this rule in last 1h".
- **Detectors** — current Tier Config rebranded so SOC can find
  it. Per-class toggle (sqli, xss, …) + per-tier overrides in
  one screen. Locked classes (compliance-pinned) clearly marked.
- **Access Lists** — Blacklist + Whitelist merged. Tabs for IP /
  CIDR / ASN. Plus: bulk paste-CSV import (currently missing),
  TTL picker in the add form (currently server-side only),
  "rule this fired against in the last 24h" annotation.
- **Routing & Upstreams** — current Upstreams page expanded.
  *Critical fix*: protocol picker becomes `<select>` with
  `http | https | grpc | h2c | tcp`, not the boolean `tls`. Each
  pool's connection card shows protocol pill. Multi-protocol
  upstream support is already a v0.1 design goal per
  `Architecture.md` §3.
- **Compliance Profile** [NEW] — config UI for `compliance.modes`
  (PCI / HIPAA / SOC2 / GDPR / FIPS). Currently set in YAML +
  restart. Page shows: which classes are clamped, which routes
  inherit which mode, and which detectors a given mode forces ON.

#### OBSERVABILITY

- **Performance** [NEW] — latency p50/p95/p99 by route + by tier
  (the missing analytics). Error rate by route. Throughput
  histogram. Backed by new `/api/analytics/latency` and
  `/api/analytics/routes` endpoints (Phase 1 work below).
- **Health & SLOs** — current Tracking page minus the runtime/
  scaling cards (those move to Scaling). Keep: SLO burn, alert
  receiver health, drain button, audit chain verify, cluster
  peers, GitOps status.
- **Audit Trail** — current Audit Log + a new "Chain Verify"
  button that runs `waf audit verify` against the visible window
  and shows pass/fail. CSV export (currently button is wired but
  download path missing).
- **Scaling** — current Scaling page (L1 workers + L2 cluster + L3
  state). Keep as is.

#### ADMIN

- **Settings** — current Settings page. Add: AEGIS_INSECURE_COOKIES
  status banner so dev operators know why session/CSRF cookies
  don't have the Secure flag.
- **Reports** [NEW] — daily / weekly digest generation. Compliance
  report (per `compliance.modes`). Top attackers by week. MTTR by
  alert type. Exports as CSV / PDF / JSON.
- **Help & Guide** — keep.

---

## Critical bug fixes (Phase 1 — before any restructure)

These are blockers the user surfaced. Each is a contained fix that
ships independently of the larger restructure.

| # | Bug | Root cause | Fix |
|---|-----|------------|-----|
| 1 | **CSRF still failing for some sessions** | Browser session set BEFORE the `AEGIS_INSECURE_COOKIES=1` fix landed; old cookies have `Secure` flag, browser silently drops them on HTTP. | (a) Add boot log: `cookies: secure=on/off` so operator can see which mode is active. (b) Add `make login-reset` target that hits `/admin/logout` + clears local `aegis_*` cookies. (c) Document in QUICKSTART. |
| 2 | **Upstream "DOWN" + "undefined NaN members up"** | Backend returned `healthy: 0` (fixed in `fe39722`), but the dashboard JSX uses `pool.healthy ?? '?'` and falls through to NaN when totals are NaN. | Audit `pool.healthy` + `pool.total` consumers in `pages.jsx`; default to 0 not NaN; render "—" for unknown. |
| 3 | **Live Feed path always `/`** | NOT a bug — paths render correctly in code. User saw `/` because the Go mock upstream's `handleRoot` matched `/` as the catch-all and the test traffic was `curl /`. | Document in QUICKSTART that `/` is the only path the dev mock answers; `make mock-load` drives varied paths now. |
| 4 | **Live Attack Origins map empty** | `/api/attacks/top` returns `country: null` when MaxMind GeoIP DB isn't loaded. Pill says "geo DB not loaded" but operator missed it. | Make the "geo DB not loaded" pill clickable → opens new Threat Intel page (Phase 2) with one-click GeoIP setup wizard. Phase 1: better empty-state copy + link to install instructions. |
| 5 | **Analytics latency p50/p95/p99 missing** | No JSON API for histogram metrics; only Prometheus scrape at `/metrics`. | Add `GET /api/analytics/latency` returning `{p50, p95, p99}` per `route` + per `tier` over a window. Wire to PageAnalytics. ~150 LOC backend + 50 frontend. |
| 6 | **Analytics error rate by route missing** | No per-route aggregation in backend. | Add `GET /api/analytics/routes` returning `[{route, total, blocked, errors_5xx, error_rate_pct}]`. ~100 LOC backend + 30 frontend. |
| 7 | **Upstream protocol picker is boolean** | `tls: bool` covers HTTP/HTTPS only; backend `PoolConfig` has no `scheme` field. | Backend: extend `PoolConfig` with `scheme: enum {http, https, grpc, h2c, tcp}` (defaults to `http`/`https` derived from current `tls` flag for back-compat). Dashboard: add `<select>` to PoolEditModal. ~80 LOC each side. |
| 8 | **Audit Log / Live Feed feel duplicate** | They aren't (Live = SSE request stream, Audit = polled all-events trail) but the visual surface is similar enough that operators conflate them. | Add a banner row to each page explaining the relationship. Phase 2: add cross-links ("see this in Audit Trail" button on Live Feed rows). |

Estimated time for Phase 1: ~1.5 days. Each row is a contained PR.

---

## Implementation phases

### Phase 1 — Critical fixes (1.5 days)
Ships every row in the bug table above. No structural changes.
Each row a single commit. PRs land green into `develop`.

**Acceptance**: every issue the user listed is verifiable green.
`make smoke` + `make mock-load` show realistic data on every page.

### Phase 2 — Information architecture (2-3 days)
Ships the sidebar restructure WITHOUT new pages — just renames
and merges:
- "Configuration" → "Policy"
- "Tracking" → "Observability" (with Tracking page → "Health & SLOs")
- Blacklist + Whitelist → Access Lists (single page, tabs)
- Attack Events → Attack Analytics

**Acceptance**: every existing feature still reachable from the
new IA. No backend changes — pure frontend rearrangement.

### Phase 3 — New SOC pages (5-7 days)
Each page ~1 day of work (some new APIs, mostly UI):

1. **Performance** (1d) — uses the latency / routes APIs from
   Phase 1. Largely new page.
2. **Investigation** (1.5d) — single-input pivot. Reuses every
   existing API. New "audit search" UX.
3. **Incidents** (1.5d) — needs `GET /api/alerts/active` +
   `POST /api/alerts/{id}/ack` + alert-rule builder. New
   backend.
4. **Threat Intel** (1d) — surfaces existing TAXII / GeoIP /
   STIX backend state in UI. Adds feed-management endpoints.
5. **Compliance Profile** (0.5d) — UI over existing
   `compliance.modes` config block.
6. **Reports** (0.5d) — ships CSV export first; PDF later.

**Acceptance**: every page renders with real data on a fresh
`make run-dev` + `make mock-load`. Every action audit-chained.

### Phase 4 — Enterprise polish (deferred until 1-3 land)
- Role-based access control (Reader / Editor / Admin)
- Bulk operations (CSV import for blacklist, batch rule toggle)
- Risk-score trending chart
- Forensics request-body capture (compliance-gated)
- E2E Playwright tests for every page (`tests/dashboard/`)

---

## Open questions for the user

Before kicking off Phase 1:

1. **Phase ordering** — proceed Phase 1 → 2 → 3 sequentially, or
   parallel (some Phase 3 work can happen before IA changes
   land)?
2. **"Compliance Profile" page priority** — ship in Phase 3, or
   defer to Phase 4? Depends on whether you have a compliance
   regime to test against.
3. **"Reports" depth** — CSV export only (Phase 3), or also PDF
   + scheduled delivery? PDF needs a headless-Chrome dependency.
4. **Audit ring forensics** — do you want optional request-body
   capture (with TTL) in this refactor, or strictly Phase 4?
   This is the biggest scope-creep risk.
5. **Rename or keep page IDs** — e.g. `#blacklist` → `#access-lists`
   breaks any saved bookmarks. Acceptable, or keep
   redirects?

Reply with answers + "go" before I start Phase 1.

---

## Cross-references

- Audit findings (this session): see chat transcript
  `2026-05-02` from "I quick test the console with mock data"
- Existing per-page docs: `docs/control-plane/enterprise/pages/*.md`
- Backend API surface: see audit summary in this plan §"Backend
  API surface" (delegated to Explore agent 2026-05-02)
- Earlier related plans:
  - `plans/dashboard-redesign.md` (DD-T0..T8 — closed)
  - `plans/console-config-pages.md` (CC-T1..T3 — partial)
  - `plans/console-qa.md` (CQA / CQF — closed)
