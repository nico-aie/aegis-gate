# Console QA — full feature audit (`CQA-T*`)

> **Status:** Active — awaiting kickoff. Track ID prefix
> `CQA-T<n>`. Goal: every screen, every button, every
> action works end-to-end with **real, live data** —
> no static fixtures, no Math.random, no dead buttons,
> no broken mutations.

---

## 0 · Why

The dashboard surface has grown across DD-T0..T8 (initial UI),
CI-T1..T12 (live API hooks), CC-T1.\* + CC-T2.\* (config pages
mutations), HACK-T1 (mock-data retirement), HACK-T3 (rule
simulator), HACK-T4 (config-versions + rollback), and
MTLS-T7 (SAN allowlist). That's ~15 audit-mutated handlers,
~25 read endpoints, and 12 sidebar pages. Coverage has been
incremental — each track verified its own surface but no
single sweep has confirmed **every interaction on every
page works in the current build**.

Round-1 will visit the console. We want to land it with
zero broken buttons, zero stale fixtures, zero fake numbers.

## 1 · Inventory

### 1.1 Pages (12 sidebar entries + Help)

| Route | Page | Purpose |
|---|---|---|
| `#/overview` | `PageOverview` | Topline stats + sparklines |
| `#/live` | `PageLiveFeed` | SSE stream of decisions |
| `#/attacks` | `PageAttackEvents` | Attack analytics |
| `#/analytics` | `PageAnalytics` | Time series + SLOs + certs |
| `#/audit` | `PageAuditLog` | Audit chain browse + filter + verify |
| `#/rules` | `PageRuleManager` | Rule CRUD + simulator |
| `#/tiers` | `PageTierConfig` | Detector mask per tier |
| `#/upstreams` | `PageUpstreams` | Upstream pools CRUD + health |
| `#/blacklist` | `ListPage kind="blacklist"` | IP blacklist CRUD |
| `#/whitelist` | `ListPage kind="whitelist"` | IP whitelist CRUD |
| `#/settings` | `PageSettings` | Mode toggle + risk thresholds + config history + rollback + mTLS SAN allowlist |
| `#/tracking` | `PageTracking` | Cluster + SLO alerts + alert receivers |
| `#/scaling` | `PageScaling` | L1/L2/L3 scaling status |
| `#/help` | `PageHelp` | Operator help |

### 1.2 Cross-cutting interactive elements

- TopBar (env pill, mode pill, drain button, logout)
- Sidebar nav (active highlight)
- Toast container (success / warn / err)
- Status bar (clock, build, conn)

## 2 · Acceptance criteria per page

A page passes QA when **all** of the following are true:

1. **Data is live.** Every visible number / row / chart
   resolves to a real `/api/*` call (or `/dashboard/sse`).
   Zero `Math.random()` in code, zero references to
   `window.RULES / BLACKLIST / WHITELIST / UPSTREAMS / CLUSTER
   / CERTS / ALERTS / ADMIN_LOG / TIERS / ATTACKER_GEO / ROUTES
   / REGIONS / ATTACK_CATS / ORIGIN` static fixtures, zero
   "demo mode" placeholders.
2. **Empty states are honest.** When the underlying API
   returns `[]` or 404 the page renders an explanatory
   message, not stale fake rows.
3. **Every button works.** Click → expected side effect →
   visible feedback (toast / inline status / row change).
   No "Coming soon" tooltips. No `onClick={() => {}}`.
4. **Every form submits.** Fields validate, the
   audit-mutated PUT/POST/DELETE lands, the audit-chain
   entry is visible on the Audit Log page within 2 s,
   and the page refreshes its own state.
5. **CSRF + auth gates hold.** A mutation without
   `x-csrf-token` returns 403; a logged-out session can't
   mutate.
6. **Hot-reload is visible.** `/api/config/version`
   increments after every audit-mutated change; the
   ConfigVersionsCard on Settings shows the new entry
   newest-first.
7. **No console errors.** Browser DevTools console shows
   zero red errors during page load + interaction.
8. **No 4xx / 5xx leaks.** DevTools Network tab shows
   only 200 / 201 / 204 for successful flows; 4xx only
   on intentional negative tests.

## 3 · Slice map

Sliced page-by-page so QA can be parallelized across
multiple sessions if needed.

| Slice | Page | Estimated time | Dependencies |
|---|---|---|---|
| **CQA-T1** | Overview | 30 min | none |
| **CQA-T2** | Live Feed (SSE) | 30 min | requires hot traffic to verify stream |
| **CQA-T3** | Attack Events | 30 min | needs detector hits in audit ring |
| **CQA-T4** | Analytics | 45 min | SLO + cert + timeseries hooks |
| **CQA-T5** | Audit Log | 45 min | filter + verify + cross-link from rollback |
| **CQA-T6** | Rule Manager | 60 min | rule CRUD + toggle + simulator + paste-from-audit |
| **CQA-T7** | Tier Config | 45 min | detector mask audit-mutated PUT + per-tier override |
| **CQA-T8** | Upstreams | 60 min | pool CRUD + member CRUD + drain + health |
| **CQA-T9** | Blacklist + Whitelist | 30 min | one ListPage component, two kinds |
| **CQA-T10** | Settings | 90 min | mode toggle, risk thresholds, config versions card with rollback, mTLS SAN allowlist (add / remove / test) |
| **CQA-T11** | Tracking | 60 min | cluster, SLO alerts ack, alert receivers CRUD + test |
| **CQA-T12** | Scaling | 30 min | state-backend health, drain |
| **CQA-T13** | Cross-cutting | 30 min | TopBar drain, logout, toast lifetime, status-bar clock |
| **CQA-T14** | Mock-data audit | 30 min | grep sweep + fixture-removal verification |

Total wall-clock: ~9 hours of manual QA, parallelizable.

## 4 · Per-page QA template

Each slice produces a row in the run report:

```markdown
### CQA-T<n> · <Page>

| Item | Type | Verified | Notes |
|---|---|---|---|
| useFooApi (hook) | data load | ✅ / ❌ | endpoint URL + status |
| <button> Save | mutation | ✅ / ❌ | audit chain entry id |
| Empty state | render | ✅ / ❌ | screenshot-on-fail |
| ...

**Console errors:** none / list
**Network 4xx/5xx:** none / list
**Audit chain:** seq before → seq after, list of new actions
**Verdict:** ✅ pass / ❌ fail (issue id)
```

## 5 · Tooling

Two paths — pick by what's available:

- **Manual** (always works): operator drives the dashboard
  in a real browser with DevTools open; checks Network +
  Console tabs; cross-references Audit Log page.
- **Automated** (faster, partial coverage): Playwright
  script under `tests/dashboard/cqa-suite.mjs` walks each
  page, asserts no console errors, hits each visible
  button, asserts a 200/204 + a new audit row. The
  capture-screenshots harness already exists at
  `tests/dashboard/capture-screenshots.mjs` — extend it.

The first pass is **manual**. Automation is a follow-up
once the manual pass establishes ground truth.

## 6 · Output

Each slice writes its row to a single run report:

```
tests/results/run-cqa-<YYYYMMDD>/
├── README.md                     # consolidated table
├── per-slice/
│   ├── CQA-T01-overview.md
│   ├── CQA-T02-live-feed.md
│   └── ...
├── screenshots/                  # pass + fail captures
└── network-logs/                 # HAR exports per slice
```

The consolidated `README.md` rolls up to a single
**Pass / Fail / Blocked** verdict per slice.

## 7 · Pre-checks (do these before kickoff)

1. ✅ `cargo build --release -p aegis-bin` clean.
2. ✅ Workspace tests green.
3. ✅ Dashboard bundle freshly built
   (`bash crates/aegis-control/assets/dashboard/build.sh`).
4. ✅ Audit log empty (`rm waf_audit.log` before boot) so
   the chain entries from this run are easy to read.
5. ✅ Boot against `config/dev.yaml` so the dev creds
   work (`admin / aegis-test-1234`).
6. ✅ Drive a couple of detector probes so Attack Events
   has data to render (the page's empty state is also a
   valid pass — but content render is more thorough).

## 8 · Known watch-list (heard before, verify here)

- `PageAttackEvents` was wired in HACK-T1; confirm
  detector breakdown + bot mix + threat-intel widgets
  show real numbers, not zeros.
- `PageAnalytics` SLO pills + cert freshness should
  reflect the live values from `/api/slo` + `/api/certs`.
- `PageRuleManager` simulator card (HACK-T3) should
  return BLOCK on a SQLi probe; rule CRUD edits should
  hot-apply within 2 s.
- `ConfigVersionsCard` Rollback button (HACK-T4
  follow-up) should be enabled only on rollback-able
  rows (`mode_set` v1) and should two-step confirm.
- `MtlsSansCard` (MTLS-T7 follow-up) — verify add /
  remove / test against an empty initial allowlist on
  dev config.
- Alert receivers card test button: clicking should
  send a synthetic SLO alert and surface the dispatch
  outcome ring.
- `PageScaling` `/api/state` should show in-memory
  backend on dev config; switch to redis fixture for
  cross-validation.

## 9 · Definition of Done

- [ ] All 14 slices have a row in the run report.
- [ ] No slice marked **Fail** without an open ticket /
      follow-up plan entry.
- [ ] Zero `Math.random()` in `pages.jsx` source (✅
      currently 0; the matches the grep finds are inside
      comments, not code).
- [ ] Zero static-fixture fallbacks in pages.jsx.
- [ ] All audit-mutated buttons round-trip through
      `/api/config/versions` (rollback-able when
      applicable).
- [ ] Run report committed under `tests/results/run-cqa-*`.
- [ ] `Implement-Progress.md` Last Completed entry follows
      § 0.3 protocol.
