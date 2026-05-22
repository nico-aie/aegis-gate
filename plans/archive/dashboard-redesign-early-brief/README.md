# Dashboard Redesign Track — early brief (ARCHIVED)

> **Status:** Superseded — never executed in this shape.
>
> The eleven-milestone (M0..M10) breakdown in this folder was
> the early planning artefact for a Claude Design–driven dashboard
> redesign. It was replaced before execution by the simpler
> DD-T0..T8 plan that actually shipped — see
> [`../../dashboard-redesign.md`](../dashboard-redesign.md) and
> the closing run-10 README under
> [`../../../tests/results/run-10-2026-04-30-dashboard-redesign/`](../../../tests/results/archive/run-10-2026-04-30-dashboard-redesign).
>
> Kept here for historical reference only. Do not link to this
> tree from new work.

## Inputs the track depends on

| Input | Where | Status |
|---|---|---|
| Design contract per page | [`docs/control-plane/enterprise/pages/*.md`](./pages) | done |
| API contract | [`docs/control-plane/enterprise/api.md`](../../../docs/control-plane/enterprise/api.md) | done |
| Layout / theme / a11y / components doc bundle | [`docs/control-plane/enterprise/{layout,theme,accessibility,components}.md`](../../../docs/control-plane/enterprise) | done — but theme + components need a refresh under M0 |
| Admin login HTTP route | F-T1 in `post-k6-followup.md` | **pending — blocks ship** |
| Asset embedder + bundle-size budget | `crates/aegis-control/src/dashboard/assets.rs` + `tests/dashboard_polish.rs` | done; budget is 700 KB raw |

## Plan layout

```
plans/dashboard-redesign/
├── README.md                           ← this file (index + ordering)
├── workflow.md                         ← how to drive Claude through each stage
├── design-system.md                    ← tokens, typography, motion, dark/light
├── milestone-0-foundations.md          ← shell + components + tokens — must land first
└── pages/
    ├── README.md                       ← per-page plan template + index
    ├── M1-overview.md
    ├── M2-live-feed.md
    ├── M10-settings.md
    └── (M3..M9 added as work begins)
```

The three seed page plans (`M1-overview`, `M2-live-feed`,
`M10-settings`) are written as concrete examples. The rest
of the milestones (M3 attack events, M4 audit log,
M5 analytics, M6 rule manager, M7 tier config, M8 blacklist
+ whitelist combined, M9 tracking) follow the same template
in `pages/README.md` and can be filled in just-in-time —
working ahead means your design assumptions go stale before
they ship.

## Milestone ordering

Pages are ordered by how much they de-risk the rest of the
track. Land **M0** before any page. After M0, the order is
loose — but stick to it on a fresh redesign, because each
milestone resolves design questions the next one inherits.

| ID | Milestone | Why this slot | Effort |
|---|---|---|---|
| **M0** | Foundations — design tokens, chrome shell, refreshed components | Every page consumes these; landing them first means each page milestone is *page work*, not chrome work | ~5 days |
| **M1** | Overview page | Highest-traffic page, sets the visual bar for the rest | ~3 days |
| **M2** | Live Feed | Real-time SSE + filter chips + drawer flow — hardest interaction model. De-risks the SSE chrome before easier pages copy from it. | ~4 days |
| **M3** | Attack Events | Reuses Live Feed's table + drawer; lower-stakes follow-on | ~2 days |
| **M4** | Audit Log | Same shape; adds hash-chain verify pill | ~2 days |
| **M5** | Analytics | Time-window picker + charts library decision (extracted from M0) | ~3 days |
| **M6** | Rule Manager | First page with a heavy editor — Monaco / textarea decision | ~4 days |
| **M7** | Tier Config | Per-tier override grid (already partly built in P3) | ~2 days |
| **M8** | Blacklist + Whitelist (combined) | Same data model, two views, paired CRUD | ~2 days |
| **M9** | Tracking | SLO / cluster / cert / GitOps / alerts dashboard — heavy on glanceable widgets | ~3 days |
| **M10** | Settings | Configures every P1–P8 toggle — depends on every prior page's component decisions | ~3 days |

**Total:** ~33 days serial; parallelisable to ~3 weeks with two
hands once M0 has landed.

## Definition of done for the track

- Every page passes the acceptance template in
  `pages/README.md` (visual review, a11y AA, keyboard, empty
  / loading / error / stale states, dark + light themes,
  responsive at 1280 / 1440 / 1920, bundle budget).
- `tests/dashboard_polish.rs` budgets still hold.
- `tests/api/run-all.sh` still exits 0 on a fresh run (the
  redesign must not break any contract).
- A new k6 script `tests/load/dashboard-soak.js` runs a
  representative dashboard browse session for 5 minutes
  without leaking memory or breaking the SSE channel.
- Dark + light themes documented in
  `docs/control-plane/enterprise/theme.md` (refreshed under M0).
- Each page has at least one Playwright E2E spec under
  `tests/e2e/dashboard/` (a new directory).

## How to start

1. Read [`workflow.md`](./workflow.md). It defines the three
   prompt templates you'll re-use for every page.
2. Read [`design-system.md`](./design-system.md). Decide
   whether the M0 token set is acceptable or needs a tweak
   before you commit.
3. Land [`milestone-0-foundations.md`](./milestone-0-foundations.md).
4. Open [`pages/README.md`](./pages/README.md), pick M1, and
   walk the workflow stages.
5. Keep the loop tight: design brief → code → screenshot
   review → ship. Don't accumulate >1 unfinished milestone.
