# Layout

## Frame

```
┌────────────────────────────────────────────────────────────────────────┐
│  TOP BAR  (48px) — logo · env · health LED · search · user menu        │
├────────────┬───────────────────────────────────────────────────────────┤
│            │                                                           │
│  SIDEBAR   │                  CONTENT FRAME                            │
│  (240px)   │                                                           │
│            │   page-specific layout (see pages/*.md)                   │
│            │                                                           │
│            │                                                           │
│            │                                                           │
├────────────┴───────────────────────────────────────────────────────────┤
│  STATUS BAR (24px) — connection state · cluster size · last sync       │
└────────────────────────────────────────────────────────────────────────┘
```

- Sidebar: fixed width 240px on `>= 1024px`. Collapses to icon-only
  64px on `>= 768px`. Becomes a top drawer (hamburger) on `< 768px`.
- Top bar: fixed 48px tall. Always visible.
- Status bar: fixed 24px tall. Shows SSE connection state, cluster
  member count, last config sync timestamp, audit-chain status pill.
- Content: the only scrollable region.

## Top bar

| Slot | Element | Behaviour |
|------|---------|-----------|
| L1 | Logo + product name "Aegis WAF" | Links to `/dashboard/` |
| L2 | Version badge `v0.x.y` | From `/api/about` |
| L3 | Environment label | Reads `admin.environment` (e.g. `prod`, `staging`); colour-coded |
| C  | Global search | Cmd-K palette: jumps to a page, a rule, or an IP lookup |
| R1 | Health LED | Green/amber/red from `/healthz/ready` poll |
| R2 | User menu | Shows admin name, sign-out, theme toggle |

## Sidebar

```
┌──── OPERATOR ─────┐
│  Overview         │   ← dashboard root
│  Live Feed        │
│  Attack Events    │
│  Analytics        │
│  Audit Log        │
│                   │
├──── CONFIG ───────┤
│  Rule Manager     │
│  Tier Config      │
│  Blacklist        │
│  Whitelist        │
│  Settings         │
│                   │
├──── TRACKING ─────┤
│  Tracking         │   ← SLO + cluster + GitOps + cert health
└───────────────────┘
```

- Each item: 36px tall row, 16px icon, label, optional badge (count
  or status dot).
- Active page: 4px left accent bar in `--color-accent`, background
  `--surface-active`.
- Hover: background `--surface-hover`, no animation longer than
  120 ms.
- Section headings: 11px uppercase, `--text-muted`, 8px vertical
  padding.

## Content frame

- Outer padding 24px on `>= 1024px`, 16px on `< 1024px`.
- Each page renders into a 12-column grid with 16px gutters.
- Page header: H1 + subtitle + optional action button row, 56px tall.
- Below header: page-specific layout per [`pages/`](pages/).

## Routing

Client-side router using `history.pushState`. Routes:

```
/dashboard/                 → redirects to /dashboard/overview
/dashboard/overview
/dashboard/live
/dashboard/attacks
/dashboard/analytics
/dashboard/audit
/dashboard/rules
/dashboard/tiers
/dashboard/blacklist
/dashboard/whitelist
/dashboard/settings
/dashboard/tracking
```

The server returns the SPA shell for any path under `/dashboard/`
(except `/dashboard/sse` and `/dashboard/assets/*`). The client
parses the path and mounts the corresponding page module.

## Breakpoints

| Name | Min width | Sidebar | Top bar | Grid |
|------|-----------|---------|---------|------|
| sm   | 0         | drawer  | compact | 4 col |
| md   | 768px     | icons   | full    | 8 col |
| lg   | 1024px    | full    | full    | 12 col |
| xl   | 1440px    | full    | full    | 12 col, max 1440px |

## Density modes

Two density presets, persisted in `localStorage` under
`aegis.dashboard.density`:

- **Comfortable** (default) — 36px rows, 24px page padding.
- **Compact** — 28px rows, 16px page padding. For SOC operators on
  smaller screens running multiple consoles side-by-side.

## Empty / error / loading states

Every widget defines all four states:

1. **Loading** — shimmer placeholder for ≤ 1s; if data still
   missing, swap to a static "Loading…" with no spinning element.
2. **Empty** — icon + headline + one-line hint ("No attacks in the
   last 5 minutes — quiet is good.").
3. **Error** — icon + short message + Retry button. Never expose
   stack traces or internal paths (see [`security.md`](security.md)).
4. **Stale** — small badge "Updated 12s ago" if the polling client
   hasn't received fresh data in > 2 polling intervals.

## Component library

See [`components.md`](components.md). Roughly: stat card, line chart,
pie chart, table (sortable, paged), badge, pill, drawer, modal,
toast, code block (for diffs).
