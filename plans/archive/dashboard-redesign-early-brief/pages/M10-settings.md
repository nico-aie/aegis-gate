# M10 — Settings

> **Status:** Queued — M10 — Settings page redesign brief.
>
> See [`README.md`](../../README.md) for the track status board.

> **Status.** seed
>
> **Effort.** ~3 days
>
> **Depends on.** M0 + every other page milestone in the
> track. Settings ships **last** because it's the page that
> *configures* every feature P1–P8 added — every component
> decision the prior milestones lock in feeds this page.
>
> **Why this milestone is the convergence.** The current
> `settings.js` is the most concentrated example of the
> "data wired, presentation thin" problem the redesign
> solves: it touches 5 endpoints, has 4 panels with no real
> hierarchy, and is the only operator-facing path for
> half-the toggles in P1–P8.

## Inputs

- Design contract: [`docs/control-plane/enterprise/pages/settings.md`](../../../docs/control-plane/enterprise/pages/settings.md)
- API endpoints used:
  - `GET /api/about` (build / env)
  - `GET /api/admin/sessions`
  - `GET /api/admin/break-glass`
  - `GET /api/integrations`
  - `GET /api/detectors` *(P2 + P3)*
  - `PUT /api/detectors` *(P2 + P3, audit-mutated)*
  - `GET /api/loadmode` *(P7)*
  - `PUT /api/loadmode` *(P7, audit-mutated)*
  - `GET /api/logging` *(P8)*
  - `PUT /api/logging` *(P8, audit-mutated)*
  - `GET /api/cold-tier` *(P8)*
  - `POST /api/admin/password` *(D-M4 deferred — gated on F-T1 + the password endpoint landing)*
  - `POST /api/admin/break-glass` *(D-M4 deferred)*
- Components reused from M0: `stat-card` (read-only build /
  env), `table` (sessions, sinks), `drawer` (long-form
  edits like password change), `confirm`, `toast`,
  `banner`, `badge`, `diff` (preview of toggle changes),
  `skeleton`.
- New components introduced: **`toggle-grid`** —
  generalises the per-tier mask grid built ad-hoc in P3
  into a reusable component with a "compliance lock"
  affordance per cell. Hand it the data, get back a
  controlled grid; reusable wherever multiple boolean
  toggles share a common semantic.

## User goals

1. **Find a knob.** Operator under pressure: "where do I
   pin load mode to Critical?" — lands on Settings, knob is
   visible without scrolling, action takes ≤ 2 clicks.
2. **See the consequences.** Before saving a multi-toggle
   change (e.g. flipping 3 detector classes), preview what
   the new mask looks like and what the audit-chain entry
   *will* record.
3. **Audit my last action.** "What did I change in the last
   hour?" — Settings shows a side panel of the last 10
   admin chain entries scoped to my session, deep-linked to
   `/audit?actor=me`.

## Scope

### In

Settings becomes a *navigable* page rather than a stack of
unrelated panels. Sidebar-within-page (or sticky table of
contents) so jumping between sections is fast.

Sections, in priority order:

1. **Operational mode** (P7) — load-mode pin / unpin,
   threshold tuning (read-only, links to `waf.yaml` for
   edits), live RPS readout.
2. **Logging verbosity** (P8) — slider over the 6 levels +
   a preview of "what an audit event will look like at
   this level".
3. **Detection classes** (P2 + P3) — base mask + per-tier
   override grid (the existing UI from P3 → polish into the
   `toggle-grid` component).
4. **Cold-tier sinks** (P8) — read-only inventory of
   configured sinks, delivery state.
5. **Account & access** — password change drawer (gated on
   the `POST /api/admin/password` endpoint), active sessions
   table, break-glass panel.
6. **Integrations** — Grafana / Alertmanager / GitOps /
   Prometheus URLs, read-only.
7. **About** — build SHA, environment label, version.

The "preview before save" affordance is the differentiator:
every mutating section has a *staging* state. Click toggles
→ "Save 3 changes" button appears at the top → click → diff
preview (using the `diff` component) → confirm → audit chain
entry → toast.

### Out

- Tenant management (deferred RBAC track).
- API token management (deferred RBAC track).
- Theme / language preferences (these are user-scoped,
  surface in the topbar account menu, not Settings).
- Compliance profile editing (Settings shows the active
  profile; editing happens via `waf.yaml` + GitOps).

## Acceptance

- Every user goal reachable in ≤ 2 clicks from the page
  load.
- Every mutating PUT goes through the existing AuditedMutate
  pipeline. No new endpoint added by this milestone.
- Stage-grouped change preview matches the actual
  before/after diff that lands in the audit chain entry —
  verified by an integration test.
- Page module < 32 KB raw despite the section count
  (achievable because each section delegates to existing
  components; the bulk is layout glue).
- A k6 scenario `tests/load/settings-stress.js`
  (new) opens the page, flips 3 detector toggles + 1 load
  mode + 1 verbosity, saves, asserts that the audit
  endpoint surfaces 5 admin entries within 2 s.
- Both themes look intentional under the screenshot review.

## Layout sketch

```
┌────────────────────────────────────────────────────────────────────┐
│  Settings                                                          │
├──────────┬─────────────────────────────────────────────────────────┤
│ in-page  │  Operational mode                                       │
│   nav    │   Mode:    elevated   [▾ Pin to Critical]               │
│          │   RPS:     2 458 / 8 000  → Critical at 8 000           │
│ • Op'l   │   Override: pinned by you, 14:02 — [Clear pin]          │
│ • Logs   │ ───────────────────────────────────────────────────────│
│ • Det.   │  Logging verbosity                                      │
│ • Sinks  │   silent ─ error ─ warn ─ ●info ─ debug ─ trace         │
│ • Acct   │   Preview: { class: "detection", action: "block", … }   │
│ • Integ  │ ───────────────────────────────────────────────────────│
│ • About  │  Detection classes                                      │
│          │   Base mask:          ☑ sqli ☑ xss …  ☑ recon          │
│          │   Critical overrides: (none — uses base)                │
│          │   …                                                     │
│          │                                                         │
│          │ ╔═══════════════════════════════════════════╗           │
│          │ ║  3 changes staged                          ║           │
│          │ ║  [Discard]  [Preview diff]  [Save → audit]║           │
│          │ ╚═══════════════════════════════════════════╝           │
└──────────┴─────────────────────────────────────────────────────────┘
```

## Open questions

- **Staging model.** Should staged changes persist across
  navigation (LocalStorage) or evaporate on leave? Argues
  for evaporate-on-leave with a confirm dialog; resolve in
  the brief.
- **Threshold tuning.** Is `load_mode.elevated_rps` editable
  from Settings or read-only? Argues for read-only at this
  milestone (operators tune via `waf.yaml`); a follow-up
  could add the PUT once `cfg`-mutation lands as a track.
- **Account section.** Hides until F-T1 + the password
  endpoint exist. The plan should decide whether M10 ships
  with a placeholder section or omits it cleanly.
- **`toggle-grid` compliance lock.** When a detector class
  is locked by `cfg.compliance.modes`, does the grid *grey
  it out* or *prevent toggle but show "locked by PCI"
  tooltip*? Resolve in the brief; precedent in the existing
  P3 UI is "locked tooltip".

## Out-of-scope drift log

(Empty until work begins.)
