---
id: 2026-05-11-ux-proposals-policy-pages
date: 2026-05-11T17:30Z
severity: INFO
area: dashboard
component: policy-section
status: proposal
test_mode: full-qc
---

# UI/UX upgrade proposals — Policy section (Rules, Detectors & Tiers, Access Lists, Routing & Upstreams, Traffic Gates)

Concrete proposals after a 30-minute SOC-analyst walk-through of
every Policy page. Each proposal carries: **why** (operator
behavior that motivates it), **what** (the change), **size**
(rough implementation effort), and **expected impact**.

These are decoupled from the bug findings (HIGH-01 … LOW-07) —
those need to ship first. The proposals here are the
"sharpening the knife" round.

---

## P1 — Add a "current policy" cheat-card at the top of each Policy page

**Why.** A SOC analyst opening Rules / Access Lists / Detectors today
has to read the whole page to learn what the WAF is currently
enforcing. The data is *there* — 1 rule total, 0 blacklist entries,
AI enabled, 4 tiers active — but it's spread across five pages.

**What.** Add a single 60-px card at the top of every Policy page
that summarises *the WAF's current posture in one line*:

```
WAF posture · ENFORCE · 4 tiers active · AI on · 1 rule · 0 blacklist · 0 whitelist · DDoS observe-only off
```

Chip each token; clicking a chip jumps to the relevant page.
Read-only summary, no controls.

**Size.** Small. Backend data is already there
(`/api/loadmode`, `/api/rules`, `/api/blacklist`, etc.); one
`PolicyPostureCard` component shared across the 5 pages.

**Expected impact.** Page-entry orientation cost drops from
~15s (scan the page) to ~2s (read the card). S1 "I just got
paged" scenario goes from 3 → 5.

---

## P2 — Detectors & Tiers: lift the "Live policy for <tier>" panel above the tier list

**Why.** The right-most panel ("Live policy for critical") is the
single most useful surface on the Detectors page — it explains
in plain words what happens when a request hits this tier. But
it sits *below* the tier picker, so operators have to click a
tier card first. On a fresh load `critical` is the default
selection and the panel renders fine — but it's tucked away.

**What.** Pin the live-policy panel as a permanent right-side
column on Detectors & Tiers. Tier cards stay clickable; the
panel always shows the selected tier's policy. The page already
has the headroom (the bottom of the page is empty space).

**Size.** Layout-only CSS rework; ~1 hour.

**Expected impact.** Operators stop reading the per-tier card
microcopy ("block when score ≥ 50") and start reading the
operator-grade explanation ("Block when this single request's
detector scores sum to ≥ 50. Edit on this card → Edit tier.").

---

## P3 — Rules page: split Rule Simulator from the rule list view

**Why.** Today the Rules page has three stacked panels:
1. Simulator (top)
2. Rule list + detail (bottom).

The Simulator panel is always visible, even when the operator
is editing rule #47 — taking ~200 vertical pixels for a feature
the operator isn't using right now.

**What.** Two options:

- **A** (preferred): Tab the page — `Rules` tab (default, list +
  detail) and `Simulator` tab (the current top panel, full-width).
  Each tab gets the full viewport.
- **B**: Collapse the Simulator panel by default. Sticky
  "Simulate this rule" button on each rule's detail view that
  expands the panel with the rule's pattern pre-filled.

Recommend A; the Simulator is powerful enough (per INFO-01) to
deserve its own tab.

**Size.** Medium. ~3-4 hours of React refactor.

**Expected impact.** Rule list density goes up. Operators
managing 50+ rules see more rows without scrolling.

---

## P4 — Access Lists: surface the "matched in last hour" count per entry

**Why.** Blacklist entries are added defensively ("this IP was
attacking us last week"). Over time, the list grows. Operators
need a signal for *which entries are still earning their keep*
vs. *which can be retired*.

**What.** Add a `HITS · 1h` (and `· 24h` on hover) column to the
Access Lists tables. Cell shows the count of times the entry
matched a request in the window. Empty cells (0 hits in 24h) get
a `consider removing` link that drops the operator into a
remove-confirm modal.

The backend already counts (`/api/attacks/top` returns hit
counts per attacker), so this is a cross-tabulation more than a
new data store.

**Size.** Medium. ~3 hours including a backend endpoint
`/api/blacklist/hits` that maps entry IDs → window-bucketed
counts.

**Expected impact.** Blacklist hygiene goes from "manual periodic
review" to "see and remove at a glance". S2-adjacent: the SOC
analyst sees which entries protect them.

---

## P5 — Routing & Upstreams: route table needs a "Active in last 60s" pill

**Why.** Right now the route table tells operators *what's
configured*, not *what's serving traffic*. A route can match the
config but receive zero traffic for hours — operators should
notice that.

**What.** Add a small green/amber/red pulse pill in the leftmost
column showing `req/min · last 60s` for each route. Green > 1
req/min, amber 0-1 req/min, red 0 req/min for ≥ 5 min. Tooltip
on the pill: "Last request: 23 s ago" or "No requests in 6 m".

**Size.** Medium. Backend per-route counter exists in
`/api/stats/timeseries`; needs a per-route projection endpoint or
client-side bucket projection.

**Expected impact.** Misconfigured routes (catch-all blocks
specific routes, route order wrong, host header mismatch) become
obvious without driving synthetic traffic.

---

## P6 — Traffic Gates: gate-execution order visualisation

**Why.** The page intro reads *"Five per-flow controls that fire
**before** the detector chain"* — but doesn't show the order.
Operators reading the page can't tell whether Strike-Block runs
before or after Access List.

**What.** A small "request flow" diagram at the top of the page:

```
[ Inbound TCP ]
  → 1. Access List       (gate 1 — currently 0 / 0 entries)
  → 2. Strike-Block      (gate 2 — DISABLED)
  → 3. Cumulative IP gate (gate 3 — LIVE · challenge ≥ 99998)
  → 4. Volumetric        (gate 4 — global rate limit · current 0 req/s)
  → 5. Pattern matcher   (gate 5 — engine details on Detectors & Tiers)
  → [ Detector chain ]
```

Each numbered step is a chip with the gate's current state. Make
chips clickable — they scroll to the corresponding section.

**Size.** Small. ~2 hours of static-with-chip-link rendering.

**Expected impact.** Gate-ordering questions disappear from the
operator's "is X before Y?" mental model. Onboarding the next
SOC hire saves an hour.

---

## P7 — Cross-page deep-link consistency

**Why.** F-03 added the audit deep-link `?rule_id=...` and it
works. But adjacent surfaces don't follow the pattern:
- Detectors & Tiers' tier cards don't carry a tier=critical URL.
- Access Lists doesn't deep-link a single entry.
- Routing & Upstreams doesn't deep-link a single route.
- Audit Trail filters change the URL fragment but not the deep-
  linkable state (client IP, request_id, action class are
  stateful in React but the URL stays `#/audit`).

**What.** Adopt one URL pattern across the Policy section:
`#/<page>?<filter-key>=<value>` where the page reads the filter
on mount. The same pattern the Rules → Audit deep-link uses.

**Size.** Medium. Per-page URL reads on mount; one effect each.

**Expected impact.** Operators paste a URL into Slack and the
recipient lands on the exact view, not just the page. Massive
incident-review benefit.

---

## P8 — Inline "Why this matters" microcopy on dangerous toggles

**Why.** Several toggles change behavior in non-obvious ways:
- AI Disable (F-06 has the explainer modal — good)
- Detector mask flips (Edit Base mask — currently no explainer
  on the chip click)
- Tier override edits (Edit tier modal — partial)
- DDoS observe-only (Traffic Gates Edit on Strike-Block)
- Response Filtering toggles (once HIGH-01 is fixed)

**What.** Adopt one pattern: every audit-mutated control carries
a 1-line "what this does" line right under it. Two-three sentence
"why" expandable below. Mirror the F-06 / F-07 modal voice:
impact + scope + reversibility.

**Size.** Small per-control; ~10 controls × 5 min copy + render
work.

**Expected impact.** Operator confidence on Day-1 climbs. Fewer
"did I just take production offline?" Slack pings.

---

## P9 — Move the "Refresh" button next to the page title, not in the top-right

**Why.** Pages with a Refresh button in the top right (Rules,
Detectors & Tiers, Audit Trail, Routing & Upstreams) put the
button next to the primary action (`+ New rule`, `+ Add route`).
Operators reach for Refresh more often than the destructive
buttons; muscle memory says "title left, refresh right of title".

**What.** Move Refresh to a small circular icon-button next to
the page title (left side). Top-right keeps the primary action.

**Size.** Small CSS / JSX rework; ~30 min.

**Expected impact.** Refresh becomes a one-click action. Top-right
real-estate goes to one canonical primary action per page.

---

## P10 — Footer status pills (SSE / Cluster / Audit chain / GitOps / Build)

**Why.** The footer pills (`SSE (demo) | Cluster 1/1 | Audit
chain DEMO | GitOps OFF | Build 0.1.0 · session 139s`) are
**excellent** — they answer "is the dashboard talking to a real
backend?" in one glance. But two of the four pills today read
`DEMO` / `OFF` on a normal dev boot, which makes the line feel
like a warning when it's just an environment label.

**What.** Add a small `dev/staging/prod` tone — if `DEMO` is
common in dev, mute the styling so it sits at neutral grey, not
yellow. Reserve yellow for actual concerns ("Audit chain
SUSPENDED").

**Size.** Trivial CSS tweak.

**Expected impact.** Footer reads as "environment summary", not
"five things to worry about".

---

## Priority ordering

| # | Proposal | Effort | Operator impact |
|---|---|---|---|
| P1 | Policy posture cheat-card | S | High |
| P7 | Deep-link consistency | M | High |
| P6 | Traffic Gates flow diagram | S | High |
| P3 | Rules tabbed view | M | Medium |
| P4 | Access Lists hit-counter | M | Medium |
| P2 | Detectors live-policy column | S | Medium |
| P5 | Route activity pill | M | Medium |
| P8 | Microcopy pass | S | Medium |
| P9 | Refresh button placement | S | Low |
| P10 | Footer pill tone | S | Low |

