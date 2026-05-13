---
id: 2026-05-12-ux-proposals-admin
date: 2026-05-12T08:34Z
severity: INFO
area: dashboard
component: admin-section
status: proposal
test_mode: full-qc
---

# UI/UX upgrade proposals — Admin (Settings, Reports, Help & Guide)

Concrete proposals after the Admin pass. Each carries **why**,
**what**, **size**, and **expected impact**.

These are independent of the bug findings (MED-ADM-01,
LOW-ADM-01..06) — those need to ship first. The proposals here
sharpen the surface once the gaps are closed.

---

## ADM-P1 — Settings: collapse "not yet wired" cards by default

**Why.** Settings has ~10 cards. Three of them (Active admin
sessions, Break-glass, External integrations) carry "(handler
not yet wired)" subtitles — meaning the operator can't actually
mutate from the UI today. They still take vertical space and
visual attention, pushing the actually-actionable cards
(Response Filtering, mTLS) further down.

**What.** Add a default-collapsed state to cards whose mutation
handler isn't wired:

```
▶ Active admin sessions · 0 active · view-only (handler not yet wired)
▶ Break-glass · INACTIVE · view-only (handler not yet wired)
▶ External integrations · 0/4 configured · view-only (handler not yet wired)
```

Operator clicks the chevron to expand and see the row data.
Default-collapsed cards take ~1 line instead of ~5. Once the
mutation handlers land, the cards default-expand and the
chevron either disappears or stays as user control.

**Size.** Small. ~30 LoC per card (a `useCollapse` hook).

**Expected impact.** Settings becomes scannable. The actually-
configurable cards (Response Filtering, mTLS, Shadow Mode) sit
above the fold.

---

## ADM-P2 — Reports: add a date-range picker + history panel

**Why.** The current Reports page is one-shot — click Download,
get whatever's in the audit ring right now. Operators doing
weekly reviews don't have a way to say "give me last Tuesday's
attack data". And the page subtitle "scheduled delivery not
built yet" already promises a future feature with no UI seam.

**What.** Above the four cards, add a small filter bar:

```
[From: 2026-05-05] [To: 2026-05-12] [Generate]    Recent exports ▼
```

Date-range picker drives a single `Generate` button that
populates the four download cards with date-scoped URLs. The
"Recent exports" expandable shows the last 10 generations
(timestamp + range + size) — operators can re-download a prior
report without re-generating.

**Size.** Medium. ~1 day. Server needs date-range params on the
report endpoints; dashboard adds the filter bar + history list
(stored in localStorage).

**Expected impact.** Compliance reviews stop being "scrape the
audit ring at the moment I happen to remember" and become "scope
the time window I care about". The history panel kills the
"Did I already pull last week's report?" question.

---

## ADM-P3 — Help & Guide: surface the FAQ inline on every page

**Why.** The Help & Guide FAQ is exceptional (see INFO-ADM-01),
but operators only see it when they navigate to Help & Guide.
A SOC analyst staring at a 100% blocked rate on a particular IP
won't think to open Help to find the "A request shows IP risk =
100 but the action is ALLOW. Bug?" answer — they'll file the bug
report instead.

**What.** Each page in the dashboard gets a small `?` icon next
to the page title. Click it: a slide-in panel shows the FAQ
entries scoped to this page's domain. For example:

- Overview's `?` icon → "What's the difference between Rate Limit
  and the DDoS gate?", "Why is Audit Trail hiding request
  decisions by default?"
- Detectors & Tiers' `?` icon → "I toggled a detector OFF on the
  tier pipeline list. Why is it still firing?", "How do I enable
  the AI detector?"
- Investigation's `?` icon → "A request shows IP risk = 100 but
  the action is ALLOW. Bug?"

The mapping lives in Help & Guide's source (one tag per FAQ
entry); each page declares which tags it surfaces.

**Size.** Medium. ~6 hours. FAQ entries get a `tags: ["overview",
"detectors"]` metadata field; each page imports the tag-filtered
list and renders it in a `<HelpDrawer/>`.

**Expected impact.** Operators stop opening tickets that the
FAQ already answers. Onboarding tax drops further.

---

## ADM-P4 — Settings: surface the most recent 3 Config-history rows as a sticky strip

**Why.** Settings Config history is great for forensics — every
audit-mutated change in newest-first order. But operators making
a change today want to know "did my last 3 mutations actually
land?" without scrolling to find them in a paginated list.

**What.** Above the Config history table, add a sticky strip
showing the latest 3 mutations:

```
Latest: #62 INCIDENT_ACK · 1m ago · admin · #61 INCIDENT_ACK · 2m ago · #60 RESPONSE_FILTER_PUT · 5m ago · admin
```

Clicking a strip entry scrolls to the corresponding row in the
table below. The strip auto-updates as new mutations land.

**Size.** Small. ~30 LoC. Same data source, just a different
projection.

**Expected impact.** "Did the change I just made land?" becomes
a zero-click answer (the strip already shows it). Reduces the
muscle-memory "click Refresh to see if my change registered"
pattern.

---

## ADM-P5 — Reports: lift "scheduled delivery" from "not built yet" to a roadmap chip

**Why.** The page subtitle reads *"CSV / JSON exports of audit +
summary data · scheduled delivery not built yet"*. The
"not built yet" framing tells operators what's missing but
not when it might land. Compliance shops want to plan their
review cadence around the feature.

**What.** Replace "scheduled delivery not built yet" with a
chip-style affordance:

```
CSV / JSON exports of audit + summary data    [📅 SCHEDULED DELIVERY · planned] [Get notified →]
```

The "Get notified" CTA captures an email or a Slack channel for
the launch announcement. The "planned" chip optionally carries
a target sprint or quarter.

**Size.** Small. ~1 hour for the chip + notify modal.

**Expected impact.** Operators get a clear "feature is on the
roadmap" signal. Notify list helps prioritise (if 12 ops teams
sign up, ship it sooner).

---

## ADM-P6 — Settings: visual section anchors for the long-scroll cards

**Why.** Settings is currently a single long scroll: Config
history → mTLS mode → mTLS SANs → Shadow Mode → Cumulative IP
risk note → Challenge Engine → Honeypot Paths → Response
Filtering → Active admin sessions → Break-glass → External
integrations → Certificates. Operators looking for a specific
card scroll-hunt.

**What.** Add a small sticky left-side "in this page" nav next
to the page title:

```
Aegis WAF · Settings              In this page:
- Config history                 - Audit
- mTLS mode                      - Security
- Response Filtering             - Filters
- Active admin sessions          - Sessions
- External integrations          - Integrations
- Certificates                   - Certs
```

Click → scroll-to-anchor. Each card grows a fragment id
(`#config-history`, `#mtls-mode`, ...) so deep-links work.

**Size.** Small. ~1 hour.

**Expected impact.** Operators jump to the card they need in
one click. Settings becomes scannable.

---

## ADM-P7 — Help & Guide: searchable

**Why.** The Help & Guide FAQ has 8+ entries today and will grow.
"How do I test a route by hostname?" requires the operator to
mentally scan all entries.

**What.** A search input at the top of Help & Guide:

```
[ 🔍 Search the guide... ]    Get started · How it works · Glossary · Workflows · FAQ
```

Typing filters all tabs' content in real time. Highlight match
positions in each entry's body.

**Size.** Small. ~2 hours of full-text-search in the rendered
content.

**Expected impact.** Help & Guide scales past 50+ FAQ entries
without becoming a long-scroll wall.

---

## ADM-P8 — Reports + Settings: "Copy as cURL" affordance on every audit-mutated control

**Why.** The Live Feed drawer ships a "Copy as cURL" button
(INFO-SO-02 last sprint). Operators love it. The same affordance
would let SOC engineers script up the audit-mutated controls
that don't yet have UI handlers (Settings → break-glass,
session-terminate, integration-edit per LOW-ADM-01).

**What.** Each Settings card with an audit-mutated control adds
a small "Copy as cURL" inline link below the control:

```
mTLS mode
  configured: disabled · effective: disabled
  [ disabled ]  [ optional ]  [ required ]
                 Copy as cURL: curl -X PUT -H 'x-csrf-token: ...' \
                   -H 'content-type: application/json' \
                   -d '{"mode": "optional"}' http://127.0.0.1:9443/api/mode
```

The cURL string is pre-baked with the current CSRF + the
selected value. Operators paste it into a shell or a runbook.

**Size.** Medium. ~3 hours — a shared `CopyAsCurl({method, path,
body})` component used everywhere.

**Expected impact.** Operators script up the rough edges
without waiting for full UI handlers. Bridges the "(handler
not yet wired)" gap from LOW-ADM-01.

---

## Priority ordering

| # | Proposal | Effort | Operator impact |
|---|---|---|---|
| ADM-P1 | Collapse "not yet wired" Settings cards | S | High — Settings becomes scannable |
| ADM-P4 | Sticky latest-3 mutations strip on Settings | S | High — "did my change land?" zero-click |
| ADM-P3 | Page-scoped FAQ drawer | M | High — operator self-service |
| ADM-P8 | Copy-as-cURL on every audit-mutated control | M | Medium — bridges the wired-handler gap |
| ADM-P6 | Settings in-page anchor nav | S | Medium — long-scroll mitigation |
| ADM-P2 | Reports date-range picker + history | M | Medium — compliance workflow |
| ADM-P7 | Help & Guide search | S | Medium — future-proofs the FAQ |
| ADM-P5 | "Scheduled delivery" notify chip | S | Low — small roadmap-comms win |

