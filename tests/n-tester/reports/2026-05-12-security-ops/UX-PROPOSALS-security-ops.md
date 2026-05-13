---
id: 2026-05-12-ux-proposals-security-ops
date: 2026-05-12T00:24Z
severity: INFO
area: dashboard
component: security-ops-section
status: proposal
test_mode: full-qc
---

# UI/UX upgrade proposals — Security Ops (Overview, Live Feed, Incidents, Investigation, Top Attackers)

Concrete proposals after an end-to-end SOC walk-through against
~100 spoofed-IP attacks. Each carries **why** (operator behavior
that motivates it), **what** (the change), **size**, and
**expected impact**.

These are decoupled from the bug findings (HIGH-SO-01 …
LOW-SO-04) — the bugs should ship first. The proposals here are
the "next round of sharpening".

---

## SO-P1 — Surface the "is anything wrong?" answer at the top of every Security Ops page

**Why.** Overview is the only place a SOC analyst can see
"detection rate, block rate, current attackers" at a glance. Live
Feed / Incidents / Investigation / Top Attackers all force the
operator to mentally compute the same thing from raw rows. On a
busy day the analyst pings between pages every 10 seconds.

**What.** Add a single-line "Security Ops posture" cheat-card at
the top of every Security Ops page, mirroring the Policy posture
cheat-card shipped in Phase 3a:

```
SEC OPS · 12 RPS · 86 BLOCKED LAST 15M · 5 ACTIVE ATTACKERS · 3 ALERTS FIRING · 1 INCIDENT ACKED · CHAIN OK
```

Each chip click navigates to the relevant Security Ops page,
pre-filtered to the chip's domain.

**Size.** Small. Backend data already in `/api/stats/timeseries`,
`/api/attacks/top`, `/api/alerts`, `/api/incidents`. One
`SecOpsPostureCard` component shared across 5 pages.

**Expected impact.** Page-entry orientation cost drops from
~10s (read the page) to ~2s (read the card). S1 + S2 both
benefit.

---

## SO-P2 — Live Feed: add an "Auto-pin" filter for the current attacker

**Why.** A SOC analyst typically focuses on one attacker for
60–120 seconds (read their requests, decide block/whitelist,
move on). Today Live Feed scrolls all traffic; if the attacker
the analyst is reading slows down they get pushed off-screen.

**What.** When the analyst clicks a row's drawer, add an
"📌 Pin this IP" toggle. With pin active:
- New rows from that IP highlight in the feed.
- Other rows compress to a single "+27 others" line.
- The feed auto-scrolls only when a pinned-IP row arrives.

Pin clears on tab change or explicit unpin.

**Size.** Medium. ~3-4 hours of React state work; backend doesn't
change.

**Expected impact.** "Read this attacker's session" workflow goes
from re-scrolling-and-filtering to a focused stream. S3 climbs.

---

## SO-P3 — Investigation: real pivot filter (closes MED-SO-02 properly)

**Why.** See MED-SO-02. The pivot input is the page's reason for
existing.

**What.** Filter the KPI cards + Audit timeline + Detector
breakdown by the pivot, server-side. Add
`?client_ip=<>`, `?request_id=<>`, `?rule_id=<>` query params to
`/api/audit/since` and the related counter endpoints.

**Size.** Medium. ~1 day server + ~30 min dashboard.

**Expected impact.** Investigation goes from "pivot is a
suggestion" to "pivot is the page's filter". S3 from 3 → 5.

---

## SO-P4 — Top Attackers: per-row mini-sparkline of the last 60s

**Why.** A SOC analyst looking at the Top Attackers list wants
to know whether each attacker is "still attacking right now" or
"was loud 30 minutes ago but quiet now". Today HITS is a single
integer; LAST SEEN is the most recent timestamp. Neither answers
"is this still happening".

**What.** Add a thin mini-sparkline column showing the
attacker's hits/second over the last 60s (12 buckets of 5s
each). Active attackers spike on the right; cooled-off ones
flatline. Width ~80px, just enough to scan ten attackers at once.

**Size.** Small backend (Phase 3b's `RouteActivityWindow`
pattern reused for per-IP), small dashboard.

**Expected impact.** Identifies who's currently active without
needing time-window juggling. S2 climbs.

---

## SO-P5 — Incidents: lifecycle overlay (closes MED-SO-04 properly)

**Why.** See MED-SO-04.

**What.** Server-side: incidents overlay store, audit-mutated,
joined into `/api/incidents.incidents` so the dashboard sees the
post-ack state. Dashboard: keep the existing chips and table;
they'll start rendering ACKED / SNOOZED rows automatically once
the API returns them.

**Size.** Medium. ~1 day server + 0 dashboard (the page is
already wired to read `incidents`, just gets `[]` today).

**Expected impact.** Incidents page becomes a real workflow tool
instead of a read-only alert mirror.

---

## SO-P6 — Overview: "Live attack origins" map should retain the last 5 minutes

**Why.** The map says "Real-time geolocation of blocked
requests · last 60s" — but on a fresh-driven WAF it goes dark
the moment the burst ends. SOC analysts often page after an
incident and arrive 2-3 minutes after the burst stopped. They
should still see what happened.

**What.** Extend the window to 5m (configurable via a pill row
just like the Traffic chart). Pulse the most-recent ~30s in a
brighter shade, fade older points. Operator can rewind by
clicking a timeline scrubber under the map.

**Size.** Medium. Backend already keeps the per-IP hit ring;
dashboard adds the scrubber.

**Expected impact.** Operators who arrive late can still see
what just happened. Postmortems get a built-in replay.

---

## SO-P7 — Investigation: render request-body snippets in the timeline

**Why.** Today the Audit timeline rows are scalar (IP / method /
path / rule_id). The real "what did this attacker do" question
is usually about the payload — sqli pattern, xss vector, SSRF
target.

**What.** Add a small expandable per-row chevron. Expanded row
shows up to 200 chars of the request URL query + body (redacted
if `Pipeline::on_body_frame` flagged it). Server returns it
under `event.fields.payload_excerpt`.

**Size.** Medium. Audit emitter needs to include the excerpt
(it has the data; the dashboard just doesn't see it).

**Expected impact.** Forensics work happens on the dashboard
instead of grepping logs.

---

## SO-P8 — Live Feed: keyboard shortcuts

**Why.** Live Feed is a workhorse view. The fewer mouse round-
trips the better.

**What.** Standard SOC keyboard ergonomics:
- `J` / `K`: next / previous row, opens drawer
- `P`: toggle Pause/Resume
- `B`: in drawer, Block IP
- `W`: in drawer, Whitelist
- `Esc`: close drawer
- `/`: focus the search input

**Size.** Small. ~2 hours of keymap wiring.

**Expected impact.** Power users get a 3-4× speed-up on triage.

---

## SO-P9 — Top Attackers: AS-level grouping toggle

**Why.** Operators occasionally see one attack from many IPs in
the same AS (botnet, cloud abuse). Per-IP Top Attackers buries
the signal because each IP has 1-2 hits.

**What.** A toggle pill: `IP` (default) / `ASN` / `Country`.
With ASN active, rows group `(asn, country)` and HITS sums.
Block button on a grouped row opens a confirm asking whether to
block the whole CIDR (server resolves AS-prefix to CIDR list) or
just the top contributing IP.

**Size.** Medium. ~3 hours dashboard + ~1 day server
(`/api/attacks/top-by-asn`).

**Expected impact.** Catches botnet-class attacks the per-IP view
misses today.

---

## SO-P10 — Incidents: "Suggested action" column

**Why.** Operators staring at three DataPlaneAvailability alerts
on a healthy WAF wonder "should I ack? snooze? something
deeper?". The alert name doesn't help.

**What.** Add a "SUGGESTED" column with a one-line recommendation:
- `DataPlaneAvailability-1h` with stub-pool 502s → "Configure
  a real upstream pool, then resolve."
- An attack-rate spike alert → "Check Top Attackers; consider
  Block on the top contributor."
- Cert expiring soon → "Renew cert or set ACME · runbook →"
The recommendation can be hand-written per SLI in `cfg.alerts`.

**Size.** Small backend (one extra field per SLO definition),
small dashboard.

**Expected impact.** SOC onboarding tax drops. Day-1 operators
don't need to know "what to do" — the dashboard tells them.

---

## Priority ordering

| # | Proposal | Effort | Operator impact |
|---|---|---|---|
| SO-P1 | Sec Ops posture cheat-card | S | High |
| SO-P3 | Real Investigation pivot filter | M | High |
| SO-P5 | Incidents lifecycle overlay | M | High |
| SO-P2 | Live Feed pin-an-attacker | M | Medium-High |
| SO-P8 | Live Feed keyboard shortcuts | S | Medium |
| SO-P6 | Map 5m retention + scrubber | M | Medium |
| SO-P10 | Suggested-action column | S | Medium |
| SO-P4 | Top Attackers mini-sparkline | M | Medium |
| SO-P7 | Audit timeline payload excerpts | M | Medium |
| SO-P9 | AS-level grouping | M | Medium |

