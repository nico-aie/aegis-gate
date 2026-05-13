---
id: 2026-05-12-ux-proposals-observability
date: 2026-05-12T07:30Z
severity: INFO
area: dashboard
component: observability-section
status: proposal
test_mode: full-qc
---

# UI/UX upgrade proposals — Observability (Performance, Health & SLOs, Audit Trail, Scaling)

Concrete proposals after a full pass through the 4 Observability
pages. Each carries **why**, **what**, **size**, and **expected
impact**.

These are independent of the bug findings (MED-OBS-01, LOW-OBS-01..05)
— those need to ship first. The proposals here are the sharpening
round.

---

## OBS-P1 — Performance: per-detector latency table needs a "% of total" column

**Why.** Today the table shows `path_traversal: 84 samples · p50
0.026 / p95 0.049 / p99 0.580 ms`. The samples count is constant
across rows (because every detector runs on every request), so
the operator's mental model is "which detector adds the most
total time to the chain". p99 alone doesn't answer that — a slow
p99 on a rare detector matters less than a medium p99 on a
common one.

**What.** Add a `% OF TOTAL` column right of `P99 (MS)`. Compute
as `(p50 × samples) / Σ(p50 × samples) × 100`. Sort the table
by this column by default. Operators see "recon eats 18% of the
detector chain" at a glance.

**Size.** Small. ~10 LoC dashboard. Backend already gives the
data.

**Expected impact.** Optimisation conversations go from "p99 is
high here" to "this detector class is the biggest spend" —
which is what the SRE actually needs to prioritise.

---

## OBS-P2 — Health & SLOs: alert channel health snapshot above the alert list

**Why.** The Active alerts list and the Alert channels card live
in different sections. An operator opening the page during an
incident asks "are my alerts even reaching me?" — and that
answer lives in the Alert channels row's status pill ("FAILED 3×
· VIPTALK RETURNED 401 UNAUTHORIZE" was the answer in this run).
But the channel status is two scrolls below the alert list.

**What.** Above the Active alerts list, surface a one-line
header chip: `1 channel configured · 0 healthy · 1 failing` with
clickable scroll-to-channel anchor. On a healthy boot it's a
green chip; on a single failing channel it's red and the chip
turns into a CTA: *"1 channel is failing — Click to inspect"*.

**Size.** Small. ~15 LoC. Backend data is already in
`/api/alert-receivers`.

**Expected impact.** Operators don't get caught by "we did
configure VipTalk but the credentials rotated and now alerts
silently fail" — the dashboard surfaces it the moment they hit
the page.

---

## OBS-P3 — Audit Trail: copy-row-as-curl affordance

**Why.** The Live Feed drawer's "Copy as cURL" button (INFO-SO-02
from the previous sprint) was called out as the single best
affordance. The Audit Trail page has the same data (request
context for blocked / allowed events) but no equivalent
affordance — operators reading an audit row have to retype the
attack from memory if they want to replay it.

**What.** Each detection-class row on the Audit Trail gets a
small `[...]` hover-menu with `Copy as cURL` / `Pivot to
Investigation` / `Block IP` / `Whitelist`. Same actions as the
Live Feed drawer; same code. The hover menu opens on row hover
to keep the table density unchanged.

**Size.** Medium. ~30 LoC (shared menu component + per-row
trigger). Backend gives the request shape via existing
`/api/audit/since` response.

**Expected impact.** Audit forensics work doesn't require
context-switching to Live Feed. Operators reviewing post-
incident don't lose information just because the alert is older
than the Live Feed buffer (Live Feed defaults to 80 rows).

---

## OBS-P4 — Scaling: per-layer "what changed" timeline

**Why.** Each Scaling layer has a status snapshot. Operators
asked "when did this change?" don't get an answer from the
current page — they have to cross-reference Audit Trail by hand.

**What.** Each layer card gets a small "Recent changes" footer
with the last 3 audit-chained changes scoped to that layer:

```
Layer 1 · In-node workers
  WORKERS 12 · MODE auto · BLOCKING POOL 512 · CPU AFFINITY off
  Recent changes:
    11:24:06 alert_receiver_test by admin
    (no L1 changes in the last 24h)
```

If no changes: explicit "no L1 changes in the last 24h" copy so
operators know they're seeing the live state.

**Size.** Small. ~15 LoC dashboard reading from `/api/audit/
since?class=<scope>`. Each layer has a tag the audit emitter
already carries (`loadmode_pin` for L1, `cluster_drain` for L2,
etc.).

**Expected impact.** "Did we drain the node yesterday?" gets a
1-second answer instead of a 5-step Audit-Trail cross-reference.

---

## OBS-P5 — Performance: side-by-side "now vs. baseline" mode

**Why.** Performance regressions are diff-y. "p99 is 5ms" doesn't
mean much; "p99 is 5ms vs. baseline 1.03ms" is a fire. The skill
docs reference a baseline at
`tests/results/run-perf-5krps-prod-balanced-2026-05-02-v3/` but
the dashboard doesn't read it.

**What.** Add a "Show baseline overlay" toggle at the top of the
Performance page. When on, every chart + table renders a dotted
"baseline" line / column behind the current value. The baseline
source is `/api/perf/baseline` (server reads the file at boot)
or a hardcoded JSON the dashboard ships.

**Size.** Medium. ~1 day. Backend exposes baseline; dashboard
adds the overlay.

**Expected impact.** Performance regressions surface immediately
instead of "I think this number is bad?".

---

## OBS-P6 — Health & SLOs: SLO "burn rate" sparkline column

**Why.** The page shows `data_plane_availability: 0.00% current
/ 99.90% target / 0% LEFT` — three numbers. But the SLO budget
math the page exposes (`burn_rate: 999.99`, `budget_consumed_pct:
99999.99` from `/api/incidents`) is way richer. Operators
benefit from seeing "burn rate over time" not just "current".

**What.** Add a small inline sparkline column to the SLO budget
table showing the last 1h of burn rate. Colored red when above
1.0 (burning faster than budget), green below. ~60 px wide
column, one tick per minute.

**Size.** Small dashboard (~15 LoC) + small backend (a 60-bucket
ring for each SLO).

**Expected impact.** SRE conversations go from "we're burning
budget" to "we've been burning at 5× for the last 12 minutes" —
the latter answers "how long until breach?" automatically.

---

## OBS-P7 — Audit Trail: pin a chain hash as the "audit-chain proof" anchor

**Why.** The chain hash is the WAF's tamper-evident audit proof.
Operators occasionally need to copy the latest hash into a
compliance log ("at $time the audit chain head was $hash"). The
hash is visible on every row but there's no "this is the chain
head" indicator — the operator has to mentally identify the
newest row.

**What.** A small "Chain head" callout above the table:

```
Chain head: 79b423060542a3683fc7b522be452e1bf14f6f8881eef557172d33318ee9755e  (at 11:24:06)
  [Copy] [Pin]
```

`Pin` saves the hash to localStorage; on next visit the page
shows "Last pin: <hash> at <time> · 18 events since" — operators
have a stable handle for "where was I in the chain last time I
reviewed?"

**Size.** Small. ~20 LoC. No backend change.

**Expected impact.** Compliance reviews go from "scroll to top,
copy the timestamp + hash" to one click. The pin gives
operators a personal bookmark for chain review.

---

## OBS-P8 — Cross-cut: per-page Refresh affordance state

**Why.** The Refresh icon-button next to page titles (shipped
previous sprint as P9) is consistent across pages. But the
button doesn't reflect whether the page is "fresh" or "stale"
— operators don't know if the data they're looking at is
from 5 seconds ago or 5 minutes ago.

**What.** Add a tiny relative-time label next to the Refresh
icon: `updated 4s ago` (green) / `updated 32s ago` (neutral) /
`updated 5m ago` (yellow — refresh suggested). On hover, the
absolute timestamp. Clicking the icon updates the label.

**Size.** Small. Each page already tracks the last-fetch time
in its hook; surface it.

**Expected impact.** No more "is this stale?" confusion when an
operator alt-tabs back to a dashboard tab they left 10 minutes
ago.

---

## Priority ordering

| # | Proposal | Effort | Operator impact |
|---|---|---|---|
| OBS-P2 | Alert-channel-health chip on Health page | S | High — surfaces silent alert failures |
| OBS-P8 | Per-page "updated Xs ago" label | S | High — stale-state confusion gone |
| OBS-P1 | Detector "% of total" column | S | Medium — direct SRE win |
| OBS-P3 | Audit Trail Copy-as-cURL menu | M | Medium — forensics consistency |
| OBS-P6 | SLO burn-rate sparkline | M | Medium — SRE clarity |
| OBS-P7 | Chain-head pin affordance | S | Medium — compliance ergonomics |
| OBS-P4 | Scaling per-layer change log | S | Medium — operational provenance |
| OBS-P5 | Perf baseline overlay | M | Medium — regression detection |

