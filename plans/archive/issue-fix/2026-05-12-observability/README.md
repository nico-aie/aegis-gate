---
id: 2026-05-12-observability-fix-plan
date: 2026-05-12
status: ready
source_report: tests/n-tester/reports/2026-05-12-observability/
prior_sprint: plans/issue-fix/2026-05-12-security-ops/README.md
---

# Fix plan — 2026-05-12 Observability QC findings

## Headline

The Security Ops sprint (HIGH + 4 MEDIUM + 4 LOW + 3 UX-A) all
verified green on the live build. The Observability pass surfaced
**one MEDIUM regression** on top of the Security Ops sprint
(MED-OBS-01 — overlay write doesn't persist on ack) plus **five
small LOW polish gaps** across the four Observability pages.

No CRITICAL / HIGH. No SOC workflow blocker. The MED is a partial
regression on the previous sprint's PR-MED-SRV — fixable in one
file inside an hour.

Eight UX proposals (OBS-P1..P8) are deferred to a follow-up; each
is its own scoped PR.

## Findings recap

| ID | Sev | Area | One-line |
|---|---|---|---|
| MED-OBS-01 | MEDIUM | incidents · lifecycle-overlay | Ack POST 200 + green toast but `acked_at` / `acked_by` stay `null`; overlay write keyed wrong |
| LOW-OBS-01 | LOW | performance | "Latency by route" empty while "Error rate by route" populated |
| LOW-OBS-02 | LOW | router | `#/health-slos` 404; sidebar label says "Health & SLOs" |
| LOW-OBS-03 | LOW | tracking | "Test failed: unknown error" when upstream returned 401 |
| LOW-OBS-04 | LOW | audit trail | RULE column `—` on detection rows |
| LOW-OBS-05 | LOW | performance | Block-ratio peak time mixes 12h + AM/PM with rest of dashboard |

## Verified-fine (from previous sprint)

All seven PRs of the 2026-05-12 Security Ops fix plan
(`f4c6958..a685b5d`) verified live: HIGH-SO-01 unblocked, MED-SO-02
(Investigation pivot filter), MED-SO-03 (Incidents columns),
MED-SO-05 (detector breakdown fallback), MED-SO-06 (audit timeline
columns), PR-MED-SRV (read path), PR-LOW (×4), PR-UX-A1 (posture
cheat-card), PR-UX-A2 (server-side audit filter), PR-UX-A3 (Live
Feed keyboard shortcuts).

Only MED-SO-04 is **partially** verified — read path works (GET
returns the proper incident shape) but the ack write doesn't
land. Documented as MED-OBS-01.

## Root-cause analysis

### MED-OBS-01 — ID format mismatch between GET shape and dashboard ack URL

Reproduced via code read of:
- `crates/aegis-control/src/api/incidents.rs:69-71` — server
  `alert_id()` returns `format!("{:?}:{}", a.sli, a.fired_at.timestamp())`
  → `"DataPlaneAvailability:1778570234"` (no window in id).
- `crates/aegis-control/src/api/tracking.rs:369` — alerts API
  produces `name = format!("{:?}-{}h", a.sli, a.window_hours)` →
  `"DataPlaneAvailability-1h"` (window IS in name).
- `crates/aegis-control/assets/dashboard/src/pages.jsx:7990` —
  PageIncidents synthesizes `id = a.id || ${name}:${ts}` →
  `"DataPlaneAvailability-1h:1778570234"` (window in id).
- `crates/aegis-proxy/src/admin_mutate.rs:1184` — ack handler
  calls `incidents.ack(&alert_id_owned, ...)` where
  `alert_id_owned` is the path param from the URL — so the
  overlay store gets written under key
  `"DataPlaneAvailability-1h:1778570234"`.
- `crates/aegis-control/src/api/incidents.rs:153` — `enrich()`
  calls `alert_id(&a)` → looks up overlay by
  `"DataPlaneAvailability:1778570234"` — **MISSES** the overlay
  the ack just wrote.

So the overlay store actually DOES write on ack — but `enrich()`
on the next GET looks it up by the wrong key and returns the
default ("firing"). The Audit chain captures `incident_ack`
honestly (admin_mutate writes the chain entry separately), which
is why the QA sees an `incident_ack` row in Audit Trail.

**Fix.** Make `alert_id(&a)` produce the same id format the
dashboard sends on the ack URL:

```rust
pub fn alert_id(a: &SloAlert) -> String {
    format!("{:?}-{}h:{}", a.sli, a.window_hours, a.fired_at.timestamp())
}
```

Multi-window alerts (1h / 6h / 72h) now track as distinct
incidents, which matches the alerts list (which already separates
them) and the dashboard's existing row identity.

The dashboard's `merged.id` synthesis already matches this format,
so no JSX change is required. Once GET returns
`acked_at` populated, the page transitions the row automatically
(the lifecycle UI was always correctly wired — it was waiting on
the overlay to actually land).

### LOW-OBS-01 — Latency-by-route empty

`crates/aegis-control/src/api/route_metrics.rs` exposes
`/api/analytics/latency/routes`. The dashboard hook
`useRouteLatencyApi()` reads from there. Need to verify whether
the aggregator actually buckets per-route latency or whether the
ring walk skips blocked requests.

If it skips blocked: the empty-state copy should say so
explicitly (operator reads "no per-route samples" as "broken"
when in fact "all your traffic was blocked, so no resolved
requests have latency data" is the honest message).

Either:
- Source fix: include blocked requests in the per-route latency
  bucket (their data-plane processing time is real even when the
  upstream isn't hit).
- Copy fix: rewrite the empty state to be precise.

Cheaper path first → **copy fix in PR-LOW-OBS**.

### LOW-OBS-02 — `#/health-slos` 404

Same pattern as LOW-SO-02 (previous sprint). One-liner in
`crates/aegis-control/assets/dashboard/src/app.jsx::ROUTE_REDIRECTS`.

### LOW-OBS-03 — Test alert "unknown error"

`crates/aegis-control/src/api/alert_receivers.rs` test handler
returns the upstream HTTP status + body; the dashboard's toast
swallows it. Need to surface the same shape the channel row's
status pill renders.

### LOW-OBS-04 — Audit Trail RULE column `—`

Same fix pattern as MED-SO-06 (previous sprint) but on a different
code path — PageAuditLog at
`crates/aegis-control/assets/dashboard/src/pages.jsx:1355` rather
than PageInvestigation. Apply the same
`event.fields.detectors?.join(',') || extractResourceId(event)`
fallback.

### LOW-OBS-05 — Mixed 12h/AM-PM time format

Specific to the Performance Block-ratio card's peak-time copy.
Standardize on 24h `HH:MM` to match the rest of the dashboard.

## Phases & ship order

### Phase 1 — MED-OBS-01 (alert_id format alignment) ★ ship first

Single PR. Server-only change. ~30 min including tests.

**Files**
- `crates/aegis-control/src/api/incidents.rs` — update `alert_id()`,
  update existing tests for the new id format (the assertions
  that compare against the old format need new expected values).
- Add a regression test: `ack_then_enrich_returns_acknowledged_status`
  that exercises the full round-trip (ack → enrich → assert
  status). This test would have caught the bug.

**Verify**
- `cargo test -p aegis-control --lib -- api::incidents`
- Manual: drive 3 alerts, click Ack on row 1, refresh; row 1
  should now be ACKED with the operator name + timestamp visible.

### Phase 2 — LOW polish bundle (5 items)

Single PR. Dashboard + small server. ~1h total.

**LOW-OBS-02 — `#/health-slos` route alias**
- `crates/aegis-control/assets/dashboard/src/app.jsx::ROUTE_REDIRECTS`:
  add `'health-slos': 'health'`.
- Sweep the sidebar for any other "long-form label / short route"
  pairs missed; document in PR description.

**LOW-OBS-04 — Audit Trail RULE column**
- `crates/aegis-control/assets/dashboard/src/pages.jsx::PageAuditLog`:
  apply the same `extractResourceId(event)` /
  `event.fields.detectors?.join(',')` fallback the Investigation
  timeline uses post-MED-SO-06.

**LOW-OBS-01 — Latency-by-route empty state**
- Honest copy fix first. Update the empty-state text on
  PerformancePage's Latency-by-route card to say:
  *"Per-route latency populates as resolved requests arrive.
  Blocked requests don't reach a route resolver so they aren't
  surfaced here — see Error rate by route below for blocked-traffic
  attribution."*
- If time: investigate whether the per-route aggregator should
  include blocked-traffic latency. Defer to OBS-P proposal if
  not trivial.

**LOW-OBS-03 — Test alert error surface**
- `crates/aegis-control/src/api/alert_receivers.rs::test_receiver`
  or its proxy handler: pass the upstream status + truncated body
  to the JSON error payload.
- Dashboard's toast call site: render the body when present,
  fall back to status code.

**LOW-OBS-05 — Time format consistency**
- `crates/aegis-control/assets/dashboard/src/pages.jsx::PageAnalytics`:
  the Block-ratio card's peak-time format. Switch from
  `toLocaleTimeString()` (which is locale-dependent — AM/PM in
  en-US) to a fixed `HH:MM` formatter helper or pass
  `{ hour12: false }`.

**Verify**
- Rebundle, navigate to `#/health-slos` → resolves; navigate to
  `#/audit` and check a detection row → RULE column populated;
  Performance card subtitle reads consistent 24h format; Test
  Alert with the broken VipTalk → toast shows "401 UNAUTHORIZE"
  not "unknown error".

### Phase 3 — UX proposals (8 items, deferred)

OBS-P1..P8 from `tests/n-tester/reports/2026-05-12-observability/UX-PROPOSALS-observability.md`.
Priority order per the report:

| # | Proposal | Effort | Impact |
|---|---|---|---|
| OBS-P2 | Alert-channel-health chip above alerts list | S | High |
| OBS-P8 | Per-page "updated Xs ago" label | S | High |
| OBS-P1 | Detector "% of total" column on Performance | S | Medium |
| OBS-P3 | Audit Trail Copy-as-cURL row menu | M | Medium |
| OBS-P6 | SLO burn-rate sparkline column | M | Medium |
| OBS-P7 | Chain-head pin affordance | S | Medium |
| OBS-P4 | Scaling per-layer change log | S | Medium |
| OBS-P5 | Performance baseline overlay | M | Medium |

Each ships as its own PR. Phase 3 doesn't block Phase 1/2.

## Risk register

- **alert_id change is breaking for existing overlay keys.**
  Anything stored in the overlay under the old format becomes
  unreachable. Acceptable — the overlay is in-process state, not
  persisted; it clears on process restart. No migration needed.
- **Multi-window alerts (1h/6h/72h) now track as separate incidents.**
  This is the correct behaviour (already true in the alerts list
  and on the dashboard), but if any caller depended on the old
  collapsing-by-sli behaviour they'd see N rows instead of 1.
  Spot-check `alert_id` callers — only `enrich()` and the test
  module use it today.
- **Dashboard mapping fallback** `overlayById.get(name)` at
  pages.jsx:7991 was a defence-in-depth against the old mismatch.
  Leave it in place — harmless once the primary lookup matches.

## Out of scope

- Witness signing rotation (still surfaces "no witness yet" pill).
- Cluster Layer-2 multi-node tests (single-node verified).
- LOW-OBS-05's wall-clock format on other surfaces — only the
  Block-ratio peak-time is in scope; the rest of the dashboard
  already reads 24h.
- Live-Feed keyboard shortcuts retest (PR-UX-A3 from previous
  sprint, deferred verification — no regression observed).
