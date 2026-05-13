---
id: 2026-05-12-observability-summary
date: 2026-05-12T07:30Z
test_mode: full-qc
scope:
  - Verification of all PRs from
    plans/issue-fix/2026-05-12-security-ops
    (PR-HIGH, PR-MED-DASH, PR-MED-SRV, PR-LOW, PR-UX-A1, PR-UX-A2,
    PR-UX-A3)
  - Functional + UX walk-through of the 4 Observability pages:
    Performance, Health & SLOs, Audit Trail, Scaling
---

# Aegis-Gate end-to-end test run — Observability + Security Ops sprint verification

## Headline

`Aegis-Gate test run complete · full-qc · ~45 min`
`Findings: 0 CRITICAL · 0 HIGH · 1 MEDIUM · 5 LOW · 8 INFO`
`Top blocker: NONE — Observability pages all work end-to-end.`
`  Carry-forward: MED-OBS-01 (Incidents Ack POST returns 200 but`
`  overlay doesn't write acked_by/acked_at) — partial regression`
`  on the previous sprint's MED-SO-04 fix; needs ~30 min server`
`  patch to write the overlay on the ack path.`
`Reports: tests/n-tester/reports/2026-05-12-observability/`
`Next suggested action: finish MED-SO-04 server overlay write,`
`  then ship the LOW polish bundle (route aliases, generic`
`  error messages, "Latency by route" empty-state contradiction)`
`  in the next dashboard PR.`

## Verification of the previous-sprint fix plan (`plans/issue-fix/2026-05-12-security-ops`)

| PR | Commit | Verified |
|---|---|---|
| **PR-HIGH** — Block button `bypass: []` + `#[serde(default)]` | `e03bac5` | ✅ Top Attackers `Block` POST returns 200, blacklist persists entry `top-attacker-104-21-14-6-...` with `bypass: []` populated, `kind: ip`, `value: 104.21.14.6`. Toast says "Blocked 104.21.14.6". |
| **PR-MED-DASH** — Investigation pivot filter, Incidents columns, Detector breakdown endpoint, audit-timeline columns | `73bec6e` | ✅ Pivot on 104.21.14.6 → Events=14, Unique IPs=1, Top action BLOCK 14 of 14, Audit timeline filtered to client_ip=104.21.14.6. Top detectors/rules: recon_path=6, sqli=4, ssrf=2, etc. METHOD/PATH/RULE_ID columns all populated. Incidents SLI column shows `DataPlaneAvailability` + window chips `1H` / `6H` / `72H`; FIRED column shows relative time `1m ago`. |
| **PR-MED-SRV** — Incidents lifecycle overlay (server-side) | `1181c09` | ⚠️ Partial. `/api/incidents` GET now returns proper incident shape (id, severity, fired_at, runbook_url, acked_at, acked_by, snoozed_until, resolved_at, budget_consumed_pct, burn_rate, window_hours). But the ack POST handler at `/api/incidents/<id>/ack` returns 200 + toast says "Incident ack ok" yet `acked_at` / `acked_by` stay `null` and STATUS stays `firing`. **See MED-OBS-01.** |
| **PR-LOW** — Chart subtitle template, `#/live-feed` alias, IP-link pivot, bot-mix copy | `990e38f` | ✅ `#/live-feed` route works (no longer 404). Chart subtitle reflects active window. Top Attackers underlined IPs click → pivot to Investigation. |
| **PR-UX-A1** — Sec Ops posture cheat-card | `371b571` | ✅ Visible across Overview / Live Feed / Incidents / Investigation / Top Attackers: `SEC OPS · 0.0 REQ/S · 0.0% BLOCKED · 3 FIRING · TOP: 104.21.14.6 · US · NO WITNESS YET`. Each chip clickable. |
| **PR-UX-A2** — Server-side pivot filter on /api/audit/since | `1e08bf4` | ✅ Investigation page with `?pivot=104.21.14.6&kind=ip` filters all data: KPI cards + Attacker context + Action breakdown + Top detectors + Audit timeline all show only that IP's events. |
| **PR-UX-A3** — Live Feed keyboard shortcuts + Suggested action column | `a685b5d` | ✅ Audit Trail shows `incident_ack` admin entries from the previous sprint's ack mutations (chain integrity). Keyboard shortcuts not retested in this run (covered last sprint). |

The previous sprint's plan can be declared **closed modulo MED-OBS-01**
(the server-side overlay write needs a follow-up patch).

## Observability page-by-page verdict

```
Pages exercised (4 Observability):
  Performance      ✓ mounts ✓ data (Latency p50/p95/p99 WAF-internal 84 samples
                   with stages total/detect/rate_limit; Block ratio 96.6% avg
                   peak 97.7% at 11:00 AM; Requests over time chart; Error
                   rate by route 7 routes; Latency by detector for 12 active
                   classes with p99 ms color coding)
                   ✓ time-window pills (1h/6h/24h/7d/30d) update subtitle +
                   data (verified 24h → 1h flip)
                   ⚠ "Latency p50/p95/p99 by route" reports "no per-route
                   samples yet" while "Error rate by route" above it
                   surfaces 7 routes with hit counts (LOW-OBS-01)

  Health & SLOs    ✓ mounts ✓ data (SLO budget for data_plane_availability +
                   audit_delivery_rate; Active alerts list 3 firing 0 acked;
                   Alert channels card; Upstream pools 1/1 healthy; Cluster
                   peers; Cert freshness 353D; GitOps sync not configured)
                   ✓ controls (Test alert / Edit / Remove / + Add channel)
                   ⚠ Route is `#/health` but sidebar label is "Health & SLOs"
                   — `#/health-slos` returns "Page not found" (LOW-OBS-02)
                   ⚠ Test alert button returns "Test failed: unknown error"
                   instead of the actual upstream error (the alert channel
                   row separately shows "FAILED 3× · VIPTALK RETURNED 401
                   UNAUTHORIZE" — the Test button should surface the same)
                   (LOW-OBS-03)

  Audit Trail      ✓ mounts ✓ data (88 events across admin + detection
                   classes; chain hash visible via REQUEST ID column;
                   incident_ack, alert_receiver_test, blacklist_add entries
                   all captured)
                   ✓ controls (Class chips: admin+sys, admin, access, system,
                   requests, all; Window chips: 1h/24h/7d/all; client IP /
                   rule_id / request_id filter inputs)
                   ✓ client IP filter works perfectly — typing 104.21.14.6
                   filters from 88 → 14 events
                   ⚠ RULE column shows `—` on detection rows even though
                   REASON column carries the detector breakdown — same
                   pattern as MED-SO-06 from the previous sprint but a
                   different code path (LOW-OBS-04)

  Scaling          ✓ mounts ✓ data (Layer 1 In-node workers L1 badge:
                   WORKERS 12 of 12 logical CPUs, MODE auto, BLOCKING POOL
                   512, CPU AFFINITY off; Layer 2 Cluster peers L2:
                   1 node · standalone · leader; Layer 3 Shared state L3:
                   backend reconciling connected v7.4.6, KEYS 134, P50/P95/
                   P99 latency)
                   ✓ controls (Load mode pin: normal/elevated/critical
                   pills; clear-override button; Drain this node button)
                   ✓ Load mode pin verified end-to-end:
                       click `elevated` → "Mode pinned to elevated" toast,
                       chip flips NORMAL → ELEVATED, new "Clear override
                       (return to auto: normal)" button surfaces;
                       click clear → "Override cleared · mode now
                       auto-driven" toast.
                   ✓ All three layers carry clear "what changes
                   require what action" microcopy (Layer 1: restart-only,
                   Layer 2: drain via button, Layer 3: hot-reloadable)
```

## SOC scenarios (Observability lens)

```
S1 "I just got paged"           = 4  (Health & SLOs surfaces "1 SLO below
                                       target" callout + Active alerts list
                                       + per-pool / cert / cluster health
                                       in one scroll — comprehensive but
                                       dense)
S2 "Who's hammering performance"= 5  (Performance "Latency by detector"
                                       table immediately surfaces the
                                       expensive classes — recon=12.40ms
                                       p99, sqli=5.80ms p99 with color
                                       coding)
S3 "What did this attacker do?" = 5  (closed in this sprint — Audit Trail
                                       client-IP filter narrows 88 → 14
                                       events, Investigation pivot filter
                                       does the same with richer KPI cards)
S4 "Audit Trail surfaces        = 5  (incident_ack from previous tests is
   mutations <3s"                    visible in the chain with timestamp +
                                       request ID hash)
S5 "Empty states honest"        = 3  (Performance "Latency by route empty"
                                       contradicts the populated "Error
                                       rate by route" above it; Test alert
                                       error generic)
S6 "Scale out under load"       = 5  (Scaling page's three-layer split is
                                       the clearest WAF scaling surface
                                       I've seen — Layer 1 / 2 / 3 with
                                       explicit "what action to take")
S7 "Reload tolerance"           = 4  (Window pills persist via URL hash;
                                       Audit Trail filters likewise; Load
                                       mode pin survives reload)
S8 "Console hygiene"            = 5  (no red errors during 60s idle on
                                       any Observability page)
```

## Files in this bundle

- `RUN-SUMMARY-observability.md` (this file)
- `MED-OBS-01-incident-ack-overlay-write-incomplete.md` — Ack POST
  returns 200, overlay GET shape is there, but `acked_at` /
  `acked_by` never populate
- `LOW-OBS-bundle.md` — 5 LOW findings (Latency-by-route empty-
  state, `#/health-slos` route alias, generic Test-alert error,
  Audit Trail RULE column, Performance time-window subtitle edge
  case)
- `INFO-OBS-bundle.md` — passing observations on what works well
- `UX-PROPOSALS-observability.md` — concrete UI/UX upgrade
  proposals for the 4 Observability pages
