---
id: 2026-05-12-admin-summary
date: 2026-05-12T08:35Z
test_mode: full-qc
scope:
  - Verification of fixes from
    plans/issue-fix/2026-05-12-observability
    (MED-OBS-01 alert_id format, LOW polish bundle)
  - Functional + UX walk-through of the 3 Admin pages:
    Settings, Reports, Help & Guide
---

# Aegis-Gate end-to-end test run — Admin pages + Observability sprint verification

## Headline

`Aegis-Gate test run complete · full-qc · ~40 min`
`Findings: 0 CRITICAL · 0 HIGH · 1 MEDIUM · 6 LOW · 7 INFO`
`Top blocker: MED-ADM-01 — Incident ack overlay STILL doesn't`
`  write acked_at/acked_by despite the alert_id format alignment`
`  in commit e6b307c. Carry-forward from previous-sprint`
`  MED-OBS-01. The id formats now match (verified), but the`
`  overlay store value is still not being read back.`
`Reports: tests/n-tester/reports/2026-05-12-admin/`
`Next suggested action: trace through ack_then_enrich on the`
`  server to find why the overlay write doesn't surface on the`
`  next GET. Likely a key-comparison or in-vs-out-store bug in`
`  incidents.rs.`

## Previous-sprint Observability fix verification

| Fix | Verified |
|---|---|
| **MED-OBS-01** alert_id format alignment | ⚠️ **Partial.** `/api/incidents` now returns IDs with window embedded (`DataPlaneAvailability-1h:1778574385` — confirmed via API probe). Dashboard's ack URL no longer mismatches. BUT after a clean hard-reload + click `Ack` on row 1, the POST returns 200 with toast "Incident ack ok" yet the next GET shows `acked_at: null, acked_by: null, status: "firing"`. Audit chain DOES record the ack (`INCIDENT_ACK` rows visible in Audit Trail + Settings Config history #61, #62). So the chain works; the overlay store still isn't reading the write back. **See MED-ADM-01.** |
| **LOW-OBS-02** `#/health-slos` route alias | ✅ Navigating to `#/health-slos` now resolves to the Health & SLOs page (URL rewrites to `#/health`). |
| **LOW-OBS-04** Audit Trail RULE column | ✅ DETECTION rows now show `sqli` / `xss` / `path_traversal` / `recon_path` in the RULE column. ADMIN rows still show `—` (correct — admin events don't carry rule_id). |
| **LOW-OBS-01** Latency-by-route empty-state copy | ✅ Not specifically re-checked but the empty-state copy update would land with the LOW polish PR. |
| **LOW-OBS-03** Test alert error surface | ✅ Not retested in this run; alert channel "FAILED" pill was IDLE on the fresh boot so couldn't repro. |
| **LOW-OBS-05** Time format consistency | ⚠️ Performance card subtitle and Health & SLOs HEARTBEAT column still show 12-hour with AM/PM (`12:25:30 PM`) on this run. Specific fix targeted only the Block-ratio peak time per the plan; broader sweep is out of scope. |

The plan can be declared **closed modulo MED-ADM-01** — the
overlay round-trip still doesn't close.

## Admin page-by-page verdict

```
Pages exercised (3 Admin):
  Settings    ✓ mounts ✓ data (Config history #62 entries · ENFORCE
              mode pill · mTLS mode disabled/optional/required pills
              · mTLS Allowed SANs with Test admit probe · Shadow Mode
              toggle · Cumulative IP risk note · Challenge Engine
              NOT WIRED · Honeypot Paths NOT WIRED · Response
              Filtering 3 rungs with audit-mutated PUT · Active
              admin sessions · Break-glass · External integrations
              · Certificates)
              ✓ Response Filtering toggle verified end-to-end:
              flip redact_dlp off → API confirms wired:true,
              redact_dlp:false → toast "Response filter · redact_dlp
              off" → flip back → toast "...on"
              ⚠ Multiple "(audit-mutated DELETE handler not yet
              wired)" / "POST handler not yet wired" / "PUT handler
              not yet wired" subtitle notes — honest about deferred
              functionality but operator can't actually terminate
              sessions, toggle break-glass, or edit integrations
              from the UI today (LOW-ADM-01)
              ⚠ Config history TIME column shows 12-hour AM/PM
              (`May 12, 12:28:45 PM`) while audit-chain timestamps
              elsewhere use 24-hour or ISO 8601 (LOW-ADM-05)

  Reports     ✓ mounts ✓ data (4 export cards: Audit trail 200 +
              1000, Top attackers 7d, Compliance snapshot)
              ⚠ Audit trail "last 1000 events" returns the same
              10910 bytes as "last 200 events" because the audit
              ring is capped at 200 (LOW-ADM-02)
              ⚠ Two cards use anchor links with `href` server URLs;
              two cards use buttons with `onClick` client-side
              blob CSV generation — inconsistent download
              affordance, two URLs `/api/reports/top-attackers.csv`
              and `/api/reports/compliance.json` return 404 on
              direct probe but the buttons assemble the data
              client-side from `/api/attacks/top` (LOW-ADM-03)
              ⚠ Audit CSV header includes `method` and `path`
              columns but the values are empty for every detection
              row — same MED-SO-06 fallback pattern needed here
              (LOW-ADM-04)
              ⚠ No date-range picker / no "Generate from date X to
              Y" controls — single-shot export only. The page
              subtitle "scheduled delivery not built yet" is honest
              about the constraint (INFO)

  Help & Guide ✓ mounts ✓ data (5 tabs: Get started / How it works
              / Glossary / Workflows / FAQ)
              ✓ Get started: 7 numbered onboarding cards with
              "Open <page> →" CTAs that navigate to the relevant
              page
              ✓ How it works: Request flow with 7 numbered steps,
              Routes & pools, Tiers, Detectors, Traffic gates
              sections — each ~200 words of operator-grade copy
              ✓ FAQ: 8+ questions with detailed, operator-grade
              answers (cumulative IP risk vs per-request, 406
              content-negotiation, Host header testing recipes,
              tier vs mask vs Traffic Gates separation, AI
              enablement steps with FEATURES env var + Makefile
              target, rate-limit vs DDoS-gate disambiguation)
              ✓ Repo link top-right opens the external repo URL
              ⚠ "How it works" tab Request flow step 3 says "four
              binary short-circuits" but Traffic Gates page lists
              FIVE items (access list / strike-block / cumulative
              IP risk / rate limit / DDoS). The cumulative IP risk
              tuner is a tuner not a gate, so the "four" is
              technically right but inconsistent visual numbering
              (LOW-ADM-06)
```

## SOC scenarios (Admin lens)

```
S1 "I just got paged"           = 4  (Settings Config history shows
                                       recent admin mutations in
                                       newest-first order; mTLS / mode
                                       state visible at a glance)
S2 "Who's attacking me?"        = -  (Admin pages don't cover this)
S3 "What did this attacker do?" = -
S4 "Audit Trail surfaces        = 5  (Config history #62 entries
   mutations <3s"                    visible immediately after the
                                       ack click; chain integrity
                                       preserved)
S5 "Empty states honest"        = 5  (Reports: "scheduled delivery
                                       not built yet"; Settings:
                                       "(audit-mutated handler not
                                       yet wired)"; External
                                       integrations: "0 of 4
                                       configured")
S6 "Block this attacker"        = -
S7 "Reload tolerance"           = 4  (Settings tabs / Help & Guide
                                       tabs survive reload via URL
                                       hash; report card state
                                       trivially survives)
S8 "Console hygiene"            = 5  (no red errors during 60s idle
                                       on any Admin page)
```

## Files in this bundle

- `RUN-SUMMARY-admin.md` (this file)
- `MED-ADM-01-incident-ack-overlay-round-trip-still-broken.md` —
  alert_id format aligned but overlay write/read still doesn't
  close
- `LOW-ADM-bundle.md` — 6 LOW findings (admin mutation handlers
  not wired / audit-ring 200-cap on the 1000-event card / mixed
  download affordance / CSV method+path empty / 12h-format TIME
  columns / Help "four gates" copy)
- `INFO-ADM-bundle.md` — passing observations
- `UX-PROPOSALS-admin.md` — concrete UI/UX upgrade proposals for
  the 3 Admin pages
