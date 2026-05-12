---
id: 2026-05-12-security-ops-summary
date: 2026-05-12T00:25Z
test_mode: full-qc
scope:
  - Verification of Phases 0.2 / 1 / 2 / 3a / 3b from
    plans/issue-fix/2026-05-11-policy-and-dns-verification
  - Functional + UX walk-through of the 5 Security Ops pages:
    Overview, Live Feed, Incidents, Investigation, Top Attackers
  - Synthetic traffic from spoofed `X-Forwarded-For` IPs across
    multiple countries (US / CN / DE / AE / RU / NL / PL / TEST-NET-3
    + 4 legitimate IPs) to exercise GeoIP enrichment + the audit ring
---

# Aegis-Gate end-to-end test run — Security Ops + previous-sprint verification

## Headline

`Aegis-Gate test run complete · full-qc · ~50 min`
`Findings: 0 CRITICAL · 1 HIGH · 5 MEDIUM · 4 LOW · 6 INFO`
`Top blocker: HIGH-SO-01 — Block button on Top Attackers + Live Feed`
`  detail drawer fails server-side ("missing field bypass") so a primary`
`  SOC workflow ("see attacker, click Block") is broken end-to-end.`
`Reports: tests/n-tester/reports/2026-05-12-security-ops/`
`Next suggested action: ship the trivial dashboard fix (send`
`  bypass: [] in the POST body) before the next release. Then`
`  triage MED-SO-02..05 (Investigation pivot doesn't actually`
`  filter; Incidents lifecycle UI doesn't reflect Ack state;`
`  Investigation detector breakdown shows 0 despite live traffic;`
`  METHOD / PATH / RULE_ID columns surface "—" everywhere).`

## Verification of the previous-sprint fix plan

All five batches from
`plans/issue-fix/2026-05-11-policy-and-dns-verification`
verified live in the running dashboard. Summary:

| Batch | Commit(s) | Operator-visible verification |
|---|---|---|
| Phase 0.2 — make-build auto-rebundle | `0a9d815`, `d521eb8` | Confirmed in `Makefile` (`dashboard:` target). Cache-Control + CI gate + README workflow note also shipped in `d521eb8`. |
| Phase 1 — MED-01..04 | `0532bc5` | Audit Trail RULE column now extracts from `fields.resource` for `rule_*` rows; Add Route modal shows one canonical error; header `UNKNOWN` red pill gone; orphan-pool compensating delete on failed route create. |
| Phase 2 — LOW polish | `337da81` | Routing & Upstreams copy reads `1 route · 1 pool routed (1 member)`; placeholder swaps done; toast unification visible. |
| Phase 3a — UX P1/P2/P6/P7/P9/P10 | `7f2ed08`, `f8274b9`, `b0522af`, `594235c`, `b6c281d` | **Policy posture cheat-card** visible at top of every Policy page (`POSTURE ENFORCE · 4 TIERS · AI OFF · 0 RULES · 0 BLACKLIST · 0 WHITELIST · DDOS ENFORCE`); **Refresh icon-button** anchored next to page titles (Overview, Rules, Routing, Top Attackers); **Traffic Gates flow diagram** (`inbound → 1. ACCESS LIST → 2. STRIKE-BLOCK → 3. CUMULATIVE IP → 4. RATE LIMIT → 5. DDOS → detector chain`); footer pills muted to neutral on a healthy boot; `#/detectors?tier=critical` deep-link reads. |
| Phase 3b — UX P3/P4/P5/P8 | `176382b`, `1d6084d`, `bebca12`, `3c59dcb` | Rules page has **Rules / Simulator tabs** (`#/rules` defaults to Rules tab); route activity pill rendered on the catch-all route as `IDLE`; per-entry hit counters in `AccessListStore` confirmed via source. P8 microcopy on detector-mask Save not exercised in this run (no mask edits). |

All fixes from the previous run are present in the live bundle.
Operator can declare the 2026-05-11 fix plan **closed** modulo any
new findings filed below.

## Synthetic-traffic driver

To populate the Security Ops dashboards with realistic signal I
fired 100 attack requests + 40 legit requests against the data
plane (`127.0.0.1:8080`), spoofing source IPs via
`X-Forwarded-For`:

| Origin | IP | Geo / ASN |
|---|---|---|
| Attackers | `5.195.235.51` | AE / AS5384 |
|  | `185.220.101.5` | DE / AS60729 (Tor exit) |
|  | `223.5.5.5` | CN / AS45102 (AliDNS) |
|  | `8.8.8.8` | US / AS15169 (Google) |
|  | `104.21.14.6` | US / AS13335 (Cloudflare) |
|  | `94.102.61.7` | NL |
|  | `203.0.113.7` | TEST-NET-3 (no geo) |
|  | `1.1.1.1` | AU/US / AS13335 |
|  | `45.135.232.41` | DE / AS215174 |
|  | `91.234.99.99` | PL |
| Legit | `8.8.4.4` / `9.9.9.9` / `1.0.0.1` / `208.67.222.222` | — |

Attack signatures included: sqli `UNION SELECT`, sqli `OR 1=1`,
xss `<script>`, xss `<img onerror>`, path traversal raw + URL-
encoded, SSRF to `169.254.169.254`, recon paths (`/.env`,
`/.git/config`, `/wp-admin/install.php`, `/phpmyadmin`,
`/aws/credentials`, `/actuator/env`, `/admin/login.php`). UAs
mixed: Mozilla, curl, Googlebot, bingbot, python-requests,
Firefox.

**Result**: 86 detections / 80 blocks / 5 unique attackers ranked
on Top Attackers / 4 countries surfaced via GeoIP enrichment in
the Live attack origins map.

## Page-by-page verdict

```
Pages exercised (5 Security Ops):
  Overview      ✓ mounts ✓ data ✓ controls (Export, Open Grafana, time-window
                pills, attack-origins map, Top attackers preview)
                ⚠ time-window pill click doesn't update chart subtitle (LOW-SO-01)
                ⚠ Block button on preview rows triggers the same broken POST
                  as HIGH-SO-01

  Live Feed     ✓ mounts ✓ data (80/80 SSE buffer, CONNECTED chip)
                ✓ controls (Pause→Resume, CSV export hook, action+tier filters,
                  search input, row → request detail drawer)
                ✓ drawer is excellent — Action / Reason / Risk / Tier / Network /
                  Request / Detection / Extra fields + Copy as cURL / Block IP /
                  Whitelist buttons
                ⚠ Sidebar URL is `#/live` but typing `#/live-feed` shows
                  "Page not found" (LOW-SO-02)
                ⚠ Block IP from drawer triggers the same broken POST as HIGH-SO-01

  Incidents     ✓ mounts ✓ data (3 firing DataPlaneAvailability alerts)
                ✓ controls (Ack / Snooze 15m / Resolve buttons; open / firing /
                  acknowledged / snoozed / resolved / all status chips)
                ⚠ SLI column shows "unknown" for every row — alert.name not mapped
                  to SLI (MED-SO-03)
                ⚠ FIRED / BUDGET / ACKED BY / NOTE columns all show "—" even
                  when the API carries `since` (MED-SO-03)
                ⚠ Ack POST returns ok, toast says "Incident ack ok" — but the row
                  stays FIRING in the UI; /api/incidents.incidents stays [].
                  Lifecycle UI is read-from-stub (MED-SO-04)

  Investigation ✓ mounts ✓ pivot input + auto-detect dropdown
                ✓ Pivot button drives URL → #/investigation?pivot=...&kind=...
                ✓ Attacker context card reads from /api/attacks/top and shows
                  Hits / Country / ASN / Risk / Categories — this is excellent
                ⚠ KPI cards (Events / Unique IPs / Window / Top action) show
                  aggregate over the whole audit ring, NOT filtered to the pivot;
                  the caption "matching this pivot" is misleading (MED-SO-02)
                ⚠ Audit timeline table does NOT filter to the pivot — shows all
                  rows regardless (MED-SO-02)
                ⚠ Detector breakdown card claims "0 detections · last 1h" while
                  /api/attacks/by-detector?window=3600 shows 50+ detections
                  (MED-SO-05)
                ⚠ Bot classification mix empty even though 86 events tagged with
                  bot UAs (Googlebot, bingbot, curl) flowed through (LOW-SO-04)
                ⚠ METHOD / PATH / RULE_ID columns surface "—" or "/" for every
                  row (MED-SO-02)

  Top Attackers ✓ mounts ✓ data (5 attackers ranked with country + ASN)
                ✓ window selector (5m / 15m / 1h / 24h)
                ✓ Pivot link → Investigation deep-linked with `?pivot=&kind=`
                ✗ Block button calls a broken endpoint — "missing field
                  bypass" 400 error (HIGH-SO-01)
                ⚠ Identifier links underlined but click does nothing — should
                  pivot to Investigation or open a detail card (LOW-SO-03)
```

## SOC scenarios

```
S1 "I just got paged"           = 4  (no UNKNOWN badge now, but 3
                                       availability alerts on a healthy
                                       WAF feel noisy)
S2 "Who's attacking me?"        = 5  (Top Attackers + Overview map + ASN
                                       + country in one glance — best in class)
S3 "What did this attacker do?" = 3  (Pivot URL works, attacker context card
                                       is great, but the audit timeline is
                                       NOT actually filtered to the pivot)
S4 "Audit Trail surfaces       = 5  (Live Feed SSE arrives in <1s; mutations
   mutations <3s"                    chained, audit-mutated tag visible)
S5 "Empty states honest"        = 3  (Investigation "0 detections last 1h"
                                       is dishonest; Bot mix shows empty
                                       despite bot-UA traffic)
S6 "Block this attacker"        = 1  (CRITICAL — broken end-to-end. Confirm
                                       prompt is good, server rejects the
                                       POST because of a schema miss)
S7 "Reload tolerance"           = 4  (Pivot URL survives reload; filters
                                       lost on reload; LIVE chip reconnects)
S8 "Console hygiene"            = 4  (No red console.error spam in 60s idle;
                                       a few network 404s on /favicon.ico
                                       and the legacy #/live-feed route)
```

## Files in this bundle

- `RUN-SUMMARY-security-ops.md` (this file)
- `HIGH-SO-01-block-button-broken.md` — Block button POST body
  missing required `bypass` field; primary SOC workflow broken
- `MED-SO-02-investigation-pivot-not-actually-filtered.md` — pivot
  KPIs + audit timeline aggregate over the whole audit ring
- `MED-SO-03-incidents-columns-not-mapped.md` — SLI / FIRED /
  BUDGET / ACKED BY / NOTE columns surface `—` or "unknown"
- `MED-SO-04-incident-ack-not-reflected.md` — Ack POST returns ok
  but UI doesn't reflect the new state
- `MED-SO-05-investigation-zero-detections.md` — Investigation
  detector breakdown reports 0 detections despite live data
- `MED-SO-06-method-path-rule-columns-empty.md` — audit-timeline
  table columns METHOD / PATH / RULE_ID are unused
- `LOW-SO-bundle.md` — 4 LOW findings (time-window pill, `#/live-feed`
  404, identifier link no-op, bot-mix empty)
- `INFO-SO-bundle.md` — passing observations
- `UX-PROPOSALS-security-ops.md` — concrete UI/UX upgrade
  proposals for the 5 Security Ops pages
