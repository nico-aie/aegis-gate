---
id: 2026-05-19-info-dashboard-shell-smoke-clean
date: 2026-05-19T12:45Z
severity: INFO
area: dashboard
component: shell + sidebar
status: open
test_mode: functional
---

# Phase 1 shell smoke clean — 17/17 pages mount, 37/37 admin APIs return 200

## Summary

Login + cookie pair + every documented admin API + every sidebar
page passes. No error-boundary cards on any page.

## Actual

- `POST /admin/login` with valid credentials → 200, sets
  `aegis_session` + `aegis_csrf` (verified via `csrf_visible: true`
  on an early console probe before Chrome's sandbox masked
  `document.cookie`).
- 37/37 documented admin API endpoints return 200 from an
  authenticated SPA session — no `failures` array.
- 17/17 sidebar items mount, no `Page render error` text on the
  body of any:
  Overview, Live Feed, Incidents, Investigation, Top Attackers,
  Routing & Upstreams, Traffic Gates, Access Lists,
  Detectors & Tiers, Rules, Performance, Health & SLOs,
  Audit Trail, Scaling, Settings, Reports, Help & Guide.
- Console error sweep (`read_console_messages onlyErrors=true`)
  found no errors or exceptions.

## Suggested fix

None.

## Severity rationale

INFO — captured for the run record.
