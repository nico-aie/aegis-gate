---
id: 2026-05-11-unknown-status-badge
date: 2026-05-11T17:11Z
severity: MEDIUM
area: dashboard
component: shell · header-status-pill
status: open
test_mode: full-qc
---

# Header shows red "UNKNOWN" pill on a healthy single-node cluster

## Summary

The top header next to "Aegis WAF v0.1.0" carries a red dot + the
text **UNKNOWN** on every Policy page (and Overview, and Settings,
and Audit Trail, etc.) for a cluster that is otherwise reporting:
`Cluster 1 node · leader`, `Upstream Healthy 3 of 3 members up`,
`/api/state.connected: true`, audit-chain hash-chained, mode
enforce. There is no actual unknown / down condition; the badge
appears on a fresh, working install.

Per the skill's S1 SOC scenario rubric: status badges should NOT
paint red on a healthy system. Operators reading this dashboard
on day one will file a P1 because the badge says UNKNOWN above
everything they touch.

## Repro

1. `make redis-up && make run-dev` (or operator's normal boot).
2. Sign into `:9443` with `admin / aegis-test-1234`.
3. Header badge top-left ≈ `(265, 20)` always reads "● UNKNOWN" in
   red, regardless of which page you're on.
4. `/api/state` reports `connected: true · backend: "reconciling"`.
5. `/api/cluster` reports `is_leader: true` + a single peer with
   `last_heartbeat` ~ now.

## Expected

When the cluster is single-node, leader, audit chain healthy, and
state backend connected, the badge should read `HEALTHY` (or
nothing — absence of a warning is informative on its own). Red is
reserved for actual outages.

## Actual

Persistent red "UNKNOWN" badge, no matter the underlying state.

## Suggested fix

Locate the component (a string search for `"UNKNOWN"` in pages.jsx
points at the shell header). The badge appears to be tracking
something other than the actual cluster state — possibly a
configured environment label (`/api/about.environment` returns
`null` in dev) used as the badge text without a fallback.

Reasonable fallback: when `environment === null`, show no badge
or show a neutral `DEV` pill. Red `UNKNOWN` is misleading.

## Severity rationale

MEDIUM. Doesn't break functionality but every operator session
opens with a red alarm-state pill that doesn't correspond to any
real problem. S1 score on this run was 3 directly because of this
badge; on a quiet day with no alerts firing it would be a 5.

