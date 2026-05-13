---
id: 2026-05-12-routing-info-bundle
date: 2026-05-12T13:13Z
severity: INFO
area: dashboard
component: routing-upstreams
status: documented
test_mode: full-qc
---

# INFO — passing observations on the Routing & Upstreams page

## INFO-RU-01 — DNS hostname resolution works end-to-end

`znews.vn:443` resolved at PUT time to two A-records:
`42.112.59.10:443` and `42.112.59.12:443`. Both members got
`host_header: "znews.vn"` defaulted from the hostname (SNI
auto-set). Audit chain captures the `pool_upsert` with the
resolved IP set. The DNS Phase 1 + Phase 2 features documented
in `plans/dns-upstream-resolution.md` are operationally solid.

The follow-up bug is purely in the scheme/TLS plumbing
(HIGH-RU-01) — the DNS resolution path itself is honest.

## INFO-RU-02 — Routing & Upstreams page header is clear

`2 routes · 2 pools routed (3 members) · LIVE · AUDIT-MUTATED`
is exactly the four-token summary the operator needs to read at
a glance. The "AUDIT-MUTATED" tag is the right operator-facing
reassurance that every change here lands in the audit chain.

## INFO-RU-03 — Route table shows the right per-route runtime
state

Each route row has:
- PRIORITY (#1, with the 0.x.x.x specificity tuple under it +
  IDLE activity chip)
- MATCH (HOST · PATH) with chips for CATCH-ALL / FALLBACK /
  PREFIX
- METHODS (ANY)
- FORWARDS TO with the pool name + scheme + member count +
  the `↳ <ip>:<port>` member list inline
- TIER · AUTH (LOW / open)
- Edit / Delete actions

The member list inline saves a click compared to "open pool
detail to see members". The scheme chip (`https · 2 members`)
is exactly the surface that would surface HIGH-RU-01 if the
table also rendered the `tls` flag — recommend adding that as
a fix-companion to HIGH-RU-01 (a `TLS ⚠ mismatch` chip when
scheme says https but tls flag says false).

