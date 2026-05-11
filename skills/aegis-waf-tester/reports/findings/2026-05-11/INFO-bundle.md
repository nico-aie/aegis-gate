---
id: 2026-05-11-info-bundle
date: 2026-05-11T17:28Z
severity: INFO
area: various
component: pass-observations
status: documented
test_mode: full-qc
---

# INFO — passing observations from this run

Things that worked well and deserve to be on record so they don't
get re-raised in future audits.

## INFO-01 — Rule Simulator detector breakdown is the best surface on the WAF

The Simulator's response card on Rules — verdict + rule + risk +
tier + Detectors Fired + **Muted (disabled by mask)** + per-class
Signals table — is a model of "show the operator everything the
backend just decided". The `MUTED (DISABLED BY MASK)` column makes
the detector mask debug-friendly in a way most WAFs don't bother
with. Keep it.

## INFO-02 — Modal copy on destructive operations is operator-grade

Two examples worth quoting (and replicating for any future
destructive op):

- F-06 AI Disable: "Attack detection from the ML model stops on
  the next request. The regex/heuristic detectors keep running.
  You can re-enable from this same button." → impact + scope +
  reversibility, in one sentence.
- F-07 Remove blacklist entry: "Removing `ip:198.51.100.50` is
  audit-mutated and cannot be undone. New requests stop matching
  this entry on the next request; in-flight requests finish on
  the old list." → audit framing + timing semantics.

Both modals are dark-themed, backdrop-dimmed, escape-cancellable.
Match this voice on the next destructive-op modal that ships.

## INFO-03 — Config history on Settings is exemplary

The Config history card on Settings — versioned, audit-mutated,
actor + source ("DASHBOARD") + reason — is exactly what a SOC
operator wants to see during an incident review. My 6 test
mutations were all surfaced (POOL_UPSERT, RULE_CREATE,
AI_ENABLED_PUT, BLACKLIST_ADD, BLACKLIST_REMOVE, POOL_UPSERT).
Each row carries a `▶` expander for the diff (not exercised in
this run but visible).

## INFO-04 — DNS Phase 1 e2e works through the dashboard

Even with the stale `app.js` (HIGH-01), the Add Route modal still
accepts `example.com:443` because the browser submits the raw text
to the backend; the backend's `dns_resolve` module does the rest
and the pool ends up with 2 members + correct `host_header`. The
end-to-end behavior verified:

- Resolved IPs: `104.20.23.154`, `172.66.147.243`
- `host_header` defaulted to `example.com` (SNI alignment)
- Loud failure on unresolvable: HTTP 400 with `reason: validation`
  and a clear message
- CSRF gating on PUT: 403 + `reason: csrf_missing_header` when
  the X-CSRF-Token header is omitted

## INFO-05 — Validation guards from Phase 2 land in the right place

The lint-time rejections for `state.backend = raft`,
`state.redis.cluster = true`, `state.reconcile.mode = latest |
fail_safe`, route `match_type: regex | glob`, and
`RuleAction::RateLimit` all live in `WafConfig::validate()` —
so any tool that loads + validates a config (CI lints, GitOps
preview, dashboard PUT) catches them before boot. The boot path
keeps defense-in-depth guards. This is the right shape.

## INFO-06 — Traffic Gates page is a clean abstraction

Five gates × per-gate "How does it work?" + status + numbers +
edit affordance is much easier to grok than the older mixed-state
Settings page that bundled DDoS + access-list + risk thresholds
into one scroll. Worth backporting the "per-card 'how does it
work?'" pattern to other pages (Detectors & Tiers especially).

## INFO-07 — Audit chain is real

`/api/audit/since` returns proper `seq` numbers + per-event `tier`
+ `class` + `request_id` hashes; the dashboard chips them on
Audit Trail. `Hash-chained · 2 events shown · LIVE` in the page
header is honest. No double-write regression observed in this run
(but no data-plane traffic either — the 60-row check from the
skill's Phase-2 driver wasn't run).

