---
id: 2026-05-03-medium-overview-status-noise
date: 2026-05-03T17:42Z
severity: MEDIUM
area: dashboard
component: overview / footer / status-badge
status: open
test_mode: full-qc
---

# Overview status badges fabricate problems on a clean dev WAF

## Summary
A SOC analyst's first-five-seconds read of Overview is muddied by
chrome that says the system is broken when nothing is. On a fresh
`make run-dev`:

- The big top-left badge reads **"UNKNOWN"** in red. Same colour
  the dashboard uses for "blocked / down / firing." Source is
  `/api/cluster.peers[0].addr == ""` — the dev profile doesn't
  bind a cluster address. Visually identical to a real outage.
- Footer reads **"GitOps UNKNOWN"** in red. Source is
  `/api/gitops/status.repo == null`. GitOps is opt-in; "not
  configured" should not paint red.
- Footer reads **"Audit chain DEMO"** in yellow. Reasonable hint
  but visually competes with the cluster badge.
- Top-right Upstream card says **"— · no members configured"**
  while `/api/upstreams` says `state: Healthy, healthy_members: 1`.
  Two different sources of truth, opposite stories.
- Block-rate card shows **"0.0%"** in red with **"142 blocked
  total"** under it. The rate is over the 1-second sliding window
  (currently zero RPS) but the cumulative count is 142. Numerator
  / denominator mismatch reads as "100% blocked."

This is the S1 SOC scenario: "I just got paged. Within 5s, can I
tell — is the WAF up? Traffic flowing? Anything blocked?" My
score is 3/5 and the things confusing me are the badges, not the
data.

## Repro
1. `make run-dev` from a fresh clone.
2. Sign in, land on Overview.
3. Look at the badge top-left, the footer strip, and the Upstream
   card. Compare to `/api/cluster`, `/api/gitops/status`,
   `/api/upstreams`.

## Expected
Badges that reflect "operating but unconfigured" should be neutral
(grey / muted) until the operator opts in. Red is for outages.
The Upstream card should reflect the same `/api/upstreams.state`
the API returns; "no members configured" is wrong when there is
exactly one member.

## Actual
Half the chrome is red on a healthy system. New operators triage
phantom problems before finding the real ones.

## Suggested fix
- Status badge: when `/api/cluster.peers[0].addr == ""`, label
  **"Single-node"** in muted text, not "UNKNOWN" in red.
- Footer: when `/api/gitops/status.repo == null`, label
  **"GitOps off"** in muted text. Reserve the red dot for
  configured-but-failing.
- Upstream card: render from `/api/upstreams.state` (the same
  source the Routing & Upstreams page uses); "Healthy 1/1" is
  correct, "no members configured" is not.
- Block-rate card: either label the bottom number "blocked total
  · session" (so it's clearly cumulative, separate from the
  rate), or move it into a tooltip.

## Severity rationale
MEDIUM. Doesn't break any feature, but it costs every new
operator a couple of minutes' worth of confusion the first time
they see it, and it permanently raises the noise floor of the
dashboard. Easy fix, recurring win.
