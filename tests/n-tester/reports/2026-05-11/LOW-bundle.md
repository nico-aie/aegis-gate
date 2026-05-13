---
id: 2026-05-11-low-findings-bundle
date: 2026-05-11T17:28Z
severity: LOW
area: dashboard
component: various
status: open
test_mode: full-qc
---

# LOW-severity findings (Policy / shell polish)

A bundle of small bugs / polish gaps observed across the Policy
section during this run. None block a release; all are <30-minute
fixes individually.

## LOW-01 — `unknown-host-86898-…` cluster node identifier

`/api/cluster.our_node` is `unknown-host-86898-1778519433894003000`
on a fresh dev boot. The "Cluster 1 node · leader" pill in the
header reads cleanly but the underlying ID is human-unfriendly.
Either fall back to `hostname` (or `make run-dev`'s configured
node_id), or hide the underlying ID in the UI for single-node
clusters.

## LOW-02 — `vnexpress` placeholder in shipping code

The Add Route modal pre-fills `vnexpress` as the Route ID
placeholder, and the Host header (SNI) field's placeholder reads
`vnexpress.net (for multi-vhost / public TLS)`. Looks like
operator-local environment seepage. Replace with a generic
`my-route` / `api.example.com` placeholder.

## LOW-03 — Toast styling drift

Some toasts render with a green-bordered card (creation success),
others with a red-bordered card (save failure). The green-on-dark
"Added blacklist entry ip:198.51.100.50" toast at bottom-right
worked fine. The Routing & Upstreams "Save failed: …" toast lands
in the same spot but its bg is darker, making the red border
harder to read. Pick one toast component and use it everywhere.

## LOW-04 — Disabled toggle / muted-text contrast

Several places use `opacity: 0.5` to mark "disabled" or "muted"
state (the muted `brute_force · 35` chip on the Detectors page,
the "AI · ml" section pre-enable). On a dark theme + low-contrast
neutral chips, 0.5 opacity drops the chip text close to the
WCAG-AA threshold. Recommend 0.6 + a stripey background to
disambiguate "disabled" from "loading".

## LOW-05 — Routing & Upstreams summary counters could be sharper

The page header reads:

```
1 route → 2 pools (3 members, 1 unreferenced)
```

After the test run that's accurate, but the phrasing implies "1
route uses 2 pools" — when in fact the second pool has no route.
A sharper read: `1 route · 1 pool routed · 1 pool unrouted (2
members)`. Same data, less mental gymnastics.

## LOW-06 — "How does it work?" expandables don't say "expanded"

On Traffic Gates the per-gate "How does it work?" expandable
collapses with a `▶` chevron. After expansion the chevron stays
`▶` — operators don't see "this is open, click to close". Flip
to `▼` on the open state.

## LOW-07 — Rules "TIER A" pill in the Rule Simulator

The Rule Simulator panel carries a small `TIER A` pill top-right
with no tooltip / no link. Operators new to the framework won't
know what Tier A means here vs. the tier-classifier tiers on the
Detectors page. Either link it to the Detectors page Risk-score
reference or add a tooltip.

