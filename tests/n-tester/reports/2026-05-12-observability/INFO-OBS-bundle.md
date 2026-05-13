---
id: 2026-05-12-observability-info-bundle
date: 2026-05-12T07:29Z
severity: INFO
area: various
component: pass-observations
status: documented
test_mode: full-qc
---

# INFO — passing observations on the Observability section

## INFO-OBS-01 — Scaling page is the best operational-state UI in the product

The Layer 1 / Layer 2 / Layer 3 split is exemplary:

- **Layer 1 · In-node workers** — workers / mode / blocking pool /
  CPU affinity numerics, with an explicit "Restart required to
  change. Edit the `runtime:` block in waf.yaml." callout. The
  operator immediately knows the leverage scope (this node only)
  and the surface to change (waf.yaml).
- **Layer 2 · Cluster peers** — "1 node · standalone · this node …
  · leader" + "Running in single-node mode — no remote peers
  configured" + **Drain this node** button with
  the perfect microcopy: *"Flips readiness to 503 — the load
  balancer pulls this node within one health-check interval."*
  That's S6-class operational copy.
- **Layer 3 · Shared state** — backend + reconciling + connected
  + version + circuit + key count + replica lag + p50/p95/p99
  latency. Live status badges everywhere.

And the **Load mode pin** affordance at the top is a complete
end-to-end working surface:
- Click `elevated` → "Mode pinned to elevated" green toast, chip
  flips NORMAL → ELEVATED, new "Clear override (return to auto:
  normal)" button surfaces.
- "Operator override active. Auto-driven mode would be `normal`."
  callout makes the override state obvious.
- Click clear → "Override cleared · mode now auto-driven".
- Audit chain captures `loadmode_pin` / `loadmode_clear`
  mutations.

Keep this page exactly as-is.

## INFO-OBS-02 — Audit Trail client-IP filter is genuinely useful

Typing `104.21.14.6` in the client IP input narrows 88 → 14
events in real time. No `Apply` button, no race condition with
the LIVE stream. The chain hashes (REQUEST ID column) are
visible at full length — copy-paste-able into any external tool.
With the previous-sprint's `?rule_id=` deep-link, the Audit Trail
becomes the SOC analyst's primary forensics view.

## INFO-OBS-03 — Performance "Latency by detector" table is exactly what an SRE wants

12 detector classes × p50 / p95 / p99 ms with color coding for
slow classes (recon=12.40ms p99 → yellow, xss=5.80ms p99 →
yellow, body_abuse=0.050ms p99 → no color). Operators see
"recon is expensive" at a glance and can decide whether to
sample-down its base mask or move its detection earlier in the
chain.

The samples count is constant across rows (84 in this run = my
attack-traffic count) which is honest — the detectors all run
on every request.

## INFO-OBS-04 — Health & SLOs SLO budget card is clear

Two SLOs visible:
- `data_plane_availability`: CURRENT 0.00% / TARGET 99.90% /
  bar empty / **0% LEFT**. With a "1 SLO below target. No
  blocked-traffic data in the last hour — the SLO breach isn't
  from detector blocks. Check upstream health and the alerts
  panel below." callout. The disambiguation between "WAF
  blocked the request" vs "upstream is down" is the right one
  for an availability SLO.
- `audit_delivery_rate`: CURRENT 100.00% / TARGET 99.99% / bar
  full green / 100% LEFT.

Clean separation, clean math, clean copy.

## INFO-OBS-05 — Posture cheat-card adapts based on actual state

The previous sprint's SO-P1 posture cheat-card surfaces the live
state on every Security Ops page. After my synthetic traffic
landed:

`SEC OPS · 0.0 REQ/S · 0.0% BLOCKED · 3 FIRING · TOP: 104.21.14.6 · US · NO WITNESS YET`

- "3 FIRING" chip is yellow when alerts are firing, green "NO
  ALERTS" when zero.
- "TOP: 104.21.14.6 · US" surfaces the top attacker + country
  inline — saves a navigation to Top Attackers.
- "NO WITNESS YET" is honest about the deferred witness feature
  rather than hiding the chip.

## INFO-OBS-06 — Block button confirm copy is operator-grade

`"Block 104.21.14.6? Adds to /api/blacklist · audit-chained."`

In 8 words: what will happen (block), where it lands (/api/
blacklist), and how to investigate later (audit-chained). The
HIGH-SO-01 fix shipped this and it deserves explicit credit.

## INFO-OBS-07 — Cert freshness card has the right time horizon

`localhost / aegis-gate.local / STATIC / EXPIRES 353D`. Showing
expiry in **days** instead of an absolute date is the right
choice for an ops dashboard — operators page when days drop
below their refresh SLA, not when the wall-clock hits a specific
date.

## INFO-OBS-08 — Footer pill row reads neutral on a healthy boot

After this sprint's PR-UX-A1 tone fix, the footer is:
`SSE (demo) | Cluster 1/1 | Audit chain DEMO | GitOps OFF | Build 0.1.0 · session 184s`

Two of four pills carry environment labels (DEMO / OFF). On a
healthy boot they render neutral grey, not warn-yellow — exactly
right for "this is an environment label, not a concern".

