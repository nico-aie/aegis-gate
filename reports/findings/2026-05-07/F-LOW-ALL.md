# Low findings — 2026-05-07

---

## F-LOW-001 · Overview page has no in-page alert banner when SLO alerts are firing

**Component:** Dashboard — Overview page  

When SLO alerts are actively firing, the only visible cue on the Overview page is a small red badge count on the bell icon in the top navigation bar. There is no in-page alert banner, highlighted card, or red status indicator on the Overview landing page itself.

A SOC analyst who opens the dashboard during an incident may not immediately notice the bell badge and will not understand the system is in an alert state until they navigate to Health & SLOs.

**Observed:** 3 DataPlaneAvailability alerts firing; Overview shows all-green summary cards (Upstream: Healthy, Active threats: 0). Nothing on the page communicates the active SLO breach.

**Fix:** When `/api/alerts` returns firing alerts, render a dismissible alert banner at the top of the Overview page: `⚠ 3 alerts firing — DataPlaneAvailability-1h (PAGE), ... → View in Health & SLOs`.

---

## F-LOW-002 · "UNKNOWN" badge in header is unexplained

**Component:** Dashboard — global header  

The header shows a persistent `● UNKNOWN` badge (red dot + "UNKNOWN" text) next to the Aegis logo. New operators or day-1 SOC analysts see this immediately and have no way to know what it indicates without prior context.

In testing, this badge appears to reflect cluster status (GitOps is OFF, the node hostname is `unknown-host-74875-...`). Neither explanation is surfaced in the UI.

**Fix:** Add a tooltip on the badge explaining the status (e.g., "Cluster status: GitOps disabled, running in standalone mode"). Consider replacing "UNKNOWN" with a more informative label for common operational states (standalone, clustered, degraded).

---

## F-LOW-003 · Dev-facing empty state message exposed in production UI

**Component:** Dashboard — Top Attackers page  

When the Top Attackers table is empty, the empty state renders:

> "No attackers ranked in the last 1h. Drive synthetic load with `make mock-load-attacks` to see the table populate."

The `make mock-load-attacks` command is a developer Makefile target and has no meaning to end users or SOC analysts.

**Fix:** Replace with a user-facing message: "No blocked sources in the selected window. Try extending the time range or drive traffic to the WAF to see attacker rankings."

---

## F-LOW-004 · `#/routing` URL does not match actual route `#/upstreams`

**Component:** Dashboard SPA router  

The Routing & Upstreams page lives at `#/upstreams`. Any documentation, external links, or bookmarks that use the more intuitive `#/routing` silently redirect to Overview. This is a discoverability issue distinct from F-MEDIUM-003 (which tracks the fix) — listed separately to flag the documentation update needed.

**Fix:** Update all internal documentation and any `href` attributes in Help & Guide that reference `#/routing` to use `#/upstreams`. Also add the route alias per F-MEDIUM-003.
