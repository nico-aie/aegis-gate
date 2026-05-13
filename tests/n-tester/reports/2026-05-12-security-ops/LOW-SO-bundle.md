---
id: 2026-05-12-low-findings-bundle
date: 2026-05-12T00:21Z
severity: LOW
area: dashboard
component: various
status: open
test_mode: full-qc
---

# LOW-severity findings (Security Ops polish)

Bundle of small bugs / polish gaps. None block release; all are
<30 min fixes each.

## LOW-SO-01 — Overview time-window pills don't update the chart subtitle

The "Traffic vs Blocked" chart has 1m / 5m / 15m / 1h pills.
Clicking any of them visually highlights but the chart subtitle
stays `"Realtime · 60s window · 1s buckets"` regardless of which
pill is active. The chart's y-axis does seem to update with new
data ranges, so the pills aren't entirely no-op — the subtitle
needs to mirror the active window.

**Fix**: in the chart component, the subtitle string should
template off the active window state: `${window} window ·
${bucketSize} buckets`. ~5 lines.

## LOW-SO-02 — `#/live-feed` is a "Page not found" but the sidebar item is "Live Feed"

The sidebar item is named "Live Feed" so a discoverable URL
fragment would be `#/live-feed`. The actual route is `#/live`.
Anyone bookmarking the URL by guessing from the sidebar label
hits "Page not found".

**Fix**: register `#/live-feed` as an alias of `#/live` so both
work. Same for any other "compact name on the URL, long name on
the sidebar" pages — quick check would surface
`top-attackers` (sidebar) vs `#/top-attackers` (route) — that
pair is fine because the route uses the long form.

## LOW-SO-03 — Top Attackers identifier links are underlined but do nothing

In the Top Attackers table, the IP column shows e.g.
`104.21.14.6` rendered as a link (underlined). Clicking it does
nothing — only the explicit "Pivot" button drives navigation.
Underline-as-affordance + no-op breaks operator intuition.

**Fix**: either make the underlined IP click pivot the same way
the Pivot button does (preferred — saves a click), or drop the
underline.

## LOW-SO-04 — Bot classification mix is empty even when bot-UA traffic flowed

I sent 40 legit requests with mixed UAs including
`Googlebot/2.1`, `bingbot/2.0`, `curl/7.79.1`, `python-requests`,
and Firefox. After the run, the Investigation page's "Bot
classification mix" card reports `no bot signal yet`. The
Overview's bot mix also showed `"unknown": 100%` from the API.

Possible causes (need a developer-side look):
- The bot classifier only runs on detection-positive requests
  (so my recon paths got classified but my legit /api/list
  requests didn't).
- The classifier needs a specific UA database that isn't loaded
  in this dev boot.
- The classifier is wired but the dashboard doesn't read its
  output.

**Fix**: investigate which of the three is true. The empty-state
copy should say something more informative than "no bot signal
yet" if the feature requires extra config.

