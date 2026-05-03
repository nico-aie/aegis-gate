---
id: 2026-05-03-medium-live-feed-no-backfill-on-mount
date: 2026-05-03T17:43Z
severity: MEDIUM
area: dashboard
component: live-feed
status: fixed
test_mode: full-qc
---

# Live Feed shows "1 of 1 events" on a busy WAF — no backfill on mount

## Summary
After driving 79 blocks visible in `/api/audit/since` and the
Audit Trail page, navigating to **Live Feed** displays:

> Live Feed · 1 of 1 events · streaming via SSE — CONNECTED
> 21:33:08 · 0.0.0.0 · GET / · LOW · CONNECTED · dashboard SSE connected

The single event is the SSE-connect handshake, IP `0.0.0.0`. None
of the 79 actual block events appear. The buffer reads
`buffer 1/80` so the feed is starting from the SSE connect, not
backfilling from the audit chain.

For an analyst who lands on Live Feed mid-incident, that page
gives the wrong impression — "nothing happening" instead of
"79 blocks in the last few minutes." The skill's `audit/since`
reconnect-replay is exactly the mechanism that should run on
page mount; today it doesn't.

(Note: the footer says `SSE (demo)`. If "demo" means "no real
events, only synthetic", that's a documented limitation —
file as MEDIUM rather than HIGH on that read. The fix is the
same either way.)

## Repro
1. From a signed-in session, drive a few blocks:
   ```bash
   for i in 1 2 3 4 5; do
     curl -s -o /dev/null -H "X-Forwarded-For: 8.8.8.8" \
       "http://127.0.0.1:8080/?q=<script>alert(1)</script>"
   done
   ```
2. Confirm via Audit Trail or `/api/audit/since?limit=20` that
   the events are recorded.
3. Click **Live Feed** in the sidebar.
4. Observe `1 of 1 events`, only the SSE connect.

## Expected
On Live Feed mount:
- Pull recent N events from `/api/audit/since` to backfill the
  table (or render `audit/since` first, then layer the SSE
  stream on top).
- Clearly distinguish synthetic SSE events from real
  request events (the SSE-connect heartbeat shouldn't count
  toward the visible event count or against the buffer).

## Actual
Page starts empty; only synthetic SSE events appear; the
operator has to navigate to Audit Trail to see what just
happened.

## Suggested fix
In the Live Feed page component (probably in
`crates/aegis-control/assets/dashboard/src/pages.jsx`), on mount:
1. Fetch `/api/audit/since?limit=80` (or whatever the buffer
   size is).
2. Filter to `action ∈ {block, allow, challenge}` (i.e. real
   request decisions, drop config / SSE-internal events).
3. Render those into the table, then start the SSE stream and
   append.

Existing `/api/audit/since` already supports the cursor pattern
the skill mentions ("`?cursor=<last>`"), so the SSE stream can
backfill *from* the cursor of the last `since` row to keep
ordering tight.

## Severity rationale
MEDIUM. It's a real loss of context for an analyst, but Audit
Trail covers the workflow at one extra click. If `SSE (demo)`
indicates the streaming layer is intentionally synthetic in dev,
this drops to LOW (and the fix becomes "ship a real SSE source
for `make run-dev` so demos look real").
