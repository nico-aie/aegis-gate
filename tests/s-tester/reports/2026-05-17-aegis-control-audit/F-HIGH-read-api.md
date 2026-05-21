---
id: 2026-05-17-high-read-api-bundle
date: 2026-05-17T00:00Z
severity: HIGH
area: dashboard · read REST API · live feed
component: crates/aegis-control/src/api/{audit,stats,attacks,incidents}.rs · crates/aegis-control/src/dashboard/sse.rs · crates/aegis-control/src/admin_auth (sessions endpoint)
interop_contract: §5.6 Realtime Dashboard · Round-1 audit search ≤30s
status: open
test_mode: source-review
---

# F-HIGH-read-api bundle — 8 issues in read REST + SSE + dashboard data

---

## RA-01 · Audit ring cap 10k → search for events older than ~2 min fails

**Component:** [api/audit.rs:33](../../../../crates/aegis-control/src/api/audit.rs#L33)

Ring buffer cap is 10,000 entries. At 100 RPS, ring fills every
~100 s — older events are dropped. The on-disk audit file (`jsonl.rs`)
has them, but the search endpoint scans the ring, not the file.

Operator searching for "an event from 10 minutes ago" gets nothing
even though the audit chain has it.

**Fix:** add a file-backed fallback. If the in-ring search returns
no hits AND `ts_from` (after F-CRITICAL-004 lands) is outside ring
window, tail the on-disk file. Index by request_id / IP / rule_id
in a sidecar SQLite for sub-second lookups.

---

## RA-02 · SSE event frames emit no `id:` line → Last-Event-ID reconnect broken

**Component:** [dashboard/sse.rs:4-7](../../../../crates/aegis-control/src/dashboard/sse.rs#L4-L7) · [admin_sse.rs:182](../../../../crates/aegis-proxy/src/admin_sse.rs#L182)

SSE protocol supports `Last-Event-ID` reconnect: client retries with
header `Last-Event-ID: <last_seq>`, server replays from that point.
Aegis emits `data:` lines only, no `id:`. EventSource can't populate
Last-Event-ID, so every reconnect loses the events between
disconnect and resubscribe.

**Fix:** emit `id: <seq>\n` before each `data:`; honour Last-Event-ID
on subscribe by replaying from `audit_ring.since(last_event_id)`
before joining the live stream.

---

## RA-03 · `attacks::top` keyed by IP only → CGNAT collapse

**Component:** [api/attacks.rs:331-360, 540-552](../../../../crates/aegis-control/src/api/attacks.rs#L331)

`attacker_identifier()` falls back to `fp:<ja4>` only for private
IPs. For public IPs, the key is IP-only. Two devices behind one
public IP (CGNAT, corporate NAT) collapse into one "top attacker"
row.

Same root cause as F-CRITICAL-001 from the security audit
(RiskTracker keyed by IP only).

**Fix:** identifier = `{ip}|{device_id_or_ja4}|{session_id}`. Bucket
the public-IP path the same way the private-IP path is.

---

## RA-04 · `stats::record` cutoff uses event_ts, not now → clock-skewed event wipes timeseries

**Component:** [api/stats.rs:177-193](../../../../crates/aegis-control/src/api/stats.rs#L177-L193)

`record()` computes `cutoff = event_sec - TIMESERIES_RETENTION_SECS`
then prunes buckets older than cutoff. A single audit event with
`ts = now + 2h` (clock-skewed node, attacker who can influence ts)
moves the cutoff 2 h forward → EVERY legitimate bucket evicted →
the timeseries chart goes empty.

**Fix:**

```diff
-let cutoff = event_sec - TIMESERIES_RETENTION_SECS;
+let event_sec = event_sec.min(now_sec);   // clamp to now
+let cutoff = now_sec - TIMESERIES_RETENTION_SECS;
```

---

## RA-05 · `stats::StatsHandler::render` upstream_provider fires outside cache slot

**Component:** [api/stats.rs:316-380](../../../../crates/aegis-control/src/api/stats.rs#L316)

The 2 s upstream-summary cache calls `upstream_provider()` on every
miss, but the cache slot is acquired AFTER the provider runs.
Concurrent dashboard tabs all call the provider in parallel on cold
cache, defeating the cache.

**Fix:** invoke `upstream_provider` once per TTL INSIDE the cache
slot. Standard "double-checked lock" pattern.

---

## RA-06 · `incidents::alert_id` collides on same-second fires

**Component:** [api/incidents.rs:81-83](../../../../crates/aegis-control/src/api/incidents.rs#L81-L83)

`alert_id` is built from `fired_at.timestamp()` (epoch seconds).
Two alerts on the same `(sli, window_hours)` firing within the same
wall-clock second collide → the second's ack write overwrites the
first.

**Fix:** use `fired_at.timestamp_micros()` or append a per-process
monotonic salt.

---

## RA-07 · `/api/admin/sessions` leaks every active session's IP + User-Agent

**Component:** [api/admin.rs:90-97](../../../../crates/aegis-control/src/api/admin.rs#L90-L97) + [api/admin.rs:136-141](../../../../crates/aegis-control/src/api/admin.rs#L136-L141)

`SessionInfo` carries `ip` + `user_agent`. The list endpoint returns
every session including those fields to any caller. With an attacker
who got one session cookie (per F-CRITICAL-002 in proxy audit) →
they learn the admin's IP + UA for further targeting.

**Fix:** mask all-but-current IP/UA when serializing for non-elevated
reads:

```rust
let masked = sessions.iter().map(|s| SessionInfo {
    ip:         if s.id == requester.id { s.ip.clone() }         else { "***".into() },
    user_agent: if s.id == requester.id { s.user_agent.clone() } else { "***".into() },
    ..s.clone()
}).collect();
```

Or RBAC-gate the endpoint (only "audit-admin" role sees full data).

---

## RA-08 · `api/audit.rs::route_stats` + `attacks::record` mutex contention on hot path

**Component:** [api/audit.rs:283-347](../../../../crates/aegis-control/src/api/audit.rs#L283-L347) · [api/attacks.rs:202-247](../../../../crates/aegis-control/src/api/attacks.rs#L202-L247)

Both functions walk/append under `Mutex<...>` on every audit event.
The per-call HashMap rebuild in `route_stats` is O(ring) per HTTP
request. Sustained dashboard polling at 1 Hz × 10k ring = 10k ops/s
under the same mutex the audit producer holds.

Under 5000 RPS proxy load, the audit producer blocks on the renderer's
lock → live-feed latency budget (§5.6 ≤5 s) violated.

**Fix:** move aggregation to the audit-bus subscriber; HTTP path
just `clone()` a precomputed snapshot (single-writer + lock-free
readers). Or switch to `DashMap` / per-detector atomic counters.

---

## Severity rationale

HIGH. Each impacts §5.6 latency budget or Round-1 audit-search
mandate. None alone is CRITICAL (the dashboard mostly works at low
load), but together they make Round-1 / Performance grading shaky.
