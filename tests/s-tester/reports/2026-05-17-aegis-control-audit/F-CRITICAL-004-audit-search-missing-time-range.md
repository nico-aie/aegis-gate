---
id: 2026-05-17-audit-search-no-time-range
date: 2026-05-17T00:00Z
severity: CRITICAL
area: dashboard · audit search
component: crates/aegis-control/src/api/audit.rs (AuditFilter::matches)
interop_contract: Round-1 "Audit Log Viewer" mandate (search by time + IP + Rule-ID + Request-ID)
status: open
test_mode: source-review
---

# F-CRITICAL-004 · Audit search has no time-range filter — Round-1 names 4 dimensions, only 3 implemented

## Summary

Round-1 official rules:

> *Audit Log Viewer: Có khả năng tìm kiếm và filter log (theo
> **thời gian**, IP, Rule ID, Request ID).*

Four dimensions specified. `AuditFilter` in `api/audit.rs` only
carries three:

[api/audit.rs:96-104](../../../../crates/aegis-control/src/api/audit.rs#L96-L104):

```rust
pub struct AuditFilter {
    pub ip: Option<String>,
    pub request_id: Option<String>,
    pub rule_id: Option<String>,
    // NO ts_from / ts_to.
}
```

And the matcher [api/audit.rs:109-146](../../../../crates/aegis-control/src/api/audit.rs#L109-L146):

```rust
pub fn matches(&self, ev: &AuditEvent) -> bool {
    if let Some(ip) = &self.ip { ... }
    if let Some(req) = &self.request_id { ... }
    if let Some(rule) = &self.rule_id { ... }
    true
    // No timestamp check.
}
```

The endpoint dispatcher in `admin_dispatch.rs:185-202` parses
`ip` / `request_id` / `rule_id` query params but no `since` / `until`.

## Impact

- **Round-1 Audit Log Viewer Pass/Fail** — fails the time-dimension
  test outright. BTC graders sending `?since=...&until=...` get the
  param silently ignored and receive every event in the cursor
  window.
- **Usability mandate** — Round-1 says "tìm 1 event ≤ 30 giây".
  Without time-range narrowing, an operator looking for "what happened
  at 14:32 yesterday" has to scroll the entire ring.
- **Compounding** — F-HIGH-read-api flags ring cap 10k; without time
  filtering, the operator gets the LAST 10k events globally, not the
  10k around the target time.

## Suggested fix

Two-line struct + matcher update + one query-param parse:

```diff
 pub struct AuditFilter {
     pub ip: Option<String>,
     pub request_id: Option<String>,
     pub rule_id: Option<String>,
+    pub ts_from: Option<chrono::DateTime<chrono::Utc>>,
+    pub ts_to:   Option<chrono::DateTime<chrono::Utc>>,
 }

 pub fn matches(&self, ev: &AuditEvent) -> bool {
+    if let Some(from) = self.ts_from {
+        if ev.ts < from { return false; }
+    }
+    if let Some(to) = self.ts_to {
+        if ev.ts > to { return false; }
+    }
     if let Some(ip) = &self.ip { ... }
     ...
 }
```

Query-param parsing (admin_dispatch.rs):

```rust
let ts_from = q.get("since")
    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
    .map(|t| t.with_timezone(&chrono::Utc));
let ts_to = q.get("until")
    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
    .map(|t| t.with_timezone(&chrono::Utc));
```

Per the spec, accept RFC-3339 timestamps. Reject malformed values
with 400 (don't silently ignore).

Cross-fix: F-HIGH-read-api M-? on ring cap — if you keep the 10k
cap, document that time-range search is limited to the ring window;
add an audit-file-on-disk fallback for older events.

## Verification

```sh
HOST="http://127.0.0.1:9443"

# Time-range search:
curl -sk "$HOST/api/audit/since?since=2026-05-17T00:00:00Z&until=2026-05-17T01:00:00Z" \
    | jq '.events | length'
# Expect: only events in that hour.

# Combined:
curl -sk "$HOST/api/audit/since?since=2026-05-17T00:00:00Z&ip=10.0.0.5&rule_id=sqli" \
    | jq '.events[] | {ts, ip, rule_id}'
```

Add a regression case asserting:
- `?since` filters correctly
- `?until` filters correctly
- Combined `?since=X&until=Y&ip=Z&rule_id=W` works as AND-of-all
- Malformed `?since=not-a-date` returns 400, not silent-ignore

## Severity rationale

CRITICAL. Round-1 explicitly names 4 dimensions, this implements 3.
~30 LoC fix.
