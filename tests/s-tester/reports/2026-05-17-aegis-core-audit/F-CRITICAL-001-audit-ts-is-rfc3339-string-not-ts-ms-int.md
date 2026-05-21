---
id: 2026-05-17-audit-ts-wrong-type-and-name
date: 2026-05-17T00:00Z
severity: CRITICAL
area: contract schema · audit event
component: crates/aegis-core/src/audit.rs (AuditEvent.ts field)
interop_contract: v2.3 §6 (audit log required field `ts_ms` — integer Unix-epoch ms)
status: open
test_mode: source-review (spot-verified)
---

# F-CRITICAL-001 · `audit.rs::AuditEvent.ts: DateTime<Utc>` serializes as RFC3339 STRING — §6 requires integer field `ts_ms`

## Summary

§6 of the v2.3 contract requires:

> *`ts_ms` — Unix epoch milliseconds (integer)*

`AuditEvent` declares the field with both the wrong NAME and the
wrong TYPE.

**Spot-verified** at [audit.rs:6](../../../../crates/aegis-core/src/audit.rs#L6):

```rust
pub struct AuditEvent {
    pub schema_version: u32,
    pub ts: chrono::DateTime<chrono::Utc>,    // ← wrong name (ts vs ts_ms), wrong type
    ...
}
```

`serde::Serialize` for `chrono::DateTime<Utc>` emits an RFC-3339
string (`"2026-05-17T00:00:00.000Z"`), NOT an integer. §6 parsers
that expect a numeric `ts_ms` field reject every event.

Compensation happens at sink level (`audit/sinks/ocsf.rs:56` calls
`ev.ts.timestamp_millis()`), but the canonical JSON that the chain
hashes (`audit/chain.rs:25`) still serializes the original string.
So:

- `./waf_audit.log` written by the interop sink: depends on which
  serializer fires — verifier mismatch.
- Hash chain integrity: hashes over RFC3339 string, not integer.

This single bug guarantees every v2.3 §6 audit event is non-compliant.

## Suggested fix

```diff
 pub struct AuditEvent {
     pub schema_version: u32,
-    pub ts: chrono::DateTime<chrono::Utc>,
+    /// Unix epoch milliseconds — §6 contract requires `ts_ms` integer.
+    pub ts_ms: i64,
     pub request_id: String,
     ...
 }

 impl AuditEvent {
     pub fn timestamp(&self) -> chrono::DateTime<chrono::Utc> {
         chrono::DateTime::<chrono::Utc>::from_timestamp_millis(self.ts_ms)
             .unwrap_or_else(chrono::Utc::now)
     }
 }
```

Every populator in the workspace (search for `AuditEvent { ts:`)
updates to set `ts_ms: chrono::Utc::now().timestamp_millis()`. Every
sink that read `ev.ts` either reads `ev.ts_ms` directly OR converts
via the helper above.

If preserving a chrono-friendly accessor matters for SIEM sinks that
already expect a `DateTime`, the helper above is enough — `ts_ms` is
the wire format, `timestamp()` is the in-memory convenience.

## Verification

After the fix:

```sh
make run-dev
curl -ski http://127.0.0.1:8080/ -o /dev/null
tail -1 ./waf_audit.log | jq .ts_ms
# Expect: an integer like 1715904000123
# Today: would be the field "ts" with a string like "2026-05-17T00:00:00Z" — or missing entirely
```

Add a contract regression test:

```rust
#[test]
fn audit_event_ts_ms_is_integer() {
    let event = AuditEvent { ts_ms: 1234, ... };
    let json: serde_json::Value = serde_json::to_value(&event).unwrap();
    assert!(json["ts_ms"].is_i64(), "ts_ms must serialize as integer");
    assert!(json.get("ts").is_none(), "old field name must not appear");
}
```

## Severity rationale

CRITICAL. Single schema bug invalidates §6 compliance on every
event the WAF produces. ~10 LoC to fix + small migration across
populator/sink call sites. Part of the audit-rs schema cluster
(F-CRITICAL-001 through 005) — land them together.
