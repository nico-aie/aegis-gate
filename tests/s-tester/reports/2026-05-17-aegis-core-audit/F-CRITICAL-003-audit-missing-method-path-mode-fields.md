---
id: 2026-05-17-audit-missing-method-path-mode
date: 2026-05-17T00:00Z
severity: CRITICAL
area: contract schema · audit event
component: crates/aegis-core/src/audit.rs (AuditEvent struct)
interop_contract: v2.3 §6 (audit log required fields method, path, mode)
status: open
test_mode: source-review (spot-verified)
---

# F-CRITICAL-003 · `audit.rs::AuditEvent` MISSING three §6-required fields: `method`, `path`, `mode`

## Summary

§6 contract enumerates 8 required audit fields. `AuditEvent` carries
5 of them (with renaming bugs filed separately as F-CRITICAL-001/002),
and is **completely missing**:

- `method` — uppercase HTTP method
- `path` — request path INCLUDING query string
- `mode` — `enforce` or `log_only` (which mode the policy was in)

**Spot-verified** at [audit.rs:4-18](aegis-gate/crates/aegis-core/src/audit.rs#L4-L18):

```rust
pub struct AuditEvent {
    pub schema_version: u32,
    pub ts: chrono::DateTime<chrono::Utc>,    // F-CRITICAL-001
    pub request_id: String,
    pub class: AuditClass,
    pub tenant_id: Option<String>,
    pub tier: Option<Tier>,
    pub action: String,                       // F-CRITICAL-004
    pub reason: String,
    pub client_ip: String,                    // F-CRITICAL-002
    pub route_id: Option<String>,
    pub rule_id: Option<String>,
    pub risk_score: Option<u32>,              // F-CRITICAL-005
    pub fields: serde_json::Value,
    // method:  MISSING
    // path:    MISSING
    // mode:    MISSING
}
```

The `fields: serde_json::Value` escape hatch (line 17) is not a
substitute — §6 validators look for TOP-LEVEL keys. Even if a
populator stuffs `method`/`path`/`mode` into `fields`, a strict
parser sees them at the wrong nesting level and reports the
top-level keys as missing.

This single bug means the SOURCE-OF-TRUTH audit struct cannot
produce a §6-compliant record AT ALL. Every sink in the workspace
that thought it was emitting §6 lines is emitting partial data —
and there is nowhere for the populator to put the missing fields.

Cross-reference: F-CRITICAL-004 from proxy audit reports the `path`
field strips the query string in `accept.rs`. That bug is moot
without this fix — currently there's no `path` field on the struct
to populate at all.

## Suggested fix

```diff
 pub struct AuditEvent {
     pub schema_version: u32,
+    /// §6 contract — Unix epoch milliseconds.
-    pub ts: chrono::DateTime<chrono::Utc>,
+    pub ts_ms: i64,
     pub request_id: String,
     pub class: AuditClass,
     pub tenant_id: Option<String>,
     pub tier: Option<Tier>,
-    pub action: String,
+    pub action: crate::decision::Action,
     pub reason: String,
+    /// §6 contract — TCP peer (NOT XFF).
-    pub client_ip: String,
+    pub ip: std::net::IpAddr,
+    /// §6 contract — uppercase HTTP method.
+    pub method: http::Method,
+    /// §6 contract — request path INCLUDING query string.
+    pub path: String,
+    /// §6 contract — policy mode at the time of the decision.
+    pub mode: crate::interop::Mode,    // enforce | log_only
     pub route_id: Option<String>,
     pub rule_id: Option<String>,
-    pub risk_score: Option<u32>,
+    /// §6 contract — integer 0..=100, always present.
+    pub risk_score: u8,
     pub fields: serde_json::Value,
+    /// §5.6 dashboard extras.
+    pub device_fp: Option<String>,
 }
```

(This diff bundles the fix for the entire `audit.rs` schema cluster
F-CRITICAL-001..005 + F-HIGH-contract-types device_fp gap, since
they all share the same Edit operation.)

`http::Method` already in workspace deps. `crate::interop::Mode`
needs to either move from `aegis-control::interop::headers` into
`aegis-core::decision` (per F-HIGH-contract-types) OR be redefined
here.

Migration: every populator in `crates/aegis-proxy/` and
`crates/aegis-control/` that constructs `AuditEvent` updates to the
new shape. Compiler enforces — about 10-15 call sites per the
previous audits' findings.

## Verification

After the fix:

```sh
make run-dev
curl -ski "http://127.0.0.1:8080/foo?bar=baz" -X POST -o /dev/null
tail -1 ./waf_audit.log | jq '{method, path, mode}'
# Expect:
# { "method": "POST", "path": "/foo?bar=baz", "mode": "enforce" }
```

Contract regression test:

```rust
#[test]
fn audit_event_has_all_8_section_6_fields() {
    let event = sample_audit_event();
    let json: serde_json::Value = serde_json::to_value(&event).unwrap();
    for required in ["request_id", "ts_ms", "ip", "method", "path", "action", "risk_score", "mode"] {
        assert!(json.get(required).is_some(), "§6 field {required} missing");
    }
}
```

## Severity rationale

CRITICAL. Three of eight §6 fields entirely absent from the
source-of-truth schema. §6 is a HARD contract on every event the
WAF emits. Largest of the audit-schema cluster — fixes ~3 separate
spec-mandates with one struct change.
