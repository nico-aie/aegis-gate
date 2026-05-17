---
id: 2026-05-17-audit-risk-score-optional
date: 2026-05-17T00:00Z
severity: CRITICAL
area: contract schema · audit event
component: crates/aegis-core/src/audit.rs (AuditEvent.risk_score)
interop_contract: v2.3 §6 (risk_score integer 0-100, always present)
status: open
test_mode: source-review (spot-verified)
---

# F-CRITICAL-005 · `audit.rs::AuditEvent.risk_score: Option<u32>` — optional + unclamped vs §6 mandatory 0..=100

## Summary

§6 specifies `risk_score` as "integer 0–100" — implied always present
(no "optional" qualifier).

**Spot-verified** at [audit.rs:16](aegis-gate/crates/aegis-core/src/audit.rs#L16):

```rust
pub risk_score: Option<u32>,
```

Two issues:

1. **Optional**: When `None`, serde emits the field as `null` (or
   omits if `skip_serializing_if`). §6 parsers expecting an integer
   reject `null` or treat the event as malformed.

2. **u32 not 0..=100**: `u32` admits 4 billion. No clamp at
   construction. A populator computing risk via `signals.sum()`
   (signals can sum arbitrarily) can push `risk_score` to 200, 500,
   etc. — violates the spec range.

Cross-ref: F-HIGH-headers-contract H-03 from control audit reported
the same issue at the HEADER stamping site (`headers.rs:222-237`).
That bug is a symptom; this struct field is the root cause.

## Suggested fix

```diff
 pub struct AuditEvent {
     ...
-    pub risk_score: Option<u32>,
+    /// §6 contract — integer 0..=100, always present.
+    pub risk_score: u8,
     ...
 }
```

`u8` (not `u32`) restricts to 0..=255, then add a newtype clamp
helper:

```rust
pub struct RiskScore(u8);

impl RiskScore {
    pub fn new(raw: u32) -> Self {
        Self(raw.min(100) as u8)
    }
}

impl From<RiskScore> for u8 {
    fn from(rs: RiskScore) -> u8 { rs.0 }
}
```

Use `RiskScore` at construction so the clamp is enforced once at the
boundary. Populators that compute `signals.sum()` clamp via
`RiskScore::new(...)`.

Removes the F-HIGH-headers-contract H-03 issue at the header layer
too — the header stamper just renders `score.to_string()` and
trusts the type.

## Verification

```rust
#[test]
fn risk_score_clamped_at_construction() {
    let rs = RiskScore::new(500);
    assert_eq!(u8::from(rs), 100);
}

#[test]
fn audit_event_risk_score_serializes_as_integer() {
    let event = AuditEvent { risk_score: 42, ... };
    let json = serde_json::to_value(&event).unwrap();
    assert_eq!(json["risk_score"], 42);
    assert!(json["risk_score"].is_u64());
}
```

## Severity rationale

CRITICAL. Optional-when-mandatory + unclamped on a contract field.
Part of audit-schema cluster — land with F-CRITICAL-001..004.
~10 LoC.
