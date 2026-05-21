---
id: 2026-05-17-audit-action-string-not-enum
date: 2026-05-17T00:00Z
severity: CRITICAL
area: contract schema · audit event · type safety
component: crates/aegis-core/src/audit.rs (AuditEvent.action) · cross-ref decision.rs::Action enum
interop_contract: v2.3 §6 (audit `action` enum), §5.1 (X-WAF-Action exact lowercase)
status: open
test_mode: source-review (spot-verified)
---

# F-CRITICAL-004 · `audit.rs::AuditEvent.action: String` (not enum) — typos accepted, no cross-crate single source of truth

## Summary

§6 + §5.1 contracts specify `action` as one of exactly 6 values:
`allow | block | challenge | rate_limit | timeout | circuit_breaker`
(lowercase, underscore-separated).

`AuditEvent.action` is declared as `String`:

**Spot-verified** at [audit.rs:11](../../../../crates/aegis-core/src/audit.rs#L11):

```rust
pub struct AuditEvent {
    ...
    pub action: String,
    ...
}
```

Consequences:

1. **Typos compile**. `event.action = "Block".into()` (capitalized),
   `event.action = "rate-limit".into()` (hyphen instead of underscore),
   `event.action = "circuit_breaker_open".into()` (extra suffix) all
   pass the type checker.

2. **No single source of truth**. The contract-correct enum exists —
   but in `aegis-control/src/interop/headers.rs:41` as
   `headers::Action`. Two parallel enums in two crates = drift
   inevitable. If a future variant is added in aegis-control but not
   in aegis-core (or vice versa), the audit log and the X-WAF-Action
   header disagree.

3. **No compile-time enforcement** that the 6 §3 variants are
   exhaustively handled. A new caller can use any string.

4. **Test fixture at audit.rs:60** already uses raw `"block".into()`
   — proving the pattern.

## Suggested fix

Move (or define) the canonical `Action` enum in `aegis-core::decision`
and use it on `AuditEvent`:

```diff
 pub struct AuditEvent {
     ...
-    pub action: String,
+    pub action: crate::decision::Action,
     ...
 }
```

The `decision::Action` enum needs F-CRITICAL-006 fixed first (add
`Timeout` + `CircuitBreaker` variants).

Add a `Display` impl that emits the exact §5.1 lowercase:

```rust
impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s = match self {
            Action::Allow             => "allow",
            Action::Block { .. }      => "block",
            Action::Challenge { .. }  => "challenge",
            Action::RateLimit { .. }  => "rate_limit",
            Action::Timeout { .. }    => "timeout",
            Action::CircuitBreaker { .. } => "circuit_breaker",
        };
        f.write_str(s)
    }
}
```

Derive `Serialize` with `#[serde(tag = "action", rename_all = "snake_case")]`
so the serialized form on the audit wire matches §5.1.

The parallel `aegis-control::interop::headers::Action` enum is then
either removed (in favor of `aegis-core::decision::Action`) or
becomes a `pub use` re-export.

## Verification

After the fix:

```rust
// Compile error on bad action:
let event = AuditEvent {
    action: "Block".into(),    // ← type error: expected Action, found String
    ...
};

// Serialization correct:
let event = AuditEvent { action: Action::Block { status: 403 }, ... };
let json = serde_json::to_string(&event).unwrap();
assert!(json.contains(r#""action":"block""#));
```

Add a contract regression test that the enum's wire format matches
every §5.1 / §6 variant byte-for-byte.

## Severity rationale

CRITICAL. String-typed enum on a contract-mandated field is the
classic source of cross-crate drift; combined with F-CRITICAL-006
(decision.rs missing variants) the result is a contract surface
where the compiler enforces nothing. Part of audit-schema cluster.
