---
id: 2026-05-17-rl-scope-missing-4-variants
date: 2026-05-17T00:00Z
severity: CRITICAL
area: config schema · rate-limit scope
component: crates/aegis-core/src/config.rs (RlScope enum)
interop_contract: official rules §5.4 — rule scope (global / per-tier / per-route-pattern / per-IP / per-user-session / per-device-fingerprint)
status: open
test_mode: source-review
---

# F-CRITICAL-009 · `RlScope` enum has only `Global \| Route` — missing 4 of 6 §5.4 mandated scopes

## Summary

Official rules §5.4 mandates 6 rule scopes:

> *Rule scope: global (toàn website), per-tier (CRITICAL/HIGH/MEDIUM/CATCH-ALL), per-route-pattern, per-IP, per-user-session, per-device-fingerprint*

**Spot-verified** at [config.rs:1818-1838](../../../../crates/aegis-core/src/config.rs#L1818-L1838):

```rust
#[serde(rename_all = "snake_case", tag = "scope")]
pub enum RlScope {
    Global,
    Route(String),
    // Tier — MISSING
    // RoutePattern — MISSING
    // Ip — MISSING
    // UserSession — MISSING
    // DeviceFingerprint — MISSING
}
```

`RlKey` (line 1828) covers the *key dimension* (`Ip | Session |
Header | JwtSub`), but `RlScope` does not let operators bind a
bucket to a Tier or to a device fingerprint — independent dimensions
that the rules text names explicitly.

This is the **schema source** of F-CRITICAL-009 from the security
audit (rule engine missing 4 of 6 scopes).

The Round-1 dashboard sells the operator a UI for these scopes that
the schema can't represent. Even after F-CRITICAL-001 (rule CRUD
doesn't rebuild RuleSet) from the control audit is fixed, an
operator-written rule using `scope: tier: critical` would fail
serde parsing.

## Suggested fix

Extend the enum to all 6 variants:

```diff
 #[serde(rename_all = "snake_case", tag = "scope")]
 pub enum RlScope {
     Global,
     Route(String),
+    /// §5.4 — bind to one of the 4 §4 tiers (Critical/High/Medium/CatchAll).
+    Tier(crate::tier::Tier),
+    /// §5.4 — glob/regex route pattern (e.g. `/api/users/*`).
+    RoutePattern(String),
+    /// §5.4 — single IP or CIDR.
+    Ip(String),
+    /// §5.4 — bind by authenticated user session ID.
+    UserSession,
+    /// §5.4 — bind by device fingerprint hash (JA4 + UA + H2 settings).
+    DeviceFingerprint,
+    /// §5.4 — composite: ALL of the listed scopes must match.
+    All(Vec<RlScope>),
+    /// §5.4 — composite: ANY of the listed scopes match.
+    Any(Vec<RlScope>),
 }
```

Add `RlKey::DeviceFp` variant in the same file (for the key-dimension
side):

```diff
 #[serde(rename_all = "snake_case", tag = "key")]
 pub enum RlKey {
     Ip,
     Session,
     Header(String),
     JwtSub,
+    DeviceFp,
+    UserId,
 }
```

Evaluator side per F-CRITICAL-009 (security audit) updates to handle
the new variants.

## Verification

YAML rule shape:

```yaml
rate_limit:
  buckets:
    - id: per-tier-critical
      scope: { tier: critical }
      key: ip
      algo: { sliding: { window_s: 60, limit: 30 } }

    - id: per-device-spike
      scope: device_fingerprint
      key: device_fp
      algo: { token_bucket: { rate: 10, burst: 30 } }

    - id: per-session-burst
      scope: user_session
      key: session
      algo: { sliding: { window_s: 10, limit: 50 } }
```

Each parses + applies + the WAF rate-limits per the bucket key.

## Severity rationale

CRITICAL. §5.4 mandate; 4 of 6 scope variants unrepresentable.
Schema fix unlocks the Round-1 rule scope dropdown on the dashboard.
~30 LoC for the enum + Tier import.
