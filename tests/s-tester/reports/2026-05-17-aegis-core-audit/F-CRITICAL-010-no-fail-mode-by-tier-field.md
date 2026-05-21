---
id: 2026-05-17-no-fail-mode-by-tier-field
date: 2026-05-17T00:00Z
severity: CRITICAL
area: config schema · failure mode
component: crates/aegis-core/src/config.rs (WafConfig) · crates/aegis-core/src/tier.rs (Tier::default_failure_mode)
interop_contract: official rules §5.8 — fail-close per tier
status: open
test_mode: source-review
---

# F-CRITICAL-010 · No `WafConfig.fail_mode_by_tier` field — §5.8 fail-close-per-tier mandate unrepresentable

## Summary

Official rules §5.8:

> *Fail-close mode cho CRITICAL tier (routes nhạy cảm): từ chối tất cả traffic nếu WAF internal error. Fail-open mode cho MEDIUM & CATCH-ALL tier: allow-through nếu WAF overloaded. Config fail-close hay fail-open phải configurable per route tier trong rule file — không hardcode.*

The spec is explicit: **per-tier configurability** required, NOT
hardcoded.

Today:
- `RouteConfig.failure_mode` ([config.rs:725-729](../../../../crates/aegis-core/src/config.rs#L725-L729))
  is **per-route only** — operators set it route by route, not by
  tier class.
- The only tier→failure-mode mapping is hardcoded in
  `tier.rs:26-31` (`Tier::default_failure_mode`). Operators cannot
  override.

Operators reading §5.8 expect to write:

```yaml
fail_mode_by_tier:
  critical: fail_close
  high:     fail_open
  medium:   fail_open
  catch_all: fail_open
```

There's no schema field for this. The audit-mutated dashboard config
also has nowhere to surface it.

## Suggested fix

Add a top-level field on `WafConfig`:

```diff
 pub struct WafConfig {
     ...
+    /// §5.8 — per-tier failure mode. Falls back to
+    /// `Tier::default_failure_mode()` for tiers not listed.
+    #[serde(default)]
+    pub fail_mode_by_tier: HashMap<crate::tier::Tier, FailureModeConfig>,
     ...
 }

 impl Default for WafConfig {
     fn default() -> Self {
         Self {
             ...
+            fail_mode_by_tier: HashMap::from([
+                (Tier::Critical, FailureModeConfig::FailClose),
+                (Tier::High,     FailureModeConfig::FailOpen),
+                (Tier::Medium,   FailureModeConfig::FailOpen),
+                (Tier::Low,      FailureModeConfig::FailOpen),  // CatchAll
+            ]),
         }
     }
 }
```

Consumer side (per F-CRITICAL-005 in security audit):

```rust
fn resolve_failure_mode(cfg: &WafConfig, route: &Route) -> FailureModeConfig {
    // Per-route override wins if set.
    if let Some(fm) = route.failure_mode {
        return fm;
    }
    // Per-tier override.
    if let Some(fm) = cfg.fail_mode_by_tier.get(&route.tier) {
        return *fm;
    }
    // Tier default (hardcoded fallback in tier.rs).
    route.tier.default_failure_mode()
}
```

Wire this resolver into:
- DDoS check (F-CRITICAL-008 + F-CRITICAL-005 security audit)
- Pipeline internal-error handling
- Rate-limit backend failure
- Detector chain panic recovery

Anywhere a `WafError` arises mid-request, consult
`resolve_failure_mode(tier)` → fail-close for CRITICAL, fail-open
elsewhere.

## Verification

```sh
# CRITICAL route during simulated WAF error → fail-close (deny):
# (induce error by killing redis backend while load runs)
curl -ski http://127.0.0.1:8080/login -i
# Expect: 503 Service Unavailable, X-WAF-Action: circuit_breaker (after F-CRITICAL-006)
# Today: 200 with no enforcement (fall-through)

# MEDIUM route during same error → fail-open (allow):
curl -ski http://127.0.0.1:8080/static/x.css -i
# Expect: 200 + upstream content
```

## Severity rationale

CRITICAL. §5.8 mandate; operators cannot configure per-tier
failure mode. Schema fix (~30 LoC) unlocks the runtime fix
(F-CRITICAL-005 in security audit).
