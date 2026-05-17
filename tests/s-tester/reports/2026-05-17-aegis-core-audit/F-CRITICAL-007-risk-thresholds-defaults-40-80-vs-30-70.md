---
id: 2026-05-17-risk-thresholds-defaults-wrong
date: 2026-05-17T00:00Z
severity: CRITICAL
area: config schema · defaults
component: crates/aegis-core/src/config.rs (RiskThresholds default_challenge_at, default_block_at, impl Default)
interop_contract: official rules §5.5 — score < 30 = Allow, 30-70 = Challenge, > 70 = Block
status: open
test_mode: source-review (spot-verified)
---

# F-CRITICAL-007 · `RiskThresholds::default = {challenge_at: 40, block_at: 80}` — spec mandates 30/70 — schema source of F-CRITICAL-006 (security audit)

## Summary

Official rules §5.5:

> *Decision threshold configurable: score < 30 = Allow, 30-70 = Challenge, > 70 = Block*

Spec values: **challenge_at = 30, block_at = 70**.

**Spot-verified** at [config.rs:1990-2008](aegis-gate/crates/aegis-core/src/config.rs#L1990-L2008):

```rust
fn default_challenge_at() -> u32 { 40 }
fn default_block_at() -> u32 { 80 }

impl Default for RiskThresholds {
    fn default() -> Self {
        Self { challenge_at: 40, block_at: 80, max: 100 }
    }
}
```

40/80, not 30/70.

This is the **schema source** of F-CRITICAL-006 from the security
audit (which observed the disagreement at runtime between two parallel
threshold sources). The defaults in this file flow through to:

- `RiskTracker::level()` consumer in aegis-security
- Every fresh deployment that doesn't explicitly override
- The dev profile + every production profile that omits the field

A score of 35:
- Spec says: Challenge (in 30-70 range)
- Today: Allow (below 40 threshold)

A score of 75:
- Spec says: Block (>70)
- Today: Challenge (in 40-80 range)

Every Round-1 / Round-2 risk-gate probe that tests boundary scores
sees the wrong behavior.

Compounding: the test `risk_config_defaults` at config.rs:2873-2879
asserts the wrong values (40/80). Fixing the defaults requires
flipping that test.

## Suggested fix

```diff
-fn default_challenge_at() -> u32 { 40 }
-fn default_block_at() -> u32 { 80 }
+fn default_challenge_at() -> u32 { 30 }
+fn default_block_at() -> u32 { 70 }

 impl Default for RiskThresholds {
     fn default() -> Self {
-        Self { challenge_at: 40, block_at: 80, max: 100 }
+        Self { challenge_at: 30, block_at: 70, max: 100 }
     }
 }
```

Update `risk_config_defaults` test:

```diff
 #[test]
 fn risk_config_defaults() {
     let t = RiskThresholds::default();
-    assert_eq!(t.challenge_at, 40);
-    assert_eq!(t.block_at, 80);
+    assert_eq!(t.challenge_at, 30);
+    assert_eq!(t.block_at, 70);
     assert_eq!(t.max, 100);
 }
```

Cross-fix: per F-CRITICAL-006 (security audit), there's a parallel
hardcoded path in `aegis-security/src/risk/mod.rs:78-84`
(`RiskEngine::classify`) that hardcodes 30/70 (matching the spec, not
the broken default). Delete that hardcoded path OR refactor it to
read `RiskThresholds`. Either way, having two threshold sources
disagreeing is the bug.

## Verification

```sh
# After fix:
make run-dev
curl -sk http://127.0.0.1:9443/api/risk/config | jq
# Expect: { "challenge_at": 30, "block_at": 70, "max": 100 }

# Send moderate-risk payload (e.g. one SQLi heuristic match → score ~35):
curl -ski "http://127.0.0.1:8080/?q='+OR+1=1"
# Expect: 429 Challenge (per 30/70 thresholds)
# Today: 200 Allow (under 40 threshold)
```

## Severity rationale

CRITICAL. Out-of-the-box defaults contradict the spec on a clearly-
documented numeric value. Single 2-LoC fix (plus test update) fixes
the cross-crate runtime disagreement (F-CRITICAL-006 in security audit).
Highest cost/benefit ratio in this crate.
