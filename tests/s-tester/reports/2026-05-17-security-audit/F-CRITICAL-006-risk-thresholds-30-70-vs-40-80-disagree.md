---
id: 2026-05-17-risk-thresholds-disagree
date: 2026-05-17T00:00Z
severity: CRITICAL
area: security · risk engine consistency
component: crates/aegis-security/src/risk/mod.rs (RiskEngine::classify) · risk/tracker.rs (RiskTracker::level) · aegis-core/src/config.rs (RiskThresholds default)
interop_contract: official rules §5.5 (thresholds 30 / 70) — and they must be configurable
status: open
test_mode: source-review
---

# F-CRITICAL-006 · Two risk-threshold sources disagree out of the box (30/70 hardcoded vs 40/80 configurable default)

## Summary

Official rules §5.5:

> *Decision threshold configurable: score < 30 = Allow, 30-70 =
> Challenge, > 70 = Block*

Shipped code has TWO parallel risk-threshold sources that disagree:

| Source | Allow | Challenge | Block | Configurable? |
|---|---|---|---|---|
| `RiskEngine::classify` (`risk/mod.rs:78-84`) | <30 | 30-70 | >70 | ❌ Hardcoded |
| `RiskTracker::level` (`tracker.rs:198-213`) + `RiskThresholds` default (`config.rs:1990-1995`) | <40 | 40-80 | ≥80 | ✅ Configurable |

A score of 50:
- Under `RiskEngine::classify` → **Challenge** (30-70 range).
- Under `RiskTracker::level` with default thresholds → **Challenge** (40-80) — coincidentally agreeing here.

A score of 35:
- Under `RiskEngine::classify` → **Challenge** (30-70).
- Under `RiskTracker::level` defaults → **Allow** (< 40).

A score of 75:
- Under `RiskEngine::classify` → **Block** (> 70).
- Under `RiskTracker::level` defaults → **Challenge** (40-80).

The data plane consumes `RiskTracker::level` (the active path), so
the effective thresholds in production are 40/80, not the spec's
30/70. The hardcoded `RiskEngine::classify` is dead code that
DISAGREES with both the spec and the active path — a maintenance
landmine.

Even ignoring `RiskEngine`, the default `40/80` is wrong vs the
spec's `30/70`. An out-of-the-box deployment fails the threshold
contract unless the operator explicitly overrides.

## Observed code path

[risk/mod.rs:78-84](../../../../crates/aegis-security/src/risk/mod.rs#L78-L84):

```rust
pub fn classify(score: u32) -> RiskLevel {
    if score < 30      { RiskLevel::Allow }
    else if score <= 70 { RiskLevel::Challenge }
    else                { RiskLevel::Block }
}
```

Hardcoded; does not read `RiskThresholds` even though it exists in
config.

[aegis-core/src/config.rs:1990-1995](../../../../crates/aegis-core/src/config.rs#L1990-L1995) — `RiskThresholds::default`:

```rust
RiskThresholds {
    challenge_at: 40,
    block_at: 80,
    max: 100,
}
```

[risk/tracker.rs:198-213](../../../../crates/aegis-security/src/risk/tracker.rs#L198-L213) — `RiskTracker::level` reads from
configurable thresholds via `self.thresholds.load()` and respects
them correctly.

## Impact

- **Intelligence rubric (20/120)** — "Risk score accuracy" is a
  scored sub-item. Effective thresholds disagree with the spec
  out of the box.
- **Score-vs-detector calibration** (cf. F-CONTRACT-GAPS C-03) —
  with default `block_at: 80`, no single regex-detector reaches the
  block threshold on its own (highest single score is 60 for AI
  detector or cmdi). Per the rubric expectation "high-confidence
  injection (SQLi/XSS/cmdi) → block", this is wrong.
- **Maintenance bug** — `RiskEngine::classify` is dead code that
  disagrees with the active path. Any future developer who refactors
  through `RiskEngine` will silently change semantics.
- **Hot-reload** — `RiskThresholds` IS hot-swappable via
  `RiskTracker::set_thresholds()`. The `RiskEngine::classify`
  hardcoded path would not honor a runtime override.

## Suggested fix

### Two parts. Both mandatory.

**1. Align defaults with the spec:**

```diff
 impl Default for RiskThresholds {
     fn default() -> Self {
         Self {
-            challenge_at: 40,
-            block_at: 80,
+            challenge_at: 30,
+            block_at: 70,
             max: 100,
         }
     }
 }
```

**2. Delete the hardcoded `RiskEngine::classify`** (or rewrite it
to consult `RiskThresholds`):

```diff
 impl RiskEngine {
-    pub fn classify(score: u32) -> RiskLevel {
-        if score < 30      { RiskLevel::Allow }
-        else if score <= 70 { RiskLevel::Challenge }
-        else                { RiskLevel::Block }
-    }
+    pub fn classify(&self, score: u32) -> RiskLevel {
+        let t = self.thresholds.load();
+        if score < t.challenge_at { RiskLevel::Allow }
+        else if score < t.block_at { RiskLevel::Challenge }
+        else                       { RiskLevel::Block }
+    }
 }
```

Decide whether `RiskEngine` itself is used anywhere; if it's the
"state-backed alternative" that's never wired in (per
F-CRITICAL-008's pipeline bypass), consider deleting the whole
module to remove the disagreement source.

### Re-tune detector scores

After thresholds drop to 30/70, the per-detector deltas in
`detectors/scores.rs` need a single-hit-can-block path for
high-confidence detectors. E.g.:

```rust
pub const SCORE_SQLI_HIGH:  u32 = 80;  // single hit → block
pub const SCORE_CMDI_HIGH:  u32 = 80;
pub const SCORE_XSS_HIGH:   u32 = 80;
pub const SCORE_LOG4SHELL:  u32 = 90;
pub const SCORE_HEURISTIC:  u32 = 35;  // single hit → challenge
```

Per F-CONTRACT-GAPS C-03 — needs a coordinated calibration pass.

## Verification

After fixes:

```sh
HOST="http://127.0.0.1:8080"

# Send a clean SQLi probe — expect block on first hit.
curl -ski "$HOST/?q=1%27%20OR%20%271%27%3D%271" -i | grep -i '^x-waf-'
# x-waf-action: block

# Inspect risk:
curl -sk "$HOST/api/risk" | jq '.[] | {ip, score, level}'
# level should be "block", score >= 70 (in new threshold space).

# Configure custom thresholds via dashboard PUT:
curl -sk -X PUT "$HOST/api/risk/thresholds" \
    -d '{"challenge_at":20,"block_at":50}'

# Repeat the probe — same payload now under tighter thresholds:
# block should still fire (or even earlier).
```

Regression case: assert `RiskTracker::level(...)` and the (rewritten)
`RiskEngine::classify(...)` agree for all scores in 0..=100.

## Severity rationale

CRITICAL on two grounds: (a) default thresholds disagree with the
spec out of the box, costing rubric points before any tuning; (b)
two disagreeing classify paths in the code is a latent semantic bug
waiting to fire on the next refactor. Fix is ~30 LoC.
