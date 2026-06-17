---
id: 2026-06-17-F-V26-003
severity: MEDIUM
area: "interop · §5.1 / §6 risk_score range"
component: crates/aegis-proxy/src/admin_dispatch.rs:1322 · crates/aegis-core/src/risk/mod.rs:134 · config.rs (risk.max)
contract: v2.6 §5.1 (X-WAF-Risk-Score integer 0–100) + §6 (risk_score 0–100)
status: open
test_mode: source-review
---

# F-V26-003 — `X-WAF-Risk-Score` (and audit `risk_score`) not clamped to 100 when `risk.max > 100`

## Contract
- §5.1: `X-WAF-Risk-Score` — *"integer 0–100 … Plain integer, no whitespace."*
- §6: audit `risk_score` — *"integer 0–100."*

## What the code does
At the single stamp site:

```rust
// crates/aegis-proxy/src/admin_dispatch.rs:1322
let effective_risk_score = decision_tag.risk_score.unwrap_or(risk_score);
// ... stamped to header (headers.rs:279, no clamp) AND audit (1355), no clamp
```

`effective_risk_score` has two sources:
- **per-request detector sum** — already `.min(100)` (`data_plane.rs:948`,
  `:2049`). Safe.
- **cumulative tracker score** — clamped to the operator-configurable
  `risk.max`, not to 100:
  ```rust
  // crates/aegis-security/src/risk/mod.rs:134
  let new_val = (current as i64 + delta as i64).clamp(0, max as i64) as u32;
  ```
  `max` comes from `RiskThresholds::max` in config (default 100, but any
  value accepted).

So with default config the value never exceeds 100 and the WAF is compliant.
With an operator config such as `risk.max: 200` (some teams set "headroom"),
a high-risk source can stamp `X-WAF-Risk-Score: 145` and write the same to
the audit log — both out of the 0–100 contract range.

(`aegis-core/src/audit.rs:264` clamps a *different* audit struct's score to
100, but the **contract** `MinimalAuditEntry` at `admin_dispatch.rs:1355`
is not clamped.)

## Impact
- Config-dependent. Default config = compliant. A non-default `risk.max > 100`
  makes a strict `^(100|[1-9]?[0-9])$` grader fail every elevated response,
  and the audit `risk_score` violates §6.
- MEDIUM because it's latent (only triggers on a specific operator config),
  but the blast radius is "every high-risk response" once triggered.

## Fix (1 LoC, fixes header + audit together)
Clamp at the stamp site so both outputs are bounded regardless of config:

```rust
let effective_risk_score = decision_tag.risk_score.unwrap_or(risk_score).min(100);
```

Optionally also reject/clamp `risk.max > 100` at config load so the internal
model and the contract agree, and document that the public score is capped
at 100.

## Verify
- Unit: stamp a `DecisionTag::block("x").with_risk_score(145)` and assert the
  header == `100` and audit entry `risk_score == 100`.
- Live: set `risk.max: 200`, drive a source past 100, assert
  `X-WAF-Risk-Score <= 100` and audit `risk_score <= 100`.
