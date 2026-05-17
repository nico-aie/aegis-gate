# Rule engine — non-Block actions in the data-plane evaluator

> **Status:** Drafted 2026-05-17. Tracks the deferred portion of
> [F-CRITICAL-001](../issue-fix/2026-05-17-control-core-security-audits/README.md)
> — the dashboard-rule-CRUD → live-engine bridge.
>
> Commit `c760d8f` landed the bridge + the **`Block { status }`**
> terminal action in the data plane. The other 5 §3 contract actions
> (`Allow`, `Challenge`, `RateLimited`, `Timeout`, `CircuitBreaker`)
> plus the non-terminal `RaiseRisk` + `LogOnly` paths fall through
> to the existing downstream paths. That choice is intentional for
> v1 — `Block` is the only action the Round-1 dashboard demo and
> the auditor's reproduction script ("Save rule that blocks SQLi →
> request returns 403") exercise. The rest are scoring depth.

## Where the gap is

In `crates/aegis-proxy/src/data_plane.rs::forward_allow_to_upstream`,
right after the mTLS-required check and before CONNECT dispatch:

```rust
if let Some(rules) = ctx.active_ruleset.get() {
    let snapshot = rules.snapshot();
    if !snapshot.is_empty() {
        let decision = aegis_security::rules::evaluate(&snapshot, &view, &route_ctx);
        if let aegis_core::decision::Action::Block { status } = decision.action {
            // ... return 403 + DecisionTag::block(rule_id)
        }
        // ALL other variants fall through silently.
    }
}
```

The `if let` discards every variant except `Block`. The engine
correctly computed the right action (eval.rs returns `RateLimited`,
`Challenge`, etc. per the rule body) — the data plane just
doesn't enforce it.

## Why each variant is deferred (not "missing")

| Variant | Status | Why deferred |
|---|---|---|
| `Allow` | Implicit pass-through | An `allow` rule that fires means "don't block, don't challenge". With only `Block` honored, the existing downstream path already lets the request through — same observable outcome. The miss: an `allow` rule that should **bypass** the detector-driven block at higher risk (operator allowlist for a known-noisy endpoint) doesn't actually skip detection. Fix: lift the rule-eval gate ABOVE the detector chain so `Allow` short-circuits. |
| `Challenge { level }` | Stubbed | The challenge subsystem in `crates/aegis-security/src/challenge/` already issues PoW / CAPTCHA bodies and the data plane has the challenge path for detector-driven challenges. The rule evaluator's `Challenge` just needs to route into the same emit path with `rule_id = decision.rule_id` so the §5 stamper produces `X-WAF-Action: challenge`. ~30 LoC. |
| `RateLimited { retry_after_s }` | Stubbed | Needs to route into the same `IpRateLimiter::trigger`-equivalent shape the existing rate-limit gate uses, OR a simpler "rule-attributed" 429 response with `Retry-After`. The §3 contract accepts either. ~40 LoC if we go with the simple 429 response. |
| `Timeout { deadline_ms }` | Not wired anywhere yet | Per F-CRITICAL-006 the `Action::Timeout` variant exists in `decision.rs` but no proxy path emits it. A rule-driven timeout would be the first emitter — needs a design call on whether "rule says timeout" maps to "drop the request now" or "set a tighter deadline on the upstream forward". Recommend: not wire until the broader Timeout story (deadline policies, upstream timeouts) lands as a feature. |
| `CircuitBreaker { retry_after_s }` | Not wired anywhere yet | Same shape as Timeout — the variant exists, no emitter today. A rule-driven `circuit_breaker` is an unusual decision (operators don't usually open a breaker from a per-rule match). Defer until a concrete use case lands. |
| `RaiseRisk(u32)` | Stubbed | The engine's evaluator already accumulates `RaiseRisk` values into `accumulated_risk` before returning, but the data plane discards `decision.risk_score`. Wire: pass `decision.risk_score` into the existing `risk.record_malicious(peer_ip, score)` call so rule-driven risk feeds the cumulative tracker. ~10 LoC. |
| `LogOnly` | Implicit pass-through (correctly) | A `log_only` rule that fires should record the match in the audit log and otherwise let the request continue. Today: the audit emission happens at the downstream allow/block site; rule-attributed log_only doesn't carry a distinct audit shape. Fix: emit a synthetic `AuditEvent` with `class = Detection`, `action = "log_only"`, `rule_id = <id>` at the rule-eval site. Ties into the audit-schema rebuild (Phase C.2) since the audit event currently lacks `method`/`path`/`mode`. ~50 LoC pending C.2. |

## Suggested phasing

**Phase 1 — Allow + RaiseRisk** (small, high-leverage)
- Lift rule eval ABOVE the detector chain in `handle_data_request_inner`,
  using a synthetic minimal `RouteCtx { route_id: String::new(), ... }`.
  `Scope::Route` rules won't match (route_id `""` ≠ any operator route),
  `Scope::Global` rules will fire — which is the 95% case.
- Honor `Allow` terminally (skip detectors, forward upstream).
- Pass `decision.risk_score` into `risk.record_malicious(peer_ip, score)`.
- ~80 LoC, one commit.

**Phase 2 — Challenge + RateLimited** (medium)
- Route `Challenge` into the existing challenge emit path.
- Route `RateLimited` into a 429 + `Retry-After` response with
  `rule_id` attribution.
- ~80 LoC, one commit.

**Phase 3 — LogOnly + AuditEvent schema** (gated on Phase C.2)
- Synthesise an `AuditEvent` per matched `log_only` rule.
- Needs `method`/`path`/`mode` fields landed (Phase C.2 in the
  audit fix plan).
- ~50 LoC after C.2 unblocks.

**Phase 4 — Timeout + CircuitBreaker** (deferred indefinitely)
- Only land if a real operator use case surfaces. The Action
  variants exist for §3 wire-shape parity; rule-driven emission
  is an aspirational composition we don't need to support
  preemptively.

## Acceptance for each phase

A new unit test per phase in `crates/aegis-proxy/tests/` that
constructs a `RuleSet` with one rule, calls a handler shim, and
asserts the resulting `(Response, DecisionTag)` pair. The bridge
unit tests in `aegis-control/src/api/rules.rs` already pin the
CRUD → RuleSet flow; these new tests pin RuleSet → data-plane
behavior per action.

## What we explicitly do NOT plan to do

- **Wire RuleAction enum into `aegis_core::decision::Action`
  variants 1-for-1.** `RuleAction` is the engine's
  operator-language; `Action` is the wire decision. Today
  `aegis_security::rules::evaluate` already does the translation.
  We do not want a 6-variant duplication on the data-plane side.

## References

- `crates/aegis-proxy/src/data_plane.rs` (rule-eval gate)
- `crates/aegis-security/src/rules/eval.rs::evaluate_with_ctx` (the
  translation from `RuleAction` → `Decision`)
- `crates/aegis-security/src/rules/ast.rs::RuleAction` (the 6
  variants the engine emits)
- `crates/aegis-core/src/decision.rs::Action` (the 6 wire actions
  per v2.3 §3)
- `Hackathon_Doc/EN_waf_interop_contract_v2.3.md §3` (decision
  classes — what the wire stamper emits)
- Commit `c760d8f` (Layer A + B that landed Block).
