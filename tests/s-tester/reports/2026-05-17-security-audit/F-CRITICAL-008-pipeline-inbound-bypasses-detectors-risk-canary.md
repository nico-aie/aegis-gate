---
id: 2026-05-17-pipeline-inbound-bypasses-security
date: 2026-05-17T00:00Z
severity: CRITICAL
area: security · pipeline orchestrator (SDK trait)
component: crates/aegis-security/src/pipeline.rs (SecurityPipeline::inbound)
interop_contract: Architecture & Code Quality rubric (15/120) — public SDK surface must not bypass security
status: open
test_mode: source-review
---

# F-CRITICAL-008 · `SecurityPipeline::inbound` (the SDK trait) runs ONLY the rule engine — no detectors, no risk tracker, no canary check, no tier policy

## Summary

`Pipeline::inbound` is the public trait surface that
`aegis-security` exposes as a `SecurityPipeline` for external
consumers (the dashboard SDK, the test harness, potentially future
GitOps drivers). It is documented in the trait module as the "pipe
all requests through this" entry point.

In practice the data plane bypasses it and inlines its own pipeline
(detectors + rate-limit + risk + canary) in `aegis-proxy/src/data_plane.rs`.
The trait body only invokes the rule engine — no detector chain, no
risk score consultation, no canary check, no tier-aware fail-close.

This is dangerous for two reasons:

1. **Any external consumer** (SDK user, future GitOps driver, test
   harness) who wires `Pipeline::inbound` gets a half-WAF: rules
   only, no behavioral / risk / detector defenses.
2. **The trait body lies about its semantics**. The trait name
   "SecurityPipeline" implies full pipeline; the body provides
   one stage of it.

## Observed code path

[pipeline.rs:139-158](../../../../crates/aegis-security/src/pipeline.rs#L139-L158) — comment block:

> *"NOTE: This is NOT the production hot path. The proxy data
> plane bypasses this trait and inlines detectors + risk."*

[pipeline.rs:159-167](../../../../crates/aegis-security/src/pipeline.rs#L159-L167) — body:

```rust
fn inbound(&self, req: &Request) -> Verdict {
    // rule engine only.
    self.rules.eval(req)
}
```

No call to:
- `self.detectors.run_all_filtered(req)` (detector chain)
- `self.risk_tracker.level(ip)` (risk score)
- canary path check
- tier-aware failure mode

[pipeline.rs:11-62](../../../../crates/aegis-security/src/pipeline.rs#L11-L62)
defines `classify_tier()` (CRITICAL / HIGH / MEDIUM / CATCH-ALL
classification), but `Pipeline::inbound` never calls it. The fail-close
vs fail-open branching the tier function returns is therefore unused
on the trait surface.

## Impact

- **Architecture rubric (15/120)** — "Plugin-ready architecture" is
  enumerated; the public plugin surface bypasses security.
- **Any third-party integration** (e.g. an external `GitOpsDriver`
  that wires the trait) gets dangerous semantics: thinks it's running
  the WAF pipeline, actually only running rule eval.
- **Test reliability** — tests that exercise the trait surface
  produce different verdicts than tests against the data plane.
  Coverage gaps hide.
- **Refactor risk** — a future engineer who consolidates the
  data-plane inline path into the trait body would silently flip
  behavior unless they carefully audit the bypass.

## Suggested fix

Two viable paths:

### Option A — Wire the full pipeline in the trait body

Move the inline pipeline from `aegis-proxy/src/data_plane.rs` into
`SecurityPipeline::inbound` so the trait IS the canonical pipeline:

```rust
fn inbound(&self, req: &Request, ctx: &RequestCtx) -> Verdict {
    // 1. Canary path check (F-CRITICAL-007 fix).
    if self.canary.paths.iter().any(|p| path_matches(p, req.uri().path())) {
        self.risk_tracker.set_score_at(ctx.key(), u32::MAX);
        self.state.auto_block(ctx.peer.ip(), self.canary.ttl);
        return Verdict::Block { rule_id: "canary.honeypot_hit" };
    }

    // 2. Blacklist / strike-block / rate-limit.
    if let Some(v) = self.state.is_blocked(ctx.peer.ip()) { return Verdict::Block(...); }
    if let Some(v) = self.rate_limit.consume(ctx) { return v; }

    // 3. Detectors.
    let signals = self.detectors.run_all_filtered(req, ctx);

    // 4. Risk tracker (per F-CRITICAL-001 fixed key shape).
    let level = self.risk_tracker.record_signals(&ctx.key(), &signals);

    // 5. Rule engine (last stage, can override).
    let rule_verdict = self.rules.eval(req, ctx);

    // 6. Tier-aware fail-close on internal errors.
    if let Verdict::InternalError(_) = rule_verdict {
        return match ctx.tier {
            Tier::Critical => Verdict::Block { rule_id: "fail_close.critical" },
            _              => Verdict::Allow,
        };
    }

    combine(level, rule_verdict, signals)
}
```

Then `data_plane.rs` calls `pipeline.inbound(req, ctx)` once instead
of inlining ~500 LoC of pipeline logic.

### Option B — Delete the trait

If the SDK surface isn't actually used externally, delete it. The
data plane's inline pipeline is the single source of truth. Document
the bypass and remove the misleading trait.

**Recommendation: Option A** — the trait IS valuable for testability
and future SDK use. The bypass shape is a code-rot anti-pattern that
should be removed.

## Verification

After Option A:

```sh
# A unit test invoking SecurityPipeline::inbound on an SQLi payload
# should now return Verdict::Block, NOT just rule-engine output.
cargo test --package aegis-security pipeline_inbound_sqli_blocks
```

Add coverage to `tests/contract/` that compares trait-surface verdicts
against data-plane behaviour on a corpus of canonical attacks.

## Severity rationale

CRITICAL on the basis that the public SDK surface lies about its
semantics. The fix is a non-trivial refactor but pays back: data
plane shrinks, tests can target the trait, future SDK consumers get
correct behaviour. Architecture rubric depends on this being right.
