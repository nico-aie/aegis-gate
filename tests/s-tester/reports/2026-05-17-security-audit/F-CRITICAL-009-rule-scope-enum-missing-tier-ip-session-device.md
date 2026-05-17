---
id: 2026-05-17-rule-scope-enum-missing-4-of-6
date: 2026-05-17T00:00Z
severity: CRITICAL
area: security · rule engine
component: crates/aegis-security/src/rules/ast.rs (Scope enum) · rules/eval.rs (scope evaluation)
interop_contract: official rules §5.4 — required rule scopes
status: open
test_mode: source-review
---

# F-CRITICAL-009 · Rule `Scope` enum supports only `Global` + `Route(String)` — missing 4 of 6 required scopes per §5.4

## Summary

Official rules §5.4 enumerate the rule scopes that the system MUST
support:

> *Rule scope: global (toàn website), per-tier (CRITICAL/HIGH/MEDIUM/CATCH-ALL),
> per-route-pattern, per-IP, per-user-session, per-device-fingerprint*

| Required scope | Status |
|---|---|
| `global` | ✅ `Scope::Global` |
| `per-tier` (CRITICAL/HIGH/MEDIUM/CATCH-ALL) | ❌ Missing |
| `per-route-pattern` | ⚠️ Partial — only exact `route_id` match, no glob/regex |
| `per-IP` | ❌ Missing |
| `per-user-session` | ❌ Missing |
| `per-device-fingerprint` | ❌ Missing |

Operators today cannot write a rule like:

```yaml
# WANTED — not parseable:
- id: tighten-critical-tier
  scope:
    tier: critical
  condition: { rate_above: 30, window_s: 60 }
  action: rate_limit

- id: known-bad-device
  scope:
    device: abc123def456
  condition: true
  action: block

- id: session-honeypot
  scope:
    session: <attacker-known-session>
  condition: { path_matches: "^/admin" }
  action: block
```

## Observed code path

[rules/ast.rs:20-24](aegis-gate/crates/aegis-security/src/rules/ast.rs#L20-L24):

```rust
pub enum Scope {
    Global,
    Route(String),     // matches route_id exactly; no glob/regex
}
```

[rules/eval.rs:138-145](aegis-gate/crates/aegis-security/src/rules/eval.rs#L138-L145) — evaluation:

```rust
fn matches_scope(rule: &Rule, ctx: &EvalContext) -> bool {
    match &rule.scope {
        Scope::Global => true,
        Scope::Route(id) => ctx.route_id.as_deref() == Some(id.as_str()),
    }
}
```

No code path can evaluate tier / IP / session / device scopes
because they don't exist in the enum.

## Impact

- **§5.4 violation** — 4 of 6 mandated scopes unimplemented.
- **Extensibility rubric (10/120)** — "Rule system: hot-reload,
  per-scope (IP/user/session/device), priority resolution" is
  explicitly enumerated. 4/6 missing → ~33% achievable.
- **Operator workflow** — incident response often involves "block
  this one device" or "rate-limit this one session" overrides
  produced from the dashboard. Without those scopes, the operator
  has only "block this one IP" (via blacklist, separate codepath)
  and "block this one route" (via global rule with `path_matches`).
- **Compounds with F-CRITICAL-001 / F-CRITICAL-002**: without
  device/session in the risk + rate-limit key shape AND without
  device/session-scoped rules, there's literally no way to target
  device or session in any policy mechanism.

## Suggested fix

Extend the enum + the evaluator. Minimal additions:

```diff
 pub enum Scope {
     Global,
     Route(String),
+    Tier(aegis_core::tier::Tier),
+    Ip(String),                       // CIDR or exact
+    Session(String),                  // exact session id
+    Device(String),                   // exact device-fp hash
+    // Optional: composite combinator
+    All(Vec<Scope>),
+    Any(Vec<Scope>),
 }
```

Evaluator updates:

```diff
 fn matches_scope(rule: &Rule, ctx: &EvalContext) -> bool {
     match &rule.scope {
         Scope::Global => true,
         Scope::Route(id) => ctx.route_id.as_deref() == Some(id.as_str()),
+        Scope::Tier(t) => ctx.tier == Some(*t),
+        Scope::Ip(cidr) => parse_cidr(cidr).map_or(false, |net| net.contains(&ctx.peer.ip())),
+        Scope::Session(s) => ctx.session_id.as_deref() == Some(s.as_str()),
+        Scope::Device(d) => ctx.device_fp.as_deref() == Some(d.as_str()),
+        Scope::All(scopes) => scopes.iter().all(|s| matches_scope(&Rule { scope: s.clone(), ..rule.clone() }, ctx)),
+        Scope::Any(scopes) => scopes.iter().any(|s| matches_scope(&Rule { scope: s.clone(), ..rule.clone() }, ctx)),
     }
 }
```

YAML shape (serde tagged enum or external tagging):

```yaml
- id: block-known-bot-device
  scope:
    device: 9f2c3a...
  action: block

- id: per-tier-rate
  scope:
    tier: critical
  condition: { rate_above: 30, window_s: 60 }
  action: rate_limit

- id: composite
  scope:
    all:
      - tier: high
      - ip: 198.51.100.0/24
  action: challenge
```

Plumb `ctx.tier` / `ctx.session_id` / `ctx.device_fp` into
`EvalContext` from the data plane (tier already exists; session +
device need to be propagated per F-CRITICAL-001's plumbing fix).

### Linter follow-up (cf. F-HIGH-rules-engine)

The current linter HARD-REJECTS rules with `RuleAction::RateLimit`
("not wired" — but it IS wired). Once you add the new scope variants,
also re-enable RateLimit in the linter so per-tier rate-limit rules
actually validate.

## Verification

After the fix:

```sh
# Write a per-tier rule:
cat > rules/tier-test.yaml <<'EOF'
- id: tier-critical-rate
  scope: { tier: critical }
  condition: true
  action: rate_limit
  priority: 100
EOF

# Hot-reload:
curl -sk -X PUT "$HOST/api/rules/reload"

# Confirm the rule matches CRITICAL-tier paths but not MEDIUM:
curl -ski "$HOST/login"        # CRITICAL — should rate-limit
curl -ski "$HOST/static/x.css" # MEDIUM — should pass
```

Add unit tests in `rules/eval.rs` for each new scope variant.

## Severity rationale

CRITICAL. Four-of-six required scopes missing AND the work blocks
operator-facing incident response. Net-new ~80 LoC plus plumbing.
The Extensibility rubric checks this exactly; an absent feature
fails the rubric outright.
