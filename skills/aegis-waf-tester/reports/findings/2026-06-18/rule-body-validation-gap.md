---
id: 2026-06-18-rule-body-validation-gap
date: 2026-06-18T07:30Z
severity: MEDIUM
area: admin-api
component: rules (POST /api/rules)
status: open
test_mode: full-qc
---

# Malformed rule body accepted with 201 — `validate_rule_body` never parses rule syntax

## Summary
`POST /api/rules` accepts a syntactically-broken rule `body` and returns
**201 "config activated; propagates to all nodes"**, then stores it as an
active rule (`active_rule_count` increments, the id appears in `GET /api/rules`).
The body validator only checks *non-empty* and *under size cap* — it never
parses the rule DSL. An operator who pastes a broken rule gets a false success
signal; the rule can never match, and a future cold restart that re-parses the
inline rule from the config file is a latent boot-failure risk. This deviates
from contract scenario **C7 (Corrupted Configuration → "Rejected safely;
existing config remains active")**.

## Repro
From the admin plane (`:9443`), authenticated, with a valid CSRF token:

```js
// body is deliberately broken YAML (same string the repo uses as its
// `invalid_rules_yaml()` test fixture)
await fetch("/api/rules", {
  method:"POST",
  headers:{"content-type":"application/json","x-csrf-token": CSRF},
  credentials:"include",
  body: JSON.stringify({ id:"qa-rule-bad", body:"not: [valid: yaml: for: rules", enabled:true })
});
// -> HTTP 201  {"id":"qa-rule-bad","note":"config activated; propagates ...","ok":true}

// ~3 s later:
await fetch("/api/rules", {credentials:"include"}).then(r=>r.json());
// -> { rules:[{ id:"qa-rule-bad", ... }] }   active_rule_count: 1
```

## Expected
Per contract C7 and parity with the other validators on this same endpoint
(reserved-id collision correctly returns **400**, empty body returns an error),
a body that is not valid rule DSL should be **rejected with 400/422** and a
machine-readable error, leaving the existing ruleset untouched.

## Actual
- `validate_rule_body()` (`crates/aegis-control/src/api/rules.rs`) only emits
  errors for: empty body, body over `MAX_BODY_BYTES`. It adds TODO-marker
  warnings. It performs **no YAML/structure parse** of the rule.
- Result: `"not: [valid: yaml: for: rules"` → **201**, activated, listed,
  counted. `healthz/ready.config_loaded` stayed `true` (no crash), but the
  rule is inert.

## Suggested fix
In `validate_rule_body` (rules.rs), after the empty/size checks, attempt the
real parse the engine uses — `serde_yaml::from_str::<…rules::ast::Rule>()`
(or the existing `RuleSet` loader) on the assembled rule — and fold any parse
error into `ValidateResponse.errors` with line/col. The `handle_rules_post`
path already calls `validate_rule_body` and already returns 400 for the
reserved-id case, so gating on a non-empty `errors` list closes this with no
new wiring. Add a unit test using the existing `invalid_rules_yaml()` fixture
asserting a 400.

## Severity rationale
MEDIUM, not HIGH: running traffic and the existing config are unaffected, and
the WAF does not crash. MEDIUM, not LOW: it is a genuine validation gap on a
mutation endpoint that returns a **misleading 201 "config activated"** for
content that can never work, undermining the Extensibility/rule-authoring
surface, and it leaves a malformed inline rule in the persisted config doc that
a cold restart's YAML loader may reject — a latent availability risk. Directly
contradicts contract C7's "rejected safely."
