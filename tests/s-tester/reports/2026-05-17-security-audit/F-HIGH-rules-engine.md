---
id: 2026-05-17-high-rules-engine-bundle
date: 2026-05-17T00:00Z
severity: HIGH
area: security · rule engine
component: crates/aegis-security/src/rules/{eval.rs, parser.rs, linter.rs, ast.rs}
interop_contract: official rules §5.4 (Rule system)
status: open
test_mode: source-review
---

# F-HIGH-rules-engine bundle — 6 correctness + performance issues in the rule engine

---

## R-01 · Regex recompiled on every request

**Component:** [rules/eval.rs:354-356](../../../../crates/aegis-security/src/rules/eval.rs#L354-L356)

`matches_op` calls `regex::Regex::new(pattern)` per match per
request. For a 1000-rule policy with N regex match-ops, that's
thousands of regex compilations per request — orders of magnitude
slower than steady-state.

**Fix:** compile once at rule-load (in `RuleSet::load`) and cache
`Arc<Regex>` on the AST node:

```diff
 pub enum MatchOp {
-    Regex(String),
+    Regex { src: String, compiled: OnceCell<Arc<Regex>> },
 }
```

Lazy-init on first eval; cache for subsequent calls.

---

## R-02 · Rule list re-sorted by priority on every request

**Component:** [rules/eval.rs:130-131](../../../../crates/aegis-security/src/rules/eval.rs#L130-L131)

```rust
let mut sorted = self.rules.clone();
sorted.sort_by(...);
```

`O(N log N)` per request. With 1000 rules: ~10000 compare ops per
request on the hot path. Plus an allocation for the cloned Vec.

**Fix:** sort once in `RuleSet::load` and store the sorted Vec.
Eval iterates the pre-sorted vec.

---

## R-03 · Linter HARD-REJECTS rules using `RuleAction::RateLimit` despite it being wired

**Component:** [rules/linter.rs:85-95](../../../../crates/aegis-security/src/rules/linter.rs#L85-L95)

The linter contains:

```rust
if let RuleAction::RateLimit { .. } = &rule.action {
    return Err(UnwiredAction { rule: rule.id.clone(), action: "rate_limit" });
}
```

The comment claims rate-limit "is not wired" — but
[eval.rs:181-228](../../../../crates/aegis-security/src/rules/eval.rs#L181-L228) clearly
wires it via `EvalContext::rate_limit`, with tests passing. Stale
lint rejects every rule file that uses the spec-required
`rate-limit` action. Operators who write a policy per §5.4 can't
validate it.

**Fix:** remove the `UnwiredAction` branch for `RateLimit`. The
action IS wired.

---

## R-04 · Cookie value truncated at `=` (use `splitn(2, '=')`)

**Component:** [rules/eval.rs:298-302](../../../../crates/aegis-security/src/rules/eval.rs#L298-L302)

```rust
let (name, value) = pair.split_once('=').unwrap_or(("", ""));
```

For session tokens with `=` in the value (base64 padding always ends
in `=`), the value gets truncated at the first `=`. E.g. cookie
`s=abc==` → value parsed as `abc` (loses the trailing `==`).

Rules matching cookie values silently match a truncated string.

**Fix:** use `splitn(2, '=')`:

```rust
let mut it = pair.splitn(2, '=');
let (name, value) = (it.next().unwrap_or(""), it.next().unwrap_or(""));
```

---

## R-05 · `BodyMatches` runs on a `peek(8192)` window

**Component:** [rules/eval.rs:294-296](../../../../crates/aegis-security/src/rules/eval.rs#L294-L296)

Rule body match peeks first 8 KiB. Attacker can hide payload bytes
after the 8 KiB cutoff. Acceptable for performance, but combined
with R-01 (regex compiled per request) the cost per evaluation is
already high — and the 8 KiB cap is hardcoded, not configurable.

**Fix:** make `body_peek_bytes` a `RuleSet` config field. For
critical-tier rules, allow operator to extend the peek window.
Document the trade-off.

---

## R-06 · YAML parser has no document-size bound

**Component:** [rules/parser.rs:7](../../../../crates/aegis-security/src/rules/parser.rs#L7)

`serde_yaml::from_str(yaml)` is called with no size or depth bound.
A malicious uploaded YAML file (e.g. via the hot-reload endpoint —
which per F-CRITICAL-002 from the proxy audit is anonymous-callable)
can consume unbounded memory at parse.

**Fix:** the hot-reload endpoint should bound input size before
parsing (e.g. 1 MiB cap). Optionally: add depth-bounded parsing
(serde_yaml doesn't expose this; consider switching to
`saphyr` / `yaml-rust2`).

---

## Severity rationale

HIGH. Each affects either correctness (R-03, R-04), performance
under load (R-01, R-02), or robustness (R-05, R-06). None is
exploitable for a complete bypass on its own, but R-01 + R-02
together degrade WAF throughput enough to risk the 5 ms p99 / 5000
RPS SLA the rules name (§5.1).
