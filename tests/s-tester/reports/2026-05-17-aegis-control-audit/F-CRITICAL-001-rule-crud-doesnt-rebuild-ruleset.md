---
id: 2026-05-17-rule-crud-doesnt-rebuild-ruleset
date: 2026-05-17T00:00Z
severity: CRITICAL
area: dashboard · mutation API · rule engine
component: crates/aegis-proxy/src/admin_mutate.rs (handle_rules_post/put/delete/toggle) · crates/aegis-control/src/api/rules.rs · crates/aegis-control/src/dashboard_services.rs
interop_contract: Round-1 "Tính hiệu lực" + Hot-reload ≤10s · §5.4 rule system
status: open
test_mode: source-review (spot-verified)
---

# F-CRITICAL-001 · Rule CRUD only mutates `services.rules` (RuleStore); live `Arc<RuleSet>` is NEVER rebuilt → operator clicks "Save rule" but real traffic behavior unchanged

## Summary

The dashboard's rule CRUD handlers (`POST /api/rules`, `PUT /api/rules/{id}`, `DELETE /api/rules/{id}`, `PUT /api/rules/{id}/toggle`)
all mutate `services.rules` — a simple in-memory `RuleStore`
(`api/rules.rs:175,188,215,253`). The data-plane security pipeline,
however, reads from `Arc<RuleSet>` constructed once at boot in
`aegis-bin/src/main.rs:232`. **The two stores share no plumbing.**

Operator workflow:
1. Operator opens dashboard, navigates to Rules page.
2. Clicks "Save rule" with a new rule.
3. Server responds 200 with audit-chain entry committed.
4. Dashboard shows "Rule saved successfully".
5. Real traffic behavior is **unchanged**: the new rule never fires;
   a disabled rule still fires; a deleted rule still fires.

This is a textbook **"Tính hiệu lực"** violation per Round-1 spec:

> *Tất cả feature/policy được trình bày trong UI/UX hoặc mô tả trong
> tài liệu submit phải có tác động thực tế tới behavior của
> WAF-PROXY. UI đẹp, workflow đầy đủ ... sẽ không được tính là hợp
> lệ nếu feature đó chỉ là demo/mock hoặc không điều khiển được
> WAF-PROXY thật.*

Round-1 is Pass/Fail. This bug alone is enough to fail.

## Observed code path

**Spot-verified** at [admin_mutate.rs:1600,1680,1746,1803](aegis-gate/crates/aegis-proxy/src/admin_mutate.rs#L1600):

```rust
// handle_rules_post:
let rules_store = services.rules.clone();   // RuleStore, not Arc<RuleSet>
...
rules_store.upsert(rule).expect("rule store poisoned");
```

`services.rules` is `Arc<RuleStore>` — the dashboard's persistence layer.
The data plane never reads it.

The data-plane pipeline reads `Arc<RuleSet>` (constructed in
`aegis-bin/src/main.rs:232`):

```rust
let rule_set = Arc::new(RuleSet::load(&cfg.rules)?);
let security_pipeline = AegisSecurityPipeline::new(rule_set, ...);
```

There is NO place in the codebase that re-builds `RuleSet` from
`RuleStore::list()` after a mutation lands.

## Impact

- **Round-1 dashboard "Tính hiệu lực" Pass/Fail** — fails outright.
- **§5.4 rule system** — "Hỗ trợ thêm/sửa/xóa rule KHÔNG cần rebuild binary — hot-reload bắt buộc". The dashboard UI looks like it
  supports this; the underlying behavior doesn't.
- **§5.5 risk score** — rule deltas wired through `RuleStore` don't
  reach `RiskTracker` because no rule actually evaluates.
- **Operator confusion** — debugging "why doesn't my new rule work"
  is opaque because the audit chain shows the mutation landed and the
  dashboard shows the rule as active.

## Suggested fix

Wrap the active rule set in `ArcSwap<RuleSet>` so the data plane
sees the latest. Rebuild after every successful mutation:

```diff
 // dashboard_services.rs — change services.rules from RuleStore alone
 // to (RuleStore, ArcSwap<RuleSet>):
 pub struct DashboardServices {
     pub rules: Arc<RuleStore>,
+    pub active_ruleset: Arc<ArcSwap<RuleSet>>,
     ...
 }

 // After every successful mutation in handle_rules_{post,put,delete,toggle}:
+let rebuilt = RuleSet::build_from(&services.rules.list())?;
+services.active_ruleset.store(Arc::new(rebuilt));
```

The data-plane security pipeline reads via `active_ruleset.load()`
on every request (already lock-free with ArcSwap).

Boot-time wiring in `aegis-bin/src/main.rs:232`:

```diff
-let rule_set = Arc::new(RuleSet::load(&cfg.rules)?);
-let security_pipeline = AegisSecurityPipeline::new(rule_set, ...);
+let active_ruleset = Arc::new(ArcSwap::new(Arc::new(RuleSet::load(&cfg.rules)?)));
+let security_pipeline = AegisSecurityPipeline::new(active_ruleset.clone(), ...);
+services.active_ruleset = active_ruleset;
```

Add an end-to-end integration test in `tests/api/`:

```sh
# Send a clean SQLi probe — should pass (no rule).
curl -sk "$HOST/?q=' OR 1=1--" -o /dev/null -w "%{http_code}\n"
# 200 (no rule)

# Create a rule that blocks SQLi.
curl -sk -X POST "$HOST/api/rules" -d '{"id":"block-sqli", "body":"...", "enabled":true}'

# Send same probe — must now be blocked.
curl -sk "$HOST/?q=' OR 1=1--" -o /dev/null -w "%{http_code}\n"
# Expect: 403. Today: still 200.
```

## Severity rationale

CRITICAL. Single bug that fails Round-1 Pass/Fail on dashboard
"Tính hiệu lực". The fix is mechanical (~150 LoC) but touches
multiple files. The complete absence of this wiring suggests the
backend was scaffolded as a persistence layer first with the
"actually apply to data plane" step deferred.
