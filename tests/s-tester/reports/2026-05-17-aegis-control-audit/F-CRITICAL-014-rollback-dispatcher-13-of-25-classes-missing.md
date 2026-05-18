---
id: 2026-05-17-rollback-dispatcher-13-classes-missing
date: 2026-05-17T00:00Z
severity: CRITICAL
area: dashboard · rollback
component: crates/aegis-control/src/api/rollback.rs (ROLLBACKABLE_ACTIONS allowlist)
interop_contract: §5.9 bonus (config versioning + rollback) · Round-1 hot-reload + audit-mutated
status: open
test_mode: source-review
---

# F-CRITICAL-014 · Rollback dispatcher silently fails on ~13 of ~25 mutation classes — §5.9 bonus partially uncollected

## Summary

`ROLLBACKABLE_ACTIONS` at [api/rollback.rs:57-79](aegis-gate/crates/aegis-control/src/api/rollback.rs#L57-L79)
allowlists the audit-action labels that the rollback endpoint can
undo. The actual set of mutation labels the WAF emits is ~25. The
allowlist covers ~12. The missing 13+:

- `alert_receivers_set`
- `route_upsert`, `route_delete`
- `pool_upsert`, `pool_delete`
- `upstreams_config_set`
- `mtls_ca_bundle_set`
- `client_auth_mode_set`
- `ddos_set`
- `strikes_set`
- `rate_limit_set`
- (and a few more depending on feature build)

Operator workflow:
1. Operator updates an upstream pool ("`pool_upsert`" audit emit).
2. Realizes mistake, clicks "Rollback to #N" in the dashboard
   config-versions page.
3. Server responds 422 `NotRollbackable`.

The dashboard's history view promises a rollback path that the API
silently refuses for the bulk of mutation classes. Operators
discover this only when something goes wrong.

Compounding: `lookup_event` at [api/rollback.rs:799-812](aegis-gate/crates/aegis-control/src/api/rollback.rs#L799-L812)
pulls the entire 10k audit ring and linear-scans for each rollback
call. Acceptable today but Performance-rubric-relevant at scale.

## Observed code path

[api/rollback.rs:57-79](aegis-gate/crates/aegis-control/src/api/rollback.rs#L57-L79):

```rust
pub const ROLLBACKABLE_ACTIONS: &[&str] = &[
    "rule_upsert", "rule_delete", "rule_toggle",
    "detector_mask_set",
    "risk_thresholds_set",
    "loadmode_set",
    "compliance_modes_set",
    "tier_overrides_set",
    "blacklist_add", "blacklist_remove",
    "whitelist_add", "whitelist_remove",
    // pool_upsert, route_upsert, alert_receivers_set, mtls_ca_bundle_set,
    // ddos_set, rate_limit_set, strikes_set, upstreams_config_set, ...
    // ALL MISSING.
];
```

[api/rollback.rs:177-218](aegis-gate/crates/aegis-control/src/api/rollback.rs#L177-L218) — dispatcher:

```rust
fn lookup_action(event: &AuditEvent) -> Result<RollbackKind> {
    if !ROLLBACKABLE_ACTIONS.contains(&event.action.as_str()) {
        return Err(RollbackError::NotRollbackable);
    }
    ...
}
```

## Impact

- **§5.9 bonus "config versioning + rollback"** — partially uncollected. Operators see the rollback button → click it → 422.
- **Round-1 hot-reload story** — rollback is the "oh no, undo that change" complement to hot-reload. Without it, operators making a mistake have to manually re-create the prior state.
- **Operator experience** — "rollback always works" is a strong UX expectation; "rollback works for some kinds of mutations" is confusing and error-prone.

## Suggested fix

Three additive steps.

### 1. Expand the allowlist + implement per-action `apply_*_rollback`

For each missing action, mirror the existing pattern:

```rust
// Add to ROLLBACKABLE_ACTIONS:
"pool_upsert", "pool_delete", "route_upsert", "route_delete",
"alert_receivers_set", "mtls_ca_bundle_set", "client_auth_mode_set",
"upstreams_config_set", "ddos_set", "strikes_set", "rate_limit_set",

// Add dispatch branches:
"pool_upsert" => apply_pool_rollback(...),
"alert_receivers_set" => apply_alert_receivers_rollback(...),
...
```

Each `apply_*_rollback` reads `event.fields.before` (the pre-mutation
state stored in the audit entry — verify this is captured at mutation
time), validates it, and applies via the same path as a forward
mutation. Audit-mutated like all other operations.

### 2. Index the audit ring for O(1) lookup

```rust
pub struct AuditRing {
    events: VecDeque<AuditEvent>,
    by_request_id: HashMap<String, usize>,    // index
    // bound by ring capacity; rebuild on rotation
}
```

`lookup_event(request_id)` becomes O(1) instead of O(10k).

### 3. Per-mutation rollback test

Each new action variant gets a `tests/api/rollback_<action>.sh`:

```sh
# Apply mutation
curl -sk -X POST "$HOST/api/upstreams/pool/X" -d '...'
request_id=$(...)

# Rollback
curl -sk -X POST "$HOST/api/config/rollback/$request_id"

# Verify state matches pre-mutation snapshot
curl -sk "$HOST/api/upstreams/pool/X" | jq
# Expect: matches the before state.
```

## Verification

```sh
# Pick any non-allowlisted action:
curl -sk -X POST "$HOST/api/upstreams/pool/test" -d '{...}'
# Captures audit entry with action: pool_upsert

# Try to rollback:
request_id=$(...)
curl -sk -X POST "$HOST/api/config/rollback/$request_id" -i
# Today: 422 NotRollbackable.
# After fix: 200 + pool reverts.
```

## Severity rationale

CRITICAL on §5.9 bonus loss (operator-quality scoring) plus UX gap
(dashboard promises rollback that doesn't work). Each missing action
is ~30-50 LoC; ~400 LoC total to round out the allowlist.
