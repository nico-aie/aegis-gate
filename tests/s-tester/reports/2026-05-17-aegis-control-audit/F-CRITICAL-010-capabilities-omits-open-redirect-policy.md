---
id: 2026-05-17-capabilities-omits-open-redirect
date: 2026-05-17T00:00Z
severity: CRITICAL
area: interop · v2.3 capabilities
component: crates/aegis-proxy/src/run.rs:1629-1642 (build_interop_runtime) · crates/aegis-control/src/interop/rule_map.rs:55
interop_contract: v2.3 §2.3 (capabilities advertises supported policies) · §2.5 (set_profile)
status: open
test_mode: source-review
---

# F-CRITICAL-010 · v2.3 capabilities response omits `open_redirect` while detector emits it — contract drift causing `set_profile` `unsupported` + live rule firing

## Summary

The v2.3 contract capabilities response advertises supported features
and policies (§2.3); `set_profile` (§2.5) accepts those policy names
to flip mode. If a policy isn't advertised, calling `set_profile`
for it gets returned in `unsupported`.

In Aegis:

- `crates/aegis-proxy/src/run.rs:1629-1642` populates the
  `rules_engine.policies` list — 12 entries (sqli, xss,
  path_traversal, ssrf, cmdi, etc.). **`open_redirect` is NOT in
  the list.**

- `crates/aegis-control/src/interop/rule_map.rs:55` maps the rule_id
  `open_redirect` (and alias `openredir`) to feature
  `rules_engine.open_redirect`.

- The open-redirect detector (`aegis-security/src/detectors/open_redirect.rs:211`)
  emits the `open_redirect` rule_id at runtime — so the rule fires
  on live traffic.

Result of a BTC grader call:

```sh
POST /__waf_control/set_profile
{
  "scope": "policies",
  "mode": "log_only",
  "feature": "rules_engine",
  "policies": ["open_redirect"]
}
```

Response: `{"unsupported": ["open_redirect"]}` — yet the rule
continues to BLOCK live traffic (because the detector reads the
mask, and the mask wasn't flipped). The grader's subsequent probe
that expects an open-redirect payload to reach upstream (log_only
mode) gets BLOCKED instead.

Even the project's own test fixture at `interop/control.rs:505`
includes `open_redirect` in the test's capability map — proving
the omission in `run.rs:1641` is unintentional drift.

## Observed code path

[aegis-proxy/src/run.rs:1629-1642](aegis-gate/crates/aegis-proxy/src/run.rs#L1629-L1642):

```rust
let rules_engine_caps = CapabilityFeature {
    supported: true,
    toggleable: true,
    policies: vec![
        "sqli".into(),
        "xss".into(),
        "path_traversal".into(),
        "ssrf".into(),
        "header_injection".into(),
        "command_injection".into(),
        "template_injection".into(),
        "nosql_injection".into(),
        "body_abuse".into(),
        "brute_force".into(),
        "recon".into(),
        // open_redirect MISSING.
    ],
};
```

[interop/rule_map.rs:55](aegis-gate/crates/aegis-control/src/interop/rule_map.rs#L55):

```rust
"open_redirect" | "openredir" => Some(("rules_engine", "open_redirect")),
```

## Impact

- **§2.3 / §2.5 contract drift** — capabilities response is
  incomplete; `set_profile` reports `unsupported` for a real
  capability.
- **Log-only mode probe** — BTC's standard log-only verification
  on `open_redirect` (see §3 / §7 normalization) cannot work; the
  detector keeps blocking.
- **Per-detector scoring** — open-redirect false-positive /
  false-negative testing is broken at the protocol layer.
- **Trust signal** — easy bug for graders to find (compare
  capabilities response keys against detector emits). Sloppy.

## Suggested fix

One-line addition:

```diff
 policies: vec![
     "sqli".into(),
     ...
     "recon".into(),
+    "open_redirect".into(),
 ],
```

Add a regression test in `tests/contract/` that walks every
`rule_id` the detectors emit and confirms it has a corresponding
entry in the capability response:

```rust
#[test]
fn every_detector_rule_id_is_in_capabilities() {
    let runtime = build_test_runtime();
    let caps = runtime.capabilities();
    let advertised_policies: HashSet<_> = caps.features.values()
        .flat_map(|f| f.policies.iter().cloned())
        .collect();

    for detector in all_detectors() {
        for rule_id in detector.rule_ids() {
            let (feature, policy) = rule_map::rule_to_feature(rule_id)
                .expect(&format!("rule_id {rule_id} has no feature mapping"));
            assert!(advertised_policies.contains(policy),
                "detector emits {rule_id} (feature={feature}, policy={policy}) but capabilities omits it");
        }
    }
}
```

## Verification

```sh
SECRET="${AEGIS_BENCHMARK_SECRET:-waf-hackathon-2026-ctrl}"
HOST="http://127.0.0.1:8080"

curl -sk -H "X-Benchmark-Secret: $SECRET" \
    "$HOST/__waf_control/capabilities" | \
    jq '.features.rules_engine.policies'
# Expect: includes "open_redirect"

curl -sk -X POST -H "X-Benchmark-Secret: $SECRET" \
    -H 'content-type: application/json' \
    -d '{"scope":"policies","feature":"rules_engine","policies":["open_redirect"],"mode":"log_only"}' \
    "$HOST/__waf_control/set_profile" | jq
# Expect: applied succeeds, unsupported is empty
# Today: { unsupported: ["open_redirect"] }
```

## Severity rationale

CRITICAL. Contract drift on a §2.3 / §2.5 surface that the OC
harness directly tests. 1 LoC fix. Symptomatic of missing
test coverage between capability list and detector emits.
