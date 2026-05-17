---
id: 2026-05-17-zero-deny-unknown-fields-in-config
date: 2026-05-17T00:00Z
severity: CRITICAL
area: config schema · serde discipline
component: crates/aegis-core/src/config.rs (every struct)
interop_contract: schema-discipline / silent-feature-loss prevention
status: open
test_mode: source-review (spot-verified — `grep -c "deny_unknown_fields" config.rs` returns 0)
---

# F-CRITICAL-013 · ZERO uses of `#[serde(deny_unknown_fields)]` in `config.rs` (4024 LoC) — typos silently drop, explaining many "ghost feature" reports

## Summary

**Spot-verified** via `grep -c "deny_unknown_fields" crates/aegis-core/src/config.rs` returns `0`.

Not a single struct in 4024 LoC uses
`#[serde(deny_unknown_fields)]`. Combined with `#[serde(default)]`
applied liberally, this means:

- A typo like `routs: ...` (instead of `routes:`) silently drops
  the field — operator's routes table is empty at runtime.
- `risk_thresholds: ...` (instead of `risk:`) — risk config falls
  to defaults; operator's tuning ignored.
- `ddos.tightened_rps:` (instead of `tightened_per_ip_rps:`) —
  field ignored; operator confused.
- `compliance.modes:` typo'd to `compliance.mode:` (singular) →
  modes list empty → no compliance enforcement (compounding
  F-CRITICAL-002 from control audit).

This is the **schema-discipline source** of many "I configured X but
the WAF doesn't honor X" reports across all prior audits. Operators
think they configured something; serde silently drops the field;
runtime falls to defaults.

The Round-1 dashboard's "tính hiệu lực" mandate is impossible to
satisfy when operator config can silently disappear.

## Suggested fix

Apply `#[serde(deny_unknown_fields)]` to every top-level + nested
struct in `config.rs`:

```diff
+#[serde(deny_unknown_fields)]
 pub struct WafConfig {
     pub schema_version: u32,
     pub admin: AdminConfig,
     pub listeners: ListenersConfig,
     pub routes: Vec<RouteConfig>,
     pub upstreams: HashMap<String, PoolConfig>,
     pub detectors: DetectorsConfig,
     pub rules: RulesConfig,
     pub rate_limit: RateLimitConfig,
     pub risk: RiskConfig,
     pub ddos: DdosConfig,
     pub compliance: ComplianceProfile,
     pub audit: AuditConfig,
     pub tls: TlsConfig,
     pub state: StateConfig,
     ...
 }

+#[serde(deny_unknown_fields)]
 pub struct RiskConfig { ... }

+#[serde(deny_unknown_fields)]
 pub struct RiskThresholds { ... }

+#[serde(deny_unknown_fields)]
 pub struct DdosConfig { ... }

+#[serde(deny_unknown_fields)]
 pub struct DetectorsConfig { ... }

+#[serde(deny_unknown_fields)]
 pub struct ComplianceProfile { ... }

+#[serde(deny_unknown_fields)]
 pub struct TlsConfig { ... }

+#[serde(deny_unknown_fields)]
 pub struct AcmeConfig { ... }

+#[serde(deny_unknown_fields)]
 pub struct ClientAuthConfig { ... }

+#[serde(deny_unknown_fields)]
 pub struct RouteConfig { ... }

+#[serde(deny_unknown_fields)]
 pub struct PoolConfig { ... }

+#[serde(deny_unknown_fields)]
 pub struct AuditConfig { ... }

+#[serde(deny_unknown_fields)]
 pub struct AdminConfig { ... }

// ... etc for every struct.
```

**At minimum, apply to `WafConfig`** (the root struct). That catches
the most damaging typos at the top level — `routs:` instead of
`routes:` becomes a parse error instead of silent drop.

After the change, every existing `dev.yaml` / `prod.yaml` config
file must validate. Fixing accidentally-typo'd field names in the
shipped configs becomes a clear migration step.

Strategy:
1. Add `#[serde(deny_unknown_fields)]` to `WafConfig` first
2. Boot every profile (`dev.yaml`, `prod-balanced.yaml`,
   `prod-strict.yaml`, `prod-high-throughput.yaml`); fix every
   serde error.
3. Recursively add to nested structs (one at a time so errors stay
   isolated).

## Verification

After the fix:

```yaml
# bad.yaml — typo'd field name
routs:
  - path: /
    upstream: backend
```

```sh
./waf validate --config bad.yaml
# Today: validates clean (silently dropped, no routes loaded)
# After fix: ERROR: unknown field `routs`, expected `routes`
```

Add a unit test:

```rust
#[test]
fn unknown_field_at_top_level_rejected() {
    let yaml = "routs: []\n";
    let err = serde_yaml::from_str::<WafConfig>(yaml).unwrap_err();
    assert!(err.to_string().contains("unknown field"));
}
```

## Severity rationale

CRITICAL on schema-discipline grounds. Single annotation change
catches an entire bug class. Explains why F-CRITICAL-005/006/008/009
(prior audits) all share the same exposure surface ("I set the
field but the WAF doesn't honor it"). 14 LoC of annotations across
12+ structs.
