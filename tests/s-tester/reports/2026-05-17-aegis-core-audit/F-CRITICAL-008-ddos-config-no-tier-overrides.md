---
id: 2026-05-17-ddos-config-no-tier-overrides
date: 2026-05-17T00:00Z
severity: CRITICAL
area: config schema · DDoS protection
component: crates/aegis-core/src/config.rs (DdosConfig)
interop_contract: official rules §5.2 #03 — DDoS configurable per route tier
status: open
test_mode: source-review
---

# F-CRITICAL-008 · `DdosConfig` has no `tier_overrides` field — §5.2 #03 per-tier mandate unrepresentable; schema source of F-CRITICAL-005 (security audit)

## Summary

Official rules §5.2 #03:

> *DDoS Protection: Burst detection + auto block + configurable threshold **per route tier**. Fail-close mode cho CRITICAL tier, fail-open cho MEDIUM/CATCH-ALL tier.*

**Spot-verified** at [config.rs:2164-2202](../../../../crates/aegis-core/src/config.rs#L2164-L2202):

```rust
pub struct DdosConfig {
    pub enabled: bool,
    pub observe_only: bool,
    pub per_ip_limit: u32,         // ← single global
    pub per_ip_window_s: u32,      // ← single global
    pub block_ttl_s: u32,
    pub spike_multiplier: f64,
    pub tightened_per_ip_rps: u32,
    // tier_overrides: MISSING
}
```

All thresholds are scalar/global. There is no
`HashMap<Tier, DdosTierOverride>` field. Operator config CANNOT
express different DDoS thresholds for CRITICAL vs MEDIUM tier.

The §5.2 #03 mandate (and the Round-1 tiered protection table from
§4 in the official rules) is unrepresentable at the schema layer.

This is the **schema source** of F-CRITICAL-005 in the security
audit, which observed at runtime that DDoS has no per-tier threshold
+ no fail-close-per-tier wiring. The runtime bug is downstream of
this schema gap — a runtime fix without a schema field has nowhere
to read the per-tier value from.

## Suggested fix

Add per-tier override map:

```diff
 pub struct DdosConfig {
     pub enabled: bool,
     pub observe_only: bool,
-    pub per_ip_limit: u32,
-    pub per_ip_window_s: u32,
-    pub block_ttl_s: u32,
-    pub spike_multiplier: f64,
-    pub tightened_per_ip_rps: u32,
+    /// Default applied when no tier-specific override.
+    pub default: DdosTierLimit,
+    /// Per-tier overrides (CRITICAL / HIGH / MEDIUM / CATCH-ALL).
+    pub tier_overrides: HashMap<Tier, DdosTierLimit>,
 }

+#[derive(Clone, Debug, Deserialize, Serialize)]
+pub struct DdosTierLimit {
+    pub per_ip_limit: u32,
+    pub per_ip_window_s: u32,
+    pub block_ttl_s: u32,
+    pub spike_multiplier: f64,
+    pub tightened_per_ip_rps: u32,
+    /// Tier-specific failure mode (§5.8).
+    pub failure_mode: FailureModeConfig,
+}
```

Sensible defaults aligned with §4 tier table:

```rust
impl Default for DdosConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            observe_only: false,
            default: DdosTierLimit {
                per_ip_limit: 1000, per_ip_window_s: 10,
                block_ttl_s: 300, spike_multiplier: 3.0,
                tightened_per_ip_rps: 500,
                failure_mode: FailureModeConfig::FailOpen,
            },
            tier_overrides: HashMap::from([
                (Tier::Critical, DdosTierLimit {
                    per_ip_limit: 30, per_ip_window_s: 60,
                    block_ttl_s: 3600, spike_multiplier: 2.0,
                    tightened_per_ip_rps: 10,
                    failure_mode: FailureModeConfig::FailClose,
                }),
                (Tier::High, DdosTierLimit {
                    per_ip_limit: 200, per_ip_window_s: 10,
                    block_ttl_s: 600, spike_multiplier: 2.5,
                    tightened_per_ip_rps: 100,
                    failure_mode: FailureModeConfig::FailOpen,
                }),
                (Tier::Medium, DdosTierLimit {
                    per_ip_limit: 500, per_ip_window_s: 10,
                    block_ttl_s: 300, spike_multiplier: 3.0,
                    tightened_per_ip_rps: 250,
                    failure_mode: FailureModeConfig::FailOpen,
                }),
            ]),
        }
    }
}
```

Consumer-side fix per F-CRITICAL-005 (security audit) now has a
schema to read from:

```rust
let limit = cfg.ddos.tier_overrides
    .get(&route.tier)
    .unwrap_or(&cfg.ddos.default);
ddos_runtime.check(ip, &limit)?;
```

## Verification

```yaml
# waf.yaml
ddos:
  default:
    per_ip_limit: 1000
    failure_mode: fail_open
    ...
  tier_overrides:
    critical:
      per_ip_limit: 30
      failure_mode: fail_close
      ...
```

```sh
# CRITICAL tier route (/login) should rate-limit faster:
for i in $(seq 1 50); do curl -sk http://127.0.0.1:8080/login -o /dev/null & done; wait
# Expect: many 429/503 (CRITICAL hard-limited).

for i in $(seq 1 50); do curl -sk http://127.0.0.1:8080/static/x.css -o /dev/null & done; wait
# Expect: 50 × 200 (MEDIUM wider limit).
```

## Severity rationale

CRITICAL. §5.2 #03 + §5.8 mandates unrepresentable in current
schema. Schema source of F-CRITICAL-005 (security audit). Schema +
consumer-fix together ~150 LoC.
