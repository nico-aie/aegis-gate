---
id: 2026-05-17-detectors-config-no-per-tier-mask
date: 2026-05-17T00:00Z
severity: CRITICAL
area: config schema · detector mask
component: crates/aegis-core/src/config.rs (DetectorsConfig)
interop_contract: official rules §4 tier policy table — distinct detector pipeline per tier
status: open
test_mode: source-review
---

# F-CRITICAL-011 · `DetectorsConfig` has no per-tier mask — §4 tier policy mandates distinct detector pipeline per tier

## Summary

§4 of the official rules tier-policy table:

| Tier | Policy |
|---|---|
| CRITICAL `/login /otp /deposit /withdrawal` | **Full stack**: rate limit per-user, device fingerprint, behavioral check, transaction velocity, fail-close, canary |
| HIGH `/game/* /api/* /user/*` | DDoS protection, rate limit per-IP & per-session, OWASP detection, smart caching, bot filter |
| MEDIUM `/static/* /assets/* /public/*` | Rate limit cơ bản, path traversal detect, cache aggressively |
| CATCH-ALL `/**` | Baseline: SQLi/XSS detect, rate limit, block known-bad IP, log all |

Each tier has a DISTINCT detector pipeline. CRITICAL runs ALL
detectors; CATCH-ALL runs only the baseline pair.

**Spot-verified** at [config.rs:2014-2068](aegis-gate/crates/aegis-core/src/config.rs#L2014-L2068):

`DetectorsConfig` is a single global `DetectorToggle` struct. No
`per_tier: HashMap<Tier, DetectorsConfig>` field exists.

Operators cannot:
- Enable `command_injection` only on CRITICAL (cheap on CRITICAL,
  expensive false-positive risk on CATCH-ALL)
- Disable `recon` on MEDIUM (operator-chosen tradeoff)
- Pin the §4 "Full stack" detector set on CRITICAL while running
  baseline on CATCH-ALL

The mask is all-or-nothing globally, which violates the §4 tier-
policy intent.

## Suggested fix

```diff
 pub struct DetectorsConfig {
     pub sqli: DetectorToggle,
     pub xss: DetectorToggle,
     ...
+    /// §4 per-tier overrides. Tier-specific toggles override the
+    /// global toggle for that tier.
+    #[serde(default)]
+    pub per_tier: HashMap<crate::tier::Tier, TierDetectorMask>,
 }

+#[derive(Clone, Debug, Default, Deserialize, Serialize)]
+pub struct TierDetectorMask {
+    /// `Some(true)` = force enabled on this tier; `Some(false)` =
+    /// force disabled; `None` = inherit global.
+    pub sqli: Option<bool>,
+    pub xss: Option<bool>,
+    pub path_traversal: Option<bool>,
+    pub ssrf: Option<bool>,
+    pub header_injection: Option<bool>,
+    pub command_injection: Option<bool>,
+    pub template_injection: Option<bool>,
+    pub nosql_injection: Option<bool>,
+    pub open_redirect: Option<bool>,
+    pub body_abuse: Option<bool>,
+    pub recon: Option<bool>,
+    pub brute_force: Option<bool>,
+    pub ai: Option<bool>,
+}
```

Default per §4 table:

```rust
impl Default for DetectorsConfig {
    fn default() -> Self {
        Self {
            // Global: baseline only.
            sqli: DetectorToggle { enabled: true },
            xss:  DetectorToggle { enabled: true },
            // ... others default to disabled global ...
            per_tier: HashMap::from([
                (Tier::Critical, TierDetectorMask {
                    // Full stack ON.
                    command_injection: Some(true),
                    template_injection: Some(true),
                    nosql_injection: Some(true),
                    body_abuse: Some(true),
                    brute_force: Some(true),
                    ai: Some(true),
                    ..Default::default()
                }),
                (Tier::High, TierDetectorMask {
                    // OWASP detection.
                    ssrf: Some(true),
                    header_injection: Some(true),
                    path_traversal: Some(true),
                    ..Default::default()
                }),
                (Tier::Medium, TierDetectorMask {
                    // Path-traversal only above baseline.
                    path_traversal: Some(true),
                    ..Default::default()
                }),
                (Tier::Low, TierDetectorMask {
                    // CATCH-ALL: baseline only — let global decide.
                    ..Default::default()
                }),
            ]),
        }
    }
}
```

Consumer-side resolver:

```rust
fn resolve_mask(cfg: &DetectorsConfig, tier: Tier) -> ResolvedMask {
    let global = ResolvedMask::from(cfg);
    let tier_override = cfg.per_tier.get(&tier).cloned().unwrap_or_default();
    global.apply_overrides(&tier_override)
}
```

Cross-fix: the `aegis-security/src/detectors/mask.rs::ResolvedMask`
consumer needs to call `resolve_mask(cfg, route.tier)` on every
request instead of reading the global mask.

## Verification

```sh
# CRITICAL route — command_injection detector fires:
curl -ski "http://127.0.0.1:8080/login" -d 'user=$(whoami)' -i
# Expect: 403 + X-WAF-Rule-Id: cmdi

# MEDIUM route — command_injection NOT in mask (per default), passes:
curl -ski "http://127.0.0.1:8080/static/x.css" -X POST -d 'foo=$(whoami)' -i
# Expect: 200 (CSS, no enforcement) — cheap, no FP risk
```

## Severity rationale

CRITICAL. §4 tier-policy table mandate; operators cannot pin
different detector pipelines per tier. Schema fix ~50 LoC.
