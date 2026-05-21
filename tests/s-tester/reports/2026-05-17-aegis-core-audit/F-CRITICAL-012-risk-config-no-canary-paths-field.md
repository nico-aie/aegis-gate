---
id: 2026-05-17-risk-config-no-canary-paths
date: 2026-05-17T00:00Z
severity: CRITICAL
area: config schema · canary / honeypot
component: crates/aegis-core/src/config.rs (RiskConfig)
interop_contract: official rules §5.5 — canary endpoints → MAX score + immediate IP block
status: open
test_mode: source-review
---

# F-CRITICAL-012 · `RiskConfig` has no `canary_paths` field — Round-1 §5.5 canary mandate has no schema surface

## Summary

Official rules §5.5:

> *Canary Endpoint / Honeypot: deploy decoy paths (/admin-test, /api-debug). Bất kỳ request nào hit = auto set risk score = MAX, block IP ngay.*

**Spot-verified** at [config.rs:1844-1862](../../../../crates/aegis-core/src/config.rs#L1844-L1862):

`RiskConfig` has `thresholds`, `decay`, `strikes`, etc. — but no
field for the canary path list. Operators cannot configure honeypot
endpoints via YAML.

This is the **schema source** of F-CRITICAL-007 from the security
audit (canary doesn't block IP). The runtime tag-based hack
(`Signal::tag == "recon_path"`) was implemented as a workaround for
the absent schema field, and it doesn't actually block the IP because
there's no operator-defined path list to drive the auto-block call.

## Suggested fix

```diff
 pub struct RiskConfig {
     ...
+    /// §5.5 canary / honeypot endpoints. Any request to a path in
+    /// this list triggers an immediate max-score + auto-block on the
+    /// source IP. Supports glob (`*` / `**`) per `globset` crate.
+    #[serde(default = "default_canary_paths")]
+    pub canary_paths: Vec<String>,
+    /// TTL for the auto-block triggered by canary hit.
+    #[serde(default = "default_canary_block_ttl_s")]
+    pub canary_block_ttl_s: u32,
 }

+fn default_canary_paths() -> Vec<String> {
+    vec![
+        "/admin-test".into(),
+        "/api-debug".into(),
+        "/.git/*".into(),
+        "/.env".into(),
+        "/wp-admin".into(),
+        "/phpmyadmin".into(),
+        "/.aws/credentials".into(),
+        "/.kube/config".into(),
+    ]
+}

+fn default_canary_block_ttl_s() -> u32 {
+    3600  // 1 hour default
+}
```

Consumer side (per F-CRITICAL-007 in security audit):

```rust
// pipeline.rs — front-load before detectors.
let canary_matcher = globset::GlobSetBuilder::new()
    .with_patterns(&cfg.risk.canary_paths)
    .build()?;
if canary_matcher.is_match(req.uri().path()) {
    risk_tracker.set_score_at(&ctx.key(), u32::MAX);
    state.auto_block(ip, Duration::from_secs(cfg.risk.canary_block_ttl_s)).await?;
    return Ok(Response::builder()
        .status(403)
        .body(Full::new(Bytes::from("blocked: honeypot")))
        .unwrap_or_else(|_| internal_500()));
}
```

## Verification

```sh
HOST="http://127.0.0.1:8080"
curl -ski "$HOST/admin-test" -o /dev/null -w "first=%{http_code}\n"
# Expect: 403

# Immediate follow-up from the same IP to a benign path — must be blocked:
curl -ski "$HOST/" -o /dev/null -w "after_canary=%{http_code}\n"
# Expect: 403 (auto-block kicked in)
# Today: 200 (no auto-block path on canary hit)
```

## Severity rationale

CRITICAL. §5.5 canary mandate fully unrepresentable in schema.
Schema fix ~15 LoC unlocks the F-CRITICAL-007 (security audit)
runtime fix.
