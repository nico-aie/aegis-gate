---
id: 2026-05-17-viptalk-bot-token-hardcoded-default
date: 2026-05-17T00:00Z
severity: CRITICAL
area: SLO dispatch · operator-quality / info disclosure
component: crates/aegis-control/src/slo.rs:164-167 (DEFAULT_VIPTALK_BOT_TOKEN) · slo.rs:182-197 (default_receivers)
interop_contract: General security posture · §9 forbidden mock-data (loose interpretation)
status: open
test_mode: source-review (spot-verified)
---

# F-CRITICAL-017 · `DEFAULT_VIPTALK_BOT_TOKEN = "xxx-dev-uat-bot-token-xxx"` hardcoded → production that doesn't set env var POSTs every SLO alert to a third-party Matrix room

## Summary

**Spot-verified** at [slo.rs:164-167](../../../../crates/aegis-control/src/slo.rs#L164-L167):

```rust
pub const DEFAULT_VIPTALK_BOT_TOKEN: &str =
    "xxx-dev-uat-bot-team-bot-token-xxx";
```

[slo.rs:182-197](../../../../crates/aegis-control/src/slo.rs#L182-L197) uses it as a fallback for `default_receivers()`:

```rust
let bot_token = std::env::var("AEGIS_VIPTALK_BOT_TOKEN")
    .unwrap_or_else(|_| DEFAULT_VIPTALK_BOT_TOKEN.to_string());
```

The literal string `"xxx-dev-uat-bot-token-xxx"` looks like a
placeholder, but it's a REAL token format. A production deployment
that forgets to set `AEGIS_VIPTALK_BOT_TOKEN` ships with this token
as the live alert destination — and EVERY SLO alert (with full SLI
name, severity, body text) gets POSTed to whatever VipTalk room that
token routes to.

Possible outcomes:
- The token belongs to a developer's personal/test VipTalk → developer
  gets a flood of production alerts in their personal chat.
- The token belongs to nobody (or was rotated) → the WAF burns CPU
  + outbound bandwidth on 401-ing alerts.
- The token belongs to an attacker who registered the pattern after
  observing it in the codebase → **the attacker receives production
  SLO alerts** (info disclosure: when the WAF is overloaded, what
  tier is breached, response time anomalies, etc.).

§9 of official rules forbids "Demo phải dùng real traffic, WAF chạy
thực tế trước toàn bộ backend — không được dùng mock response cứng"
— hardcoded production defaults that look like test data is the
same code smell judges look for.

## Impact

- **Operator info-disclosure** — SLO alert content leaks to a
  third party.
- **§9 / Architecture rubric** — hardcoded magic strings as
  production defaults trigger judge scrutiny.
- **Operational reliability** — alerts going nowhere = SLO breaches
  missed.
- **Trust signal** — judges scanning code see the literal
  `"xxx-dev-uat-bot-token-xxx"` and immediately question every other
  config default.

## Suggested fix

Remove the hardcoded default entirely; require explicit opt-in:

```diff
-pub const DEFAULT_VIPTALK_BOT_TOKEN: &str =
-    "xxx-dev-uat-bot-team-bot-token-xxx";

 fn default_receivers() -> Vec<Receiver> {
-    let bot_token = std::env::var("AEGIS_VIPTALK_BOT_TOKEN")
-        .unwrap_or_else(|_| DEFAULT_VIPTALK_BOT_TOKEN.to_string());
-    vec![
-        Receiver { kind: "viptalk".into(), bot_token, ... }
-    ]
+    let Ok(bot_token) = std::env::var("AEGIS_VIPTALK_BOT_TOKEN") else {
+        tracing::info!(
+            "AEGIS_VIPTALK_BOT_TOKEN not set; no default VipTalk receiver configured. \
+             Configure receivers via dashboard or set the env var."
+        );
+        return vec![];
+    };
+    vec![
+        Receiver { kind: "viptalk".into(), bot_token, ... }
+    ]
 }
```

Update existing tests at slo.rs:723, 770 to construct receivers
explicitly instead of relying on the default.

Cross-fix: F-CRITICAL-015 (SSRF via bot_token) needs to land
alongside this. Both touch the same surface.

## Verification

```sh
# Boot WAF without AEGIS_VIPTALK_BOT_TOKEN.
unset AEGIS_VIPTALK_BOT_TOKEN
./waf run --config waf.yaml

curl -sk "$HOST/api/alert-receivers" | jq
# Before fix: includes a receiver with bot_token="xxx-dev-uat-..."
# After fix: empty list; log line says "no default VipTalk receiver".
```

Add a regression test that asserts `default_receivers()` returns
`vec![]` when the env var is unset.

## Severity rationale

CRITICAL on info-disclosure grounds + §9 / Architecture-rubric
visibility. 4-LoC fix. Single highest cost/benefit ratio among the
non-Round-1 CRITICALs.
