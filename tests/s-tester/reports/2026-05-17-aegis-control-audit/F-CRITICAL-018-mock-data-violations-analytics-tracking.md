---
id: 2026-05-17-mock-data-violations-analytics-tracking
date: 2026-05-17T00:00Z
severity: CRITICAL
area: read API · §9 forbidden mock-data
component: crates/aegis-control/src/api/analytics.rs · crates/aegis-control/src/api/tracking.rs
interop_contract: §9 "Demo phải dùng real traffic ... không được dùng mock response cứng" + Round-1 "Tính hiệu lực"
status: open
test_mode: source-review
---

# F-CRITICAL-018 · `api/analytics.rs` returns hardcoded `0.0` for every key + `api/tracking.rs` returns 6 `placeholder()` constructors → §9 mock-data violations

## Summary

§9 explicitly forbids mock data:

> *✕ Sử dụng dữ liệu giả hoặc demo fake — BỊ LOẠI NGAY LẬP TỨC.*

Round-1 explicitly forbids "Tính hiệu lực" theater:

> *UI/UX đẹp + workflow đầy đủ KHÔNG được tính là hợp lệ nếu feature
> chỉ là demo/mock hoặc không điều khiển được WAF-PROXY thật.*

The dashboard's analytics + tracking pages serve mock data when
their data providers are unwired:

### analytics.rs:170-176

```rust
fn query(&self, key: &str) -> serde_json::Value {
    match key {
        // ... allow-list of known keys ...
        _ => serde_json::json!({ "value": 0.0 })  // hardcoded 0.0
    }
}
```

Per the agent's reading, comment at lines 18-20 explicitly says
"synthetic value of 0.0". Any chart driven by `/api/analytics/query`
is mock until the Prometheus registry is plumbed.

### tracking.rs

Six `placeholder()` constructors:

- `render_slo` falls through to a placeholder when SLO provider isn't wired
- `render_certs` placeholder
- `render_gitops` placeholder (cross-ref F-CRITICAL-005 — GitOps is dead code, so this always returns placeholder)
- `render_alerts` placeholder
- `render_cert_renew` always returns 405 "not_supported"
- (one more — Agent B reading)

Each placeholder returns canned data (`availability: 99.99`,
`current_holder: None`, `peers: []`, `last_sync: None`,
`signature_ok: true`, `firing: []`). Operators see these on the
dashboard as if they were live values.

## Impact

- **§9 disqualification risk** — judges scanning the codebase find
  `placeholder()` constructors and the `0.0` fallback. Could be
  ruled "BỊ LOẠI NGAY LẬP TỨC" depending on judge interpretation.
- **Round-1 "Tính hiệu lực"** — pages whose backing data is
  placeholder fail the "UI feature must impact real WAF behavior"
  test.
- **Operator misdirection** — dashboards showing `availability: 99.99` when no SLO is wired give false confidence.
- **Compounding** with F-CRITICAL-005 (GitOps dead) — `render_gitops`
  placeholder is locked-in until F-CRITICAL-005 is fixed.

## Suggested fix

### analytics.rs — wire to real Prometheus registry

```diff
 pub struct AnalyticsHandler {
-    // no field
+    registry: Arc<prometheus::Registry>,
 }

 impl AnalyticsHandler {
     pub fn new(registry: Arc<prometheus::Registry>) -> Self {
         Self { registry }
     }

     fn query(&self, key: &str) -> serde_json::Value {
-        match key {
-            _ => serde_json::json!({ "value": 0.0 })
-        }
+        let metric_families = self.registry.gather();
+        match key {
+            "request_rate"      => sum_counter(&metric_families, "aegis_requests_total"),
+            "block_rate"        => sum_counter(&metric_families, "aegis_blocks_total"),
+            "risk_score_p99"    => histogram_p99(&metric_families, "aegis_risk_score"),
+            ...
+            _ => return serde_json::json!({ "error": "unknown_key" }),
+        }
     }
 }
```

For unknown keys, return 404, not silently `0.0`.

### tracking.rs — fail-loud when providers unwired

For each `placeholder()` constructor, return an honest 503 "provider not configured" instead of canned data:

```diff
 pub fn render_slo(&self) -> Response {
     match &self.slo_engine {
         Some(engine) => engine.snapshot().to_response(),
-        None => Response::ok(placeholder_slo()),
+        None => Response::service_unavailable(
+            "slo provider not configured",
+        ),
     }
 }
```

Same pattern for certs/gitops/alerts. The 503 response gives
operators a clear signal ("we need to wire this") instead of
fooling them with placeholder values.

Alternative: have the dashboard SPA hide the entire page section
when the provider is unwired, instead of showing canned data.

### render_cert_renew — wire or hide

Per Agent B M-?: dashboard shows "Renew" button but `render_cert_renew`
returns 405. Either wire to the ACME path or hide the button when
cert provider isn't configured.

## Verification

```sh
HOST="http://127.0.0.1:9443"

# Without Prometheus wired:
curl -sk "$HOST/api/analytics/query?key=request_rate" | jq
# After fix: 503 "registry not configured" OR real value
# Today: { "value": 0.0 }

# Without SLO wired:
curl -sk "$HOST/api/slo" | jq
# After fix: 503 "slo provider not configured"
# Today: { "availability": 99.99, ... }
```

Regression test:

```sh
# Spin up WAF WITHOUT optional features.
# Assert that /api/analytics/query, /api/slo, /api/gitops,
# /api/alerts return 503 (not 200 with canned data).
```

## Severity rationale

CRITICAL on §9 disqualification risk. Even if judges don't read the
mock data as "fake data" per the §9 wording, the Round-1 "Tính hiệu
lực" rule fires when dashboard data doesn't reflect WAF behavior.
~50 LoC fix per endpoint family.
