---
id: 2026-05-17-healthz-missing-round1-fields
date: 2026-05-17T00:00Z
severity: CRITICAL
area: dashboard · health endpoint
component: crates/aegis-control/src/health.rs (HealthResponse) · crates/aegis-control/src/api/{admin,state}.rs
interop_contract: Round-1 "Health/Status View (BẮT BUỘC)"
status: open
test_mode: source-review (spot-verified)
---

# F-CRITICAL-003 · `/healthz` missing uptime / mode / active-rule-count — Round-1 mandate not satisfied

## Summary

Round-1 official rules (WAF-FE section):

> *Health/Status View: Hiển thị được trạng thái cơ bản của WAF
> (**Uptime, Mode hiện tại, Số lượng rule đang active**).*

Three fields named explicitly. None of them appear in any `/healthz`
response.

Spot-verified at [health.rs:13-19](aegis-gate/crates/aegis-control/src/health.rs#L13-L19): `HealthChecks` carries:

- `config_loaded: bool`
- `state_backend_up: bool`
- `certs_loaded: bool`
- `pool_has_healthy: bool`
- `draining: bool`

That's five booleans, none of which match Round-1.

The three required fields exist elsewhere:
- **Uptime**: only at `/api/about::started_at` (computed client-side from the wall-clock at boot).
- **Mode**: only at `/api/runtime` (LoadMode).
- **Active rule count**: only at `/api/rules` (count by listing).

Three separate endpoints, none of them `/healthz`. A BTC grader
hitting `/healthz` per spec sees only the boolean blob and marks
"không đạt".

## Observed code path

[health.rs:13-19](aegis-gate/crates/aegis-control/src/health.rs#L13-L19):

```rust
pub struct HealthChecks {
    pub config_loaded: bool,
    pub state_backend_up: bool,
    pub certs_loaded: bool,
    pub pool_has_healthy: bool,
    pub draining: bool,
}
```

[health.rs:55-72](aegis-gate/crates/aegis-control/src/health.rs#L55-L72) — `render_health` builds the response from these
booleans only. No `uptime_seconds` / `mode` / `active_rule_count`
fields, no method on `DashboardServices` to fetch them.

## Impact

- **Round-1 Health/Status View Pass/Fail** — fails outright.
- **Operator workflow** — debugging "is WAF healthy enough to take
  traffic" requires three round-trips to three endpoints, not the
  single `/healthz` poll that k8s + LB use by convention.
- **k8s readiness probes** — the standard pattern is a single
  `/healthz/ready` that returns enough context to decide. Today's
  response is just `{ok: true|false}` shape.

## Suggested fix

Extend `HealthResponse` and the rendering helpers:

```diff
 pub struct HealthResponse {
     pub status: &'static str,        // "ok" | "degraded" | "draining"
     pub checks: HealthChecks,
+    pub uptime_seconds: u64,
+    pub mode: HealthMode,            // load_mode + fail_mode
+    pub active_rule_count: u32,
 }

+#[derive(Serialize)]
+pub struct HealthMode {
+    pub load_mode: String,           // "normal" | "critical" | "emergency" | ...
+    pub default_fail_mode: String,   // "open" | "close" | "per_tier"
+}
```

Wire-in via `DashboardServices`:

```rust
let started_at = services.started_at;     // already exists
let uptime_seconds = started_at.elapsed().as_secs();
let mode = HealthMode {
    load_mode: services.load_gauge.snapshot().load_mode.to_string(),
    default_fail_mode: cfg.security.default_failure_mode.to_string(),
};
let active_rule_count = services.rules.list().iter().filter(|r| r.enabled).count() as u32;

HealthResponse {
    status: ...,
    checks: ...,
    uptime_seconds,
    mode,
    active_rule_count,
}
```

Cross-fix: F-HIGH-slo-metrics flags that `/healthz/live` returns 503
on draining — fix that too (move draining to `/healthz/ready` only).

## Verification

```sh
HOST="http://127.0.0.1:9443"
curl -sk "$HOST/healthz" | jq
# Expect:
# {
#   "status": "ok",
#   "checks": { ... },
#   "uptime_seconds": 12345,
#   "mode": { "load_mode": "normal", "default_fail_mode": "per_tier" },
#   "active_rule_count": 27
# }
```

Add a Round-1 conformance test in `tests/api/`:

```sh
curl -sk "$HOST/healthz" | jq -e '.uptime_seconds > 0 and .mode and (.active_rule_count | type) == "number"'
# Must pass.
```

## Severity rationale

CRITICAL. Round-1 explicitly names the 3 fields; none present. Trivial
fix (~40 LoC + plumbing). Failing this is failing a hard pass/fail
mandate.
