---
id: 2026-06-17-section-05-headers
contract_section: "§5 — Mandatory Observability Headers"
checklist_ids: C-5-* C-5.1-* C-5.2-* C-5.3-*
verdict: MOSTLY (1 HIGH F-V26-001, 1 MEDIUM F-V26-003)
test_mode: source-review
---

# §5 — Mandatory Observability Headers

Primary code: `crates/aegis-control/src/interop/headers.rs`,
single stamp site `crates/aegis-proxy/src/admin_dispatch.rs:1280 stamp_interop_response`.

## §5 / §5.1 — 6 headers on every response — ⚠️ MOSTLY

`Decision::stamp` (`headers.rs:277`) unconditionally inserts all 6 headers
and **replaces** (not appends) existing values (test
`stamp_replaces_existing_value_not_appends`). `stamp_interop_response` is
the single choke-point invoked on **every** response, incl. the control-plane
hidden-404 (`accept.rs:1802`). So C-5-01 (present on every response,
incl. allow/block/challenge/rate_limit/timeout/circuit_breaker) is satisfied.

Per-header format check:

| Header | §5.1 format | Aegis | Verdict |
|--------|-------------|-------|---------|
| `X-WAF-Request-Id` | unique 8–64 chars `[A-Za-z0-9._-]` | `uuid::Uuid::new_v4()` 36 chars (`admin_dispatch.rs:1302`) | ✅ |
| `X-WAF-Risk-Score` | integer 0–100 | `effective_risk_score.to_string()` — **no clamp** | ⚠️ **F-V26-003** |
| `X-WAF-Action` | one of 6, lowercase exact | `Action::as_str` | ✅ |
| `X-WAF-Rule-Id` | alphanumeric + hyphens, or `none` | underscores + comma lists emitted | ❌ **F-V26-001** |
| `X-WAF-Cache` | HIT/MISS/BYPASS uppercase | `CacheState::as_str` | ✅ |
| `X-WAF-Mode` | enforce/log_only lowercase | `Mode::as_str` | ✅ |

> v2.6 note: `X-WAF-Request-Id` was relaxed from strict UUID v4 to "any
> unique token, 8–64 chars". The live UUID v4 is comfortably inside that.
> The old F-HIGH H-01 is **resolved by v2.6**.

### F-V26-001 (HIGH) — rule-id format
`X-WAF-Rule-Id` is stamped from `decision_tag.rule_id` verbatim
(`admin_dispatch.rs:1327` → `headers.rs:284`), with no sanitization.
Emitted values include underscores (`unmatched_route`,
`websocket_no_upstream_pool`, `connect_dns_failed`, …) and comma-joined
detector lists (`data_plane.rs:1051 tags.join(",")` → e.g. `sqli,xss`).
A strict `^([A-Za-z0-9-]+|none)$` grader fails these. See F-V26-001 file.

### F-V26-003 (MEDIUM) — risk-score not clamped
`effective_risk_score` (`admin_dispatch.rs:1322`) is stamped with no
`.min(100)`. Per-request detector sums are `.min(100)` (`data_plane.rs:948`),
but the cumulative tracker score is clamped to the operator-configurable
`risk.max` (`aegis-core risk/mod.rs:134`), default 100. If an operator sets
`risk.max > 100`, both the header and audit log emit a value > 100, failing
`integer 0–100`. See F-V26-003 file.

## §5.2 — Additional headers — ✅ PASS
- `X-WAF-Overhead-Latency` extra header uses the `X-WAF-` prefix
  (`headers.rs:37`), doesn't replace any required header, carries no secret.
  Compliant bonus telemetry (C-5.2-01..05).

## §5.3 — Consistency rules — ✅ PASS

| ID | Rule | Result | Evidence |
|----|------|--------|----------|
| C-5.3-01/02/03 | action matches behaviour; log_only reports intent, forwards upstream | ✅ | log_only arms forward to upstream + stamp intended action + `X-WAF-Mode: log_only` |
| C-5.3-04 | mode reflects firing policy | ✅ | `mode_for_rule(rule_id)` |
| C-5.3-05 | risk score after evaluating current request | ✅ | data plane stamps `post_state.score` at decision |
| C-5.3-06 | rule_id = `none` when no detector | ✅ | `unwrap_or("none")` (`headers.rs:284`) |
| C-5.3-07 | cache = BYPASS on dynamic/sensitive | ✅ | default `Bypass`; smart-cache only flips on cacheable routes |
| C-5.3-08 | request_id matches audit log | ✅ | same `request_id` var used for header + `MinimalAuditEntry` (`admin_dispatch.rs:1302,1346`) |
| C-5.3-09 | headers on allowed responses too | ✅ | allow path runs the same stamp site |

## Net
The header subsystem is centralized and well-tested; both findings are at
the single stamp site and are tiny fixes that fix header **and** audit in
lock-step.
