---
id: 2026-05-17-high-headers-contract-bundle
date: 2026-05-17T00:00Z
severity: HIGH
area: interop · §5.1 header value contract
component: crates/aegis-control/src/interop/headers.rs · crates/aegis-proxy/src/accept.rs:1235 · crates/aegis-proxy/src/data_plane.rs (rule_id emit sites)
interop_contract: v2.3 §5.1 mandatory header EXACT format
status: open
test_mode: source-review
---

# F-HIGH-headers-contract bundle — 3 §5.1 header-value format violations (strict graders fail on every response)

---

## H-01 · `X-WAF-Request-Id` is 64-char blake3 hex, NOT UUID v4

**Component:** [accept.rs:1235-1243](../../../../crates/aegis-proxy/src/accept.rs#L1235) · [interop/headers.rs:225](../../../../crates/aegis-control/src/interop/headers.rs#L225)

§5.1 specifies `X-WAF-Request-Id` as **"UUID v4 string"**, format
example `550e8400-e29b-41d4-a716-446655440000` (36 chars,
dash-separated, version nibble `4`).

Aegis emits a 64-char hex string from `blake3::hash(...)[..64]`.
Strict graders that regex-validate against the UUID v4 pattern
`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`
reject every response.

This is also F-HIGH-004 from the earlier audit re-flagged with the
**format-violation angle** (the prior finding was about entropy;
this is about shape).

**Fix:** use `uuid::Uuid::new_v4().to_string()`:

```diff
-let request_id = blake3::hash(format!("{peer}:{nanos}:{path}").as_bytes())
-    .to_hex().to_string();
+let request_id = uuid::Uuid::new_v4().to_string();
```

---

## H-02 · `X-WAF-Rule-Id` uses underscores, not hyphens

**Component:** rule_id literals scattered in [data_plane.rs](../../../../crates/aegis-proxy/src/data_plane.rs) (~12 sites)

§5.1 specifies `X-WAF-Rule-Id` as `"Alphanumeric + hyphens, e.g.
rule-001"`. Strict regex: `^([A-Za-z0-9-]+|none)$`.

Aegis emits underscored rule IDs at several sites:
- `mtls_required`
- `unmatched_route`
- `connect_to_non_tcp_route`
- `non_connect_to_tcp_route`
- `websocket_no_upstream_pool`
- `websocket_no_healthy_member`
- `websocket_no_upgrade_extension`
- `websocket_upstream_forward_failed`
- (plus underscored detector rule IDs in security crate)

Some IDs ARE hyphenated (`body-too-large`, `risk-strikes`) — the
inconsistency is internal.

A strict grader's regex fails on every underscored emission.

**Fix:** centralized conversion at stamp time (cheapest):

```rust
// interop/headers.rs::stamp:
fn sanitize_rule_id(id: &str) -> String {
    id.chars()
        .map(|c| if c == '_' { '-' } else { c })
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect()
}
```

Or fix every emit site to use hyphens. Centralized is safer because
it catches every future drift automatically.

---

## H-03 · `X-WAF-Risk-Score` no `.min(100)` clamp; operator-config `risk.max > 100` leaks

**Component:** [interop/headers.rs:222-237](../../../../crates/aegis-control/src/interop/headers.rs#L222-L237)

§5.1 specifies `X-WAF-Risk-Score` as `"Plain integer, no whitespace.
e.g. 42"` with range `"integer 0–100"`.

Aegis writes `self.risk_score.to_string()` with no clamp.
`RiskThresholds::max` is operator-configurable
([aegis-core/src/config.rs:1986](../../../../crates/aegis-core/src/config.rs#L1986));
default 100 but ANY value accepted. With operator config
`risk.max: 200`, the header emits `X-WAF-Risk-Score: 145`.

Strict graders check `^(100|[1-9]?[0-9])$` — fails on any 3-digit
value above 100.

**Fix:**

```diff
-self.risk_score.to_string()
+self.risk_score.min(100).to_string()
```

Or stricter: clamp `RiskThresholds::max` to ≤ 100 at config load
(reject configs that exceed). The current model lets operators set
`max: 1000` to allow "headroom" — that headroom is wrong because
the contract caps at 100.

---

## Severity rationale

HIGH on contract-validation grounds. Each one alone would be MEDIUM
(strict regex graders are uncommon); together they paint a
"contract-shape sloppiness" picture that affects every response.
Combined fix: ~10 LoC across the three sites.
