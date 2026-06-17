---
id: 2026-06-17-F-V26-001
severity: HIGH
area: "interop · §5.1 X-WAF-Rule-Id value format"
component: crates/aegis-control/src/interop/headers.rs:284 · crates/aegis-proxy/src/data_plane.rs (rule_id emit sites)
contract: v2.6 §5.1
status: open
test_mode: source-review
---

# F-V26-001 — `X-WAF-Rule-Id` emits underscores + comma lists (violates §5.1 "alphanumeric + hyphens")

## Contract
§5.1 pins `X-WAF-Rule-Id` to: *"Alphanumeric + hyphens, e.g. `rule-001`,
`policy-default`, or `none`."* Strict regex: `^([A-Za-z0-9-]+|none)$`.

## What the code does
`Decision::stamp` writes the rule-id verbatim with no sanitization:

```rust
// crates/aegis-control/src/interop/headers.rs:281
insert(headers, RULE_ID, self.rule_id.as_deref().unwrap_or("none"));
```

The value comes straight from `decision_tag.rule_id`
(`admin_dispatch.rs:1327`), which the data plane fills with two
non-compliant shapes:

1. **Underscored identifiers** (dozens of sites in `data_plane.rs`):
   `unmatched_route`, `connect_to_non_tcp_route`, `non_connect_to_tcp_route`,
   `connect_authority_missing`, `connect_dns_failed`, `connect_denied`,
   `websocket_no_upstream_pool`, `websocket_no_upgrade_extension`,
   `websocket_no_healthy_member`, plus underscored detector rule-ids from
   `aegis-security`.

2. **Comma-joined detector lists**: detections forward/label with
   `tags.join(",")` →
   ```rust
   // crates/aegis-proxy/src/data_plane.rs:1051
   tags.join(",")        // e.g. "sqli,xss"
   ```
   `,` is neither alphanumeric nor a hyphen.

Some IDs already are hyphenated (`risk-challenge`, `body-too-large`,
`rate-limit-burst`) — the inconsistency is internal, which makes a global
fix the right call.

## Impact
A grader that regex-validates `X-WAF-Rule-Id` (the contract gives an exact
format) fails **every** response whose decision used an underscored rule or
a multi-detector label. Because the audit `rule_id` is copied from the same
field (`admin_dispatch.rs:1357`), the audit log carries the same shape — so
header/log stay consistent, but both are "wrong shape" together.

Severity HIGH on contract-validation grounds: it affects a large fraction of
non-allow decisions and is trivial to fix.

## Fix (centralized, ~6 LoC)
Sanitize at the single stamp site so every current and future emitter is
covered:

```rust
// interop/headers.rs — apply inside stamp() before insert(RULE_ID, ..)
fn sanitize_rule_id(id: &str) -> String {
    let s: String = id.chars()
        .map(|c| if c == '_' { '-' } else { c })
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    if s.is_empty() { "none".into() } else { s }
}
```

Note the comma-list case: `sqli,xss` → `sqlixss` after filtering, which is
ugly. Prefer joining detector tags with `-` at the source
(`data_plane.rs:1051` `tags.join("-")`) **and** keeping the sanitizer as a
backstop. Decide whether multi-detector attribution should collapse to the
single highest-weight detector instead (cleaner `X-WAF-Rule-Id`, and the
full list can live in a bonus `X-WAF-*` header / audit field).

## Verify
- Unit: extend `headers.rs` tests — stamp `DecisionTag::block("websocket_no_upstream_pool")`
  and assert the header matches `^[A-Za-z0-9-]+$`.
- Live: fire an SQLi+XSS combo and a CONNECT-to-non-TCP route; assert both
  `X-WAF-Rule-Id` responses pass the regex.
