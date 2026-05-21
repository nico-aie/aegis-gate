---
id: 2026-05-17-action-enum-missing-2-variants
date: 2026-05-17T00:00Z
severity: CRITICAL
area: contract schema · decision enum
component: crates/aegis-core/src/decision.rs (Action enum)
interop_contract: v2.3 §3 (6 decision classes), §5.1 (X-WAF-Action enum)
status: open
test_mode: source-review (spot-verified)
---

# F-CRITICAL-006 · `decision.rs::Action` enum has only 4 of 6 §3 variants — `Timeout` and `CircuitBreaker` MISSING → structural root cause of F-CONTRACT-001 (proxy audit)

## Summary

§3 of v2.3 contract enumerates EXACTLY 6 decision classes:

| Decision | Meaning |
|---|---|
| `allow` | Proxy to upstream |
| `block` | Deny before upstream |
| `challenge` | Hold + require PoW/CAPTCHA |
| `rate_limit` | Deny due to rate threshold |
| `timeout` | Upstream non-response |
| `circuit_breaker` | Upstream unhealthy, refuse |

**Spot-verified** at [decision.rs:10-15](../../../../crates/aegis-core/src/decision.rs#L10-L15):

```rust
pub enum Action {
    Allow,
    Block { status: u16 },
    Challenge { level: ChallengeLevel },
    RateLimited { retry_after_s: u32 },
    // Timeout — MISSING
    // CircuitBreaker — MISSING
}
```

4 of 6. Additionally:

- `RateLimited` name diverges from spec's `rate_limit` (cosmetic but
  breaks any code that pattern-matches on the snake_case literal).
- No `Serialize` / `Display` derived — every consumer hand-rolls a
  stringifier; `aegis-control/src/interop/headers.rs:50` does exactly
  this for a DIFFERENT parallel enum, guaranteeing cross-crate drift.

## Why this matters — structural root cause of F-CONTRACT-001

From the proxy audit, F-CONTRACT-001 reported:

> WS no-healthy-member returns `block` instead of `circuit_breaker` per §3.

The proxy literally **has no `Action::CircuitBreaker` variant to
construct**. Same story for upstream timeouts (returns `block`
instead of `timeout`). The proxy audit treated this as a per-call-site
bug; **it's actually a schema bug** — every site that should emit
`circuit_breaker` or `timeout` falls back to `block` because the type
doesn't offer the option.

## Suggested fix

```diff
 pub enum Action {
     Allow,
     Block { status: u16 },
     Challenge { level: ChallengeLevel },
-    RateLimited { retry_after_s: u32 },
+    RateLimit { retry_after_s: u32 },
+    /// §3 — upstream non-response (typically status 504).
+    Timeout { after_ms: u32 },
+    /// §3 — upstream unhealthy, refuse (typically status 503).
+    CircuitBreaker { reason_code: &'static str },
 }
```

Add `Serialize + Display` per the F-CRITICAL-004 fix:

```rust
impl Action {
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::Allow                  => "allow",
            Action::Block { .. }           => "block",
            Action::Challenge { .. }       => "challenge",
            Action::RateLimit { .. }       => "rate_limit",
            Action::Timeout { .. }         => "timeout",
            Action::CircuitBreaker { .. }  => "circuit_breaker",
        }
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
```

Delete the parallel `aegis-control::interop::headers::Action` enum;
re-export via `pub use aegis_core::decision::Action`.

Update the proxy call sites (per F-CONTRACT-001 in proxy audit):

```diff
 // data_plane.rs WS no-healthy-member:
-DecisionTag::block("websocket_no_healthy_member")
+DecisionTag::circuit_breaker("websocket_no_healthy_member")

 // forward.rs upstream timeout:
-DecisionTag::block("upstream_timeout")
+DecisionTag::timeout("upstream_timeout")
```

(Status codes: `circuit_breaker` → 503, `timeout` → 504 per §4
recommended HTTP behavior table.)

## Verification

```rust
#[test]
fn action_enum_has_all_six_section_3_variants() {
    use Action::*;
    let variants = [
        Allow,
        Block { status: 403 },
        Challenge { level: ChallengeLevel::Low },
        RateLimit { retry_after_s: 30 },
        Timeout { after_ms: 5000 },
        CircuitBreaker { reason_code: "upstream-unhealthy" },
    ];
    let strings: Vec<_> = variants.iter().map(|v| v.as_str()).collect();
    assert_eq!(strings, vec!["allow", "block", "challenge", "rate_limit", "timeout", "circuit_breaker"]);
}
```

End-to-end repro of F-CONTRACT-001 fix:

```sh
# Configure a WS route with no healthy upstream member.
# Send a WS upgrade request.
curl -ski -H 'Upgrade: websocket' -H 'Connection: upgrade' http://127.0.0.1:8080/ws -i
# Expect: HTTP/1.1 503 + X-WAF-Action: circuit_breaker
# Today: HTTP/1.1 502 + X-WAF-Action: block (per F-CONTRACT-001)
```

## Severity rationale

CRITICAL. Two of six §3 variants entirely missing — the proxy CANNOT
emit those actions because the type doesn't allow it. Fixes
F-CONTRACT-001 (proxy audit) at the structural layer. ~15 LoC for
the enum + cross-crate cleanup.
