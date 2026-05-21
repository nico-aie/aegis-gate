---
id: 2026-05-17-ddos-no-per-tier-no-fail-close
date: 2026-05-17T00:00Z
severity: CRITICAL
area: security · DDoS protection
component: crates/aegis-security/src/ddos.rs
interop_contract: official rules §5.2 #03 (DDoS per-tier threshold) + §5.8 (fail-close/fail-open per tier)
status: open
test_mode: source-review
---

# F-CRITICAL-005 · DDoS has no per-tier threshold and no fail-close/fail-open per tier

## Summary

Official rules §5.2 #03 are specific:

> *"Burst detection + auto block + configurable threshold **per route tier**.
> Fail-close mode cho CRITICAL tier, fail-open cho MEDIUM/CATCH-ALL tier"*

§5.8 ("Graceful Degradation") repeats:

> *"Fail-close mode cho CRITICAL tier (routes nhạy cảm): từ chối tất
> cả traffic nếu WAF internal error — an toàn hơn là để traffic
> pass-through. Fail-open mode cho MEDIUM & CATCH-ALL tier: allow-through
> nếu WAF overloaded."*

Shipped `ddos.rs`:

- `DdosConfig` has ONE global `per_ip_limit` / `per_ip_window_s` —
  no per-tier override.
- `DdosRuntime::check(ip)` doesn't take a tier argument.
- The doc comment at lines 132-135 states the runtime fails OPEN on
  errors REGARDLESS of tier ("when StateBackend errors, we admit").
  Same fail-open default applies to `/login` (CRITICAL) and `/static/*`
  (MEDIUM).

## Observed code path

[ddos.rs:7-33](../../../../crates/aegis-security/src/ddos.rs#L7-L33) — `DdosConfig`:

```rust
pub struct DdosConfig {
    pub enabled: bool,
    pub observe_only: bool,
    pub per_ip_limit: u32,         // ← single global value
    pub per_ip_window_s: u32,
    pub spike_threshold_rps: u32,
    ...
    // No `tier_overrides: HashMap<Tier, PerIpLimit>` field.
}
```

[ddos.rs:209-253](../../../../crates/aegis-security/src/ddos.rs#L209-L253) — `check`:

```rust
pub fn check(&self, ip: IpAddr) -> Decision {
    //         ^^^^^^^^^^^^ no `tier` parameter
    ...
}
```

Default per-IP limit (`ddos.rs:39`) is hardcoded — e.g.
`per_ip_limit: 1000, per_ip_window_s: 10`. A real attacker doing
100 RPS slides under the limit; a legitimate API user
(authenticated, polling) doing 200 RPS could trip it. Neither is
the contract intent.

## Impact

- **§5.2 #03 violation** — single global threshold cannot satisfy
  "per route tier".
- **§5.8 violation** — no fail-close path on CRITICAL. An internal
  WAF error during the Attack Battle DDoS-against-WAF scenario lets
  traffic to `/login`, `/otp`, `/deposit`, `/withdrawal` straight
  through.
- **Security Effectiveness rubric (40/120)** — §5.2 #03 is "BẮT BUỘC"
  (mandatory).
- **Intelligence rubric (20/120)** — "Fail-close/fail-open behavior
  đúng per endpoint" is explicitly enumerated.
- **Attack Battle scenario 01 (DDoS L4/L7 incl. against WAF)** —
  the WAF's "graceful degradation behavior" is what gets graded;
  with fail-open on everything, the WAF degrades into "no WAF at
  all" under stress, which is the worst possible behaviour for
  CRITICAL routes.

## Suggested fix

### Add per-tier thresholds

```diff
 pub struct DdosConfig {
     pub enabled: bool,
     pub observe_only: bool,
-    pub per_ip_limit: u32,
-    pub per_ip_window_s: u32,
+    pub default_limit: PerIpLimit,
+    pub tier_overrides: HashMap<Tier, PerIpLimit>,
     pub spike_threshold_rps: u32,
     ...
 }

+pub struct PerIpLimit {
+    pub limit: u32,
+    pub window_s: u32,
+    pub failure_mode: FailureMode,   // FailClose | FailOpen
+}
```

Reasonable defaults aligned with the official rules table:

```yaml
ddos:
  default_limit:   { limit: 1000, window_s: 10, failure_mode: fail_open }  # CATCH-ALL
  tier_overrides:
    critical:      { limit: 30,   window_s: 60, failure_mode: fail_close } # /login /otp /deposit /withdraw
    high:          { limit: 200,  window_s: 10, failure_mode: fail_open }  # /api/* /game/* /user/*
    medium:        { limit: 500,  window_s: 10, failure_mode: fail_open }  # /static/* /assets/*
```

### Take `tier` in `check()`

```diff
-pub fn check(&self, ip: IpAddr) -> Decision { ... }
+pub fn check(&self, ip: IpAddr, tier: Tier) -> Decision {
+    let limit = self.cfg.tier_overrides
+        .get(&tier)
+        .unwrap_or(&self.cfg.default_limit);
+    let decision = self.check_against(ip, limit);
+    // Per-tier failure mode:
+    if matches!(decision, Decision::InternalError) {
+        match limit.failure_mode {
+            FailureMode::FailClose => Decision::Block,    // CRITICAL safe
+            FailureMode::FailOpen  => Decision::Allow,
+        }
+    } else {
+        decision
+    }
+}
```

### Gate auto_block on observe_only

Spot-verified: [ddos.rs:233-234](../../../../crates/aegis-security/src/ddos.rs#L233-L234) calls
`auto_block(ip)` unconditionally even when `observe_only=true`.
Side-effects during observation defeat the purpose of an observation
mode.

```diff
-self.state.auto_block(ip, ttl).ok();
+if !self.cfg.observe_only {
+    self.state.auto_block(ip, ttl).ok();
+}
```

### Plumb tier from data plane

The route table already carries tier info. Pass it through every
`check()` site:

```rust
let tier = route.tier;                       // already known
let decision = ddos.check(peer.ip(), tier);
```

## Verification

```sh
HOST="http://127.0.0.1:8080"

# CRITICAL tier: simulate WAF internal error and verify fail-close.
# (Hard to inject directly; can verify by setting tier_override to very
#  low limit and confirming /login blocks while /static/ passes at same RPS.)
for i in $(seq 1 50); do curl -sk "$HOST/login" -o /dev/null & done; wait
# Expect: many 429 / 503 — CRITICAL is hard-limited.

for i in $(seq 1 50); do curl -sk "$HOST/static/x.css" -o /dev/null & done; wait
# Expect: 50 × 200 — MEDIUM has a wider limit.

# Confirm tier mapping by checking audit log rule_id:
tail -5 ./waf_audit.log | jq '{path, rule_id}'
# Should show ddos.critical.* for /login, ddos.medium.* for /static.
```

Regression cases in `tests/security/`:
- DDoS per-tier limit asymmetry
- Fail-close on simulated internal error for CRITICAL tier
- Fail-open on simulated internal error for CATCH-ALL tier

## Severity rationale

CRITICAL. Two explicit §-clauses (§5.2 #03 + §5.8) unimplemented.
Attack Battle scenario 01 directly probes graceful-degradation
behavior under DDoS. Fix is a config-shape change + threading the
tier through. ~100 LoC.
