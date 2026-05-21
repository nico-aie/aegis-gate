---
id: 2026-05-17-medium-bundle-aegis-core-audit
date: 2026-05-17T00:00Z
severity: MEDIUM
area: multiple
component: per-item — see Component line
interop_contract: latent / posture / fragility
status: open
test_mode: source-review
---

# F-MEDIUM bundle — ~30 MEDIUM-grade findings from the aegis-core audit

---

## config.rs

### M-01 · No regex compile-check at config parse
**Component:** [config.rs:1780-1788](../../../../crates/aegis-core/src/config.rs#L1780-L1788) + DLP regexes line 2263
Operator regexes not compiled at parse → ReDoS-prone patterns panic/hang at runtime instead of failing boot. `strict_compile: false` default. Flip to true and compile via `RegexBuilder::size_limit/dfa_size_limit`.

### M-02 · No rule conflict detection across `RateLimitRule`s
**Component:** [config.rs:1804-1815](../../../../crates/aegis-core/src/config.rs#L1804-L1815)
Duplicate `id` or contradictory `scope/key/algo` combinations not detected. `validate()` should build `HashSet<&str>` and reject duplicates for `routes[*].id` and `rate_limit.buckets[*].id`.

### M-03 · `RouteConfig.methods` not validated
**Component:** [config.rs:723](../../../../crates/aegis-core/src/config.rs#L723)
Operators can write `methods: [POST, foo, bar]` and it parses. Validate against known-method allowlist.

### M-04 · `StateConfig` doesn't cross-check `Redis` backend with `redis:` block
**Component:** [config.rs:1689-1697](../../../../crates/aegis-core/src/config.rs#L1689-L1697)
Bare `backend: redis` with `redis: None` parses; should fail at `validate()`.

### M-05 · `RedisConfig.urls: Vec<String>` unvalidated
**Component:** [config.rs:1759-1767](../../../../crates/aegis-core/src/config.rs#L1759-L1767)
Typos like `redi://...` silently pass. Parse each URL in `validate()`.

### M-06 · `MemberConfig.host_header` SNI gap docstring not in top-level
**Component:** [config.rs:1396-1426](../../../../crates/aegis-core/src/config.rs#L1396-L1426)
Multi-paragraph TODO acknowledges the SNI gap; track at top-level too.

### M-07 · `OtelConfig.headers` carries auth tokens in clear text
**Component:** [config.rs:2304-2330](../../../../crates/aegis-core/src/config.rs#L2304-L2330)
Same secret-hygiene concern as `*_ref` fields. Require `${secret:env:NAME}` form.

### M-08 · `WafConfig::validate()` missing port-collision check between admin + listeners
**Component:** [config.rs:380-533](../../../../crates/aegis-core/src/config.rs#L380-L533)
- `admin.bind` differs from `listeners.data[*].bind`?
- `tls.advertise_h3` only set when H3 listener exists?
- `acme.challenge: Http01` requires `listeners.force_https`?
- `Pool.scheme == Grpc` ⇒ `connection.tls = true`?

All boot-time-detectable; none currently checked.

### M-09 · `OpenRedirectConfig.allowed_domains` glob entries not validated
**Component:** [config.rs:2222-2236](../../../../crates/aegis-core/src/config.rs#L2222-L2236)
`*.*.example.com` or bare `*` silently slips through.

### M-10 · Test-asserted hardcoded values pin operator-facing defaults
**Component:** [config.rs:2873-2879, 3063-3083](../../../../crates/aegis-core/src/config.rs#L2873-L2879)
`risk_config_defaults` test pins the (wrong) 40/80 in unit scope. Constrains schema evolution.

### M-11 · `ConfigEvent::Failed { error: String }` loses structured context
**Component:** [config.rs:14-20](../../../../crates/aegis-core/src/config.rs#L14-L20)
Use `serde_json::Value` or dedicated error enum for SIEM-friendly emission.

### M-12 · No `#[serde(rename_all = "snake_case")]` on `WafConfig` itself
**Component:** [config.rs root](../../../../crates/aegis-core/src/config.rs)
Field names are snake_case by Rust convention so they round-trip, but discipline is implicit not declared.

### M-13 · `DetectorToggle` has no per-detector tuning surface
**Component:** [config.rs:2106-2109](../../../../crates/aegis-core/src/config.rs#L2106-L2109)
Only `enabled`. Operators will want SQLi confidence threshold, max-payload-bytes-per-scan, etc.

### M-14 · `audit.pseudonymize_ip` HMAC key not exposed in schema
**Component:** [config.rs:2389](../../../../crates/aegis-core/src/config.rs#L2389)
No `pseudonymize_key_ref: Option<String>`. Algorithm undocumented.

---

## audit.rs

### M-15 · Missing `device_fp` first-class field
**Component:** [audit.rs (entire file)](../../../../crates/aegis-core/src/audit.rs)
§5.6 dashboard audit log includes `device_fp`. Add `pub device_fp: Option<String>`.

### M-16 · `AuditBus` swallows send failures silently
**Component:** [audit.rs:31-45](../../../../crates/aegis-core/src/audit.rs#L31-L45)
Line 39 `let _ = ...` — dropped emissions should increment a counter.

---

## tier.rs

### M-17 · `FailureMode` no Serialize/Deserialize/as_str
**Component:** [tier.rs:21-23](../../../../crates/aegis-core/src/tier.rs#L21-L23)
Hot path can't render for audit/dashboard. Test at line 51 only validates mapping not wire form.

---

## load_mode.rs

### M-18 · No tier-aware admission API
**Component:** [load_mode.rs (entire file)](../../../../crates/aegis-core/src/load_mode.rs)
`LoadMode` controls audit detail. No `decide_admit(tier, mode) -> bool` per §5.8. Tier failure-mode and load mode never meet.

### M-19 · Spawned task never observes shutdown
**Component:** [load_mode.rs:296](../../../../crates/aegis-core/src/load_mode.rs#L296)
Task holds clone of `Arc<LoadGaugeInner>` and leaks if gauge owner drops. Thread a `tokio::sync::watch::Receiver<bool>`.

### M-20 · `(count as f64 / secs).round() as u64`
**Component:** [load_mode.rs:245](../../../../crates/aegis-core/src/load_mode.rs#L245)
f64→u64 saturating cast loses precision above 2^53. Not realistic at WAF rates but flag.

---

## state.rs

### M-21 · `add_risk` `delta: i32` admits arbitrary negative
**Component:** [state.rs:154-155](../../../../crates/aegis-core/src/state.rs#L154-L155)
No clamp documented. Document saturation semantics.

### M-22 · `health()` default returns `connected: true`
**Component:** [state.rs:170](../../../../crates/aegis-core/src/state.rs#L170)
"Unknown is assumed up" on security-critical trait. Backend swap forgetting `health()` override is invisible to ops. Re-confirm dashboard alert pattern matches `"unknown"` label.

---

## pipeline.rs

### M-23 · `OutboundAction::Abort` has no rule_id, no status code
**Component:** [pipeline.rs:48](../../../../crates/aegis-core/src/pipeline.rs#L48)
Less metadata than `Decision::Block`. Downstream sinks can't attribute.

---

## tcp_destination.rs

### M-24 · `ipnet::Ipv4Net::new(v4, 32).unwrap()` — defensible but fragile
**Component:** [tcp_destination.rs:128-129](../../../../crates/aegis-core/src/tcp_destination.rs#L128-L129)
Current ipnet contract guarantees ≤32/≤128 succeed. Future major bump could invalidate. Use `expect("prefix /32 and /128 are constants")`.

### M-25 · `parse_authority` doesn't validate port != 0
**Component:** [tcp_destination.rs:215-226](../../../../crates/aegis-core/src/tcp_destination.rs#L215-L226)
`"203.0.113.1:0"` returns `Some((addr, 0))`. Inconsistent with `parse_rule` which rejects port 0.

### M-26 · `parse_authority` no IDN/punycode handling, no length cap
**Component:** [tcp_destination.rs:215-226](../../../../crates/aegis-core/src/tcp_destination.rs#L215-L226)
DNS authority not validated. Add sibling `parse_dns_authority` with `ascii_only && len <= 253 && labels <= 63`.

---

## break_glass.rs

### M-27 · No TTL / auto-deactivate
**Component:** [break_glass.rs:47-56](../../../../crates/aegis-core/src/break_glass.rs#L47-L56)
Break-glass is forever-on for process lifetime. Forgotten env var on long-running pod = silent failure. Add `BREAK_GLASS_DEADLINE: Instant`.

### M-28 · Process-global statics with no per-test isolation
**Component:** [break_glass.rs:38-40](../../../../crates/aegis-core/src/break_glass.rs#L38-L40)
`_reset_for_test` gated `cfg(test)` of this crate only. Integration-test crates can't reset.

---

## sd.rs

### M-29 · `MemberAddr` has no health/last-seen field
**Component:** [sd.rs:3-8](../../../../crates/aegis-core/src/sd.rs#L3-L8)
Per-endpoint health lives in proxy discovery impl. Consumers can't filter dead endpoints uniformly.

### M-30 · `ServiceDiscovery` trait has zero impls workspace-wide
**Component:** [sd.rs:11-15](../../../../crates/aegis-core/src/sd.rs#L11-L15)
Same dead-trait pattern as ClusterMembership. Consul impl uses a local non-trait type at `sd/consul.rs`.

---

## lib.rs

### M-31 · Bulk pub use re-exports legacy traits
**Component:** [lib.rs:23-42](../../../../crates/aegis-core/src/lib.rs#L23-L42)
`ClusterMembership`, `Lease`, `NodeInfo` re-exported alongside live `LeaseStore`. Drop dead re-exports.

---

## Severity rationale

All MEDIUM because each:
- Affects a narrow case OR is latent OR
- Is fragility / hygiene rather than active bug OR
- Is operator-edge

None alone justifies an individual file. Bundled for a single
hardening PR.
