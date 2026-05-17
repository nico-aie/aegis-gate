---
id: 2026-05-17-high-contract-types-bundle
date: 2026-05-17T00:00Z
severity: HIGH
area: contract types
component: crates/aegis-core/src/{decision,tier,risk,context,audit,state}.rs
interop_contract: cross-crate type discipline + §5.5 / §3 / §6
status: open
test_mode: source-review
---

# F-HIGH-contract-types bundle — 6 type-shape issues in contract types (beyond F-CRITICAL-001..006)

---

## CT-01 · `decision.rs::Action` has no Serialize / Display impl

**Component:** [decision.rs](aegis-gate/crates/aegis-core/src/decision.rs) (whole file)

The enum doesn't derive Serialize and has no Display. Every consumer
hand-rolls a stringifier — and `aegis-control/src/interop/headers.rs:50`
does exactly that for a DIFFERENT parallel enum. Cross-crate drift
inevitable.

**Fix:** add `#[derive(Serialize)]` with `#[serde(rename_all = "snake_case", tag = "action")]`. Add `impl Display`. See F-CRITICAL-004 + F-CRITICAL-006 for the variant/string mapping table.

---

## CT-02 · `tier.rs` has no `classify_path` — policy logic lives in aegis-security

**Component:** [tier.rs](aegis-gate/crates/aegis-core/src/tier.rs) + `aegis-security/src/pipeline.rs:11`

`Tier` is a pure data type in this crate. The §4 path-classification
logic (`/login | /otp | /deposit | /withdrawal` → Critical, etc.)
lives in `aegis-security/src/pipeline.rs:11`. This means:

- The simulator (`aegis-control/src/api/simulator.rs:217`) depends
  on `aegis-security`.
- The proxy (`aegis-proxy/src/data_plane.rs:482`) depends on
  `aegis-security`.
- Any out-of-tree tier consumer (e.g. a test harness, future SDK
  user) drags in the entire security crate.
- The §4 table can't be audited from the contract-types crate
  alone.

**Fix:** move `classify_tier` (+ its config-driven path table) into
`aegis-core::tier`. Add an operator-config override surface
(`cfg.tiers.path_overrides: HashMap<String, Tier>`).

---

## CT-03 · `risk.rs::RiskKey` has no constructor — enables F-CRITICAL-001 (security audit)

**Component:** [risk.rs:1-9](aegis-gate/crates/aegis-core/src/risk.rs#L1-L9)

The struct is correctly shaped (4 axes: ip + device_fp + session +
tenant_id, derives `Hash + Eq + Clone`). But all fields are pub
with no `new()` / builder. A consumer can construct:

```rust
RiskKey {
    ip,
    device_fp: None,
    session: None,
    tenant_id: None,
}
```

— silently dropping 3 of 4 axes. This is the **structural enabler**
of F-CRITICAL-001 (security audit, RiskTracker keyed by IpAddr).
Compiler emits no warning.

**Fix:** add `RiskKey::from_request(&RequestCtx) -> Self` that pulls
all axes from a typed context. Add a `#[must_use]` doc warning that
bare struct construction is a bug pattern. Optionally `#[non_exhaustive]`
to prevent direct struct-literal construction outside the crate.

```rust
impl RiskKey {
    pub fn from_request(ctx: &RequestCtx) -> Self {
        Self {
            ip: ctx.peer.ip(),
            device_fp: ctx.device_fingerprint.clone(),
            session: ctx.session_id.clone(),
            tenant_id: ctx.tenant_id.clone(),
        }
    }
}
```

Plus `#[non_exhaustive]` on the struct.

---

## CT-04 · `context.rs::RequestCtx` missing `device_fp` + `session_id` fields

**Component:** [context.rs:6-13](aegis-gate/crates/aegis-core/src/context.rs#L6-L13)

`RequestCtx` carries `request_id`, `client.ip`, `tls_fingerprint`,
`h2_fingerprint`, `user_agent`, `tenant_id`, `trace_id`, free-form
`fields`. The two axes RiskKey needs (`device_fp`, `session`) are
NOT first-class — they'd have to be stuffed into
`fields: BTreeMap<String, FieldValue>` (line 12) and hoped-for at
every consumer.

**This is the structural enabler of F-CRITICAL-001 (security audit)**.
Even if RiskKey had a `from_request` helper (CT-03), there's no
typed source on RequestCtx.

**Fix:**

```diff
 pub struct RequestCtx {
     pub request_id: String,
     pub client: ClientInfo,
+    pub device_fingerprint: Option<String>,
+    pub session_id: Option<String>,
     pub tls_fingerprint: Option<String>,
     pub h2_fingerprint: Option<String>,
     pub user_agent: Option<String>,
     pub tenant_id: Option<String>,
     pub trace_id: Option<String>,
     pub fields: BTreeMap<String, FieldValue>,
 }
```

---

## CT-05 · `context.rs::RequestCtx` missing `tier: Option<Tier>` field

**Component:** [context.rs:6-13](aegis-gate/crates/aegis-core/src/context.rs#L6-L13)

Tier lives on `RouteCtx` (line 38). For tier-aware fail-mode in error
paths where no route matched (e.g. accept-stage failures, parse
errors), nothing carries the tier. Risk: §5.8 fail-close on CRITICAL
is unreachable when classification didn't complete.

**Fix:** add `pub tier: Option<Tier>` on `RequestCtx`, populated
post-classify. When tier is `None`, default-fail behavior should be
conservative (fail-close).

---

## CT-06 · `audit.rs::client_ip: String` instead of `IpAddr`

**Component:** [audit.rs:13](aegis-gate/crates/aegis-core/src/audit.rs#L13)

Stringly-typed IP defers normalization to every populator. F-CRITICAL-004
(audit `path` strips query, proxy audit) shares the same pattern —
untyped `String` lets the populator forget to normalize.

Cross-fix: this is included in F-CRITICAL-002 (rename `client_ip` →
`ip`) but flagging the TYPE issue separately. The rename should be
to `pub ip: IpAddr`, not `pub ip: String`.

**Fix:** see F-CRITICAL-002 diff. Add `IpAddr` to imports.

Bonus: add a separate `xff_chain: Vec<IpAddr>` field if XFF needs
surfacing for §5.6 dashboard (it's currently absent from `AuditEvent`).

---

## Severity rationale

HIGH. Each affects either cross-crate type discipline (CT-01, CT-02),
structural enablement of CRITICAL bugs elsewhere (CT-03, CT-04, CT-05),
or contract field typing (CT-06). None alone is CRITICAL.
