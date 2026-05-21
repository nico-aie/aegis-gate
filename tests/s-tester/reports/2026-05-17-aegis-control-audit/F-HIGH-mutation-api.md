---
id: 2026-05-17-high-mutation-api-bundle
date: 2026-05-17T00:00Z
severity: HIGH
area: dashboard · mutation REST API
component: crates/aegis-control/src/api/{rules,upstreams_config,blacklist,simulator,mtls_ca_bundle,rollback}.rs · crates/aegis-control/src/api/mtls_mode.rs
interop_contract: Round-1 "Tính hiệu lực" · §5.4 rule validation
status: open
test_mode: source-review
---

# F-HIGH-mutation-api bundle — 7 issues in mutation API beyond F-CRITICAL-001/014

---

## MA-01 · `validate_rule_body` is a stub (accepts "this is not a rule")

**Component:** [api/rules.rs:97-130](../../../../crates/aegis-control/src/api/rules.rs#L97-L130)

The doc comment line 96 admits: *"Toy validator. Real grammar lives in `aegis-security`."* It checks empty-body + size + a TODO marker
sentinel. The actual rule linter from `aegis_security::rules` is NOT
invoked. PUT body `{"id":"x","body":"this is not a rule"}` is accepted
and persisted.

§5.4 requires "Rule format: YAML hoặc TOML. Rule phải có: condition (match), action (allow/block/challenge/rate-limit), risk_score_delta".
A stub validator doesn't enforce any of that.

Combined with F-CRITICAL-001 (rule changes don't reach data plane):
the validation gap doesn't bite TODAY but will the moment rules
actually fire.

**Fix:** call `aegis_security::rules::Linter::lint(&parsed_rule)?` from `validate_rule_body`. Reject on any error.

---

## MA-02 · `validate_pool` no SSRF cap on operator-supplied upstream members

**Component:** [api/upstreams_config.rs:252-280](../../../../crates/aegis-control/src/api/upstreams_config.rs#L252-L280)

`validate_pool` accepts `members: Vec<Member>` with no:
- Upper bound on `len()` (operator can paste 100k members)
- Loopback / link-local rejection (operator can route to `169.254.169.254:80`)
- Internal CIDR rejection (operator can route to `10.0.0.0/8`)

Combined with F-CRITICAL-002 (no admin auth) → anonymous attacker
adds an upstream pool pointing at the cloud metadata endpoint,
adds a route to it, exfils IMDS responses through the WAF.

**Fix:** add validation:

```rust
fn validate_member(member: &Member) -> Result<()> {
    let addr = parse_addr(&member.addr)?;
    if addr.ip().is_loopback() || addr.ip().is_private() || is_link_local(addr.ip()) {
        return Err(ValidationError::ForbiddenInternalAddress);
    }
    Ok(())
}

fn validate_pool(pool: &Pool) -> Result<()> {
    if pool.members.len() > MAX_MEMBERS_PER_POOL {       // e.g. 256
        return Err(ValidationError::TooManyMembers);
    }
    for m in &pool.members { validate_member(m)?; }
    Ok(())
}
```

Operator can opt-in to internal IPs via `cfg.upstreams.allow_internal_addresses: true` for split-horizon deployments.

---

## MA-03 · `blacklist::bulk_insert` no cap, N mutex re-locks

**Component:** [api/blacklist.rs:354-402](../../../../crates/aegis-control/src/api/blacklist.rs#L354-L402)

`bulk_insert` re-locks the underlying mutex once per entry inside a
loop with no upper bound on N. An operator paste of 10M lines is
accepted: O(N) memory, O(N) lock churn, validate-then-apply iterates
the same Vec twice without releasing capacity.

DoS vector on `/api/blacklist`.

**Fix:**
1. Cap input size at the body-size limit (after F-HIGH-admin A-01 in proxy audit lands).
2. Cap `entries.len() <= MAX_BULK_BLACKLIST` (e.g. 10_000); return 400 if exceeded.
3. Take the mutex ONCE around the whole insert loop.

---

## MA-04 · `simulator` shares LIVE detector mask + no body cap

**Component:** [api/simulator.rs:64, 222-249](../../../../crates/aegis-control/src/api/simulator.rs#L222-L249)

Doc at lines 1-9 claims "no side effects". True for risk store, but
`simulate()` calls `mask.resolve(...)` against the LIVE
`SharedDetectorMask`. An operator disabling sqli on the Detectors
page silently changes simulator verdicts.

Plus: `SimulateRequest.body` has no size cap. A 100 MB body fed to
every detector via `/api/rules/simulate` = admin DoS.

**Fix:**

```diff
+const MAX_SIMULATE_BODY: usize = 64 * 1024;     // 64 KiB
 pub fn simulate(req: SimulateRequest, ...) {
+    if req.body.len() > MAX_SIMULATE_BODY {
+        return Err(SimulateError::BodyTooLarge);
+    }
     ...
 }
```

For mask isolation: snapshot the mask once at handler entry; pass
the snapshot to `run_all_filtered_observed`. Operator changes
mid-simulation don't affect it.

---

## MA-05 · `rollback::apply_detector_mask_rollback` skips compliance clamp

**Component:** [api/rollback.rs:206-208, 638](../../../../crates/aegis-control/src/api/rollback.rs#L206)

`apply_detector_mask_rollback` calls `mask.store_state` UNCONDITIONALLY,
including with a `before` field that produces a non-compliant mask
state. The forward PUT path (`detectors.rs:205-221`) runs through
`enforce_compliance_clamp` first — rollback doesn't.

A historical audit entry with sqli=false (recorded BEFORE PCI mode
was turned on) gets rolled back into a now-PCI-compliant deployment
→ sqli flips off in violation of the compliance pin.

(Note: per F-CRITICAL-002, `COMPLIANCE_PINNED` is currently empty
so the clamp is a no-op anyway. After F-CRITICAL-002 is fixed, this
HIGH becomes immediately exploitable.)

**Fix:** mirror the forward path — call `enforce_compliance_clamp`
after `store_state`:

```rust
let mut rolled_state = parse_state(&event.fields.before)?;
mask.store_state(rolled_state.clone());
let mut clamped = mask.resolve(...);
enforce_compliance_clamp(&mut clamped, &services.compliance_modes);
mask.store_state(clamped);
```

---

## MA-06 · `mtls_mode` PUT sets `requires_restart: true` instead of hot-swapping

**Component:** [api/mtls_mode.rs:120-126](../../../../crates/aegis-control/src/api/mtls_mode.rs#L120-L126)

`render_mode_response` sets `requires_restart: true` whenever the
override differs from configured. The store updates an ArcSwap but
the rustls acceptor is only rebuilt on cfg.tls swaps.

Operator flips `disabled → required` in the UI → dashboard says
"saved" but client cert is still optional until process restart.

This is a "Tính hiệu lực" miss (similar shape to F-CRITICAL-001).
Round-1 says hot-reload ≤10 s with UI confirmation.

**Fix:** plumb a `Notify` from the mtls_mode store to the listener
to rebuild the rustls acceptor in place. Or accept the requires_restart
limitation BUT only when documented in the response (today the response
just sets the bool — the UI needs to surface it).

---

## MA-07 · `mtls_ca_bundle` no upper PEM size cap, no parser fuel limit

**Component:** [api/mtls_ca_bundle.rs:107-146](../../../../crates/aegis-control/src/api/mtls_ca_bundle.rs#L107-L146)

`parse_and_preview` iterates `rustls_pemfile::certs` until
exhaustion, calling SHA-256 on every cert block. 1 GB of
`-----BEGIN CERTIFICATE-----` blocks crashes the admin listener.

**Fix:** check `pem.len() > MAX_BUNDLE_BYTES` (e.g. 1 MiB) at the
top of `parse_and_preview`. Optionally cap cert count at 1024.

---

## Severity rationale

HIGH. Each affects either a Round-1 mandate (MA-06 hot-reload) or
operator-DoS / SSRF vectors (MA-02, MA-03, MA-04, MA-07). MA-01 +
MA-05 are correctness gaps that compound with F-CRITICAL-001/002.
