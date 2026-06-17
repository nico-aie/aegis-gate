---
id: 2026-06-17-F-V26-002
severity: MEDIUM
area: "interop · §2.5 set_profile unsupported handling"
component: crates/aegis-control/src/interop/control.rs:596 · control.rs:196 (status map)
contract: v2.6 §2.5 (Unsupported items)
status: open
test_mode: source-review
---

# F-V26-002 — `set_profile` returns 422 for an unknown feature in `policies` scope; v2.6 says 400/422 aborts the run

## Contract (v2.6 §2.5 — Unsupported items)
> 1. **(Recommended — safe for benchmark)** Return HTTP `200 OK` with a
>    machine-readable `unsupported` list … This is the safest approach and
>    **will not affect the benchmark run**.
> 2. **(Optional — punitive)** Return `400`/`422` … **the benchmark run will
>    be aborted after the current test completes.**
>
> When a WAF receives a `scope` it does not fully support … it SHOULD return
> `200 OK` and populate the `unsupported` list. If the WAF returns `400` or
> `422` for partially-supported profiles instead, the benchmark run will be
> aborted.

## What the code does
`validate_and_apply` handles three of the four unknown-target cases with the
**safe** 200 + `unsupported` list:

- unknown feature in `scope: features` → pushed to `unsupported`, 200
  (`control.rs:572-578`).
- unknown policy under a known feature in `scope: policies` → pushed to
  `unsupported`, 200 (`control.rs:599-604`).

But an **unknown feature name in `scope: policies`** returns an error:

```rust
// crates/aegis-control/src/interop/control.rs:596
let known = self.features.get(feature).ok_or_else(|| {
    ControlError::Unsupported(format!("feature {feature}"))
})?;
```

`ControlError::Unsupported` maps to **HTTP 422** (`control.rs:200`). The
dispatcher returns that status directly (`admin_dispatch.rs:1066`). The unit
test `set_profile_unknown_feature_in_policies_scope_returns_422` even pins
this behavior.

## Impact
If the benchmark probes a feature name the WAF doesn't expose via a
`policies`-scope call (plausible during capability discovery / negative
testing), the WAF answers 422. Per v2.6 that **aborts the benchmark run
after the current test** — potentially zeroing every remaining test in the
batch. This is a behavior the contract explicitly labels punitive and tells
WAFs to avoid.

This is a v2.6-specific risk: §2.5's "200 is recommended / 422 aborts"
language is sharper than the v2.3 text the code was written against (the
422 path predates v2.6).

## Fix (~3 LoC)
Treat an unknown feature in `policies` scope the same as the other unknown
cases — list it in `unsupported`, return 200:

```rust
SetProfileScope::Policies => {
    let feature = req.feature.as_ref().ok_or_else(|| BadRequest(..))?;
    let policies = req.policies.as_ref().ok_or_else(|| BadRequest(..))?;
    if policies.is_empty() { return Err(BadRequest(..)); }
    match self.features.get(feature) {
        None => {
            // unknown feature: report each requested policy as unsupported
            for p in policies { unsupported.push(format!("{feature}.{p}")); }
        }
        Some(known) => for p in policies {
            if !known.policies.contains(p) {
                unsupported.push(format!("{feature}.{p}"));
            } else {
                self.modes.set_policy(feature, p, mode);
            }
        }
    }
}
```

Keep `BadRequest` (400) only for genuinely malformed bodies (missing
required field, empty list, `scope:all` with extra fields) — those are not
"unsupported profile" cases and 400 is correct there.

## Verify
- Update `set_profile_unknown_feature_in_policies_scope_returns_422` to
  assert 200 + `unsupported == ["nope.x"]`.
- Live: `POST set_profile {scope:policies, feature:"does_not_exist",
  policies:["x"], mode:"log_only"}` → expect 200, not 422.
