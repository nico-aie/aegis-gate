# Fix plan — `jwt_inspection` can't be disabled from Detectors & Tiers

> **Status:** Drafted 2026-06-12. Code-verified against `develop`.
> QC: toggling **JWT inspection** off in the Detectors & Tiers card has no
> effect — JWT attacks keep being blocked. **Severity:** Medium (operator can't
> turn the class off; not a security hole, the opposite).

---

## 1. Root cause (confirmed)

The runtime mask wiring for `jwt_inspection` is **complete** — id `"jwt_inspection"`
maps to `DetectorClass::JwtInspection` (bit `1<<16`), and the dispatcher gates
it via `mask.is_enabled_id`. So at the detector-chain level it *would* honour
the bit.

The break is in the **mask-PUT → config-doc translation**. A toggle on
`/api/detectors` is folded into the persisted YAML by `patch_detectors`
(`crates/aegis-proxy/src/admin_mutate.rs`), which carries a **hardcoded list**
of `(DetectorClass, mask.field)` pairs to write `cfg.detectors.<class>.enabled`.
That list — and the sibling per-tier-override list — were **never updated for
`jwt_inspection`** when the class was added (Phase A2):

- `admin_mutate.rs:~3675` (base mask, in `patch_detectors`): lists sqli … canary
  (15 classes) + ai sibling, **missing `JwtInspection`**. The comment still says
  "the other 15 mask bits".
- `admin_mutate.rs:3606-3622` (per-tier override `tier_override_yaml`): the
  `("name", mb.field)` list is likewise **missing `("jwt_inspection", …)`**.

**Effect:** the dashboard sends `jwt_inspection: false`, but `patch_detectors`
never writes `detectors.jwt_inspection.enabled = false`. The config keeps the
default (`enabled: true`); on activation the rebuilt mask
(`MaskState::from_detectors_config`) re-derives the bit as ON, so the detector
keeps running. The toggle silently no-ops.

This is the **same family** as the velocity bug (a per-detector enumeration
site that drifted), but a *different* site — the `all_registered_detectors_map_to_a_class`
drift guard added for velocity checks `id()` ↔ class, not `patch_detectors`
completeness, so it didn't catch this.

## 2. Fix

1. **`patch_detectors` base list** — add
   `(DetectorClass::JwtInspection, mask.jwt_inspection)` to the loop at
   `admin_mutate.rs:~3675`; bump the "other 15" comment to 16.
2. **`tier_override_yaml` list** (`admin_mutate.rs:3606`) — add
   `("jwt_inspection", mb.jwt_inspection)` so per-tier JWT overrides persist too.
   (`cfg.detectors.jwt_inspection` is a `JwtInspectionConfig` with an `.enabled`
   field, like `OpenRedirectConfig`, so the `yaml_child_map(...).enabled` write
   path already works.)

## 3. Guard against recurrence (do this — it's the systemic fix)

Add a drift-guard test that fails the build whenever a `DetectorClass` is added
without wiring `patch_detectors`. Build a `DetectorMaskBody` with every class
disabled, run `patch_detectors`, and assert every `cfg.detectors.<class>.enabled`
(and the `ai` sibling) is written `false`:

```rust
#[test]
fn patch_detectors_writes_every_detector_class() {
    use aegis_security::detectors::{DetectorClass, DetectorMask, DetectorMaskBody};
    let mb = DetectorMaskBody::from(DetectorMask::none()); // all off
    let out = patch_detectors(BASE_YAML, &put_body_with_mask(mb)).unwrap();
    let v: serde_yaml::Value = serde_yaml::from_str(&out).unwrap();
    for c in DetectorClass::ALL {
        if c == DetectorClass::Ai { // routes to the cfg.ai sibling block
            assert_eq!(v["ai"]["enabled"].as_bool(), Some(false));
            continue;
        }
        assert_eq!(
            v["detectors"][c.as_str()]["enabled"].as_bool(), Some(false),
            "patch_detectors didn't write detectors.{}.enabled", c.as_str(),
        );
    }
}
```

This closes the *class* of bug: any future detector that's added to
`DetectorClass::ALL` but not to the `patch_detectors` list fails CI here, the
same way the velocity guard does for id↔class drift.

## 4. Testing
- Unit: the §3 guard; existing `patch_detectors_*` tests stay green.
- Integration / manual: toggle `jwt_inspection` off in Detectors & Tiers, send a
  `Cookie: sid=<alg:none JWT>` request, confirm it is **allowed** (no
  `jwt_alg_none` block) and the audit shows the class disabled. Re-enable →
  blocks again. Mind the dev single-IP / XFF reset between runs
  ([[feedback_dev_xff_single_ip_gates]]); verify outcome via HTTP status /
  `X-WAF-Mode`, not `X-WAF-Action` ([[feedback_waf_action_vs_mode]]).

## 5. Scope
Trivial, isolated, no schema/UI change (the dashboard already renders the
toggle + sends the field; only the backend fold was incomplete). One small PR.

## 6. Related
- `VELOCITY_SEQUENCE_BUG_REPORT.md` — same family (enumeration-site drift),
  different site. The velocity drift-guard doesn't cover `patch_detectors`.
- Phase A2 (`jwt-and-smuggling-detection.md`) — where `JwtInspection` was added;
  `patch_detectors` was the one wiring site missed.
