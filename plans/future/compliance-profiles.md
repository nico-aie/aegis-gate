# Compliance Profiles — deferred-future plan

> **Status (2026-05-10): Deferred.** `cfg.compliance.modes` is
> still parsed, the dashboard's Compliance page surfaces the
> declared list as documentation tags, and the API exposes
> `compliance_modes` + `locked_classes` shapes — but
> `locked_classes` is always empty today, the clamp is a no-op,
> and operators may freely enable or disable any detector class
> regardless of which modes are declared.
>
> This document captures the per-regime feature plan we paused
> so future operators have a single restoration spec rather than
> recomposing it from scattered comments.

## Why deferred

Two reasons drove the 2026-05-10 deferral:

1. **Operator surprise.** With lock-by-mode active, an operator
   who turned on `pci_dss` then tried to disable `sqli` got a
   validation error with no obvious recovery path. The Compliance
   page was three pages away from the Detectors page where the
   click happened, and the YAML knob was the only escape hatch.

2. **Benchmark interaction.** The contract's `X-WAF-Risk-Score`
   accumulation+decay invariant (§5.1, §7) is best tested with a
   mask the benchmarker fully controls. Auto-pinning four classes
   when any mode is active complicated lifecycle test setup.

Removing the clamp does not remove the modes themselves — they
still document operator intent on the dashboard and remain
available as boot-time signals if a future feature needs them
(e.g. log-redaction toggles, retention floors, alert routing).

## Code anchor

Today's no-op behavior comes from one slice:

```rust
// crates/aegis-control/src/api/detectors.rs
const COMPLIANCE_PINNED: &[DetectorClass] = &[];
```

To bring lock-by-mode back, repopulate the slice with the
historical class list:

```rust
const COMPLIANCE_PINNED: &[DetectorClass] = &[
    DetectorClass::Sqli,
    DetectorClass::Xss,
    DetectorClass::PathTraversal,
    DetectorClass::Ssrf,
];
```

Then update / restore:

- the test assertions in `detectors.rs::tests`,
  `detectors_persist.rs::tests`,
  `dashboard_services.rs::tests::detector_mask_compliance_clamp_*`,
  `aegis-proxy/src/config_source/reload.rs::tests`, and
  `aegis-proxy/src/supervisor.rs::hot_reload_*` to verify the
  force-back behavior;
- the dashboard chip rendering (the `locked` short-circuit in
  `DetectorMaskCard::renderRow` already exists — empty list
  hides it today);
- the Compliance page banner copy (`PageCompliance` in
  `pages.jsx`) — remove the deferral notice;
- the `Detectors & Tiers` card subtitle — restore the
  "Locked classes (🔒) are pinned…" wording;
- the docs we trimmed: `README.md` "Compliance" bullet,
  `Architecture.md` §24 + Section 32 testing matrix,
  `docs/operator/usage.md` § Compliance Profiles,
  `docs/operator/profiles.md` `compliance.modes` rows.

## Future per-regime feature plan (paused)

When the lock comes back, these were the pre-deferral
per-regime expectations (from the original Architecture.md §24
+ docs/operator/profiles.md):

### FIPS 140-2 / 140-3
- TLS / HMAC / PRNG primitives sourced from the `aws-lc-rs`
  FIPS allowlist only.
- Boot fails fast if a non-FIPS primitive is referenced.

### PCI-DSS v4.0
- PAN masking in audit logs and outbound responses.
- TLS 1.2+ only on PCI-scope listeners.
- Audit retention floor ≥ 90 days.
- No CVV / CVC stored anywhere.

### SOC 2 (Common Criteria 6.1)
- Hash-chained audit log (already implemented).
- Admin change trail surfaced via `Audit Trail` page.
- Access-review export endpoint.
- SLI / SLO monitoring (already implemented on `Health & SLOs`).

### GDPR (Art. 32(1)(b))
- PII redaction before logs leave the node.
- Residency pinning — exporter refuses cross-region delivery.
- Right-to-erasure endpoint on `/api/gdpr/erase`.
- Retention ceiling enforcement.

### HIPAA (§164.312)
- PHI-safe log mode suppressing bodies + flagged headers on
  routes tagged `phi: true`.
- BAA dedication flag on per-tenant audit metadata.

### Cross-regime semantics
- Modes **stack**; the strictest setting wins.
- Conflicting config refused at load time (e.g. PCI demands
  TLS 1.2+ but `cfg.tls.min_version: "1.0"` would refuse boot).
- A single "compliance-mode profile" config switch flips
  every knob into the strictest regime.
- Dry-run validator (`waf validate --strict`) runs the
  compliance check before the `ArcSwap` swap.

### Detector pin baseline
The four classes pinned by *any* active mode (cross-section of
PCI 6.5, HIPAA §164.312, SOC 2 CC 6.1, GDPR Art. 32(1)(b)
detection mandates):

- `sqli`
- `xss`
- `path_traversal`
- `ssrf`

A future revision can broaden this with per-regime granularity
(PCI adds `command_injection`, HIPAA adds `nosql_injection`, …)
but the baseline above is what we shipped before the deferral.

## Restoration checklist

When ready to re-enable:

- [ ] Repopulate `COMPLIANCE_PINNED` (see code anchor above).
- [ ] Restore tests listed in the Code anchor section.
- [ ] Update dashboard messaging (Compliance banner, mask card
      subtitle, chip lock rendering — `locked` chip already
      handles non-empty list).
- [ ] Decide whether per-regime granularity is in-scope or
      keep the cross-section baseline.
- [ ] Implement the per-regime feature list (TLS allowlist,
      PAN masking, residency pinning, PHI log mode, …) — these
      are *separate* from the detector pin and were deferred
      together for grouping.
- [ ] Run the strict-profile boot tests once primitives land.

## Operator-facing communication when restoring

- Add a release note: "Compliance lock-by-mode is back. Setting
  `compliance.modes: [pci]` now pins sqli/xss/path_traversal/
  ssrf to ON; disabling them via the dashboard returns a
  validation error."
- Update operator docs (README, Architecture, usage, profiles)
  to drop the deferred-status banners.
- Refresh the Compliance dashboard banner to remove the
  deferral notice.
