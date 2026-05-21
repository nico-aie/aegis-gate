---
id: 2026-05-17-compliance-modes-are-theater
date: 2026-05-17T00:00Z
severity: CRITICAL
area: dashboard · compliance modes
component: crates/aegis-control/src/api/detectors.rs (COMPLIANCE_PINNED) · crates/aegis-control/src/compliance/*.rs (fips/pci/gdpr/hipaa/soc2)
interop_contract: Round-1 "Tính hiệu lực" · README claim of "compliance modes"
status: open
test_mode: source-review (spot-verified)
---

# F-CRITICAL-002 · `COMPLIANCE_PINNED = &[]` + TLS stack ignores compliance config fields → FIPS/PCI/HIPAA dashboard toggles do NOTHING

## Summary

The dashboard's Compliance page lets operators enable FIPS / PCI /
SOC2 / GDPR / HIPAA modes. Each profile (`compliance/{fips,pci,gdpr,hipaa,soc2}.rs::apply`)
mutates `cfg.compliance.min_tls_version`,
`cfg.compliance.disallow_algorithms`, `pseudonymize_ip`,
`retention_days`, etc. But:

**Half 1: Detector mask pinning is a no-op.**
Spot-verified at [api/detectors.rs:113](../../../../crates/aegis-control/src/api/detectors.rs#L113):

```rust
const COMPLIANCE_PINNED: &[DetectorClass] = &[];
```

The empty const makes `enforce_compliance_clamp` (lines 117 + 131) a
no-op for every mode. The test at `dashboard_services.rs:901-965`
literally asserts "lock is deferred — sqli flips off as proposed".
So an operator with "PCI mode on" can still disable SQLi via
`PUT /api/detectors` and nothing forces it back.

**Half 2: TLS profile fields are never read.**
`compliance::fips::apply` mutates `cfg.compliance.min_tls_version` and
`disallow_algorithms`. `compliance/fips.rs::provider_for(cfg)`
returns `"aws-lc-rs"`. But:

```sh
grep -rn "min_tls_version\|disallow_algorithms" crates/aegis-proxy/src/
```

returns **ZERO HITS**. The TLS stack in `listener/tls.rs:141` and
`listener/tls_policy.rs:55` installs `ring` unconditionally,
regardless of `fips::provider_for(cfg)`.

Result: FIPS mode is dashboard-only theater. The "FIPS mode on" badge
appears, but the WAF runs `ring` (non-FIPS) and accepts any TLS
version cfg.tls.min_protocol_version was originally set to.

## Observed code path

[api/detectors.rs:113-145](../../../../crates/aegis-control/src/api/detectors.rs#L113-L145):

```rust
const COMPLIANCE_PINNED: &[DetectorClass] = &[];   // empty!

pub(crate) fn is_compliance_pinned(class: DetectorClass, modes: &ComplianceModes) -> bool {
    !modes.is_empty() && COMPLIANCE_PINNED.contains(&class)
    //                                     ^^^^^^^^ always false
}

pub(crate) fn enforce_compliance_clamp(mask: &mut ResolvedMask, modes: &ComplianceModes) {
    if modes.is_empty() {
        return;
    }
    for &class in COMPLIANCE_PINNED {   // empty loop
        mask.set(class, true);
    }
}
```

[compliance/fips.rs:32-45](aegis-gate/crates/aegis-control/src/compliance/fips.rs#L32-L45) — `apply` sets `cfg.compliance.min_tls_version = "1.3"`,
`cfg.compliance.disallow_algorithms = ["sha1", "md5"]`. But the
TLS listener constructor never reads either field.

Compounding: per the audit agent, `compliance::apply` is invoked in
`aegis-bin/src/main.rs:386` ONLY for `cmd_validate` (the `waf validate`
CLI). The proxy boot path (`aegis-proxy/src/run.rs:285-301`) only
re-applies `apply_live_mask_with_compliance` which calls the same
empty `COMPLIANCE_PINNED` clamp. On `waf run`, the compliance
config-mutations never fire at all.

## Impact

- **Round-1 "Tính hiệu lực" Pass/Fail** — fails. UI toggle "PCI on" → no behavior change. BTC verifies via real traffic per spec.
- **README claim** of "Compliance modes — `cfg.compliance.modes` accepts documentation tags (fips, pci, soc2, gdpr, hipaa)" — true that the tags are accepted; FALSE that anything enforces.
- The README itself half-admits: *"Lock-by-mode (auto-pinning detector classes when a mode is active) is deferred"*. But the deferral is total — even TLS profile (the part NOT deferred per the README) isn't wired either.
- **Strategic risk**: if BTC asks "show me PCI mode in action" and the team can't demonstrate behavior change, this becomes a "documentation lies" item that may cast doubt on every other claim.

## Suggested fix

### Wire TLS profile fields

```rust
// aegis-proxy/src/listener/tls.rs::build_server_config:
let mut builder = rustls::ServerConfig::builder()
    .with_safe_default_cipher_suites()
    .with_safe_default_kx_groups()
    .with_protocol_versions(&match cfg.compliance.min_tls_version.as_deref() {
        Some("1.3") => &[&rustls::version::TLS13],
        Some("1.2") => &[&rustls::version::TLS12, &rustls::version::TLS13],
        _           => rustls::ALL_VERSIONS,
    })?;

// Provider selection (FIPS → aws-lc-rs):
let provider = match crate::compliance::fips::provider_for(cfg) {
    "aws-lc-rs" => rustls::crypto::aws_lc_rs::default_provider(),
    _           => rustls::crypto::ring::default_provider(),
};
provider.install_default().unwrap();
```

### Populate `COMPLIANCE_PINNED` per mode

Split into per-mode constants:

```rust
const PCI_PINNED:   &[DetectorClass] = &[DetectorClass::Sqli, DetectorClass::Xss, DetectorClass::PathTraversal, DetectorClass::Ssrf, DetectorClass::HeaderInjection];
const HIPAA_PINNED: &[DetectorClass] = &[/* same as PCI + body-abuse for PHI shapes */];
const SOC2_PINNED:  &[DetectorClass] = &[/* full set */];
const FIPS_PINNED:  &[DetectorClass] = &[/* full set; FIPS demands tested crypto everywhere */];
const GDPR_PINNED:  &[DetectorClass] = &[/* DLP class + body-abuse for PII shapes */];

pub(crate) fn enforce_compliance_clamp(mask: &mut ResolvedMask, modes: &ComplianceModes) {
    if modes.fips { for &c in FIPS_PINNED { mask.set(c, true); } }
    if modes.pci  { for &c in PCI_PINNED  { mask.set(c, true); } }
    ...
}
```

Update the failing test at `dashboard_services.rs:901-965` to assert
that PCI-mode sqli flip-off is REJECTED.

### Re-apply on boot

Move `compliance::apply` from `cmd_validate`-only to
`build_security_pipeline` in the proxy boot path so config mutations
land on `waf run` too.

## Verification

```sh
# Enable PCI mode.
curl -sk -X PUT "$HOST/api/compliance" -d '{"modes":["pci"]}'

# Try to disable SQLi detector via dashboard.
curl -sk -X PUT "$HOST/api/detectors" -d '{"mask":{"sqli":false}}' -i
# Expect: 403 with body explaining PCI pinning.
# Today: 200, sqli flips off.

# Probe TLS:
echo "" | openssl s_client -connect 127.0.0.1:8443 -tls1_2 2>&1 | grep "Cipher\|Protocol"
# Expect: TLS 1.3 only (per PCI minimum).
# Today: TLS 1.2 negotiates fine.

# Provider check:
curl -sk http://127.0.0.1:9443/api/about | jq .tls_provider
# Expect: "aws-lc-rs" when fips=on. Today: "ring".
```

## Severity rationale

CRITICAL. Two distinct failures (mask pinning + TLS profile) that
together negate the entire compliance feature. Round-1 "Tính hiệu lực"
Pass/Fail. The README claim is partly honest ("deferred") but
operators reading the dashboard see no warning.
