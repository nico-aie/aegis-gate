# Compliance Modes (v2, enterprise)

> **Enterprise addendum.** FIPS 140-2/3, PCI-DSS, HIPAA, SOC 2, and
> GDPR modes enable specific technical controls — ciphers, retention,
> redaction, audit rigor — with a single config switch each.

## Purpose

Ship controls that auditors can tick off: cipher allowlists, retention
enforcement, data minimization, tamper-evident logging, change approval.
Turning on a mode **locks** conflicting options so an operator can't
accidentally weaken the posture.

## Supported modes

### FIPS 140-2 / 140-3

- Only `aws-lc-rs` FIPS-validated crypto provider
- Cipher allowlist enforced at config load
- TLS 1.2+ only; specific curve list (`P-256`, `P-384`)
- Random: `/dev/urandom` on Linux, FIPS DRBG on supported platforms
- Non-FIPS config items refused by validator, not silently downgraded

### PCI-DSS 4.0

- TLS 1.2+ only, weak suites refused
- 90-day minimum audit retention, 1-year recommended
- Card number patterns blocked in request + response bodies
- Admin access logged with actor + reason + approval
- Quarterly rule review tracked in the admin change log

### HIPAA

- PHI patterns redacted in audit logs and dashboard live feed
- Body scanning on PHI routes (`body_scan: true`)
- BAA-relevant config flags (dedicated infra, no cross-tenant logs)
- At-rest encryption required for the state backend
- Breach notification hook on access to PHI fields with no
  corresponding authorization claim

### SOC 2

- Hash-chain audit logging with external witness
- Change-approval gate on admin API mutations
- Quarterly access review exports
- Uptime / SLI metrics exposed via [`slo-sli-alerting.md`](./slo-sli-alerting.md)

### GDPR

- Right-to-erasure workflow (see
  [`data-residency-retention.md`](./data-residency-retention.md))
- Pseudonymization: client IP / UA stored as salted hash after N days
- Per-region pinning for audit sinks (data-residency)
- Explicit retention ceilings per event class

## Mode stacking

Modes stack. PCI + HIPAA + SOC 2 activates the strictest setting
from any of them for each control. The validator prints a summary
at load time:

```
[compliance] mode=fips+pci+hipaa+soc2
[compliance] tls_min=1.2 ciphers=fips+pci
[compliance] audit_retention_days=365 (pci floor=90, soc2 floor=365)
[compliance] hash_chain=required (soc2)
[compliance] redact_phi=required (hipaa)
```

## Refusal behavior

A config that violates an active mode is **rejected** at load time
with a specific error: `compliance: pci forbids TLS 1.1 (tls.min_version)`.
There is no "warn and continue" path.

## Configuration

```yaml
compliance:
  modes: [fips, pci, soc2]
  audit_retention_days: 365
  change_approval: required
  redact_phi: false
  data_residency:
    region: eu-west-1
```

## Implementation

- `src/compliance/mode.rs` — enum + stacking logic
- `src/compliance/validate.rs` — cross-config checks
- `src/compliance/ciphers.rs` — TLS allowlist per mode
- `src/compliance/retention.rs` — audit sink retention enforcement
- `src/compliance/report.rs` — auditor-friendly summary export

## Performance notes

- Mode checks run once at config load, not per request
- Cipher selection is a compile-time `rustls` config; zero runtime cost
- Redaction cost is already accounted for in
  [`response-filtering.md`](./response-filtering.md)
