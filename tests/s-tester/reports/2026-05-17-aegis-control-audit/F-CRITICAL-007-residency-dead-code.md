---
id: 2026-05-17-residency-dead-code
date: 2026-05-17T00:00Z
severity: CRITICAL
area: data residency · GDPR
component: crates/aegis-control/src/residency.rs
interop_contract: README claim "data residency pin required for GDPR" · compliance/mod.rs:11
status: open
test_mode: source-review (spot-verified via grep)
---

# F-CRITICAL-007 · `residency.rs` (527 LoC) is dead code — README's GDPR region-pin claim is unenforced

## Summary

`residency.rs` is a 527-line module with `RegionPin`, `sweep`,
`erase_subject`, `rechain`, and tests. Production callers: ZERO.

**Spot-verified** with `grep -rn "RegionPin\|residency::" crates/ --include="*.rs" | grep -v "src/residency.rs"`: returns ZERO HITS outside the file's own tests.

README promises that GDPR compliance mode pins data residency:

> *Compliance modes — `cfg.compliance.modes` accepts documentation
> tags (fips, pci, soc2, gdpr, hipaa) ... locks-by-mode...*

`compliance/gdpr.rs::apply` mutates `cfg.compliance.region_pin` and
similar fields, but no boot path constructs a `RegionPin` from those
values, and no audit-spool / state-backend / sink consults
`RegionPin::allows` before write.

So an operator who enables "GDPR mode":
- sees the dashboard badge
- gets the compliance.rs config mutations applied to in-memory cfg
- has NO actual region admission control
- audit events ship to whatever sink is configured, regardless of
  region restriction

## Observed code path

`residency.rs` defines:

```rust
pub struct RegionPin {
    pub allowed_regions: Vec<String>,
    pub strict: bool,
    ...
}

impl RegionPin {
    pub fn allows(&self, region: &str) -> bool { ... }
}

pub fn sweep(...) -> SweepResult { ... }            // PII expiry
pub fn erase_subject(...) -> Result<()> { ... }     // GDPR right-to-erasure
pub fn rechain(...) -> Result<()> { ... }           // audit re-hash after erasure
```

```sh
$ grep -rn "RegionPin\|residency::" crates/ --include="*.rs" | grep -v "src/residency.rs"
# (no output)
```

Zero call sites.

## Impact

- **README veracity** — GDPR / residency are claimed features. Not delivered.
- **GDPR compliance posture** — operators relying on the WAF for GDPR auditing get no actual region enforcement, no right-to-erasure flow, no PII sweep.
- **Combined with F-CRITICAL-002** (compliance modes are theater) — the entire compliance story collapses for any judge probing deeper than the badge.

## Suggested fix

### Path A — Wire it

1. At boot in `aegis-proxy/src/run.rs`, construct `RegionPin` from
   `cfg.compliance.region_pin` (or `cfg.residency.allowed_regions`).
2. Pass to audit-chain writers, state-backend writers, sinks. Each
   write call checks `region_pin.allows(self.region)`; on deny,
   either short-circuit (data NOT written) or log + drop.
3. Wire `erase_subject` to an admin endpoint (`POST /api/audit/erase` with a subject ID, audit-mutated like every other mutation).
4. Spawn a periodic `sweep` task per `cfg.audit.pii_ttl`.

### Path B — Delete

If GDPR is out of scope for the deadline:
- Delete `residency.rs`.
- Remove GDPR-mode references from README and from
  `compliance/gdpr.rs` (or make `gdpr.rs::apply` a no-op with a
  warn log).

The half-shipped state misleads operators making GDPR-driven
purchase / configuration decisions.

## Verification

After Path A:

```sh
# Configure GDPR mode + EU-only region pin.
curl -sk -X PUT "$HOST/api/compliance" -d '{"modes":["gdpr"]}'
curl -sk -X PUT "$HOST/api/residency" -d '{"allowed_regions":["eu-west-1"],"strict":true}'

# Send traffic from US-East node — audit emit should be REJECTED
# (returned via dispatch to a US-region sink throws).
# (Hard to test from a single-region setup; verify via unit test.)

# Right-to-erasure:
curl -sk -X POST "$HOST/api/audit/erase" -d '{"subject_id":"user-12345"}'
# Expect: rewrites every audit entry that references user-12345,
# rechains hashes, emits audit entry for the erasure itself.
```

## Severity rationale

CRITICAL because the README is making compliance claims that map to
real legal exposure (GDPR fines). Half-shipped is dangerous. Either
deliver fully (~200 LoC of plumbing) or remove cleanly (~50 LoC +
README edit + compliance/gdpr.rs simplification).
