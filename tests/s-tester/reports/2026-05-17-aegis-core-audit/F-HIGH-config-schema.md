---
id: 2026-05-17-high-config-schema-bundle
date: 2026-05-17T00:00Z
severity: HIGH
area: config schema gaps
component: crates/aegis-core/src/config.rs (multiple structs)
interop_contract: Round-1 §5.2 / §5.7 / §5.9 + compliance modes
status: open
test_mode: source-review
---

# F-HIGH-config-schema bundle — 9 schema gaps in config.rs (beyond F-CRITICAL-007..013)

---

## CS-01 · ComplianceProfile fields inert — `validate_tls_hardening` reads `tls.*` not `compliance.*`

**Component:** [config.rs:2739-2749](../../../../crates/aegis-core/src/config.rs#L2739-L2749) + [config.rs:574](../../../../crates/aegis-core/src/config.rs#L574)

`ComplianceProfile.min_tls_version`, `disallow_algorithms`,
`pii_pseudonymize` exist as fields but `validate_tls_hardening`
reads `tls.min_version`, not `compliance.min_tls_version`. No
compliance→TLS bridge exists.

Schema-side root cause of F-CRITICAL-002 (control audit).

**Fix:** in `WafConfig::validate()`, when `compliance.modes`
includes `Pci` or `Fips`, require/clamp `tls.min_version`. Merge
`compliance.disallow_algorithms` into a TLS-stack-honored field.
Wire `compliance.pii_pseudonymize` into `audit.pseudonymize_ip`.

---

## CS-02 · No `VelocitySequenceRule` type for §5.2 #10 transaction velocity

**Component:** [config.rs:1804-1815](../../../../crates/aegis-core/src/config.rs#L1804-L1815) + no sequence type anywhere

§5.2 #10 (Login→OTP→Deposit window N, withdrawal-after-deposit
window M) has no schema representation. `RateLimitRule.window` is a
plain `Duration`, not a multi-step sequence.

**Fix:** add `pub velocity_sequences: Vec<VelocitySequenceRule>` to
`RateLimitConfig`:

```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VelocitySequenceRule {
    pub id: String,
    pub steps: Vec<VelocityStep>,        // ordered events to match
    pub window: Duration,                // total window for sequence
    pub action: RuleAction,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VelocityStep {
    pub action_class: String,             // login | otp | deposit | withdraw | ...
    pub max_gap: Option<Duration>,        // max time between this step and previous
}
```

Cross-fix: schema for F-CRITICAL-003 (security audit, velocity
sequence engine missing) starts here.

---

## CS-03 · No `BehavioralConfig` schema for §5.2 #09 signal thresholds

**Component:** [config.rs:2014-2068](../../../../crates/aegis-core/src/config.rs#L2014-L2068)

§5.2 #09 names 4 behavioral signals (inter-request <50ms, zero-depth
session, missing Referer on sensitive routes, timing variance). No
`DetectorsConfig.behavioral: BehavioralConfig { ... }` block exists.

**Fix:**

```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BehavioralConfig {
    pub inter_request_floor_ms: u32,     // default 50
    pub zero_depth_threshold: u32,       // default: 0 (any first-request to CRITICAL)
    pub require_referer_on_sensitive: bool,  // default true
    pub timing_cov_max: f64,             // default 0.05 (low CoV = bot-like)
}
```

---

## CS-04 · No body-decompression cap

**Component:** [config.rs:1467-1513](../../../../crates/aegis-core/src/config.rs#L1467-L1513) + [config.rs:2256](../../../../crates/aegis-core/src/config.rs#L2256)

§5.3 names "decompression bomb" as a Body Abuse vector. `DlpConfig.max_scan_bytes` (line 2256) and `QuotaConfig.client_max_body_size`
exist but cap RAW body size, not DECOMPRESSED size.

**Fix:** add to `QuotaConfig`:

```rust
pub max_decompressed_body_bytes: u64,       // default 64 MiB
pub decompression_ratio_cap: u32,           // default 1000 (1KB:1MB)
```

---

## CS-05 · No `ResponseFilterConfig` schema for §5.7

**Component:** config.rs — no such struct exists

§5.7 names: 5xx body size cap, JSON field-mask list, debug-header
allow-list. DLP has `patterns` (regex over body) but no structured
field-mask, no 5xx envelope cap.

Schema-side source of F-CRITICAL-013 (control audit response-filter
issues).

**Fix:**

```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResponseFilterConfig {
    pub five_xx_body_cap_bytes: u64,        // default 4 KiB
    pub json_field_mask: Vec<String>,       // ["card_number", "bank_account", "ssn"]
    pub debug_header_allowlist: Vec<String>,
    pub strip_debug_headers: bool,          // default true
}
```

Add to `WafConfig` as `pub response_filter: ResponseFilterConfig`.

---

## CS-06 · GeoIpConfig lacks ASN-classification feed paths

**Component:** [config.rs:215-222](../../../../crates/aegis-core/src/config.rs#L215-L222)

§5.2 #05 requires Tor exit + datacenter ASN classification.
`GeoIpConfig` only carries MaxMind country+ASN DBs; the categorization
feeds (Tor list, datacenter ASN list) are absent.

**Fix:**

```rust
pub tor_exit_list: Option<PathBuf>,
pub datacenter_asn_list: Option<PathBuf>,
pub vpn_provider_asn_list: Option<PathBuf>,
pub refresh_interval: Duration,             // default 1h
```

---

## CS-07 · mTLS allow-list is global only, not per-route

**Component:** [config.rs:1523-1551](../../../../crates/aegis-core/src/config.rs#L1523-L1551) + [config.rs:745](../../../../crates/aegis-core/src/config.rs#L745)

`tls.client_auth.allowed_sans` is global. `RouteConfig.auth_required:
Vec<String>` carries only kind labels (`mtls`/`spiffe`), not specific
SANs per route.

**Fix:** add `pub auth_required_sans: Vec<String>` per
`RouteConfig`. Operator can demand specific identity per route, not
just "any mTLS cert".

---

## CS-08 · No `schema_version` field on WafConfig

**Component:** [config.rs:1845-1862](../../../../crates/aegis-core/src/config.rs#L1845-L1862)

`AuditEvent.schema_version` exists (audit.rs:5) but `WafConfig` itself
has no version field. §5.9 GitOps + config versioning requires this;
hot-reload can't reject incompatible bumps; rollback is ambiguous.

**Fix:**

```rust
pub struct WafConfig {
    /// Config schema version. Bump on breaking changes.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    ...
}

fn default_schema_version() -> u32 { 1 }
```

Validate in `WafConfig::validate()`:

```rust
if self.schema_version != EXPECTED_SCHEMA_VERSION {
    return Err(WafError::Config(format!(
        "config schema_version {} unsupported (expected {})",
        self.schema_version, EXPECTED_SCHEMA_VERSION
    )));
}
```

---

## CS-09 · Secret-typed fields are plain String with `#[derive(Debug)]` parent

**Component:** [config.rs:166-168](../../../../crates/aegis-core/src/config.rs#L166-L168) + [config.rs:2602-2605](../../../../crates/aegis-core/src/config.rs#L2602-L2605) + [config.rs:2469](../../../../crates/aegis-core/src/config.rs#L2469) + [config.rs:2287](../../../../crates/aegis-core/src/config.rs#L2287) + [config.rs:2545](../../../../crates/aegis-core/src/config.rs#L2545)

`InteropConfig.control_secret: Option<String>` — plain String.
Parent struct has `#[derive(Debug)]`. Any `dbg!()` / panic / trace
emit prints the secret.

Other secret-shaped fields: `DashboardAuthConfig.password_hash_ref`,
`csrf_secret_ref`, `Splunk { token_ref }`, `FpeConfig.key_ref`,
`WitnessConfig.signer_ref`.

**Fix:**
- For the actual secret (`control_secret`): wrap in
  `secrecy::SecretString` or `zeroize::Zeroizing<String>`.
- For `*_ref` fields: document they are references, not raw secrets,
  via doc comment. If any resolves to a raw value, wrap that too.

```diff
-pub control_secret: Option<String>,
+pub control_secret: Option<secrecy::SecretString>,
```

Add `#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]` where
applicable.

---

## Severity rationale

HIGH. Each affects a §5 mandate (CS-01..05) or operational hygiene
(CS-06..09). None alone is CRITICAL (the system boots and serves
traffic), but each leaves a contract surface unrepresentable.
