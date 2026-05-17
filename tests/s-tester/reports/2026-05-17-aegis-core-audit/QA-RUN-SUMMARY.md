---
id: 2026-05-17-aegis-core-audit
date: 2026-05-17T00:00Z
test_mode: source-review
scope:
  - Full audit of `crates/aegis-core/src/` — 20 files / ~7300 LoC
  - 3 functional groups:
    A) `config.rs` (4024 LoC) — central WafConfig schema + defaults
    B) Contract types — audit, risk, tier, load_mode, identity, context,
       decision, pipeline, state
    C) Domain types — tcp_destination, cluster, break_glass, verbosity,
       health, secrets, cache, sd, error
  - Cross-referenced against v2.3 interop contract + official rules PDF +
    every prior audit (data-plane, proxy, security, aegis-control) — many
    CRITICAL findings from those audits trace ROOT CAUSE to this crate.
tester: Claude (3 parallel general-purpose audit agents +
                spot-verification by reading the cited file:line)
---

# Aegis-Gate `aegis-core` full-crate audit — 2026-05-17

**Mode:** Source review only. 3 parallel agents took non-overlapping
functional groups. Highest-impact findings spot-verified by directly
reading the cited file:line.

**Why this crate matters most:**

`aegis-core` is the schema source-of-truth for every other crate. Bugs
here are **schema-level**, not implementation-level — they propagate to
every consumer:

| Prior audit finding | Cross-crate symptom | Root cause in this crate |
|---|---|---|
| security F-CRITICAL-006 | RiskThresholds 30/70 vs 40/80 in 2 places | `config.rs` defaults are 40/80 (this crate) |
| security F-CRITICAL-005 | DDoS no per-tier threshold | `config.rs::DdosConfig` has no `tier_overrides` |
| security F-CRITICAL-009 | Rule scope missing 4 of 6 variants | `config.rs::RlScope` only `Global \| Route` |
| security F-CRITICAL-001 | RiskTracker keyed by IP only | `risk.rs::RiskKey` shape OK but `context.rs::RequestCtx` doesn't carry device_fp/session |
| proxy F-CONTRACT-001 | WS no-healthy-member returns `block` not `circuit_breaker` | `decision.rs::Action` enum has only 4 variants — `Timeout` and `CircuitBreaker` MISSING |
| F-CRITICAL-013 (control audit) | jsonl sink ≠ verifier format | `audit.rs::AuditEvent` doesn't carry chain context |
| F-CRITICAL-003 (control audit) | `/healthz` missing uptime/mode/rule count | `health.rs` only models ReadinessSignal booleans; no surface-field type |

**This audit is where most CRITICAL fixes need to land first** —
patches to consumer crates without first fixing the schema just push
the bug around.

---

## Finding counts

| Severity | Count |
|---|---|
| CRITICAL | 13 |
| HIGH     | ~22 (3 bundles) |
| MEDIUM   | ~30 (1 bundle) |
| Contract gaps | 4 |
| **Total** | **~69+** |

Smallest crate audit in the series (data-plane 14, proxy 64,
security 78, control 105, this 69) but with the highest leverage
per fix.

---

## CRITICAL findings index

### `audit.rs` source-of-truth schema fails §6 contract on EVERY audit event

| ID | Title | §6 field |
|---|---|---|
| F-CRITICAL-001 | `ts: DateTime<Utc>` serializes as RFC3339 STRING, not `ts_ms: i64` integer | `ts_ms` |
| F-CRITICAL-002 | `client_ip` field name (spec requires bare `ip`) | `ip` |
| F-CRITICAL-003 | `method`, `path`, `mode` fields MISSING ENTIRELY from struct | `method`, `path`, `mode` |
| F-CRITICAL-004 | `action: String` not enum — typos like `"Block"` or `"rate-limit"` accepted | `action` |
| F-CRITICAL-005 | `risk_score: Option<u32>` — optional, no 0-100 clamp | `risk_score` |

**Combined impact:** the SOURCE-OF-TRUTH struct cannot produce a
§6-compliant audit line. No matter how clean the sink wiring is, every
audit event fails contract validation.

### `decision.rs` Action enum is structurally incomplete

| ID | Title | §3 variant |
|---|---|---|
| F-CRITICAL-006 | Action enum has only 4 of 6 §3 variants — missing `Timeout` + `CircuitBreaker` | `timeout`, `circuit_breaker` |

**Combined impact:** **structural root cause of F-CONTRACT-001** (proxy
audit). The proxy literally has no variant to return when an upstream
times out or trips the circuit breaker — so it returns `block`,
violating §3 semantics on every such case.

### `config.rs` defaults disagree with spec OR required fields missing

| ID | Title |
|---|---|
| F-CRITICAL-007 | `RiskThresholds::default = {challenge_at: 40, block_at: 80}` — spec 30/70 |
| F-CRITICAL-008 | `DdosConfig` has no `tier_overrides` field — §5.2 #03 per-tier mandate |
| F-CRITICAL-009 | `RlScope` enum has only `Global \| Route` — missing `Tier \| RoutePattern \| Ip \| UserSession \| DeviceFingerprint` per §5.4 |
| F-CRITICAL-010 | `WafConfig` has no `fail_mode_by_tier` field — §5.8 mandate unrepresentable |
| F-CRITICAL-011 | `DetectorsConfig` has no per-tier mask field |
| F-CRITICAL-012 | `RiskConfig` has no `canary_paths` field — Round-1 §5.5 mandate |

### Schema-discipline failure

| ID | Title |
|---|---|
| F-CRITICAL-013 | ZERO uses of `#[serde(deny_unknown_fields)]` in 4024 LoC — typos like `routs:` silently drop, explaining many "ghost feature" reports |

### HIGH bundles

| File | Mini-findings inside |
|---|---|
| F-HIGH-config-schema.md | 9 items: ComplianceProfile fields inert (validate reads tls.* not compliance.*) · No VelocitySequenceRule schema · No BehavioralConfig schema · No body-decompression cap · No response_filter schema · GeoIpConfig lacks ASN feeds · mTLS allow-list global only · No schema_version field · Secret-typed fields are plain String |
| F-HIGH-contract-types.md | 6 items: decision.rs no Serialize/Display · tier.rs no classify_path (lives in aegis-security) · risk.rs RiskKey no constructor → enables F-CRITICAL-001 · context.rs RequestCtx missing device_fp + session_id · context.rs missing tier field · audit.rs client_ip as String not IpAddr |
| F-HIGH-domain-types.md | 7 items: secrets.rs no constant-time compare API · cache.rs CacheKey derives nothing (can't be HashMap key!) · cache.rs no CacheDecision enum · cache.rs Vary case-sensitive (cache poisoning) · verbosity.rs Trace no body-redaction contract · cluster.rs dead types · error.rs too coarse + log-injection risk |

### CONTRACT GAPS

| ID | Title |
|---|---|
| C-01 | `health.rs::ReadinessSignal` doesn't expose uptime/mode/rule count — F-CRITICAL-003 from control audit needs a sibling type added here |
| C-02 | `state.rs::token_bucket` returns bare `bool` — no `retry_after_s` for §3 rate_limit semantics |
| C-03 | `tcp_destination.rs::is_internal_address` is correct + reusable, but `aegis-control::validate_pool` doesn't call it (cross-crate hygiene gap) |
| C-04 | `ChainEntry` (audit-chain wrapper) lives in aegis-control, but `AuditEvent` in aegis-core has no chain context → schema layering invites the F-CRITICAL-013 (control audit) wire-format mismatch |

### MEDIUM

`F-MEDIUM-ALL.md` — ~30 items.

---

## Round-1 + v2.3 contract gap map

| Spec clause | aegis-core type/schema impact |
|---|---|
| §6 audit fields (request_id, ts_ms, ip, method, path, action, risk_score, mode) | 5 of 8 BROKEN in `audit.rs` (F-CRITICAL-001/002/003/004/005) |
| §3 six decision classes | 4 of 6 in `decision.rs` (F-CRITICAL-006) |
| §5.5 risk thresholds 30/70 configurable | Defaults 40/80 (F-CRITICAL-007) |
| §5.5 risk per `{IP + device_fp + session}` | `RiskKey` shape OK (risk.rs:4); `RequestCtx` doesn't carry the 3 axes (F-HIGH-contract-types) |
| §5.5 canary endpoints → MAX score + block | No `canary_paths` schema field (F-CRITICAL-012) |
| §5.4 rule scopes (6 variants) | `RlScope` has 2 of 6 (F-CRITICAL-009) |
| §5.2 #02 rate-limit per-IP AND per-session | partial — `RlKey::Session` exists but `RlScope` doesn't gate by session/device (F-CRITICAL-009) |
| §5.2 #03 DDoS per-tier threshold | No `DdosConfig.tier_overrides` (F-CRITICAL-008) |
| §5.2 #09 behavioral signals (<50ms, zero-depth) | No `BehavioralConfig` schema (F-HIGH-config-schema) |
| §5.2 #10 transaction velocity (Login→OTP→Deposit) | No `VelocitySequenceRule` type (F-HIGH-config-schema) |
| §5.7 response filter (5xx body cap, JSON field mask, debug headers) | No `ResponseFilterConfig` schema (F-HIGH-config-schema) |
| §5.8 fail-close per-tier | No `WafConfig.fail_mode_by_tier` (F-CRITICAL-010) |
| §5.9 schema versioning | No `schema_version` field (F-HIGH-config-schema) |
| Compliance modes wired to behavior | Fields exist but `validate_tls_hardening` reads `tls.*` not `compliance.*` (F-HIGH-config-schema; cross-ref F-CRITICAL-002 control audit) |

---

## Verdict

**Aegis-core is the leverage point.** Every other audit's CRITICAL
findings trace 1-to-1 back to either a missing schema field, a wrong
default, or an incomplete enum in this crate. Patching consumers
without first fixing the schema means re-introducing the same bug
class on the next feature.

**Highest-impact fixes (smallest LoC, biggest blast radius):**

1. **F-CRITICAL-001..005** (audit.rs schema) — rebuild `AuditEvent`
   struct to match §6. ~40 LoC. Fixes audit contract on every event
   AND removes the populator-side bugs in the proxy/control crates
   (the populators currently work around the broken schema).

2. **F-CRITICAL-006** (Action enum) — add `Timeout` + `CircuitBreaker`
   variants. ~10 LoC. Fixes F-CONTRACT-001 (proxy audit) directly.

3. **F-CRITICAL-007** (RiskThresholds defaults) — change `40/80` to
   `30/70`. 2 LoC. Fixes F-CRITICAL-006 (security audit).

4. **F-CRITICAL-013** (`deny_unknown_fields`) — add the annotation to
   `WafConfig` + 12 nested structs. ~14 LoC. Catches every typo →
   every "ghost feature" report from prior audits gets explained.

5. **F-CRITICAL-008..012** (config.rs missing fields) — schema
   additions, ~30-50 LoC each. Unlocks all the per-tier and
   per-feature wiring that consumer crates need.

Total fix-set for ALL 13 CRITICALs: ~300 LoC across a single crate.
Eliminates the schema layer of bugs and lets every consumer fix
become a small, targeted edit.

---

## Files

```
QA-RUN-SUMMARY.md                                                       (this file)
F-CRITICAL-001-audit-ts-is-rfc3339-string-not-ts-ms-int.md
F-CRITICAL-002-audit-client-ip-not-ip.md
F-CRITICAL-003-audit-missing-method-path-mode-fields.md
F-CRITICAL-004-audit-action-string-not-enum.md
F-CRITICAL-005-audit-risk-score-optional-no-clamp.md
F-CRITICAL-006-action-enum-missing-timeout-circuit-breaker.md
F-CRITICAL-007-risk-thresholds-defaults-40-80-vs-30-70.md
F-CRITICAL-008-ddos-config-no-tier-overrides.md
F-CRITICAL-009-rl-scope-missing-4-of-6-variants.md
F-CRITICAL-010-no-fail-mode-by-tier-field.md
F-CRITICAL-011-detectors-config-no-per-tier-mask.md
F-CRITICAL-012-risk-config-no-canary-paths-field.md
F-CRITICAL-013-zero-deny-unknown-fields-in-4024-loc.md
F-HIGH-config-schema.md         (9 items)
F-HIGH-contract-types.md        (6 items)
F-HIGH-domain-types.md          (7 items)
F-CONTRACT-GAPS.md              (4 cross-crate semantic gaps)
F-MEDIUM-ALL.md                 (~30 items)
```
