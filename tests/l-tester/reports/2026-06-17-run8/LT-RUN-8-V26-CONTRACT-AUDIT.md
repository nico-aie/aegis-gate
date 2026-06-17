# Aegis-Gate v2.6 Contract Compliance Audit — Run 8

| Field                  | Value                                                                                  |
|------------------------|----------------------------------------------------------------------------------------|
| Run ID                 | LT-RUN-8                                                                               |
| Date                   | 2026-06-17                                                                             |
| Approach               | Static source-code audit against `Hackathon_Doc/EN_waf_interop_contract_v2.6.md` and `v2.5_to_v2.6_comparison.md` |
| Scope                  | All non-UI Rust crates: `aegis-bin`, `aegis-control`, `aegis-core`, `aegis-proxy`, `aegis-security` |
| Reference contract     | `Hackathon_Doc/EN_waf_interop_contract_v2.6.md` (2026-06-10)                         |
| Delta reference        | `Hackathon_Doc/v2.5_to_v2.6_comparison.md`                                           |
| Total source files     | 317 Rust files                                                                         |
| Total findings         | **7**                                                                                  |
| Critical               | **1**                                                                                  |
| High                   | **3**                                                                                  |
| Medium                 | **2**                                                                                  |
| Low                    | **1**                                                                                  |
| Contract violations    | **4** (CRIT-01, HIGH-01, HIGH-02, HIGH-03)                                            |
| Partial impl           | **2** (MED-01, MED-02)                                                                 |
| Logic conflicts        | **1** (LOW-01)                                                                         |
| Status                 | 🔴 OPEN — 1 Critical finding will cause automated benchmark to fail the challenge-solving step |

---

## Executive Summary

This run audits the Aegis-Gate source code against the **v2.6 interop contract** (published 2026-06-10). The four priority changes from the v2.5→v2.6 delta were compared against every relevant code path.

The most severe finding is **CRIT-01**: the WAF's proof-of-work challenge uses **blake3** as the hash algorithm, but the v2.6 contract's Format B HTML example (the only published reference implementation) specifies **SHA-256**. The benchmarker will attempt SHA-256 to solve every challenge the WAF issues, and every attempt will fail. This was already flagged as TS-02 in Run 7 (test-suite logic bug), but it has not been fixed in the data-plane itself. An unsolved challenge is recorded as **FAILED** with no partial credit per §4.

**HIGH-01** identifies that two active detectors (`cookie_injection`, `jwt_inspection`) fire and block traffic but are absent from the `/__waf_control/capabilities` response. The v2.6 §2.5 explicitly requires that *all* features, including hardcoded ones, appear in capabilities. If the benchmarker tests a `jwt_*` attack, the block will occur but the OC cannot toggle the detector via `set_profile`.

**HIGH-02** is a v2.6 action-required change: the `flush_cache` no-cache path already returns `200 OK` with `supported: false`, which is correct. However, `set_profile` with `scope: "policies"` and an unknown `feature` name returns **422 Unprocessable Entity** — this is the *punitive* path that §2.5 explicitly warns will **abort the benchmark run**. The benchmarker may probe a feature name that the WAF doesn't list; that 422 kills the run.

**HIGH-03**: the challenge-verify endpoint returns `{"ok": true}` on success but no session cookie or session token. The §4 contract requires "a session cookie or token that allows the original request to proceed." Without it, the benchmarker's challenge flow stalls: the solver submits the nonce, gets 200, but the original request cannot be replayed with proof of solution.

The two Medium findings cover a `BehavioralAnalyzer` component that is documented as not wired into the live hot path, and the `deny_unknown_fields` serde attribute on `SetProfileRequest` which rejects any extra fields the benchmarker might send.

---

## Finding Index

| ID       | Severity     | Category            | Short Description                                                                   |
|----------|--------------|---------------------|-------------------------------------------------------------------------------------|
| CRIT-01  | **Critical** | Contract Violation  | PoW challenge uses blake3; contract/benchmarker expects SHA-256 — challenge unsolvable |
| HIGH-01  | **High**     | Contract Violation  | `cookie_injection` + `jwt_inspection` detectors missing from `/capabilities`        |
| HIGH-02  | **High**     | Contract Violation  | `set_profile scope=policies` returns 422 on unknown feature → aborts benchmark run  |
| HIGH-03  | **High**     | Contract Violation  | Challenge verify (POST `/challenge/verify`) returns no session cookie/token         |
| MED-01   | **Medium**   | Partial Impl        | `BehavioralAnalyzer` documented as not wired into live request path                 |
| MED-02   | **Medium**   | Logic Conflict      | `deny_unknown_fields` on `SetProfileRequest` rejects valid future benchmarker fields |
| LOW-01   | **Low**      | Logic Conflict      | Rate-limit response body uses `"rate_limited"`, contract example uses `"rate_limit_exceeded"` |

---

## Detailed Findings

---

### CRIT-01 — PoW Challenge Algorithm Mismatch: blake3 vs SHA-256 🚨

**Severity:** Critical
**Category:** Contract Violation
**Files:**
- `crates/aegis-security/src/challenge/pow.rs:115–130` (`pow_solution_valid`)
- `crates/aegis-proxy/src/data_plane.rs:1370–1395` (challenge 429 issuance)
- `crates/aegis-proxy/src/admin_dispatch.rs:1157–1195` (`handle_challenge_verify`)

**Code snippet (WAF verify — uses blake3):**
```rust
// pow.rs:115–130
pub fn pow_solution_valid(nonce: &str, counter: &str, difficulty: u8) -> bool {
    let mut hasher = Hasher::new();           // ← blake3::Hasher
    hasher.update(nonce.as_bytes());
    hasher.update(b":");
    hasher.update(counter.as_bytes());
    let h = hasher.finalize();
    leading_zero_bits(h.as_bytes()) >= difficulty
}
```

**Contract Format B (SHA-256 — the only published reference solver):**
```javascript
// EN_waf_interop_contract_v2.6.md §4 Format B
const data = new TextEncoder().encode(token + nonce);
const hash = await crypto.subtle.digest("SHA-256", data);
if (hex.startsWith("0".repeat(difficulty))) { ... }
```

**Description:**

The WAF issues a Format A JSON challenge:
```json
{
  "challenge": true,
  "challenge_type": "proof_of_work",
  "challenge_token": "<nonce>.<difficulty>.<expires_at_ms>.<mac>",
  "difficulty": 16,
  "submit_url": "/challenge/verify",
  "submit_method": "POST"
}
```

The benchmarker follows the contract's Format B HTML reference solver, which computes:
`SHA-256(challenge_token_string + nonce_counter)` and checks for `difficulty` leading zero **hex characters** (or bits — interpretation may vary).

The WAF's `handle_challenge_verify` unpacks the `challenge_token` to extract `(inner_nonce, difficulty, expires_at_ms, mac)` then verifies:
`blake3(inner_nonce + ":" + submitted_nonce)` has `difficulty` leading zero **bits**.

The mismatch is threefold:
1. **Algorithm**: blake3 vs SHA-256
2. **Input**: blake3(`inner_nonce:counter`) vs SHA-256(`challenge_token_string + counter`)
3. **Difficulty unit**: leading zero **bits** vs HTML shows leading zero **hex chars** (`"0".repeat(difficulty)` = difficulty zero hex chars = 4×difficulty zero bits)

This finding was already logged as **TS-02** in Run 7 against the test suite. The data-plane source is unchanged. Every challenge the WAF issues is unsolvable by the benchmarker. Per §4: *"If the tool cannot solve a challenge, it is a team implementation issue — not a benchmark limitation."* Result: **challenge = FAILED**, no partial credit.

**Impact:** All test cases that trigger a `challenge` action (risk score 30–70) will record `FAILED`. The OC's challenge-solver logs will show the submitted solution never satisfies the WAF's verify call.

**Suggested fix:** Replace blake3 with SHA-256 in `pow_solution_valid` and align the input to `SHA-256(challenge_token_string + counter)` where `challenge_token` is the opaque token string the client received. Verify that `difficulty` is interpreted as leading zero hex characters (4 bits per char) to match the HTML example. Update `PowIssuer::verify` accordingly and re-run the TS-02 test from Run 7 to confirm the solver now succeeds.

---

### HIGH-01 — `cookie_injection` and `jwt_inspection` Detectors Missing from Capabilities

**Severity:** High
**Category:** Contract Violation (§2.5 — Feature toggleability)
**Files:**
- `crates/aegis-proxy/src/run.rs:2268–2375` (`build_interop_runtime` — capabilities list)
- `crates/aegis-control/src/interop/rule_map.rs:47–50` (`rule_to_feature` — mapping present)
- `crates/aegis-security/src/detectors/cookie_injection.rs` (active detector)
- `crates/aegis-security/src/detectors/jwt_inspection.rs` (active detector)

**Code snippet (rule_map.rs — mapping exists):**
```rust
"cookie_injection" | "cookie_inj" => ("rules_engine", "cookie_injection"),
p if p.starts_with("jwt_") => ("rules_engine", "jwt_inspection"),
```

**Code snippet (run.rs — capabilities list — MISSING these policies):**
```rust
features.insert("rules_engine".into(), CapabilityFeature {
    supported: true,
    toggleable: true,
    policies: vec![
        "sqli", "xss", "path_traversal", "ssrf", "header_injection",
        "body_abuse", "recon", "brute_force", "ai", "command_injection",
        "template_injection", "nosql_injection", "open_redirect",
        "canary", "velocity", "behavior_signals",
        // ← "cookie_injection" and "jwt_inspection" NOT HERE
    ],
});
```

**Description:**

Both `cookie_injection` and `jwt_inspection` are:
- Active detectors with live source files in `aegis-security/src/detectors/`
- Correctly mapped in `rule_to_feature` (so `X-WAF-Mode` stamping works)
- **Absent from `build_interop_runtime`'s feature list** (so `GET /__waf_control/capabilities` does not list them)

The v2.6 §2.5 states: *"Every feature and policy supported by the WAF SHOULD be reported in the `/__waf_control/capabilities` response for transparency, **including hardcoded features**."*

When the benchmarker asks to `set_profile { scope: "policies", feature: "rules_engine", policies: ["cookie_injection"], mode: "log_only" }`, the response will list `"cookie_injection"` in the `unsupported` array — even though the detector is active and blocking traffic. The benchmarker cannot isolate this detector for independent evaluation.

More critically for scoring: if a test expects `cookie_injection` to be in `log_only` mode but the WAF blocks it anyway, the test records a `false_positive` or an unexpected `block` instead of `log_only_detected`.

**Impact:** Benchmarker cannot toggle two active detectors. Tests that isolate `cookie_injection` or `jwt_*` will see unexpected enforcement in log_only phases.

**Suggested fix:** Add `"cookie_injection"` and `"jwt_inspection"` to the `rules_engine` policy list in `build_interop_runtime` in `run.rs`. Also add the corresponding test row to `ctx_v23()` in `control.rs` to guard against future drift.

---

### HIGH-02 — `set_profile scope=policies` Returns 422 for Unknown Feature — Aborts Benchmark Run

**Severity:** High
**Category:** Contract Violation (§2.5 — Unsupported items)
**Files:**
- `crates/aegis-control/src/interop/control.rs:289–301` (`validate_and_apply`, Policies branch)
- `crates/aegis-proxy/src/admin_dispatch.rs:1068–1075` (error → HTTP status passthrough)

**Code snippet:**
```rust
// control.rs — scope=Policies branch
SetProfileScope::Policies => {
    let feature = req.feature.as_ref().ok_or_else(|| { ... })?;
    // ...
    let known = self.features.get(feature).ok_or_else(|| {
        ControlError::Unsupported(format!("feature {feature}"))  // ← status 422
    })?;
    // ...
}

// ControlError::status()
ControlError::Unsupported(_) => 422,
```

**Description:**

The v2.6 §2.5 "Unsupported items" section explicitly lists two approaches and their consequences:

1. `200 OK` + `unsupported` list → **benchmark-safe**, run continues
2. `400/422` → **punitive**, benchmark run is **aborted** after current test

When the benchmarker sends `{ "scope": "policies", "feature": "<unknown_or_unlisted>", "policies": [...] }`, the WAF's `validate_and_apply` returns `ControlError::Unsupported`, which maps to **422** via `status()`. The dispatch layer passes this status directly to the response.

The contract says: *"If the WAF returns `400` or `422` for partially-supported profiles instead, the benchmark run will be aborted."*

This applies specifically when the WAF supports `scope: "all"` but receives `scope: "policies"` for a feature it doesn't know. Returning 422 here is the punitive path.

**Impact:** Any test group that probes an undocumented or misnamed feature via `scope: "policies"` will abort the entire benchmark run from that point forward.

**Suggested fix:** Change the `Policies` branch to treat an unknown `feature` name as an unsupported item (add it to the `unsupported` list) and return `200 OK` rather than raising `ControlError::Unsupported`. Pattern already used in the `Features` branch: unknown feature names go into `unsupported` and the function returns `Ok(unsupported)`. Apply the same pattern here:
```rust
let known = match self.features.get(feature) {
    Some(f) => f,
    None => {
        // Return 200 with unsupported list — safe per §2.5
        return Ok(vec![format!("{feature}.*")]);
    }
};
```

---

### HIGH-03 — Challenge Verify Returns No Session Cookie/Token

**Severity:** High
**Category:** Contract Violation (§4 — Challenge responses)
**Files:**
- `crates/aegis-proxy/src/admin_dispatch.rs:1185–1200` (`handle_challenge_verify` success branch)

**Code snippet:**
```rust
// admin_dispatch.rs — challenge verify success
Ok(()) => json_response(
    200,
    &serde_json::json!({
        "ok": true,
        "action": "challenge_verified",
        // ← No Set-Cookie header, no session token
    }),
),
```

**Contract requirement (§4):**
```
On success, the WAF returns `200` with a session cookie or token that
allows the original request to proceed.
```

**Description:**

The `POST /challenge/verify` endpoint returns HTTP 200 with `{"ok": true, "action": "challenge_verified"}` but does **not** set a `Set-Cookie` header or return a session token in the body. The code comment at line 1185 acknowledges the gap: *"session-token cookie path is wired by the data-plane risk-bucket clear (separate concern)."*

Without a session token or cookie, the benchmarker has no credential to replay the original request and prove challenge completion. The challenge flow is:
1. Request → 429 challenge issued ✓
2. Benchmarker solves PoW (blocked by CRIT-01 above, but assuming it were fixed)
3. `POST /challenge/verify` → 200, no cookie
4. Benchmarker replays original request → WAF has no way to recognize it as challenge-verified → may issue another 429 or block

This means the `allowed_after_challenge` classification (§7 decision matrix) can never be achieved — the benchmarker always sees a second challenge or block.

**Impact:** The `challenge` action flow cannot complete. Even if CRIT-01 is fixed and the PoW is solvable, the session token step is missing, preventing the `allowed_after_challenge` outcome.

**Suggested fix:** On successful verify, issue a short-lived session cookie (e.g. `Set-Cookie: waf_challenge_pass=<signed_token>; Path=/; HttpOnly; Max-Age=300`) and wire the data-plane to accept requests carrying a valid `waf_challenge_pass` cookie without re-challenging them for the session duration. The signed token should encode at minimum the client IP and an expiry timestamp, keyed to the existing `pow_issuer` HMAC key.

---

### MED-01 — `BehavioralAnalyzer` Documented as Not Wired into Live Request Path

**Severity:** Medium
**Category:** Partial Implementation
**Files:**
- `crates/aegis-proxy/src/run.rs:2392–2400` (comment)
- `crates/aegis-security/src/behavior.rs` (implementation exists)

**Code snippet:**
```rust
// run.rs:2392–2400
// NOTE: `aegis_security::behavior::BehavioralAnalyzer` exists
// and exposes `.clear()`, but it isn't wired into the live
// request path yet. When the analyzer lands in the data
// plane, register its `.clear()` here too. Today it's a
// documented gap — log_only-style false-positive verification
// doesn't depend on it, so the v2.5 contract stays satisfied.
```

**Description:**

The `BehavioralAnalyzer` in `aegis-security/src/behavior.rs` is a complete implementation (`.clear()` method, behavioral signal detection) but has zero callers in the live data-plane hot path. The `behavior_signals` policy is listed in `/capabilities` as `toggleable: true` and `mode_for_rule` routes `behavior_` prefixed rule IDs to it — but the detector is never called during request processing.

Under v2.6 §2.5: *"If a feature is reported as `toggleable: true` but does not actually respond to mode changes… the responsibility lies with the WAF implementation."* Reporting `behavior_signals` as toggleable while the detector isn't wired creates an inconsistency: the OC may expect `set_profile` to produce observable behavior changes on `behavior_signals`, but no behavioral block will ever fire.

**Impact:** The `behavior_signals` capability entry is misleading. Tests that rely on behavioral anomaly detection (§3.1: "Behavioral anomaly — bot patterns, timing, cadence, fingerprint" → acceptable: `block`, `challenge`, `rate_limit`) will silently miss.

**Suggested fix:** Either wire `BehavioralAnalyzer` into the detector loop in `data_plane.rs` (alongside other detectors), or set `toggleable: false` in `build_interop_runtime` and document it clearly so the OC knows the policy is pending. Do not list it as `toggleable: true` if it has no effect.

---

### MED-02 — `deny_unknown_fields` on `SetProfileRequest` Rejects Future Benchmarker Fields

**Severity:** Medium
**Category:** Logic Conflict
**Files:**
- `crates/aegis-control/src/interop/control.rs:93` (`SetProfileRequest` struct)

**Code snippet:**
```rust
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]    // ← rejects any field not in this struct
pub struct SetProfileRequest {
    pub scope: SetProfileScope,
    pub mode: ModeRepr,
    #[serde(default)]
    pub features: Option<Vec<String>>,
    #[serde(default)]
    pub feature: Option<String>,
    #[serde(default)]
    pub policies: Option<Vec<String>>,
    #[serde(default = "default_cluster_scope")]
    pub cluster: bool,
}
```

**Description:**

`deny_unknown_fields` causes serde to return a deserialization error if the JSON body contains any key not listed in the struct. This means a 400 response if the benchmarker (or OC tooling) sends a `set_profile` request with any additional diagnostic or versioning field.

The contract §2.5 minimal body schema only uses `scope`, `mode`, `features`, `feature`, `policies`. The internal `cluster` field is an extension. If the OC tool ever sends, e.g., `{"scope":"all","mode":"enforce","comment":"baseline"}`, the request fails with 400 — which is benign but unexpected, and depending on whether the benchmarker treats a 400 here as a run-abort trigger (per §2.5 punitive path), could end the run.

The existing test `json_unknown_field_is_rejected` explicitly documents and asserts this behavior as intentional. However, the v2.6 contract does not authorize 400 for unknown fields — only for malformed scope/mode combinations.

**Impact:** Medium risk — the contract's minimal body never includes extra fields, but operator-added tooling or a future benchmarker version could trigger this unexpectedly.

**Suggested fix:** Remove `deny_unknown_fields` and instead validate the relevant fields explicitly (scope, mode, features/feature/policies consistency). Log a warning on unknown fields in debug builds. Retain unit tests for malformed scope/mode values.

---

### LOW-01 — Rate-Limit Response Body Error String Differs from Contract Example

**Severity:** Low
**Category:** Logic Conflict
**Files:**
- `crates/aegis-proxy/src/data_plane.rs:711` (rate-limit 429 body)

**Code snippet:**
```rust
// data_plane.rs:711
serde_json::json!({
    "error": "rate_limited",          // ← WAF uses "rate_limited"
    "reason": reason,
    "retry_after_seconds": rate_decision.retry_after_seconds,
    "strikes": post_state.strikes,
})
```

**Contract example (§4):**
```json
{
  "error": "rate_limit_exceeded",    // ← contract example uses "rate_limit_exceeded"
  "message": "Too many requests. Please slow down.",
  "retry_after_seconds": 30
}
```

**Description:**

The WAF emits `"error": "rate_limited"` while the v2.6 §4 contract example shows `"error": "rate_limit_exceeded"`. The primary detection signal (`X-WAF-Action: rate_limit` header + HTTP 429) is correct. The body field is informational per §4 ("body format flexible"), and the benchmarker uses headers as the primary signal, so this is unlikely to cause a scoring failure.

However, the v2.6 §4 contract specifies a concrete JSON body shape. A strictly compliant checker (OC manual review) may flag the field mismatch.

**Impact:** Low — headers are the primary signal; body is secondary. No automated scoring impact expected.

**Suggested fix:** Change `"error": "rate_limited"` to `"error": "rate_limit_exceeded"` in `data_plane.rs` line 711, and optionally add `"message": "Too many requests. Please slow down."` to match the contract example more closely.

---

## Cross-Crate Wiring Table

| Feature               | Configured In            | Implemented In                          | Wired Into Pipeline         | Net Status                |
|-----------------------|--------------------------|-----------------------------------------|-----------------------------|---------------------------|
| JWT auth (jwks/opa)   | `aegis-core/config.rs`   | `auth/jwt.rs` ✓                         | `pipeline.rs` ✓             | **Working**               |
| PoW challenge         | `interop.enabled=true`   | `challenge/pow.rs` ✓ (blake3)           | `data_plane.rs` ✓           | **Bypass** — wrong algo   |
| Challenge verify      | `run.rs` `pow_issuer`     | `admin_dispatch.rs::handle_challenge_verify` ✓ | `/challenge/verify` ✓ | **Partial** — no session cookie |
| Basic rate-limit      | `rate_limit.buckets`     | `rate_limit/ip_limiter.rs` ✓            | `data_plane.rs` ✓           | **Working**               |
| cookie_injection detector | `rules_engine` policy  | `detectors/cookie_injection.rs` ✓      | pipeline ✓ (fires+blocks)   | **Dead in capabilities** — not toggleable via set_profile |
| jwt_inspection detector   | `rules_engine` policy  | `detectors/jwt_inspection.rs` ✓        | pipeline ✓ (fires+blocks)   | **Dead in capabilities** — not toggleable via set_profile |
| behavior_signals      | `capabilities` `toggleable:true` | `behavior.rs` ✓             | pipeline ✗ (not wired)      | **Silent drop** — listed but never fires |
| flush_cache           | `register_flush_callback` | `cache/mod.rs` ✓                       | `/flush_cache` → 200 `supported:false` when no cache | **Working** (501/200 per v2.6) |
| reset_state (modes)   | `ModeStore` preserved    | `control.rs::reset_state_async` ✓       | `admin_dispatch.rs` ✓       | **Working** — feature/policy settings preserved per §2.4 |
| unsupported scope=features | `validate_and_apply` | `control.rs` ✓ returns `unsupported[]` | `set_profile` → 200         | **Working**               |
| unsupported scope=policies unknown feature | `validate_and_apply` | `control.rs` ✓ but returns 422 | `set_profile` → 422 | **Bypass** — aborts benchmark run |
| X-Benchmark-Secret auth | `control_secret`       | `control.rs::check_auth` ✓ (constant-time) | All `/__waf_control/*` ✓ | **Working** |
| X-WAF-* response headers | `headers.rs`          | `data_plane.rs` stamps all 6 ✓          | all responses ✓             | **Working**               |
| audit log JSONL       | `audit_path`             | `interop/audit.rs` ✓                    | `bus.emit()` hot path ✓     | **Working**               |

---

## Recommended Fix Priority (v2.6 compliance)

1. **CRIT-01 (PoW algorithm)** — Replace blake3 with SHA-256 in `pow_solution_valid` and align input concatenation and difficulty unit to the contract's Format B HTML. Fix `handle_challenge_verify` to match. Run the TS-02 test from Run 7 as a regression check.

2. **HIGH-03 (session cookie)** — Add `Set-Cookie: waf_challenge_pass=<signed_token>` to the `handle_challenge_verify` success path and wire the data-plane to honor it for the session duration.

3. **HIGH-01 (capabilities gap)** — Add `"cookie_injection"` and `"jwt_inspection"` to the `rules_engine` policy list in `build_interop_runtime` in `run.rs`. Mirror in `ctx_v23()`.

4. **HIGH-02 (422 on unknown feature)** — Change `scope=Policies` with unknown feature to return `200 OK` + `unsupported` list, not 422.

5. **MED-01 (behavior_signals)** — Either wire `BehavioralAnalyzer` or set `toggleable: false` in capabilities.

6. **MED-02 (deny_unknown_fields)** — Remove `deny_unknown_fields` from `SetProfileRequest`.

7. **LOW-01 (error string)** — Change `"rate_limited"` → `"rate_limit_exceeded"` in `data_plane.rs:711`.
