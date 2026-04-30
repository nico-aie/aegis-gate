# WAF Interop Contract v2.3

> **Audience**: WAF Hackathon Candidates

> **Scope**: Describes the decisions and control-plane interface that your WAF must expose so the event organizers can evaluate it deterministically. This means that if the event organizers perform the same action (input) under the same conditions, they must always receive the exact same output, without random differences.

---

## 1. Purpose

For automated judging, the WAF MUST provide clear observable outputs so the event organizers' benchmarking tool can classify behavior immediately. The event organizers will not interfere with source code or internal logic unless discrepancy investigation is required.

As a candidate, your WAF MUST attach the observability headers specified in §5 to every HTTP response. While the Audit log (§6) remains a mandatory requirement for correlation and post-run inspection, these response headers are critical for real-time classification and cannot be replaced by the audit log.

In addition to response observability, the WAF MUST expose a small local control plane so the event organizers can:

1. Discover supported WAF capabilities, features, and policies.
2. Reset temporary runtime state between test runs.
3. Toggle one, many, or all WAF features/policies between enforcement and log-only behavior.
4. Flush cache when caching is enabled.
5. Correlate response decisions with active policy mode.

---

## 2. WAF Control Interface

### 2.1 Required Control Endpoints

Recommended prefix:

```text
/__waf_control
```

| Method | Path | Requirement | Purpose |
|--------|------|-------------|---------|
| `GET` | `/__waf_control/capabilities` | **REQUIRED** | Allows the event organizers to discover supported WAF features, policies, and toggle controls. |
| `POST` | `/__waf_control/reset_state` | **REQUIRED** | Clears temporary WAF runtime state between test runs. |
| `POST` | `/__waf_control/set_profile` | **REQUIRED** | Toggles `enforce` / `log_only` mode for all, one, or selected features/policies. |
| `POST` | `/__waf_control/flush_cache` | **REQUIRED if caching exists** | Clears WAF cache when cache is implemented. |

All control endpoints MUST be local/admin-only and MUST NOT be proxied to upstream.

### 2.2 Authentication

Control endpoints MUST require a benchmark secret header:

```http
X-Benchmark-Secret: waf-hackathon-2026-ctrl
```

Missing/invalid secret MUST return `403 Forbidden`.

### 2.3 WAF Capabilities

Endpoint:

```http
GET /__waf_control/capabilities
```

The response MUST allow the event organizers to understand ALL the minimal controllable surface exposed by the WAF implementation.

Teams MAY expose additional implementation-specific features or policies, but they are not required to do so. The event organizers may use extra capabilities for bonus evaluation, diagnostics, or manual review.

The baseline capability names below are intentionally generic. A minimal WAF may expose only a small access-control ruleset, while more advanced WAFs MAY expose additional generic rule groups.

Minimal success response:

```json
{
  "ok": true,
  "features": {
    //SKELETON
    "rules_name": {
      "supported": true,
      "toggleable": true,
      "policies": ["policy_A", "policy_B"]
    },
    //EXAMPLE
    "access_control": {
      "supported": true,
      "toggleable": true,
      "policies": ["blacklist", "whitelist"]
    }
  },
  "active": {
    "default_mode": "enforce",
    "overrides": {}
  }
}
```

Feature and policy names are implementation-defined, but they MUST be stable within a benchmark run. Candidate-facing documentation SHOULD keep names generic. The event organizers may use this response to decide which features/policies can be toggled through `POST /__waf_control/set_profile`.

### 2.4 Runtime Reset

Endpoint:

```http
POST /__waf_control/reset_state
```

`reset_state` MUST clear temporary runtime state, including at least:

- risk state,
- rate-limit counters,
- cache state,
- challenge/session state,
- temporary client/session metadata,
- temporary enforcement state.

It SHOULD preserve long-term static config unless explicitly requested otherwise.

`reset_state` MUST NOT delete, truncate, rotate, rewrite, or otherwise modify `./waf_audit.log` or the configured audit-log file. The audit log is evidence for organizer-side correlation, backup verification, and post-run inspection, so it MUST remain append-only across WAF state resets. Implementations MAY append a structured audit event indicating that `reset_state` was called, but they MUST NOT remove prior log entries.

`reset_state` MUST be synchronous and atomic from the benchmarker's perspective. A success response MUST NOT be returned until all temporary runtime state listed above has been fully cleared. During reset, implementations MAY briefly reject or queue in-flight non-control requests, but they MUST NOT expose partially reset state after success.

If an implementation returns a successful `reset_state` response before the temporary runtime state is fully cleared, the run SHOULD NOT be treated as an automatic failure solely for that reason. However, the event organizers MAY apply a scoring penalty because premature success responses can contaminate later tests, make benchmark results flaky, or require additional manual verification.

Minimal success response:

```json
{
  "ok": true,
  "action": "reset_state",
  "audit_log_preserved": true,
  "ts_ms": 1777363200123
}
```

### 2.5 WAF Feature / Policy Mode Control

Endpoint:

```http
POST /__waf_control/set_profile
```

The WAF MUST support controlled switching of feature/policy behavior so the event organizers can evaluate the WAF deterministically without revealing hidden test logic.

This endpoint is NOT a benchmark-specific bypass or scoring shortcut. Teams MUST NOT hard-code behavior for the benchmark, hidden tests, organizer traffic, or specific payloads. Enabling evaluation compatibility means exposing deterministic control and observability semantics; it MUST NOT relax, boost, or special-case detection logic for undisclosed benchmark cases.

The event organizers may toggle:

1. all supported features/policies at once;
2. one feature/policy;
3. a list of selected features/policies.

#### Enforcement semantics

Each feature/policy mode MUST use one of the following values:

- `enforce`: the policy is active and its `X-WAF-Action` is applied to traffic. For example, if the WAF decides `block`, the request is actually blocked before upstream.
- `log_only`: the policy is evaluated normally and MUST still report the intended `X-WAF-Action`, `X-WAF-Rule-Id`, and audit-log evidence that would have been produced in `enforce` mode, but the enforcement effect MUST NOT be applied. In `log_only`, a policy that would have produced `block`, `challenge`, `rate_limit`, `timeout`, or `circuit_breaker` in `enforce` mode MUST report that intended action through `X-WAF-Action` and MUST report `X-WAF-Mode: log_only`, while the request SHOULD continue upstream unless blocked by non-WAF transport failures or upstream availability issues. This allows the event organizers to verify that a detector works without forcing every test request to be denied or interrupted.

Minimal request body schema:

```json
{
  "scope": "all | features | policies",
  "mode": "enforce | log_only"
}
```

Allowed values:

- `scope`: `all`, `features`, or `policies`
- `mode`: `enforce` or `log_only`

Update semantics:

- `scope: "all"` changes the default mode for all supported features/policies.
- `scope: "features"` changes only the listed features. All omitted features MUST keep their current mode.
- `scope: "policies"` changes only the listed policies. All omitted policies in the same feature, and all unrelated features, MUST keep their current mode.

Examples:

```json
{
  "scope": "all",
  "mode": "enforce"
}
```

In this example, all supported features and policies are switched to `enforce`. Any previous feature-level or policy-level `log_only` overrides SHOULD be cleared unless the WAF explicitly reports otherwise in the `active.overrides` response.

```json
{
  "scope": "features",
  "mode": "log_only",
  "features": ["access_control"]
}
```

In this example, only `access_control` is switched to `log_only`. Other features such as `rules_name` MUST remain unchanged.

```json
{
  "scope": "policies",
  "mode": "log_only",
  "feature": "access_control",
  "policies": ["blacklist"]
}
```

In this example, only the `blacklist` policy under `access_control` is switched to `log_only`. The `whitelist` policy and all other features/policies MUST remain unchanged.

Minimal success response for disabling one feature:

```json
{
  "ok": true,
  "action": "set_profile",
  "applied": {
    "scope": "features",
    "mode": "log_only",
    "features": ["access_control"]
  },
  "active": {
    "default_mode": "enforce",
    "overrides": {
      "access_control": "log_only"
    }
  },
  "unsupported": [],
  "ts_ms": 1777363201123
}
```

Minimal success response for disabling one policy:

```json
{
  "ok": true,
  "action": "set_profile",
  "applied": {
    "scope": "policies",
    "mode": "log_only",
    "feature": "access_control",
    "policies": ["blacklist"]
  },
  "active": {
    "default_mode": "enforce",
    "overrides": {
      "access_control.blacklist": "log_only"
    }
  },
  "unsupported": [],
  "ts_ms": 1777363201123
}
```

If a requested feature or policy is unsupported, the WAF MUST NOT silently ignore it. The response MUST either:

1. return `400 Bad Request` or `422 Unprocessable Entity` with a machine-readable `unsupported` list; or
2. return success only for supported items and include unsupported items in the `unsupported` list.

The chosen behavior MUST be consistent for the entire benchmark run.

### 2.6 Cache Flush

Endpoint:

```http
POST /__waf_control/flush_cache
```

If WAF caching is implemented, this endpoint MUST be supported so benchmark runs are not affected by stale cached decisions.

If caching is not implemented, WAF MAY return a clear not-supported response.

### 2.7 Response Headers for Control-Mode Correlation

For every proxied response:

- `X-WAF-Mode`: **REQUIRED** (`enforce` or `log_only`) so the event organizers can verify whether the active policy is enforcing or only logging.

When a request matches multiple policies with different active modes, `X-WAF-Mode` SHOULD reflect the mode of the policy that produced the final reported `X-WAF-Action`.

When `X-WAF-Mode: log_only`, `block`, `challenge`, `rate_limit`, `timeout`, and `circuit_breaker` decisions MUST be reported through `X-WAF-Action` as intended decisions only; the enforcement effect MUST NOT be applied.

---

## 3. WAF Decision Classes

Every request through the WAF results in exactly one decision:

| Decision | Meaning |
|----------|---------|
| `allow` | Request proxied to upstream; upstream response returned to client |
| `block` | Request denied before reaching upstream |
| `challenge` | Request held; client must solve a JS challenge or proof-of-work (PoW) before proceeding |
| `rate_limit` | Request denied because it exceeded a rate threshold |
| `timeout` | WAF proxied the request, but upstream did not respond in time |
| `circuit_breaker` | WAF refused to proxy because upstream is marked unhealthy |

### 3.1 Threat Category to Action Semantics

The following table defines the expected semantic mapping between threat categories and WAF actions. The benchmark evaluates whether the action chosen by the WAF falls within the "acceptable" set for each threat category. Multiple acceptable actions may exist for a single category; teams may choose based on their detection confidence.

| Threat Category | Acceptable Actions | Unacceptable Actions | Notes |
|-----------------|--------------------|----------------------|-------|
| High-confidence injection (SQLi, XSS, command injection, SSRF) | `block`, `challenge` | `rate_limit`, `timeout`, `allow` | `challenge` is acceptable when confidence is below the team-defined threshold |
| Low-confidence injection (heuristic match only) | `block`, `challenge`, `log_only` | — | Team's discretion based on detection model |
| Authentication abuse (credential stuffing, brute force) | `rate_limit`, `challenge`, `block` | `timeout`, `circuit_breaker` | `block` is acceptable for known-bad IP/fingerprint |
| Volumetric abuse from single source | `rate_limit`, `block` | `circuit_breaker` | `circuit_breaker` is for upstream protection, not source rate management |
| Slow-loris / connection exhaustion | `timeout`, `block` | `rate_limit` | Connection-level, not request-level |
| Upstream degradation detected by WAF | `circuit_breaker` | `block`, `rate_limit` | Action targets upstream protection, not the client |
| Reconnaissance / scanning patterns | `block`, `rate_limit`, `challenge` | — | Team's discretion |
| Known malicious IP (blacklist) | `block` | — | — |

**Important:** This table defines the semantic expectations of the contract. It is not a complete list of threat scenarios that will be tested. Teams should generalize the principles (e.g., "actions should target the actor responsible for the threat") to handle scenarios not listed.

---

## 4. Detection via HTTP Response (Primary)

The benchmarker primarily classifies WAF decisions using the required observability headers in §5. HTTP status and response body are used as compatibility signals and for user-facing behavior validation.

Recommended response behavior:

| `X-WAF-Action` | Recommended HTTP behavior |
|----------------|---------------------------|
| `allow` | Proxy the request to upstream and return the upstream response. |
| `block` | Return an explicit denial response, typically `403`. |
| `challenge` | Return a challenge response, typically `429`, with enough information for automated challenge solving. |
| `rate_limit` | Return a rate-limit response, typically `429`. |
| `timeout` | Return a timeout response, typically `504`. |
| `circuit_breaker` | Return a temporary-unavailable response, typically `503`. |

**Design intent**: Teams may use any response body format — HTML page, JSON object, or plain text — as long as the required headers remain accurate and the HTTP behavior is consistent with the reported action.

### Challenge Response Format

When the WAF returns a `challenge` (status `429` + body containing `challenge`), the response body MUST contain enough information for the benchmarker to solve the challenge programmatically. Two formats are supported:

**Format A — JSON challenge:**
```json
{
  "challenge": true,
  "challenge_type": "proof_of_work",
  "challenge_token": "abc123...",
  "difficulty": 4,
  "submit_url": "/challenge/verify",
  "submit_method": "POST"
}
```

**Format B — HTML challenge:**
```html
<!-- Body must contain "challenge" (case-insensitive) for detection -->
<form action="/challenge/verify" method="POST">
  <input type="hidden" name="challenge_token" value="abc123..." />
  <!-- JS computes nonce -->
</form>
```

**Challenge solution submission**: The benchmarker submits `POST <submit_url>` with body `{"challenge_token":"...","nonce":"..."}`. On success, the WAF should return `200` with a session cookie or token that allows the original request to proceed.

If the WAF uses a challenge format the benchmarker cannot parse, the challenge is recorded as `challenge_unsolvable` — the WAF still gets credit for issuing a challenge, but not for the "challenge success lowers score" lifecycle test.

### Minimum response requirements

Your WAF MUST include `X-WAF-Request-Id` on every response so the benchmarker can correlate request-level evidence across response headers and the audit log.

If `X-WAF-Request-Id` is missing, malformed, or inconsistent with the audit log `request_id`, the benchmarker records an observability contract failure for that request.

---

## 5. Mandatory Observability Headers

Your WAF MUST expose the required observability headers below on every HTTP response returned through the WAF, including `allow`, `block`, `challenge`, `rate_limit`, `timeout`, and `circuit_breaker` decisions.

The benchmarker uses these headers as the primary machine-readable decision interface for risk lifecycle checks, rule attribution, caching verification, control-mode correlation, and candidate dashboard evidence. HTTP status/body classification in §4 remains a compatibility fallback, but missing required observability headers are treated as a contract failure.

### 5.1 Required headers

| Header | Type | Description | Exact format |
|--------|------|-------------|-------------|
| `X-WAF-Request-Id` | UUID | Canonical request ID for this request/response pair | UUID v4 string, e.g. `550e8400-e29b-41d4-a716-446655440000` |
| `X-WAF-Risk-Score` | integer 0–100 | Current accumulated risk score for this {IP + device + session} at decision time | Plain integer, no whitespace. Example: `42` |
| `X-WAF-Action` | string | Final reported WAF decision. In `log_only`, this MUST be the intended action that would have been enforced while the request is still allowed upstream. | One of: `allow`, `block`, `challenge`, `rate_limit`, `timeout`, `circuit_breaker`; lowercase, exact match |
| `X-WAF-Rule-Id` | string or `none` | ID of the rule, model, policy, or detector that most directly caused the decision | Alphanumeric + hyphens, e.g. `rule-001`, `policy-default`, or `none` |
| `X-WAF-Cache` | `HIT` / `MISS` / `BYPASS` | Whether the response was served from the WAF cache | Uppercase, exact match. Use `BYPASS` for non-cacheable routes or when caching is disabled. |
| `X-WAF-Mode` | `enforce` / `log_only` | Whether the policy that produced the final reported action is enforcing or only logging | Lowercase, exact match: `enforce` or `log_only` |


### 5.2 Additional observability headers (scored under Dashboard criterion)
The headers listed in §5.1 are the minimum required response headers for benchmark compatibility. Teams MAY add extra `X-WAF-*` response headers to support tracing, investigation, dashboards, forensics, or operational debugging.

Additional headers MUST follow these rules:
- they MUST use the `X-WAF-` prefix;
- they MUST NOT replace or weaken any required header in §5.1;
- they MUST NOT contain secrets, raw credentials, session tokens, stack traces, or sensitive user data;
- they SHOULD be stable and machine-readable when possible.

The event organizers may consider useful extra observability as part of dashboard, intelligence, or operational-quality evaluation, but this document intentionally does not prescribe specific optional header names.

### 5.3 Header consistency rules

- `X-WAF-Action` MUST match the actual behavior of the response when `X-WAF-Mode: enforce`.
- When `X-WAF-Mode: log_only`, the WAF MUST evaluate policies normally and MUST report the intended `X-WAF-Action` that would have been enforced, while block/challenge/rate-limit/timeout/circuit_breaker enforcement MUST NOT be applied.
- In `log_only`, the request SHOULD continue upstream unless blocked by non-WAF transport failures or upstream availability issues.
- `X-WAF-Mode` MUST reflect the mode of the policy that produced the final reported `X-WAF-Action`.
- `X-WAF-Risk-Score` MUST reflect the score after evaluating the current request.
- `X-WAF-Rule-Id` MUST be `none` when no specific rule, model, or policy caused the decision.
- `X-WAF-Cache` MUST be `BYPASS` on authenticated, dynamic, sensitive, high-risk, or otherwise non-cacheable routes.
- `X-WAF-Request-Id` MUST match the audit log `request_id` for the same request.
- Required headers MUST be present on allowed responses as well as block/challenge/rate-limit/timeout/circuit_breaker responses. The benchmarker uses allowed-response risk scores to verify risk accumulation and decay (§8 of benchmark spec).

---

## 6. Audit Log (Secondary)

Your WAF writes structured JSON logs to `./waf_audit.log` (configurable path). Append-only, one JSON object per line (JSONL), SIEM-ingestible.

### Minimal required fields per entry

```json
{
  "request_id": "uuid",
  "ts_ms": 1714000000000,
  "ip": "1.2.3.4",
  "method": "POST",
  "path": "/login",
  "action": "block",
  "risk_score": 75,
  "mode": "enforce"
}
```

| Field | Type | Constraints |
|-------|------|------------|
| `request_id` | string (UUID v4) | Must match `X-WAF-Request-Id` header if both are present |
| `ts_ms` | integer | Unix epoch milliseconds |
| `ip` | string | TCP peer address (NOT XFF). IPv4 dotted decimal. |
| `method` | string | Uppercase HTTP method |
| `path` | string | Request path including query string |
| `action` | string | One of the 6 decision classes from §3 |
| `risk_score` | integer 0–100 | Score at time of decision |
| `mode` | string | `enforce` or `log_only`; must match `X-WAF-Mode` when present |

### Additional audit-log fields (scored under Dashboard criterion)

The fields listed in §6 are the minimum required audit-log fields for correlation and benchmark compatibility. Teams MAY add extra JSON fields to each audit-log entry to support tracing, investigation, dashboards, forensics, operational debugging, or richer security analytics.

Additional audit-log fields MUST follow these rules:

- they MUST NOT replace or weaken any required field in §6;
- they MUST NOT contain secrets, raw credentials, session tokens, stack traces, or sensitive user data;
- they SHOULD be stable and machine-readable when possible;
- they SHOULD preserve JSONL compatibility: one valid JSON object per line.

The event organizers may consider useful extra audit-log fields as part of dashboard, intelligence, or operational-quality evaluation, but this document intentionally does not prescribe specific optional field names.

The benchmarker reads this file after each run for correlation, diagnostics, and score validation. The audit log does not replace the mandatory response headers in §5.

### Audit Log IP Field Semantics

The `ip` field MUST be the TCP peer address (`peer_addr` / `remote_addr` from the socket), NOT a value parsed from `X-Forwarded-For` or any other header. This is critical because:
1. The benchmarker simulates different source IPs via loopback aliases.
2. XFF can be spoofed — the WAF may or may not trust it.
3. The benchmarker correlates audit log entries by TCP source IP.

---

## 7. Decision Normalization Matrix

Borderline scenarios must be classified consistently. The benchmarker primarily uses the required observability headers in §5.1, then uses HTTP status/body and organizer-side validation evidence as supporting signals.

| Required signal | How it is used during normalization |
|-----------------|--------------------------------------|
| `X-WAF-Request-Id` | Correlates response headers with the matching audit-log entry. Missing or mismatched IDs may be treated as an observability contract issue. |
| `X-WAF-Risk-Score` | Supports risk lifecycle checks, risk accumulation/decay validation, and false-positive analysis. |
| `X-WAF-Action` | Primary reported WAF decision. Expected values are `allow`, `block`, `challenge`, `rate_limit`, `timeout`, or `circuit_breaker`. |
| `X-WAF-Rule-Id` | Identifies the rule/model/policy/detector responsible for the reported action, or `none` when no specific detector applies. |
| `X-WAF-Cache` | Distinguishes cache behavior from real upstream/WAF decisions. Expected values are `HIT`, `MISS`, or `BYPASS`. |
| `X-WAF-Mode` | Distinguishes enforced decisions from detection-only `log_only` decisions. |

The classification matrix below MUST be interpreted together with the required headers above:

| Scenario | Required header expectation | Classification | Rationale |
|----------|-----------------------------|---------------|-----------|
| WAF blocks a malicious request | `X-WAF-Action: block`, `X-WAF-Mode: enforce` | `prevented` | Explicit enforced block before exploit succeeds |
| WAF rate-limits or challenges a malicious request | `X-WAF-Action: rate_limit` or `challenge`, `X-WAF-Mode: enforce` | `prevented` | Request is denied or held before reaching the vulnerable path |
| WAF times out or trips circuit breaker for a malicious request | `X-WAF-Action: timeout` or `circuit_breaker`, `X-WAF-Mode: enforce` | `prevented` | Request did not complete successfully against upstream |
| WAF allows a malicious request and organizer-side validation confirms the unsafe effect | `X-WAF-Action: allow`, `X-WAF-Mode: enforce` | `passed` | The unsafe effect was not prevented |
| WAF rewrites/sanitizes payload and organizer-side validation confirms the unsafe effect did not occur | `X-WAF-Action` SHOULD reflect the final decision, usually `allow` or `block`; `X-WAF-Rule-Id` SHOULD identify the responsible detector | `prevented_sanitized` | Attack was neutralized even if the request reached upstream |
| WAF reports a malicious request as detected but runs in log-only mode | `X-WAF-Action: block`, `challenge`, or `rate_limit`; `X-WAF-Mode: log_only` | `log_only_detected` | Detector found the issue, but enforcement was intentionally disabled by control mode |
| Legitimate request is blocked, challenged, or rate-limited outside expected stress conditions | `X-WAF-Action: block`, `challenge`, or `rate_limit`; `X-WAF-Mode: enforce` | `false_positive` | Good traffic was negatively affected by enforcement |
| Legitimate request receives a challenge and then succeeds after solver completion | `X-WAF-Action: challenge` followed by a successful allowed request with correlated `X-WAF-Request-Id` / audit evidence | `allowed_after_challenge` | Challenge was overcome and should not be counted as a false positive by itself |
| Legitimate request during DDoS/stress receives rate limit | `X-WAF-Action: rate_limit`, `X-WAF-Mode: enforce` | `collateral` | Counted separately from false positives; expected under extreme load |
| Response is served from WAF cache | `X-WAF-Cache: HIT` | Classified according to `X-WAF-Action`, with cache behavior verified separately | Prevents stale cache from being confused with fresh upstream/WAF decisions |

**Enforce rule**: In `enforce` mode, a malicious request is `prevented` when `X-WAF-Action` reports an enforced denial/control action (`block`, `challenge`, `rate_limit`, `timeout`, or `circuit_breaker`) and organizer-side validation confirms the unsafe effect did not occur.

**Log-only rule**: In `log_only` mode, the benchmarker verifies detector behavior from `X-WAF-Action`, `X-WAF-Rule-Id`, audit log evidence, and organizer-side validation evidence. Requests in `log_only` SHOULD continue upstream unless blocked by non-WAF transport failures or upstream availability issues, so the unsafe effect may still occur even when the WAF correctly reported an intended `block`, `challenge`, or `rate_limit` action.



---

## 8. WAF Startup & Binary Contract

From the competition rules — repeated here for benchmark/judgement alignment:

```text
Binary:   ./waf
Start:    ./waf run
Config:   ./waf.yaml (or ./waf.toml) — MUST exist in working directory
Logs:     ./waf_audit.log (default, configurable in config file)
```

The benchmarker/judging panel expects:
1. WAF binary exists at `./waf`
2. `./waf run` starts the WAF and begins listening before the startup timeout expires
3. WAF reads the upstream target from its config file
4. WAF listens on the port specified in config
5. `./waf_audit.log` is created once the first request is processed

### Health Check

After starting `./waf run`, the benchmarker polls the configured health endpoint until the startup timeout expires. First `200` response = WAF is ready.

If the WAF does not respond before the startup timeout expires, the benchmarker records `startup_failed`.

---

## 9. Caching Observability

If the WAF implements caching, the benchmarker verifies that cache behavior is safe and observable using `X-WAF-Cache` headers and supporting response behavior.

General expectations:

| Route type | Expected cache behavior |
|------------|------------------------|
| Sensitive, authenticated, dynamic, or high-risk routes | SHOULD NOT be cached. Return `BYPASS` when caching is skipped. |
| Static or explicitly cacheable routes | MAY be cached. Return `MISS` for the first cacheable response and `HIT` for a later response served from cache. |
| Unknown/default routes | SHOULD NOT be cached unless the WAF can prove they are safe to cache. |

`X-WAF-Cache` is mandatory on all responses. For non-cacheable routes, return `BYPASS`.

If caching is implemented, `POST /__waf_control/flush_cache` MUST clear stale cache entries before returning success.

---

## 10. Source IP Trust Model

This section clarifies how the WAF should treat source IPs and proxy headers for the competition:

| Signal | Source of truth | WAF should... |
|--------|----------------|---------------|
| TCP peer address (`peer_addr`) | Socket layer | Always log this in audit log `ip` field. Use as primary IP for rate limiting and risk scoring. |
| `X-Forwarded-For` | Request header (spoofable) | Treat as supplementary context only. Compare against `peer_addr` when useful, but do NOT use as sole IP identity. |
| `X-Real-IP` | Request header (spoofable) | Same as XFF — supplementary signal, not identity. |
| `Host` | Request header | Validate against expected hostname. Reject or sanitize unexpected values. |

**In the sandbox**: All traffic arrives from `127.0.0.x` loopback addresses. The WAF MUST treat different `127.0.0.x` addresses as distinct clients (different IPs for rate limiting, risk scoring, etc.).

---

## 11. Non-Disclosure Principle

Teams are required to implement the observability headers, audit log, startup contract, and WAF control interface above.

The event organizers do not disclose detailed benchmark scenarios, hidden payloads, rule mappings, or scoring logic in this document.

---

## 12. Version 2.3 Delta Summary

Compared to `v2.2`, this version adds:

1. A minimal WAF control plane for deterministic benchmark orchestration:
   - `GET /__waf_control/capabilities`
   - `POST /__waf_control/reset_state`
   - `POST /__waf_control/set_profile`
   - `POST /__waf_control/flush_cache` (if cache is implemented)
2. A strict secret-based protection model for control endpoints (`X-Benchmark-Secret`).
3. Explicit synchronous/atomic runtime state reset semantics to reduce cross-phase contamination while preserving the append-only WAF audit log.
4. Capability-driven feature/policy mode control (`enforce` / `log_only`) for all, one, or selected features/policies.
5. Response-level mode correlation (`X-WAF-Mode`) and support for additional implementation-defined `X-WAF-*` observability headers.
6. Updated observability and audit-log consistency rules for `log_only` mode.
