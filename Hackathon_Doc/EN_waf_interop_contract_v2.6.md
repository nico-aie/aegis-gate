# WAF Interop Contract v2.6

> **Audience**: WAF Hackathon Candidates

> **Scope**: Describes the decisions and control-plane interface that your WAF must expose so the event organizers can evaluate it deterministically. This means that if the event organizers perform the same action (input) under the same conditions, they must always receive the exact same output, without random differences.

---

## 1. Purpose

For automated judging, the WAF MUST provide clear observable outputs so the event organizers' benchmarking tool can classify behavior immediately. The event organizers will not interfere with source code or internal logic unless discrepancy investigation is required.

As a candidate, your WAF MUST attach the observability headers specified in §5 to every HTTP response. While the Audit log (§6) remains a mandatory requirement for correlation and post-run inspection, these response headers are critical for real-time classification and cannot be replaced by the audit log.

This contract covers the WAF data-plane + control-plane evaluation only. Official Rules §5.6 separately mandates a real-time **Dashboard** for live observability (request feed, attack visualisation, hot config, audit-log viewer) scored under the UI criterion. The Dashboard is not exercised by the automated benchmark — it is judged manually during Round 2 Phase 2 and monitored during the Attack Battle (Round 3) to confirm that the displayed information reflects WAF state and real traffic and that the Dashboard remains operational under load. The structured fields defined in §5 (response headers) and §6 (audit log) are sufficient input for a live dashboard.

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

All `POST` control endpoints MUST accept a request body. The benchmark tool sends `{}` (empty JSON object) for endpoints that require no parameters (`reset_state`, `flush_cache`). The WAF MUST NOT reject requests solely because a body is present.

**Response-time SLA.** Control endpoints SHOULD return within **5 seconds** under normal conditions. The benchmarker MAY treat a control call that exceeds **30 seconds** as a failure and abort the run. `reset_state` is the most likely to be slow; if your implementation requires a process restart to satisfy the clearing semantics in §2.4, budget accordingly and document it in `/__waf_control/capabilities`.

### 2.2 Authentication

Control endpoints MUST require a benchmark secret header on **every** request (`GET`, `POST`, `PUT`, `DELETE`):

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

The `"active"` object reflects the current default mode and any active per-feature or per-policy overrides. It is informative only; the benchmark tool reads it for display purposes, and omitting it is not a failure.

All successful control-plane JSON responses SHOULD include `"ok": true` for consistency, but the benchmark tool treats HTTP `200 OK` as the primary success signal.

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

`reset_state` MUST return the WAF to a **fresh runtime state** — as if the WAF had just been started — while keeping the same binary, configuration, and audit log intact. This means all accumulated state from previous test phases (including but not limited to risk scores, rate-limit counters, cache entries, challenge tokens, session data, and other temporary metadata) MUST be fully cleared, and no residual state from prior phases may influence subsequent test behaviour.

It SHOULD preserve long-term static config unless explicitly requested otherwise. **This explicitly includes feature and policy settings, whether set at runtime via `set_profile` or loaded from the configuration file (`waf.yaml` / `waf.toml`). `reset_state` MUST NOT revert any feature or policy to its default or initial state; only temporary per-request and per-session data is affected.**

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

#### Feature toggleability

Every feature and policy supported by the WAF SHOULD be reported in the `/__waf_control/capabilities` response for transparency, **including hardcoded features** that may not respond to `set_profile`. The WAF MUST support switching each listed feature or policy independently between `enforce` and `log_only` modes **where technically feasible**.

The benchmark tool relies on `set_profile` to isolate specific feature effects during evaluation. If a feature is reported as `toggleable: true` but does not actually respond to mode changes, or if a hardcoded feature causes scoring anomalies (false positives, missed detections, inconsistent header values), the responsibility lies with the WAF implementation — not the benchmark tool. Teams SHOULD report `toggleable: false` for hardcoded features that cannot be toggled, but must accept any scoring impact if those features influence benchmark results.

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

- `scope: "all"` (**MUST** be supported) changes the default mode for all supported features/policies.
- `scope: "features"` (**SHOULD** be supported) changes only the listed features. All omitted features MUST keep their current mode.
- `scope: "policies"` (**SHOULD** be supported) changes only the listed policies. All omitted policies in the same feature, and all unrelated features, MUST keep their current mode.

Per-feature and per-policy scopes are **SHOULD**, not **MUST**, because many rule engines toggle modes globally rather than per-detector. A WAF that only supports `scope: "all"` MUST still respond to `features` / `policies` requests with a clear `unsupported` list (per the rule below) rather than silently widening the scope.

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

#### Override key conventions

The `active.overrides` object uses the following key conventions:

- **Feature-level override:** key is the feature name, e.g. `"access_control"`.
- **Policy-level override:** key uses dot notation `"feature.policy"`, e.g. `"access_control.blacklist"`.

A WAF MAY use either or both forms in the same response.

#### Unsupported items

If a requested feature or policy is unsupported, the WAF MUST NOT silently ignore it. The response MUST use one of the following approaches:

1. **(Recommended — safe for benchmark)** Return HTTP `200 OK` with a machine-readable `unsupported` list naming the features or policies that could not be applied. This is the safest approach and will not affect the benchmark run.

2. **(Optional — punitive)** Return `400 Bad Request` or `422 Unprocessable Entity` with a machine-readable `unsupported` list. If the WAF chooses this approach for a partially-supported profile (e.g., `features` or `policies` scope while only `all` is natively supported), the benchmark run will be aborted after the current test completes.

When a WAF receives a `scope` it does not fully support (e.g., `features` or `policies` while only `all` is natively supported), it SHOULD return HTTP `200 OK` and populate the `unsupported` list. If the WAF returns `400` or `422` for partially-supported profiles instead, the benchmark run will be aborted.

The `unsupported` array SHOULD contain strings naming the unsupported feature or policy identifiers, using the same names as appear in the `capabilities` response (e.g. `["geo_blocking"]`).

The chosen behavior MUST be consistent for the entire benchmark run.

### 2.6 Cache Flush

Endpoint:

```http
POST /__waf_control/flush_cache
```

If WAF caching is implemented, this endpoint MUST be supported so benchmark runs are not affected by stale cached decisions.

If caching is not implemented, the WAF SHOULD return HTTP `501 Not Implemented` or `200 OK` with a clear JSON body indicating no cache exists. Other status codes (e.g. `404 Not Found`) are treated as endpoint failures by the benchmark tool.

### 2.6b Implementation Notes & Rule Schema

Per Official Rules §5.1, the WAF data-plane core MUST be a single Rust binary started with `./waf run`. Per Official Rules §2, the control plane / dashboard MAY be implemented in any language (the Rust constraint applies only to the data-plane core). Teams therefore have two ways to expose `/__waf_control/*`:

1. **In-process** — handle the endpoints inside the Rust data-plane binary on the main listening port (or a separate port on the same process).
2. **Sidecar** — run a control-plane process (any language, e.g. Node.js, Rust, Go) on a separate port. The sidecar communicates with the data-plane core through an internal mechanism (Unix socket, shared memory, in-process RPC, file-watch, IPC) to actually clear state, toggle modes, and flush cache.

Whichever approach you pick, the benchmarker sees the same HTTP contract — it makes no assumption about process topology. Both approaches MUST satisfy: local-only bind, `X-Benchmark-Secret` header (§2.2), the response-time SLA in §2.1, and the atomic/synchronous semantics in §2.4 (a successful `reset_state` response means all temporary state across the entire WAF system is cleared, not just the sidecar's local state).

The contract endpoints in §2.1 are the **only** surface the benchmarker addresses. Teams are free to expose additional admin endpoints (metrics, health, manual rule editing) outside the `/__waf_control/*` namespace for their own dashboard (Official Rules §5.6) — those will not be invoked by the automated benchmarker but may be evaluated under the Dashboard criterion.

**Hot-reload of rules** is mandatory per Official Rules §5.4, but the *mechanism* is left to each team — signal-driven, file-watch, in-process API, or any other approach that satisfies "add/edit/delete rules without rebuilding the binary." The benchmark does not call a `reload_rules` endpoint; rule-edit capability is evaluated against the team's own admin surface during the Extensibility scoring pass.

**Rule schema (machine-readable):** `benchmark-infra/schemas/rule.schema.json` is the JSON-Schema (Draft 2020-12) describing one rule. It is provided as a *reference* shape that benchmark tooling and dashboards can parse; teams are free to use YAML, TOML, or JSON as their on-disk format per Official Rules §5.4 as long as their rules express the same fields (`id`, `match`, `action`, optional `risk_score_delta`, `priority`, `scope`). `action` MUST be one of the values in §3 below.

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

### 3.1 Acceptable Actions by Threat Category

This table maps the threat categories used by the benchmarker to the set of `X-WAF-Action` values considered semantically valid for that category. A WAF that returns any action in the set for a given category satisfies the action-semantics check used by the benchmarker.

This is a **semantic compatibility map**, not a PASS criteria override. Per-test PASS conditions are determined by the organizers and may require additional signals beyond the reported action (for example, `X-WAF-Risk-Score` thresholds, session-state behavior, or challenge completion). These per-test conditions are not enumerated in this document.

| Threat category | Acceptable `X-WAF-Action` |
|---|---|
| Auth abuse (brute force, credential stuffing, password spraying) | `block`, `challenge`, `rate_limit` |
| Relay / proxy spoofing (XFF tampering, multi-hop chains) | `block`, `challenge`, OR `allow` with `X-WAF-Risk-Score > 0` |
| Behavioral anomaly (bot patterns, timing, cadence, fingerprint) | `block`, `challenge`, `rate_limit` |
| Behavioral signal (missing/spoofed header on authenticated route) | `block`, `challenge`, OR `allow` with `X-WAF-Risk-Score` delta > 0 |
| Behavioural bot discipline (session-token brute-force, IDOR enumeration) | `block`, `challenge`, `rate_limit` |
| Transaction fraud (velocity, geo, value, multi-account) | `block`, `challenge`, `rate_limit` |
| Recon / enumeration (path, OPTIONS, error harvest) | `block`, `challenge`, `rate_limit` |
| Canary probing / known-bad IP lock | `block` |
| Negative control / legitimate traffic | `allow` (with `X-WAF-Risk-Score < 10`) |

**Notes.**

1. `rate_limit` and `challenge` are distinct actions in §3, but both return HTTP `429` per §4. A benchmark test that says "PASS = at least 1 request receives 429" accepts either action.
2. For categories that permit `allow` with a risk-score signal (relay spoofing, behavioral signal), the WAF satisfies the action-semantics check by elevating `X-WAF-Risk-Score` even when not taking a blocking action. This reflects WAFs that defer mitigation to a downstream system or aggregate signals across requests.
3. Per-test PASS conditions are determined by the organizers and not enumerated here. The table defines which actions are semantically valid for each category, not their per-test score weights.
4. This table is descriptive of the action-semantics check used by the benchmarker. Teams should generalize the principles to handle scenarios not listed.

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

### 429 Challenge/Rate Limit
#### Rate-limit responses (429 — `rate_limit`)

A `rate_limit` action returns HTTP `429` without requiring a client-solving step. The WAF refuses the request when a rate threshold is exceeded.

**Basic rate-limit (mandatory).** Teams MUST implement a basic rate-limit mechanism themselves — no built-in third-party rate-limiter allowed for the basic version. The logic flow MUST follow a standard pattern: track per-client request counts within a time window, compare against a threshold, and return HTTP `429` with `X-WAF-Action: rate_limit` when exceeded. The implementation MUST be deterministic and logically sound.

Example basic rate-limit response:

```http
HTTP/1.1 429 Too Many Requests
Content-Type: application/json
Retry-After: 30
X-WAF-Request-Id: req-a1b2c3d4
X-WAF-Risk-Score: 75
X-WAF-Action: rate_limit
X-WAF-Rule-Id: rate-limit-burst
X-WAF-Cache: BYPASS
X-WAF-Mode: enforce

{
  "error": "rate_limit_exceeded",
  "message": "Too many requests. Please slow down.",
  "retry_after_seconds": 30,
  "other_param":"other_value"
}
```

Rate-limit responses MUST include a `Retry-After` response header (integer seconds) and/or a `retry_after_seconds` field in the JSON body. The benchmarker relies on `X-WAF-Action: rate_limit` and HTTP `429` as primary detection signals.

**Advanced rate-limit (optional).** Teams MAY extend with more sophisticated strategies, but all rate-limit implementations MUST be self-built — no built-in third-party rate-limiter services allowed. The basic rate-limit MUST remain functional regardless.

#### Challenge responses (429 — `challenge`)

**Basic challenge (mandatory).** Teams MUST implement a basic proof-of-work challenge themselves — no built-in third-party challenge/CAPTCHA service allowed for the basic version. The logic flow MUST follow a standard pattern: generate a token + difficulty, client finds a nonce satisfying the proof, WAF verifies the solution. The implementation MUST be deterministic and the verification logic MUST be correct (valid solutions accepted, invalid rejected).

The benchmark tool will solve challenges following the format and submission flow below. If the tool cannot solve a challenge, it is a team implementation issue — not a benchmark limitation — since the required format and flow are explicitly specified here.

Two formats are supported:

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
<html>
<body>
  <p>Verifying you are human...</p>
  <form id="challenge-form" action="/challenge/verify" method="POST">
    <input type="hidden" name="challenge_token" value="abc123..." />
    <input type="hidden" name="nonce" id="nonce" value="" />
  </form>
  <!-- JS computes nonce -->
  <script>
        (function() {
      const token = "abc123...";
      const difficulty = 4;
      const prefix = "0".repeat(difficulty);
      let nonce = 0;
      async function solve() {
        while (true) {
          const data = new TextEncoder().encode(token + nonce);
          const hash = await crypto.subtle.digest("SHA-256", data);
          const hex = [...new Uint8Array(hash)]
            .map(b => b.toString(16).padStart(2, "0")).join("");
          if (hex.startsWith(prefix)) {
            document.getElementById("nonce").value = String(nonce);
            document.getElementById("challenge-form").submit();
            return;
          }
          nonce++;
        }
      }
      solve();
    })();
  </script>
</body>
</html>
```

**Challenge solution submission**: The benchmarker submits `POST <submit_url>` with body `{"challenge_token":"...","nonce":"..."}`. On success, the WAF returns `200` with a session cookie or token that allows the original request to proceed.

If the WAF uses a challenge format the benchmarker cannot parse or solve, the challenge is recorded as **FAILED**. No partial credit is awarded for issuing an unsolvable challenge.

**Advanced challenge (optional).** Teams MAY implement additional challenge mechanisms for production hardening, but all challenge implementations MUST be self-built — no built-in third-party challenge/CAPTCHA service (Cloudflare Turnstile, Google reCAPTCHA, hCaptcha, or equivalents) allowed. The basic solvable challenge MUST remain present and parseable regardless.

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
| `X-WAF-Request-Id` | string | Canonical request ID for this request/response pair, stable across response headers and audit log | Any unique token, 8–64 chars, `[A-Za-z0-9._-]` only. UUID v4 is fine but not required. |
| `X-WAF-Risk-Score` | integer 0–100 | Current accumulated risk score for this {IP + device + session} at decision time. Thresholds in Official Rules §5.5 (`<30 allow / 30–70 challenge / >70 block`) reference this scale. | Plain integer, no whitespace. Example: `42` |
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
- Required headers MUST be present on allowed responses as well as block/challenge/rate-limit/timeout/circuit-breaker responses. The benchmarker uses allowed-response risk scores to verify risk accumulation and decay (§8 of benchmark spec).

---

## 6. Audit Log (Secondary)

Your WAF writes structured JSON logs to `./waf_audit.log` (configurable path). Append-only, one JSON object per line (JSONL), SIEM-ingestible.

### Minimal required fields per entry

```json
{
  "request_id": "req-7f3c2a",
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
| `request_id` | string | Must match `X-WAF-Request-Id` header — same format constraints (8–64 chars, `[A-Za-z0-9._-]`) |
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
1. The benchmarker may simulate distinct source IPs via loopback addresses for some attack families, where the security-relevant signal is *same single source* burst behaviour rather than geographic identity. A separate subset of test cases is fired from real externally-routed IPs, so production GeoIP / Tor-exit / ASN feeds remain useful — no benchmark-only IP convention is required.
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

## 11. Disclosure Boundary

This document and the Official Rules together define **what** the WAF is evaluated on:

- The threat-category surface, OWASP coverage list, tier policy, risk-score thresholds, behavioural and transaction-velocity rules, canary-endpoint semantics, and scoring weights are published in the Official Rules (§4–§7). Teams should design against those.
- The contract endpoints, response headers, audit-log schema, and decision normalisation matrix are defined in this contract. Teams MUST implement them as specified.

The event organizers do **not** disclose the specific payloads, individual test-case parameters, IP/timing schedules, or exact ordering used during the automated benchmark and the 45-minute Attack Battle. A WAF that hard-codes responses to a specific payload, IP, or sequence rather than detecting the underlying threat class will fail the broader coverage required by Official Rules §4 ("the WAF must protect the entire target website, not a handful of endpoints") and may be disqualified.

### 11b. Evaluation Phases

Scoring is produced from two phases that share this contract but differ in operating model:

1. **Automated benchmark (corresponds to Round 2 Phase 1 in the Candidate Briefing).** Runs the WAF against a deterministic, headless test suite. Every requirement in §§2–7 (control plane, observability headers, audit log, decision normalisation) is evaluated mechanically. `set_profile`, `reset_state`, and `flush_cache` are used between test groups to control determinism. This produces the bulk of the Security Effectiveness, Performance, Intelligence & Adaptiveness, and Extensibility points (Official Rules §6). The benchmark tool may be deployed to any team's WAF-server depending on the scenario (e.g., cross-team evaluation, isolation testing, or shared infrastructure), ensuring stable, reproducible results independent of network noise and allowing the OC to control the execution environment per scenario.

2. **Attack Battle (45 minutes, manual, live — corresponds to Round 3 in the Candidate Briefing).** The Red Team launches real-world techniques against any route on the target site. Manual intervention by the team is **strictly prohibited** (Official Rules §7) — the WAF must defend autonomously. The team's dashboard (Official Rules §5.6) is judged during this phase, and the OC MUST monitor it to verify that displayed events, metrics, and WAF state accurately reflect real traffic and that the Dashboard operates smoothly under load. The structured fields in §5.2 and §6 should be sufficient for a live operator to understand attacks as they happen. The WAF MUST continue to honour every contract clause in this document for the full 45 minutes; observability headers, audit log, and `/__waf_control/*` endpoints all remain in scope. `set_profile` will not be invoked by the Red Team — the WAF runs in `enforce` mode for the entire battle.

> **Note on manual Dashboard verification (Round 2 Phase 2):** Between the automated benchmark and the Attack Battle, the OC may also perform a manual Dashboard check where features are toggled through the admin UI to confirm they drive actual WAF behaviour. Any Dashboard-initiated toggle during this check is an operational validation step, not an invocation of `/__waf_control/set_profile` by the benchmarker.

Both phases use the same binary started by `./waf run`. There is no separate "attack mode" or "benchmark mode" — the contract is identical.

---

## 12. Version Delta Summary

### v2.6 (2026-06-10 — feature-toggle clarification + rate-limit / challenge specification)

1. **§2.4 — Runtime reset semantics clarified.** `reset_state` MUST return the WAF to a fresh runtime state as if just started — clearing all accumulated risk scores, counters, cache, and session state, ...etc — while preserving the audit log and static configuration.
2. **§2.5 — Feature toggleability clarified.** All features SHOULD be listed in `/__waf_control/capabilities` for transparency. Hardcoded features that cannot respond to `set_profile` SHOULD be reported with `toggleable: false` — teams are responsible for scoring impacts if hardcoded features affect benchmark results.
3. **§4 — Rate-limit and challenge specification (basic + advanced).** Both `rate_limit` (429) and `challenge` (429) now have explicit format examples and implementation guidance:
   - **Basic (mandatory)** — teams MUST self-implement a basic rate-limit and a basic proof-of-work challenge without third-party built-in services. Standard logic flow is required. Examples provided.
   - **Advanced (optional)** — teams MAY extend with sophisticated strategies, but all implementations MUST be self-built (no third-party rate-limiter or challenge/CAPTCHA services). The basic version MUST remain functional.
   - The benchmark tool follows the documented format and submission flow to solve challenges. If the tool cannot solve, it is a team implementation issue.
4. **§13 — Minimum Viable WAF Checklist updated.** Items added for `capabilities` accuracy and feature-toggle consistency.
5. **§2.6 — Flush cache (no cache scenario).** Clarified that WAF SHOULD return `501 Not Implemented` or `200 OK` (not `404`) when caching is not implemented.
6. **§2.8 — Unsupported items clarification.** Fixed contradiction: `200 OK` is now recommended (safe), `400/422` is optional but punitive (aborts run).
7. **§11b — Benchmark deployment flexibility.** Clarified that the benchmark tool may be deployed to any team's WAF-server depending on the scenario.
8. **§11b — Evaluation phases aligned with Candidate Briefing.** Added cross-references: automated benchmark = Round 2 Phase 1; Attack Battle = Round 3. Added note distinguishing benchmarker `set_profile` API calls from Dashboard-initiated toggles during manual verification.
9. **§11b — Dashboard monitoring in the Attack Battle is mandatory.** OC MUST monitor the Dashboard during the Attack Battle to confirm displayed information reflects WAF state and real traffic and that the Dashboard operates smoothly under load.

### v2.5 (2026-05-17 — clarification + scope-tightening release)

Clarification changes; no previously-passing WAF becomes failing.

1. **§2.6b — `reload_rules` demoted to optional.** The four-endpoint Native option is reduced to three (`set_profile`, `flush_cache`, status/metrics). Teams may handle hot-reload through any mechanism (SIGUSR1, file watcher, vendor admin API, ConfigMap rollover). Rationale: forcing a single endpoint shape tested integration boilerplate, not reload capability.
2. **§3.1 — Threat Category table simplified.** Two-column format (Threat category | Acceptable `X-WAF-Action`). Per-test PASS conditions are organizer-defined and not enumerated in the contract. Multiple action types may satisfy each category.
3. **§4 — Challenge format restricted to JSON (Format A) or HTML (Format B).** Self-built challenge logic is mandatory; third-party challenge verification services (Cloudflare Turnstile, Google reCAPTCHA, hCaptcha, or equivalents) are not permitted. An unsolvable challenge is recorded as FAILED — no partial credit.
4. **§6 — Audit-log IP semantics clarified.** Loopback addresses are simulation tooling for single-source burst families where geographic identity is irrelevant. A separate subset of test cases is fired from real externally-routed source IPs, so teams may use production GeoIP/Tor/ASN feeds (MaxMind, IPinfo, the live Tor exit list, BGP-derived ASN data) — no benchmark-only IP convention applies. Rationale: prior loopback-range simulation required teams to write GeoIP entries no production WAF would ever ship.


---

## 13. Minimum Viable WAF Checklist

To be **scored at all** by the automated benchmarker, your WAF must satisfy this minimum surface. Anything below this line is not scoring optimisation — it's the precondition for entering the run.

**Binary & startup (§8)**
- [ ] `./waf` exists, `./waf run` starts the proxy
- [ ] Listens on the port from `./waf.yaml` (or `./waf.toml`)
- [ ] Health endpoint returns `200` before the startup timeout

**Reverse proxy**
- [ ] Forwards every public-API request to the upstream target app and returns the upstream response
- [ ] Does **not** rewrite the request body unless the WAF intentionally sanitises it (see §7 `prevented_sanitized`)

**Required response headers on every response (§5.1)**
- [ ] `X-WAF-Request-Id` (unique 8–64 char token, matches audit log)
- [ ] `X-WAF-Risk-Score` (integer 0–100)
- [ ] `X-WAF-Action` (`allow` / `block` / `challenge` / `rate_limit` / `timeout` / `circuit_breaker`)
- [ ] `X-WAF-Rule-Id` (or `none`)
- [ ] `X-WAF-Cache` (`HIT` / `MISS` / `BYPASS`)
- [ ] `X-WAF-Mode` (`enforce` / `log_only`)

**Recommended (scored separately, pending benchmark-tool support)**
**Control plane (§2)**
- [ ] `GET /__waf_control/capabilities` returns the feature/policy surface
- [ ] `POST /__waf_control/reset_state` synchronously clears risk/rate-limit/challenge/cache/session state
- [ ] `POST /__waf_control/set_profile` toggles `enforce` ↔ `log_only` for at least `scope: "all"`
- [ ] `POST /__waf_control/flush_cache` (only if caching is implemented)
- [ ] All four require `X-Benchmark-Secret: waf-hackathon-2026-ctrl`; return `403` otherwise
- [ ] All four respond within 5 seconds under normal load
- [ ] Features reported as `toggleable: true` actually respond to `set_profile`
- [ ] Hardcoded features that cannot be toggled are either reported with `toggleable: false` or clearly documented as such in `capabilities`

**Audit log (§6)**
- [ ] `./waf_audit.log` is JSONL, append-only across resets
- [ ] Each line has `request_id`, `ts_ms`, `ip` (TCP peer), `method`, `path`, `action`, `risk_score`, `mode` (required)
- [ ] `request_id` matches the corresponding `X-WAF-Request-Id` header

**Behaviour under `log_only` (§5.3)**
- [ ] Detectors still fire and populate `X-WAF-Action` with the intended action
- [ ] Request is **not** blocked — traffic continues upstream

If any item above is missing, the benchmarker will record a contract failure and most threat-coverage tests will not even run against your WAF. Once these pass, the scoring criteria in Official Rules §6 apply.
