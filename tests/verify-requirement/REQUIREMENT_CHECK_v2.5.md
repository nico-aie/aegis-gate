# Requirement Verification Report — WAF Hackathon v2.5

> **Reference docs:** `Hackathon_Doc/EN_present_v2.5.md` · `Hackathon_Doc/EN_waf_interop_contract_v2.5.md`
> **Audit date:** 2026-05-19
> **Audited by:** Static source code review (aegis-gate codebase)

---

## Executive Summary

| Severity | Count |
|----------|------:|
| 🔴 CRITICAL — blocks benchmark scoring | 3 |
| 🟠 HIGH — likely causes test failures | 2 |
| 🟡 MEDIUM — partial compliance / missing deliverable | 2 |
| 🟢 PASS — fully compliant | 30 |

**Must fix before submission:** Items `C-1`, `C-2`, `C-3` below. Without these the automated benchmarker either cannot correlate audit evidence, cannot solve challenges, or cannot reach control endpoints.

---

## Critical Issues (Must Fix)

### C-1 — Challenge response field names don't match §4 Format A

**Contract §4 requires:**
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

**Code emits** (`crates/aegis-proxy/src/data_plane.rs:1068-1079`):
```json
{
  "challenge": true,
  "challenge_type": "proof_of_work",
  "nonce": "...",
  "difficulty": 16,
  "expires_at_ms": 1234567890000,
  "mac": "...",
  "submit_to": "/__waf_control/challenge_verify"
}
```

**Mismatches:**
- `nonce` → should be `challenge_token`
- `submit_to` → should be `submit_url`
- `submit_method: "POST"` is missing entirely

**Why it matters:** The benchmarker reads `challenge_token` and `submit_url` to solve the challenge. If those fields are absent or named differently, the benchmarker records **FAILED** for every challenge issued. No partial credit.

**Fix:** In `data_plane.rs` challenge body builder, rename `"nonce"` → `"challenge_token"`, rename `"submit_to"` → `"submit_url"`, add `"submit_method": "POST"`.

Also update the verify endpoint (`admin_dispatch.rs:860`, `VerifyBody` struct) to accept `challenge_token` as the field name that carries the nonce value, matching the submission contract in §4:
> "The benchmarker submits `POST <submit_url>` with body `{"challenge_token":"...","nonce":"..."}`"

---

### C-2 — `waf.yaml` audit path points to wrong location

**Contract §8:** `./waf_audit.log` is the default path benchmarker reads.

**`config/profiles/prod-balanced.yaml`** (which becomes `./waf.yaml` after `make stage`):
```yaml
interop:
  audit_path: "/var/log/aegis/contract-audit.jsonl"
```

This overrides the code default (`./waf_audit.log`) to an absolute path at `/var/log/aegis/` that may not be writable in the judging environment and **is not where the benchmarker looks**.

**Fix:** Change `prod-balanced.yaml` (and any other staged profiles) to:
```yaml
interop:
  audit_path: "./waf_audit.log"
```

---

### C-3 — `interop.control_secret` is a placeholder in staged config

**Contract §2.2:** Control endpoints must accept `X-Benchmark-Secret: waf-hackathon-2026-ctrl`.

**`config/profiles/prod-balanced.yaml`:**
```yaml
interop:
  control_secret: "REPLACE FROM SECRET MANAGER"
```

**Fix:** Set this to the exact hackathon value before staging:
```yaml
interop:
  control_secret: "waf-hackathon-2026-ctrl"
```

---

## High Priority Issues

### H-1 — `./waf` binary and `./waf.yaml` not pre-staged in repo root

**Contract §8:**
```
Binary:   ./waf
Start:    ./waf run
Config:   ./waf.yaml (or ./waf.toml) — MUST exist in working directory
```

**Current state:** Neither `./waf` nor `./waf.yaml` exists in the repo root. Judges must run `make stage` manually before evaluation. If the judging process goes straight to `./waf run`, the binary won't be found.

**Fix:** Either pre-stage them as part of the submission package, or add clear instructions in `README.md`/`QUICKSTART.md` that `make stage` must be run first. The `Makefile` `stage` target already handles this correctly — just make it a mandatory pre-submission step.

---

### H-2 — `/__waf_control/*` endpoints are on the admin port (9443), not the data plane port (8080)

**Contract §2.1:** Control endpoints are at `/__waf_control/*` and must be reachable. The benchmarker sends control requests and also sends traffic through the WAF. These need to be on the same port **or** the submission docs must clearly state which port has the control plane.

**Current state:** From `config/dev.yaml`:
- Data plane: `:8080` (plain) and `:8443` (TLS)
- Admin (control plane): `:9443`

The `/__waf_control/capabilities`, `reset_state`, `set_profile`, `flush_cache` endpoints are dispatched from `admin_dispatch.rs` which runs on the admin port. If the benchmarker sends control calls to the data plane port (8080), they will **not be handled**.

**Fix:** Either:
1. Mirror the `/__waf_control/*` routes on the data plane port as well, **or**
2. Clearly document which port the benchmarker should use for control calls in your submission, and ensure the judging team configures their tool for port 9443.

The contract says "local/admin-only" for control endpoints, so exposing on admin port is architecturally correct — but the tool configuration matters.

---

## Medium Issues

### M-1 — Missing submission guide document (§3 of candidate briefing)

**Requirement:** When submitting, teams must include a companion guide file describing the workflow of each feature/policy.

**Template from the spec:**
```
+ Policy/Feature: Blacklist
+ Description: ...
+ How it works:
1. ...
2. ...
```

**Current state:** No such document found in the repository. `README.md` and `QUICKSTART.md` cover operational setup but not the policy workflow format required by the OC.

**Fix:** Create a `SUBMISSION_GUIDE.md` (or similar) documenting each feature listed in `capabilities`: `access_control` (blacklist/whitelist), `rules_engine` (sqli, xss, path_traversal, ssrf, header_injection, body_abuse, recon, brute_force, ai, command_injection, template_injection, nosql_injection, open_redirect), `rate_limit` (per_ip), `risk_engine` (score, strikes).

---

### M-2 — Dashboard real-time requirement (≤ 5 seconds) not verifiable from source alone

**Requirement (Round 1):** Logs/Events must appear on the Dashboard within ≤ 5 seconds of the WAF processing the request.

**Current state:** The audit bus (`AuditBus` in `aegis-core/src/audit.rs`) uses a `broadcast` channel. The dashboard subscribes via SSE. The latency depends on polling interval configuration. This cannot be confirmed as ≤ 5s from static analysis alone — needs a runtime measurement.

**Recommendation:** Document the expected latency in your submission guide, and verify with a smoke test before evaluation day.

---

## Passed Requirements ✅

### §8 — Binary & Startup Contract

| Requirement | Status | Evidence |
|---|---|---|
| Binary is `./waf` | ✅ | `crates/aegis-bin/Cargo.toml`: `[[bin]] name = "waf"` |
| `./waf run` starts the proxy | ✅ | `main.rs`: `"run" => { ... run_gateway(...) }` |
| Reads config from `./waf.yaml` or `./waf.toml` | ✅ | `main.rs`: `for candidate in ["./waf.yaml", "./waf.toml"]` |
| `make stage` creates `./waf` symlink + `./waf.yaml` | ✅ | `Makefile` `stage` target |
| Health endpoint at `/__waf_control/healthz` | ✅ | `admin_dispatch.rs:771` |

### §5.1 — Mandatory Observability Headers (all 6 required)

| Header | Status | Evidence |
|---|---|---|
| `X-WAF-Request-Id` | ✅ | `headers.rs:15`, stamped in `Decision::stamp()` |
| `X-WAF-Risk-Score` | ✅ | `headers.rs:16`, integer 0–100 |
| `X-WAF-Action` | ✅ | `headers.rs:17`, all 6 lowercase values correct |
| `X-WAF-Rule-Id` | ✅ | `headers.rs:18`, defaults to `"none"` when absent |
| `X-WAF-Cache` | ✅ | `headers.rs:19`, uppercase HIT/MISS/BYPASS |
| `X-WAF-Mode` | ✅ | `headers.rs:20`, `enforce` or `log_only` |

All 6 headers are stamped on every response (allow, block, challenge, rate_limit, timeout, circuit_breaker) via `Decision::stamp()`. Unit tests in `headers.rs` verify exact wire strings and that `stamp()` replaces rather than appends.

### §5.2 — Bonus Observability Headers

| Header | Status | Notes |
|---|---|---|
| `X-WAF-Overhead-Latency` | ✅ | Latency in ms with µs precision (e.g. `12.345`) — useful for operational dashboards |

### §3 — Decision Classes

| Decision | Status |
|---|---|
| `allow` | ✅ |
| `block` | ✅ |
| `challenge` | ✅ (field names need fix per C-1) |
| `rate_limit` | ✅ |
| `timeout` | ✅ |
| `circuit_breaker` | ✅ |

All six classes are typed enums (`Action` in `headers.rs`; `AuditAction` in `audit.rs`). Wire strings match spec exactly.

### §2 — WAF Control Interface

| Endpoint | Status | Evidence |
|---|---|---|
| `GET /__waf_control/capabilities` | ✅ | `control.rs`: `capabilities()` returns full features + active state |
| `POST /__waf_control/reset_state` | ✅ | `control.rs`: `reset_state()`, synchronous, all callbacks run before response |
| `POST /__waf_control/set_profile` | ✅ | `control.rs`: `set_profile()`, supports `scope: all/features/policies` |
| `POST /__waf_control/flush_cache` | ✅ | `control.rs`: `flush_cache()`, returns `supported: false` gracefully when no cache |

### §2.2 — Authentication

| Requirement | Status | Evidence |
|---|---|---|
| `X-Benchmark-Secret` header required | ✅ | `control.rs:check_auth()` |
| Missing/wrong secret → 403 | ✅ | `ControlError::Forbidden` → HTTP 403 |
| Constant-time comparison (timing-safe) | ✅ | `constant_time_eq()` in `control.rs:28-37` |

### §2.4 — reset_state Semantics

| Requirement | Status | Evidence |
|---|---|---|
| Clears risk state | ✅ | Reset callback registered for `RiskTracker` |
| Clears rate-limit counters | ✅ | Reset callback registered for `IpRateLimiter` |
| Clears challenge/session state | ✅ | Reset callback registered |
| Does NOT delete audit log | ✅ | `reset_callbacks` never touches the JSONL sink; `audit_log_preserved: true` in response |
| Response format matches spec | ✅ | `ResetResponse { ok, action, audit_log_preserved, ts_ms }` |
| Synchronous / atomic | ✅ | All callbacks run before returning success |

### §2.5 — set_profile Semantics

| Requirement | Status | Evidence |
|---|---|---|
| `scope: "all"` sets default for all features | ✅ | `ModeStore::set_all()` |
| `scope: "features"` overrides only listed | ✅ | `ModeStore::set_feature()` |
| `scope: "policies"` overrides only listed policy | ✅ | `ModeStore::set_policy()` |
| Unsupported items listed in `unsupported` field | ✅ | Returns list, not silent ignore |
| Response shape matches spec | ✅ | `SetProfileResponse { ok, action, applied, active, unsupported, ts_ms }` |
| `scope: all` rejects extra fields → 400 | ✅ | Unit test `set_profile_scope_all_rejects_extra_fields` |

### §6 — Audit Log

| Requirement | Status | Evidence |
|---|---|---|
| JSONL format, one object per line | ✅ | `interop/audit.rs:MinimalJsonlSink` |
| Append-only (never truncated by reset) | ✅ | Opened with `OpenOptions::append(true)` |
| `request_id` (matches `X-WAF-Request-Id`) | ✅ | `MinimalAuditEntry.request_id` |
| `ts_ms` (Unix epoch milliseconds) | ✅ | `chrono::Utc::now().timestamp_millis()` |
| `ip` (TCP peer address, NOT XFF) | ✅ | `admin_dispatch.rs:1087`: `ip: peer.ip().to_string()` — raw socket address |
| `method` (uppercase) | ✅ | `method.as_str().to_string()` |
| `path` (including query string) | ✅ | `MinimalAuditEntry.path` |
| `action` (one of 6 decision classes) | ✅ | `AuditAction` typed enum |
| `risk_score` (0–100) | ✅ | Clamped to 100; `None` → 0 |
| `mode` (`enforce` or `log_only`) | ✅ | `mode.as_str()` |
| `request_id` matches `X-WAF-Request-Id` | ✅ | Same value stamped in header and log |
| Bonus: `rule_id` field | ✅ | `skip_serializing_if = "Option::is_none"` |
| Bonus: `tier` field | ✅ | `critical\|high\|medium\|low` |

### §5.3 — log_only Mode Behavior

| Requirement | Status | Evidence |
|---|---|---|
| Detectors still evaluate requests | ✅ | All detector branches check `resolve_mode()` |
| `X-WAF-Action` reports intended action | ✅ | `data_plane.rs:756-765`: `log_only_intent` carries the would-be action |
| `X-WAF-Mode: log_only` in response | ✅ | Mode stamped via `Decision::stamp()` |
| Request NOT blocked (continues upstream) | ✅ | `data_plane.rs:931`: upstream request proceeds when `log_only_intent.is_some()` |
| Audit log records intended action | ✅ | Audit entry written before upstream forward |

### §4 — Challenge System (self-built PoW)

| Requirement | Status | Evidence |
|---|---|---|
| Self-built challenge (no third-party CAPTCHA) | ✅ | `challenge/pow.rs`: stateless blake3-keyed PoW |
| Challenge body contains enough info to solve | ✅ (field names need fix per C-1) | nonce, difficulty, expiry, MAC, submit path |
| Verify endpoint exists | ✅ | `POST /__waf_control/challenge_verify` (`admin_dispatch.rs:843`) |
| Single-use nonce (replay protection) | ✅ | `state.put_nonce(nonce, ttl)` — second verify rejected |
| Session cookie/token after successful solve | ✅ | 200 response with token on correct solve |
| No external API calls for verification | ✅ | Pure blake3 computation, no outbound calls |

### Round 1 — Core Security Detection (OWASP coverage)

| Feature | Status | Evidence |
|---|---|---|
| SQLi detection | ✅ | `detectors/sql_injection.rs` (multi-layer: regex + decode passes) |
| XSS detection | ✅ | `detectors/xss.rs` |
| Path traversal | ✅ | `detectors/path_traversal.rs` |
| SSRF detection | ✅ | `detectors/ssrf.rs` |
| Command injection | ✅ | `detectors/command_injection.rs` |
| Header injection / CRLF | ✅ | `detectors/header_injection.rs` |
| Template injection (SSTI) | ✅ | `detectors/template_injection.rs` |
| NoSQL injection | ✅ | `detectors/nosql_injection.rs` |
| Brute-force / auth abuse | ✅ | `detectors/behavior_signals.rs` + strike tracking |
| Recon / path enumeration | ✅ | `detectors/recon.rs` |
| Log4Shell | ✅ | `detectors/log4shell.rs` |
| Blacklist (IP/pattern) | ✅ | `crates/aegis-security/src/blacklist/` |
| Whitelist (bypass) | ✅ | `access_control.rs` |
| Rate limiting (per-IP) | ✅ | `rate_limit/ip_limiter.rs` |
| Risk score thresholds (challenge/block) | ✅ | `challenge_at` / `block_at` configurable per profile |
| AI/ML detector | ✅ | `detectors/ai/` — ONNX model, toggleable via `set_profile` |
| Hot-reload (no restart) | ✅ | Rule edits via admin API apply without restart |

### §10 — Source IP Trust Model

| Requirement | Status | Evidence |
|---|---|---|
| Audit log `ip` = TCP peer (not XFF) | ✅ | `admin_dispatch.rs:1087`: `ip: peer.ip().to_string()` |
| XFF treated as supplementary context only | ✅ | `data_plane.rs:247-253`: XFF-resolved IP used for risk scoring but raw peer logged |
| Different 127.0.0.x addresses treated as distinct clients | ✅ | Risk key and rate limiter key on resolved IP; loopback addresses distinct |

### §9 — Caching Observability

| Requirement | Status | Evidence |
|---|---|---|
| `X-WAF-Cache` present on all responses | ✅ | Stamped via `Decision::stamp()` |
| Default `BYPASS` when no cache | ✅ | `Decision::allow()` sets `CacheState::Bypass` |

---

## Pre-Submission Checklist

Use this checklist before submitting to the OC:

```
[ ] Fix C-1: rename challenge body fields: nonce→challenge_token, submit_to→submit_url, add submit_method:"POST"
[ ] Fix C-2: change prod-balanced.yaml interop.audit_path to "./waf_audit.log"
[ ] Fix C-3: set prod-balanced.yaml interop.control_secret to "waf-hackathon-2026-ctrl"
[ ] Run `make stage` to create ./waf symlink and ./waf.yaml in project root
[ ] Verify ./waf run starts successfully and ./waf_audit.log is created on first request
[ ] Document which port (8080 or 9443) the benchmarker should use for /__waf_control/* calls
[ ] Write SUBMISSION_GUIDE.md documenting each feature/policy workflow (§3 of candidate briefing)
[ ] Smoke test: curl -H "X-Benchmark-Secret: waf-hackathon-2026-ctrl" http://localhost:9443/__waf_control/capabilities
[ ] Smoke test: challenge issue → solve → verify full flow with benchmarker-compatible field names
[ ] Smoke test: POST /__waf_control/set_profile scope:all mode:log_only → confirm requests pass through with X-WAF-Mode: log_only
[ ] Smoke test: check ./waf_audit.log contains request_id, ts_ms, ip, method, path, action, risk_score, mode
```

---

## Quick Reference: Contract Endpoints

| Endpoint | Port | Auth | Purpose |
|---|---|---|---|
| `GET /__waf_control/capabilities` | 9443 (admin) | `X-Benchmark-Secret` | Discover features |
| `POST /__waf_control/reset_state` | 9443 (admin) | `X-Benchmark-Secret` | Clear runtime state |
| `POST /__waf_control/set_profile` | 9443 (admin) | `X-Benchmark-Secret` | Toggle enforce/log_only |
| `POST /__waf_control/flush_cache` | 9443 (admin) | `X-Benchmark-Secret` | Flush cache |
| `POST /__waf_control/challenge_verify` | 9443 (admin) | none | Solve PoW challenge |
| `GET /__waf_control/healthz` | 9443 (admin) | none | Startup health probe |
| Data plane proxy | 8080 / 8443 | — | All proxied traffic |

---

*Report generated by static source audit — 2026-05-19*
