# V2.6 Contract Deep Audit — Run 10 Findings

| Field                | Value                                                                 |
|----------------------|-----------------------------------------------------------------------|
| Run ID               | LT-RUN-10                                                             |
| Date                 | 2026-06-17                                                            |
| Approach             | Static source audit — v2.6 contract deep scan; issues NOT in run8    |
| Scope                | `crates/aegis-proxy`, `crates/aegis-control`, `crates/aegis-security`, `crates/aegis-core` |
| Source files audited | 14 key files (accept.rs, admin_dispatch.rs, data_plane.rs, run.rs, audit.rs, control.rs, headers.rs, pow.rs, mod.rs/interop, xff.rs, mode.rs, token.rs) |
| Total findings       | **4**                                                                 |
| Critical             | **0**                                                                 |
| High                 | **1**                                                                 |
| Medium               | **1**                                                                 |
| Low                  | **2**                                                                 |
| Logic conflicts      | **2 confirmed**                                                       |
| Stubs / unimpl       | **0 confirmed**                                                       |
| Partial impl         | **2 confirmed**                                                       |
| Contract violations  | **1 confirmed** (§2.4 — `caches/aegis-proxy/src/run.rs`)             |
| Test suite           | ⚠ Not run — read-only static audit                                   |
| Status               | ⚠ OPEN — awaiting fix planning                                       |

---

## Executive Summary

This run extends the v2.6 contract compliance audit from run8 (which found 7 issues). All run8 findings are confirmed still-open; this run adds 4 new issues discovered through deeper static analysis of the proxy boot path, the dual-audit-stream architecture, and the DDoS/rate-limit early-exit code paths.

**Most impactful new finding (CTL-NEW-01):** `POST /__waf_control/reset_state` does not flush the WAF smart response cache. The contract §2.4 explicitly lists "cache state" among the state categories that MUST be cleared; however, the flush callback for the `ResponseCache` (L1 in-process + optional L2 Redis) is registered only with `flush_cache`, not with `reset_state`. Any benchmarker phase that calls `reset_state` between test groups will carry stale cached upstream responses into the next group, potentially contaminating detection and allow/block scoring.

**Audit architecture clarification vs run8 "PROXY-NEW" drafts:** During the previous session, three candidate findings (blake3 request_id in audit, missing method/path/mode, XFF client_ip) were targeting the internal forensic `AuditEvent` chain, not `waf_audit.log`. Deep reading of `crates/aegis-control/src/interop/audit.rs` confirms that `waf_audit.log` is written exclusively by `MinimalAuditEntry` via `stamp_interop_response`, which always generates a fresh UUID (= `X-WAF-Request-Id`), uses `peer.ip()` (TCP peer, never XFF), and always has method/path/mode populated. The contract §6 benchmarker target (`waf_audit.log`) is therefore compliant for those three fields. The forensic chain (AuditBus → tamper-evident SHA-256 chain) is an internal system not read by the benchmarker. Findings PROXY-NEW-02 and PROXY-NEW-03 are downgraded to LOW internal-consistency issues; PROXY-NEW-01 is kept as a MEDIUM operational finding.

All 6 mandatory §5.1 response headers (`X-WAF-Request-Id`, `X-WAF-Risk-Score`, `X-WAF-Action`, `X-WAF-Rule-Id`, `X-WAF-Cache`, `X-WAF-Mode`) are confirmed present on every code path via `Decision::stamp` called from `stamp_interop_response`. `X-WAF-Rule-Id: none` for allow/passthrough paths is correct per §5.3 ("MUST be `none` when no specific rule caused the decision"). Control endpoints reset_state/set_profile/flush_cache response shapes are contract-compliant; the one new contract violation is the cache-clear gap in reset_state.

---

## Finding Index

### Control Plane (CTL-NEW-*)

| ID | Severity | Category | Short Description |
|----|----------|----------|-------------------|
| CTL-NEW-01 | **High** | Contract Violation | `reset_state` does not flush WAF smart response cache (§2.4) |

### Proxy Audit Stream (PROXY-NEW-*)

| ID | Severity | Category | Short Description |
|----|----------|----------|-------------------|
| PROXY-NEW-01 | **Medium** | Logic Conflict | Forensic AuditEvent request_id never matches X-WAF-Request-Id |
| PROXY-NEW-02 | **Low** | Partial Impl | DDoS/IP rate-limit AuditEvent missing method, path, mode fields |
| PROXY-NEW-03 | **Low** | Logic Conflict | AuditEvent.client_ip uses XFF-resolved IP when trusted_proxies set |

---

## Detailed Findings

---

### CTL-NEW-01 — reset_state does not flush WAF smart response cache ⚠

**Severity:** High  
**Files:**
- `crates/aegis-proxy/src/run.rs:1513` — `register_flush_callback` wires ResponseCache only to `flush_cache`
- `crates/aegis-control/src/interop/control.rs:517–533` — `flush_cache()` uses `flush_callback`, which reset_state never calls
- `crates/aegis-proxy/src/run.rs:1474–1549` — all `register_reset_callback` / `register_async_reset_callback` sites; none clears ResponseCache

**Description:**

`reset_state` (§2.4) must clear "cache state" among several categories. The WAF smart response cache (`ResponseCache`, backed by L1 in-process + optional L2 Redis) has a dedicated flush mechanism (`flush_callback`) that is registered with `POST /__waf_control/flush_cache` only. No `register_reset_callback` or `register_async_reset_callback` site registers a cache-clear for `reset_state`.

```rust
// run.rs:1513 — registered ONLY for flush_cache, not reset_state
rt.control
    .register_flush_callback(std::sync::Arc::new(move || {
        cache_for_flush.invalidate(None);
        // ... redis pub/sub fan-out
    }));

// reset_state chain: sync callbacks (DDoS reset, device tracker, attacks agg)
// + async callback (backend.reset_ephemeral() — rate-limit/nonce/autoblock wipe)
// ResponseCache.invalidate(None) is never called on reset_state
```

`ControlContext::reset_state_async` calls:
1. `reset_state()` — sync callbacks (DDoS spike, device tracker, attacks aggregator)
2. Async callback — `backend.reset_ephemeral()` (wipes rate-limit windows, nonces, auto-block, risk keys via StateBackend)

None of these touch the smart response cache.

**Impact:** When the benchmarker calls `reset_state` between test phases (which is its primary tool for deterministic isolation), stale cached WAF responses from prior phases survive in the L1 (and L2 Redis) cache. A cached `allow` from phase N can be returned as-is in phase N+1, bypassing detection entirely for those requests. This could inflate false-negative counts and make benchmark results phase-order-dependent.

**What the code should do:** Register a reset callback that calls `cache_for_flush.invalidate(None)` (same closure as the flush_cache callback, minus the Redis fan-out which is optional on reset). Simplest fix:

```rust
// In run.rs, after registering flush_callback, also register for reset:
let cache_for_reset = upstream_ctx.cache.clone();
rt.control
    .register_reset_callback(std::sync::Arc::new(move || {
        cache_for_reset.invalidate(None);
    }));
```

---

### PROXY-NEW-01 — Forensic AuditEvent request_id never matches X-WAF-Request-Id ℹ️

**Severity:** Medium  
**Files:**
- `crates/aegis-proxy/src/accept.rs` ~line 1970 — listener generates UUID#1 for AuditEvent (allow/challenge paths)
- `crates/aegis-proxy/src/admin_dispatch.rs:1302` — `stamp_interop_response` generates UUID#2 for MinimalAuditEntry + X-WAF-Request-Id
- `crates/aegis-proxy/src/data_plane.rs` ~line 652 — DDoS/rate-limit block AuditEvent uses `blake3(peer:nanos)` as request_id

**Description:**

There are two audit systems running in parallel:

1. **`waf_audit.log` (contract-facing):** Written by `MinimalAuditEntry` via `stamp_interop_response`. Always uses UUID v4 = `X-WAF-Request-Id`. This is the file the benchmarker reads. **This is contract-compliant** ✓

2. **Forensic chain (internal):** Written by `AuditEvent` via `AuditBus`. For **block** paths, the data-plane constructs the AuditEvent with `request_id = blake3(peer:nanos)`. For **allow/challenge** paths, `accept.rs` constructs the AuditEvent with `request_id = uuid::Uuid::new_v4()` (UUID#1). In both cases, `stamp_interop_response` subsequently generates a separate UUID#2 for `X-WAF-Request-Id` and `MinimalAuditEntry`.

```rust
// accept.rs — allow path: UUID#1 for AuditEvent
let request_id = uuid::Uuid::new_v4().to_string();   // UUID#1
let event = AuditEvent { request_id: request_id.clone(), ... };
bus.emit(event);  // → forensic chain

// admin_dispatch.rs — stamp_interop_response always:
let request_id = uuid::Uuid::new_v4().to_string();   // UUID#2 (different!)
// stamps X-WAF-Request-Id = UUID#2
// writes MinimalAuditEntry { request_id: UUID#2 } → waf_audit.log
```

Result: forensic chain AuditEvent.request_id ≠ X-WAF-Request-Id for every request. Cross-system correlation by request_id is impossible.

**Impact:** When an operator investigates an incident by searching the forensic chain for a specific `X-WAF-Request-Id` from a response header or `waf_audit.log`, they will find no match. The forensic chain's richer event data (detectors[], strikes, bot_category, etc.) is effectively unreachable via the standard correlation key.

**What the code should do:** Either (a) generate the request_id once in `accept.rs`, pass it into `stamp_interop_response` instead of letting it generate its own, and thread it into the AuditEvent — or (b) have `stamp_interop_response` return the generated UUID so the listener can write the AuditEvent with the same ID afterwards. For the data-plane block path, the blake3 nonce should be replaced with the UUID that `stamp_interop_response` will generate (requires passing the ID back up or generating it before the data-plane call).

---

### PROXY-NEW-02 — DDoS/IP rate-limit AuditEvent missing method, path, mode fields ℹ️

**Severity:** Low  
**Files:**
- `crates/aegis-proxy/src/data_plane.rs` ~line 640–695 — IP rate-limit block AuditEvent
- `crates/aegis-proxy/src/data_plane.rs` ~line 630–660 — DDoS block AuditEvent
- `crates/aegis-core/src/audit.rs:222–233` — `method`, `path`, `mode` are `Option<String>` with `skip_serializing_if = "Option::is_none"`

**Description:**

Early-exit block events (IP rate-limit and DDoS) construct their `AuditEvent` before the HTTP request body is parsed and before routing occurs. These events are emitted with `method: None`, `path: None`, `mode: None`. Because these fields use `#[serde(skip_serializing_if = "Option::is_none")]`, they are completely absent from the JSONL forensic chain output for those event types.

```rust
// data_plane.rs — DDoS/IP rate-limit block AuditEvent (approximate):
let ev = AuditEvent {
    request_id: blake3::hash(format!("{}:{}", peer, nanos).as_bytes())
        .to_hex().to_string(),
    client_ip: peer_ip.to_string(),
    method: None,   // ← absent from forensic JSONL
    path:   None,   // ← absent from forensic JSONL
    mode:   None,   // ← absent from forensic JSONL
    // ...
};
```

**Note:** This does NOT affect `waf_audit.log` — `stamp_interop_response` is always called after the response is returned and populates `MinimalAuditEntry` with the correct method/path/mode. This is purely a forensic chain gap.

**Impact:** Forensic audit entries for DDoS/IP rate-limit blocks are missing HTTP context. Incident analysis or SIEM rules that filter/group by `method` or `path` will silently exclude all DDoS-block events.

**What the code should do:** The method and path are available in the `Request<_>` parts even at the early-exit stage (they're parsed before any body reads). Pass them into the AuditEvent constructor. The `mode` can be resolved from `interop_modes` the same way the rule-engine paths do it.

---

### PROXY-NEW-03 — AuditEvent.client_ip uses XFF-resolved address when trusted_proxies configured ℹ️

**Severity:** Low  
**Files:**
- `crates/aegis-security/src/ip_rep/xff.rs` — `resolve_client_ip()` walks X-Forwarded-For when `trusted_proxies` is non-empty
- `crates/aegis-proxy/src/data_plane.rs` — `peer_ip` (used for `AuditEvent.client_ip`) is the result of `resolve_client_ip()`

**Description:**

`resolve_client_ip(peer, xff_header, trusted)` returns the XFF-rightmost-trusted value when the TCP peer is in the configured `trusted_proxies` list. This resolved IP is stored as `peer_ip` and used as `AuditEvent.client_ip` in the forensic chain.

```rust
// xff.rs
pub fn resolve_client_ip(peer: IpAddr, xff: Option<&str>, trusted: &[IpNet]) -> IpAddr {
    if !is_trusted(peer, trusted) {
        return peer; // TCP peer when trusted_proxies empty (default) ✓
    }
    // walks XFF chain → returns spoofable XFF value
}
// data_plane.rs: let peer_ip = resolve_client_ip(peer.ip(), xff, &trusted_proxies);
// AuditEvent { client_ip: peer_ip.to_string(), ... }  ← XFF when proxied
```

**Note:** `waf_audit.log` (`MinimalAuditEntry.ip`) always uses `peer.ip()` directly — the TCP socket peer — and is therefore §6-compliant regardless of `trusted_proxies` configuration. This finding is forensic-chain-only.

**Impact:** When the WAF is deployed behind a trusted L4 load balancer with `trusted_proxies` set, the forensic `AuditEvent.client_ip` reflects the XFF-resolved value rather than the LB's IP. XFF can be spoofed by clients; a malicious client behind a trusted proxy can write arbitrary forensic `client_ip` values, polluting incident records with false source IPs.

**What the code should do:** The forensic `AuditEvent` should consistently record the TCP peer address (`peer.ip()`, not XFF-resolved). XFF resolution is appropriate for risk scoring and rate-limiting (where the intent is to track the real end-user), but not for the forensic audit record where authenticity of the source address matters. Separate the two concepts: keep `peer_ip` (resolved) for risk decisions; introduce `peer_tcp` (always `peer.ip()`) for the audit.

---

## Cross-Crate Wiring Analysis

| Feature | Configured In | Implemented In | Wired Into Pipeline | Net Status |
|---------|--------------|----------------|--------------------|-----------| 
| `waf_audit.log` (§6) MinimalAuditEntry | `interop/mod.rs` | `interop/audit.rs` ✓ | `admin_dispatch.rs:stamp_interop_response` ✓ | **Working** |
| `X-WAF-*` headers (§5.1) | `interop/headers.rs` | `headers.rs:Decision::stamp` ✓ | `stamp_interop_response` — all paths ✓ | **Working** |
| reset_state cache clear (§2.4) | `run.rs:flush_callback` | `ResponseCache::invalidate` ✓ | `reset_state` reset callbacks ✗ | **Logic conflict — cache survives reset** |
| reset_state rate-limit/nonce wipe (§2.4) | `run.rs:async_reset_callback` | `StateBackend::reset_ephemeral` ✓ | `reset_state_async` ✓ | **Working** |
| flush_cache endpoint (§2.6) | `run.rs:flush_callback` | `ResponseCache::invalidate` ✓ | `/__waf_control/flush_cache` ✓ | **Working** |
| PoW challenge issuance (§4) | `challenge/pow.rs:PowIssuer` | `pow_solution_valid` (blake3) ✓ | `data_plane.rs` risk=Challenge branch ✓ | **Working (blake3; CRIT-01 from run8 still open)** |
| Challenge verify (§4) | `admin_dispatch.rs` | `handle_challenge_verify` ✓ | `/challenge/verify` data-plane mount ✓ | **Working — no session cookie (HIGH-03 from run8 still open)** |
| Forensic AuditEvent request_id | `accept.rs` / `data_plane.rs` | UUID#1 / blake3 | `AuditBus` ✓ | **Logic conflict — never matches X-WAF-Request-Id** |
| Forensic AuditEvent method/path/mode | `audit.rs:Option<String>` | data_plane early paths ✗ | DDoS/rate-limit block AuditEvent ✗ | **Partial impl — fields absent for early-exit blocks** |

---

## Priority Fix Order

1. **CTL-NEW-01** — WAF smart cache survives `reset_state`; register `ResponseCache.invalidate(None)` as a sync reset callback in `run.rs`. _(effort: low — 3-line addition)_
2. **PROXY-NEW-01** — Forensic AuditEvent request_id mismatch; thread the UUID from `stamp_interop_response` back to the AuditEvent construction site. _(effort: medium — refactor of accept.rs listener path and data-plane block path)_
3. **PROXY-NEW-02** — Pass method/path/mode into early-exit DDoS/rate-limit AuditEvent constructors. _(effort: low — available in request `parts` before body read)_
4. **PROXY-NEW-03** — Use raw `peer.ip()` (not XFF-resolved) for forensic AuditEvent.client_ip; keep resolved IP for risk decisions only. _(effort: low — thread `peer.ip()` separately from `peer_ip`)_

---

## Findings Deferred from Previous Run(s)

All 7 findings from run8 remain open (no code changes observed between run8 and run10):

| Prior Run Finding | ID | Status in This Run |
|-------------------|----|--------------------|
| blake3 vs SHA-256 PoW | CRIT-01 | **Still open** — `pow_solution_valid` still uses blake3 |
| Missing capabilities entries | HIGH-01 | **Still open** — hardcoded features absent from capabilities response |
| 422 on unknown policy (scope=policies) | HIGH-02 | **Still open** — `ControlError::Unsupported` → 422 |
| No session cookie on challenge verify | HIGH-03 | **Still open** — verify 200 has no Set-Cookie |
| BehavioralAnalyzer not wired | MED-01 | **Still open** — not in detection pipeline |
| deny_unknown_fields + cluster field | MED-02 | **Still open** — `SetProfileRequest` rejects unknown fields |
| "rate_limited" vs "rate_limit_exceeded" | LOW-01 | **Still open** — 429 body uses `"error": "rate_limited"` |

---

*Report generated by master-waf-tester skill — Run 10 (2026-06-17).  
Next action: fix CTL-NEW-01 first (3-line change, high impact on benchmark determinism).*
