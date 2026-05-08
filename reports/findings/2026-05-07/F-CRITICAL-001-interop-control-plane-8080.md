# F-CRITICAL-001 · Interop control-plane endpoints unreachable on data-plane port

**Severity:** CRITICAL  
**Component:** `crates/aegis-proxy/src/accept.rs`, `crates/aegis-proxy/src/admin_dispatch.rs`  
**Interop contract:** CC-T1, CC-T2, CC-T3, CC-T4  
**Found:** 2026-05-07  

---

## Summary

All four `/__waf_control/*` endpoints required by the hackathon interop contract are blocked with 403 when called on the data-plane port `:8080`. The benchmarking harness is specified to send control calls to the same address/port it uses for traffic, so the entire benchmark control loop fails before a single test request is evaluated.

## Observed behaviour

```
GET  http://127.0.0.1:8080/__waf_control/capabilities   → 403 (detector: ssrf)
POST http://127.0.0.1:8080/__waf_control/reset_state    → 403 (detector: ssrf)
POST http://127.0.0.1:8080/__waf_control/set_profile    → 403 (detector: ssrf + ai)
POST http://127.0.0.1:8080/__waf_control/flush_cache    → 403 (detector: ssrf)
```

The same endpoints work correctly on `:9443` (admin plane) when the `X-Benchmark-Secret` header is provided.

## Root cause

`accept_loop` (data plane, `accept.rs`) calls `handle_data_request` directly for every incoming request — there is no early-exit path for `/__waf_control` before the security pipeline runs. The interception logic lives in `handle_admin_request` (`admin_dispatch.rs`) which is only called by the admin accept loop on `:9443`.

Additionally, the SSRF detector pattern `(?i)(?:https?://(?:127\.0\.0\.1|localhost))` matches the `/__waf_control/` path segment because the `waf_control` substring is absent from the check — the SSRF match fires on the loopback host appearing in the request line metadata or in the `Host` header `127.0.0.1:8080`.

## Impact

- Benchmark harness cannot call `reset_state`, `set_profile`, or `flush_cache` — all control operations fail silently with 403.
- The WAF will be evaluated with stale state from prior runs, making benchmark results non-reproducible.
- `capabilities` check at harness startup fails → harness may abort the entire run.

## Recommended fix

**Option A (preferred):** Add an early-exit check in `handle_data_request_inner` (or at the top of `accept_loop`'s per-request handler) that intercepts paths starting with `/__waf_control/` and routes them through `handle_interop_control` with secret verification — bypassing the detector pipeline entirely.

```rust
// In handle_data_request_inner, before detector pipeline:
if path.starts_with("/__waf_control/") {
    return handle_interop_control(req, services).await;
}
```

**Option B:** Document that the benchmarker must use `:9443` for control calls and `:8080` for traffic. Update `capabilities` response to advertise `control_port: 9443`.
