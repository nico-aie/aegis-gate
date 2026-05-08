# F-HIGH-003 · reset_state evicts active admin sessions

**Severity:** HIGH  
**Component:** `crates/aegis-proxy/src/admin_dispatch.rs` — `handle_reset_state`  
**Interop contract:** CC-T2  
**Found:** 2026-05-07  

---

## Summary

`POST /__waf_control/reset_state` clears all admin authentication sessions, logging every operator out of the dashboard immediately. The implementation sweeps Redis keys for WAF runtime state but does not scope the deletion to exclude `aegis_session:*` keys.

## Observed behaviour

```
# Before reset:
GET /api/about → 200 ✓  (session valid)

# Call reset_state on :9443 with X-Benchmark-Secret:
POST /__waf_control/reset_state → 200

# After reset:
GET /api/about → 302 → /admin/login  (session evicted)
```

The admin tab immediately redirected to the login page after reset_state was called during testing.

## Root cause

The `handle_reset_state` implementation in `admin_dispatch.rs` flushes Redis keys matching a pattern that includes `aegis_session:*` (admin session tokens) along with WAF runtime state keys (rate limiter counters, block decisions, challenge tokens, etc.).

The interop contract intends `reset_state` to reset *WAF enforcement state* (cached block decisions, per-IP counters, challenge state) to prepare a clean baseline for benchmarking — not to invalidate operator sessions.

## Impact

- Any operator logged into the dashboard is immediately logged out when the benchmarker calls `reset_state`.
- In a real deployment, this would be a denial-of-service against the admin plane during a benchmark run.
- Benchmark operators who rely on the dashboard for monitoring during the run lose their session.
- The re-login flow after reset_state was confirmed to work (auth is not broken), but the interruption is unexpected and disruptive.

## Recommended fix

Scope the Redis key deletion in `handle_reset_state` to exclude admin plane keys:

```rust
// Keys to preserve (do not delete):
// aegis_session:*    — admin sessions
// aegis_csrf:*       — CSRF tokens
// aegis_totp:*       — TOTP state

// Keys to flush (WAF runtime state):
// rate:*             — per-IP rate counters
// block:*            — block decisions
// challenge:*        — challenge tokens
// risk:*             — cumulative risk scores
// audit:*            — audit ring (optional; may want to preserve)
```

Alternatively, use a dedicated Redis key prefix for WAF runtime state vs. admin state, and only flush the WAF prefix.
