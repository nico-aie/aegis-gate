# RiskTracker / IpRateLimiter — data-plane composite-key extraction

> **Status:** Drafted 2026-05-18. Tracks the deferred half of
> [security F-CRITICAL-001 + 002](../issue-fix/2026-05-17-control-core-security-audits/README.md#phase-e--security-architecture-composite-keys--algorithm-correctness)
> — Phase E.
>
> Commits `01c053c` (RiskTracker) + `5936257` (IpRateLimiter)
> migrated the **storage layer** to a composite key
> `RiskKey { ip, device_fp, session, tenant_id }`. The old IP-only
> API surface is bit-compat (every legacy method internally builds
> `RiskKey::from_ip(ip)`), so the data plane keeps compiling and
> running without changes. The audit's intent — "don't conflate
> two sessions on the same NAT'd IP" — is **not yet realised**:
> until the data plane builds the full composite key, every
> request still lands in the IP-only bucket and the new map
> dimensions stay `None`.

## Where the gap is

Every data-plane call site still uses the legacy IP-only methods:

- `crates/aegis-proxy/src/data_plane.rs` — `risk.record_malicious(ip, …)`,
  `risk.level(ip)`, `risk.is_strike_blocked(ip)`, `rate_limiter.check(ip)`.
- `crates/aegis-proxy/src/accept.rs` — initial strike / level
  lookups in the accept loop.
- `crates/aegis-control/src/api/rollback.rs` — replay path
  invokes `record_malicious(ip, …)` for replayed audit entries.

Search anchor:

```bash
rg -n 'record_malicious|is_strike_blocked\(|risk\.level\(|rate_limiter\.check\(' crates
```

Each of these has a `*_with_key` twin in
`crates/aegis-security/src/risk/tracker.rs` /
`crates/aegis-security/src/rate_limit/ip_limiter.rs` that takes
the full `RiskKey`.

## What needs to land

### 1. Build the composite key at request boundary

In the data plane, just before the first risk lookup, build:

```rust
let risk_key = aegis_core::risk::RiskKey {
    ip: peer_ip,
    device_fp: signals.ja4_fingerprint.as_ref().map(|ja4| {
        // stable 32-bit hash of ja4 + UA — same shape both sides
        // of the request lifecycle so we don't fragment buckets.
        device_fp_hash(ja4, view.user_agent())
    }),
    session: view.session_cookie().map(str::to_owned),
    tenant_id: route_ctx.tenant_id.clone(),  // already in scope
};
```

Helpers to add (one file, ~30 LoC):

- `crates/aegis-security/src/identity/device_fp.rs` (new):
  `pub fn device_fp_hash(ja4: &str, ua: Option<&str>) -> String` —
  short blake3 hex digest. Stable across requests within a TLS
  session. **Don't** include IP — that's already a separate axis.

### 2. Swap call sites to the `*_with_key` variants

Mechanical sed across ~15 sites:

| Legacy | Replacement |
|---|---|
| `risk.record_malicious(ip, delta)` | `risk.record_malicious_with_key(risk_key.clone(), delta)` |
| `risk.record_clean(ip)` | `risk.record_clean_with_key(risk_key.clone())` |
| `risk.snapshot(ip)` | `risk.snapshot_with_key(&risk_key)` |
| `risk.level(ip)` | `risk.level_for_key(&risk_key)` |
| `risk.is_strike_blocked(ip)` | `risk.is_strike_blocked_for_key(&risk_key)` |
| `risk.reset(ip)` | `risk.reset_with_key(&risk_key)` |
| `rate_limiter.check(ip)` | `rate_limiter.check_with_key(risk_key.clone())` |

Keep the IP-only methods alive — `api/rollback.rs` and the
strike-block ops API hit them by IP (operator action, no session
context). Both bucket families coexist; the IP-only bucket is the
floor for any traffic whose composite axes are `None`.

### 3. Extend the wire shape

`crates/aegis-security/src/risk/tracker.rs::RiskSnapshot` today
hides `device_fp` / `session` / `tenant_id` because the dashboard
deep-links by IP alone (see `tracker.rs:370-377` TODO comment).
Once the data plane populates composite keys, a single IP will
appear in `top()` once per (device_fp, session, tenant) combo —
the dashboard will look like it has duplicate rows.

Additive change:

```rust
pub struct RiskSnapshot {
    pub ip: String,
    pub device_fp: Option<String>,   // NEW
    pub session: Option<String>,     // NEW
    pub tenant_id: Option<String>,   // NEW
    pub score: u32,
    pub strikes: u32,
    pub idle_seconds: u64,
    pub level: &'static str,
    pub strike_blocked: bool,
}
```

Populate in `top()` at `tracker.rs:409-419` from
`key.device_fp.clone()` etc. Existing JSON consumers ignore
unknown fields, so the dashboard keeps working unchanged until
its own update lands.

### 4. Dashboard table update

`crates/aegis-control/assets/dashboard/app.js` — Top Attackers
table:

- Add columns (or a "details" disclosure row): `device_fp` (first 8
  hex chars), `session` (first 8 chars), `tenant_id`.
- Collapse rows where **all three** are `None` to a single
  "IP-only" row so anonymous public-endpoint traffic doesn't
  visually fragment.
- Deep-link target stays the IP-only filter for now; per-session
  drill-down is a separate feature.

### 5. Reset endpoints

`POST /api/risk/reset` and `POST /api/gates/strikes/reset` today
take `{ip}`. Decision: keep the IP-only reset (operator UX is
simpler) AND wipe every bucket whose `RiskKey::ip` matches. Add
an admin-only `{ip, device_fp?, session?, tenant_id?}` shape for
surgical resets. That's an additive endpoint, no breaking change.

## Sizing

| Piece | Est. LoC |
|---|---|
| `device_fp_hash` helper + test | ~30 |
| Data-plane key-builder + 15 call-site swaps | ~80 |
| `RiskSnapshot` extension + `top()` populate | ~20 |
| Dashboard table columns + collapse logic | ~80 |
| Surgical reset endpoint (admin) | ~50 |
| Tests (composite keys are honoured, `None` axes still merge IP-only buckets) | ~120 |
| **Total** | **~380** |

## Why deferred (not "missing")

1. **Storage is the load-bearing piece.** Two sessions on the same
   NAT'd IP can't *physically* be separated without the composite
   map. That's done; it's enforced by the type system that all new
   call sites land in the right buckets.
2. **The data-plane wire-up is a session-context layer** — it
   needs `ja4_fingerprint` and a session cookie standard the
   product hasn't fully nailed down yet (some routes are
   stateless API; some are dashboard-cookie; some are JWT). The
   right time to pick a single source for `session` is when the
   identity-tracker work ships, not during a security-audit fix.
3. **No regression risk today.** IP-only callers keep their IP-only
   buckets. The audit finding is "the storage shape is wrong" — that
   is fixed. The follow-up finding "the data plane should *use* the
   new shape" is correct but additive and graceful.

## When to do it

Bundle with whichever of these lands first:
- Identity tracker / session-warmup work (gives us
  `signals.session_id`).
- JA4 algorithm fix (`security F-CRITICAL-011`) — once JA4 is
  trustworthy, the `device_fp` axis pulls weight.
- A Round-2 scoring-depth pass where Intelligence axis points are
  on the table.

Until then, leave the loose end documented here and link it from
the issue-fix plan's "All issue-fix phases are now closed" section.
