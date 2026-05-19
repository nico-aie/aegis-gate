# RiskTracker / IpRateLimiter — data-plane composite-key extraction

> **Status:** Drafted 2026-05-18. Updated 2026-05-19 — most of the
> data-plane swap has landed (`build_risk_key` + `*_with_key`
> production call sites); see "Where we actually stand" below.
> Tracks the remaining half of
> [security F-CRITICAL-001 + 002](../issue-fix/2026-05-17-control-core-security-audits/README.md#phase-e--security-architecture-composite-keys--algorithm-correctness)
> — Phase E.
>
> Commits `01c053c` (RiskTracker) + `5936257` (IpRateLimiter)
> migrated the **storage layer** to a composite key
> `RiskKey { ip, device_fp, session }`. The old IP-only API
> surface is bit-compat (every legacy method internally builds
> `RiskKey::from_ip(ip)`), so the data plane keeps compiling and
> running without changes. The audit's intent — "don't conflate
> two sessions on the same NAT'd IP" — is **partially realised**:
> the `session` axis is now populated from cookies, but
> `device_fp` is still `None` until JA4 is folded into the key.
>
> **2026-05-19 — `tenant_id` axis removed.** The multi-tenant
> feature was deprecated upstream; every populator site was
> hard-coded to `None`. Dropping the axis simplifies the
> composite-key surface and saves an `Option<String>` per
> bucket. `AuditEvent.tenant_id` is a separate wire-contract
> field and stays for SIEM-sink compatibility (every sink
> shape references it; removing would break the contract).

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

**Already landed** as `build_risk_key(peer_ip, headers)` in
`crates/aegis-proxy/src/data_plane.rs`. Today it populates `ip`
and `session` (via `extract_session_id`) but leaves `device_fp`
as `None` — the JA4 fingerprint is captured at the accept layer
but not folded into the key yet.

```rust
// Current shape:
aegis_core::risk::RiskKey {
    ip: peer_ip,
    device_fp: None,                            // ← still needs wiring
    session: extract_session_id(headers),       // ← done
}
```

What's left here:

- `crates/aegis-security/src/identity/device_fp.rs` (new file,
  ~30 LoC): `pub fn device_fp_hash(ja4: &str, ua: Option<&str>) -> String`
  — short blake3 hex digest. Stable across requests within a TLS
  session. **Don't** include IP — that's already a separate axis.
- Thread `signals.ja4_fingerprint` into `build_risk_key`'s caller
  and let the helper produce `Some(device_fp_hash(ja4, ua))`.

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
hides `device_fp` / `session` because the dashboard deep-links
by IP alone (see `tracker.rs:370-377` TODO comment). Once the
data plane populates composite keys, a single IP will appear in
`top()` once per (device_fp, session) combo — the dashboard will
look like it has duplicate rows.

Additive change:

```rust
pub struct RiskSnapshot {
    pub ip: String,
    pub device_fp: Option<String>,   // NEW
    pub session: Option<String>,     // NEW
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
  hex chars), `session` (first 8 chars).
- Collapse rows where **both** are `None` to a single
  "IP-only" row so anonymous public-endpoint traffic doesn't
  visually fragment.
- Deep-link target stays the IP-only filter for now; per-session
  drill-down is a separate feature.

### 5. Reset endpoints

`POST /api/risk/reset` and `POST /api/gates/strikes/reset` today
take `{ip}`. Decision: keep the IP-only reset (operator UX is
simpler) AND wipe every bucket whose `RiskKey::ip` matches. Add
an admin-only `{ip, device_fp?, session?}` shape for surgical
resets. That's an additive endpoint, no breaking change.

## Where we actually stand (2026-05-19)

| Plan item | Status |
|---|---|
| Storage layer composite key | ✅ done (commits `01c053c`, `5936257`) |
| `build_risk_key(peer_ip, headers)` helper | ✅ done (`data_plane.rs::build_risk_key`) |
| Production data-plane `*_with_key` swaps | ✅ done (8 call sites in `data_plane.rs`) |
| `extract_session_id` session axis | ✅ done — session populated from cookies |
| JA4 captured at TLS layer | ✅ done (`accept.rs:1439`) |
| `tenant_id` axis | ✅ removed (multi-tenant deprecated upstream) |
| `device_fp_hash(ja4, ua)` helper | ❌ pending |
| `device_fp` axis populated in `build_risk_key` | ❌ pending |
| `IpRateLimiter` data-plane swap | ❌ pending (`data_plane.rs:498` still IP-only `consume`) |
| `RiskSnapshot` wire-shape extension | ❌ pending |
| `top()` populator for new fields | ❌ pending |
| Dashboard Top Attackers columns | ❌ pending |
| Surgical reset endpoint | ❌ pending |

## Sizing (remaining work)

| Piece | Est. LoC |
|---|---|
| `device_fp_hash` helper + JA4 wire-up | ~50 |
| `IpRateLimiter` data-plane `consume_with_key` swap | ~20 |
| `RiskSnapshot` extension + `top()` populate | ~25 |
| Dashboard table columns + collapse logic | ~100 |
| Surgical reset endpoint (admin) | ~60 |
| Tests (composite keys honoured, IP-only buckets still merge) | ~120 |
| Docs touch (architecture/storage-and-contract, rate-limiting) | ~20 |
| **Total remaining** | **~395** |

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
