# Phase 3 — Admin Auth Gate Design Sketch

> **Status:** Design only. NO code changes yet. Pending operator review
> before implementation.
>
> **Scope:** F-CRITICAL-002 (no auth gate) + F-CRITICAL-003 (TOTP
> unwired) + F-CRITICAL-004 (X-Actor spoofable) + F-CRITICAL-005
> (token entropy) from the 2026-05-17 proxy-full s-tester audit.
> These are interdependent — fixing one in isolation leaves the
> chain internally inconsistent — so they ship together.
>
> **Estimated size:** ~250 LoC core + ~150 LoC tests. ~8 files
> touched. Phase budget: 2-3 days including the integration tests.

## What's already there

Surveying the codebase before writing new code:

| Surface | Where | State |
|---|---|---|
| Argon2 password verify | `aegis-control/src/admin_auth/password.rs` | ✅ wired into `api::login::authenticate` |
| TOTP verify (RFC 6238 SHA256) | `aegis-control/src/admin_auth/totp.rs` | ⚠️ exists, **never called from login flow** (F-CRITICAL-003) |
| Session store (HMAC cookie + per-session record) | `aegis-control/src/admin_auth/session.rs` | ✅ struct exists, methods work; but `handle_admin_request` never invokes it (F-CRITICAL-002) |
| CSRF token gen | `aegis-control/src/admin_auth/csrf.rs` | ⚠️ entropy bug — derives from `blake3(clock_nanos + counter)` (F-CRITICAL-005) |
| Per-IP login rate-limit | `aegis-control/src/admin_auth/rate_limit.rs` | ✅ wired into `api::login::authenticate` |
| IP allowlist | `cfg.admin.dashboard_auth.ip_allowlist` | ⚠️ struct exists, **never enforced** in admin dispatch (F-CRITICAL-002) |
| mTLS | `aegis-control/src/admin_auth/mtls.rs` | ✅ wired at the TLS-listener layer (optional, separate from this work) |
| X-Actor header | mutation handlers read it verbatim | ❌ **client-controlled** — anyone can spoof actor identity (F-CRITICAL-004) |

So the building blocks exist. The work is:
1. **Wire** them into a coherent middleware chain at the dispatch entry.
2. **Fix the entropy** of the two existing primitives (csrf.rs + session.rs).
3. **Stop reading** `X-Actor` as a source of identity; derive it from the validated session.
4. **Add** the TOTP step to `api::login::authenticate`.

## The auth-chain shape

The contract's auth chain (v2.3 §Dashboard Auth, also see Round-1
gates) is 7 steps. After Phase 3 every step is enforced for every
admin-port request:

```text
                Request arrives on admin listener (:9443)
                                │
                                ▼
   ┌────────────────────────────────────────────────────────────┐
   │ 1. IP allowlist (cfg.admin.dashboard_auth.ip_allowlist)    │ ← skip when empty (operator opt-in)
   │    deny → 403 + audit "admin_ip_denied"                    │
   └────────────────────────────────────────────────────────────┘
                                │
                                ▼
   ┌────────────────────────────────────────────────────────────┐
   │ 2. mTLS (when `client_auth.apply_to: [admin]` is set)      │ ← already wired at TLS layer
   │    cert presence / SAN / CA chain checked at handshake     │
   └────────────────────────────────────────────────────────────┘
                                │
                                ▼
   ┌────────────────────────────────────────────────────────────┐
   │ 3. Per-IP login-rate-limit (only for POST /api/login)      │ ← already wired
   │    deny → 429 + audit "admin_login_rate_limited"           │
   └────────────────────────────────────────────────────────────┘
                                │
                                ▼
   ┌────────────────────────────────────────────────────────────┐
   │ 4. Password (argon2id) verify                              │ ← already wired (login only)
   │    fail → 401 + audit "admin_login_failed"                 │
   └────────────────────────────────────────────────────────────┘
                                │
                                ▼
   ┌────────────────────────────────────────────────────────────┐
   │ 5. TOTP verify (when cfg.admin.dashboard_auth.totp_enabled)│ ← MISSING — Phase 3 adds it
   │    fail → 401 + audit "admin_totp_failed"                  │
   └────────────────────────────────────────────────────────────┘
                                │
                                ▼
   ┌────────────────────────────────────────────────────────────┐
   │ 6. Session mint (login) / Session validate (everything else)│ ← MISSING gate — Phase 3 adds
   │    HMAC-signed cookie; record-side `SessionStore` lookup    │
   │    fail → 401 + audit "admin_session_invalid"               │
   └────────────────────────────────────────────────────────────┘
                                │
                                ▼
   ┌────────────────────────────────────────────────────────────┐
   │ 7. CSRF (only on state-changing mutations: POST/PUT/PATCH  │ ← partly wired (csrf.rs)
   │    /DELETE except /api/login)                              │ ← entropy fix needed
   │    fail → 403 + audit "admin_csrf_invalid"                 │
   └────────────────────────────────────────────────────────────┘
                                │
                                ▼
                        actual handler runs;
                       audit row stamps actor =
                      session.user_id (NOT X-Actor)
```

## File-by-file changes

### `aegis-control/src/admin_auth/csrf.rs` (F-CRITICAL-005)

Current (pseudo):
```rust
pub fn issue() -> String {
    let now = clock::nanos();
    let cnt = COUNTER.fetch_add(1, Relaxed);
    blake3::hash(format!("csrf:{now}:{cnt}").as_bytes()).to_hex().to_string()
}
```

New:
```rust
use rand::{rngs::OsRng, RngCore};

pub fn issue() -> String {
    let mut bytes = [0u8; 32]; // 256-bit CSRF token
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}
```

Plus: add a workspace dep on `rand = "0.8"` and `hex = "0.4"` (both
already pulled in transitively via existing crates; just need explicit
declarations).

Same fix lives in `session.rs::SessionStore::create()` — currently
derives the session id from the same blake3-clock-counter shape;
replace with `OsRng.fill_bytes` over 32 bytes, hex-encoded.

### `aegis-control/src/admin_auth/totp.rs`

Already implements RFC-6238 TOTP. The QC report's "uses SHA256 while
doc/URI claims SHA1" is a separate F-HIGH-admin item (TOTP code
generator algorithm mismatch). Phase 3 fixes that drive-by:

- Change the HMAC primitive from `Hmac<Sha256>` to `Hmac<Sha1>` (RFC
  6238 default; almost every authenticator app — Google Authenticator,
  Authy, 1Password, FreeOTP — uses SHA1).
- Document the choice + add a unit test that asserts against a
  published RFC 6238 test vector so the regression is locked.

### `aegis-control/src/api/login.rs` (F-CRITICAL-003)

Current flow inside `authenticate()`:
1. Rate-limit check
2. Parse body (`{user, password}`)
3. Argon2 verify
4. → `LoginOutcome::Ok` with session + csrf cookies

New flow:
1. Rate-limit check
2. Parse body (`{user, password, totp_code}`)
3. Argon2 verify
4. **If `cfg.admin.dashboard_auth.totp_enabled`**: TOTP verify against
   the user's stored secret; on fail → `LoginOutcome::Unauthorized`
   with reason `"totp_failed"`. Same `Unauthorized` envelope as wrong
   password — no path that distinguishes password-correct-TOTP-wrong
   from password-wrong (prevents enumeration).
5. Mint session via `SessionStore::create(user_id, peer_ip, ua_hash)`.
6. Mint CSRF token via `csrf::issue()`.
7. → `LoginOutcome::Ok` with session + csrf cookies.

### `aegis-proxy/src/accept.rs` admin service_fn (F-CRITICAL-002)

The current admin `service_fn` calls `handle_admin_request(req, peer,
cfg, …)` directly with no auth check. Wrap it with a middleware:

```rust
let resp = match admin_auth_middleware::admit(&req, peer, cfg, sessions).await {
    Admit::Pass(session) => {
        // session is None for /api/login and unauthenticated public
        // paths (/healthz, /readyz, /metrics); Some(user_id) otherwise.
        handle_admin_request_with_actor(req, peer, cfg, ..., session).await
    }
    Admit::Deny { status, reason } => {
        // Audit "admin_*_denied" event + envelope JSON
        deny_response(status, reason, bus)
    }
};
```

`admit` is a stack of checks in the order on the diagram above.
**Open endpoints** (no session required): `/api/login`, `/healthz`,
`/readyz`, `/metrics`, `/dashboard/index.html` and static assets.

### `aegis-proxy/src/admin_mutate.rs` (F-CRITICAL-004)

Today (pseudo):
```rust
let actor = req.headers().get("X-Actor").unwrap_or("admin");
audit.actor = actor;
```

New:
```rust
// X-Actor is removed at the gateway and never reaches this layer.
// `session` is the validated SessionRecord from the middleware;
// `session.user_id` is the only authoritative identity.
let actor = session.user_id.as_str();
audit.actor = actor;
```

Per the spec: if a request reaches a mutation handler at all, the
middleware has already validated a session. Plain unwraps on
`Option<&Session>` here are sound — but for robustness during the
transition, we'll keep an explicit `match Some(s) => …, None => 500
+ panic-log` so any future regression where the middleware is
mis-wired surfaces loudly.

### Config

`AdminConfig.dashboard_auth` already has the right shape:
- `ip_allowlist: Vec<IpNet>` — enforced now (was decorative).
- `totp_enabled: bool` — enforced now (was decorative).
- `session_ttl_idle` / `session_ttl_absolute` — wired via SessionStore.
- `password_hash_ref` — unchanged.

One new field needed: `csrf_secret_ref` is already there for the HMAC
key over the session cookie; we'll reuse it. No new config knobs.

## What about `X-Actor` from the v2.3 contract?

§2.3 mentions the audit `actor` field should be present on
audit-mutated CRUD. Pre-fix the WAF accepted it from a request header
(spoofable). Post-fix:

- For dashboard-mutated changes (operator hits PUT through their
  browser): `actor = session.user_id` (the logged-in operator).
- For interop-control-mutated changes (OC harness via
  `/__waf_control/set_profile`): `actor = "interop_secret"` — a
  constant stamped by the dispatcher, since the only auth credential
  is the secret header. No spoofing surface.
- For hot-reload from disk (file watcher / etcd poll): `actor =
  "config_reload"` — same constant approach.

The `X-Actor` header is **silently stripped at the admin listener
boundary** so any client that tries to inject it gets it dropped
before any handler sees it. Audit event for stripping is at `info`
level (no warn — clients legitimately might set arbitrary headers).

## Open questions for review

1. **TOTP enrollment surface.** Where do operators see/copy the
   `otpauth://` URI to scan into their authenticator? Today
   `cfg.admin.dashboard_auth.totp_secret_b32` is set in YAML; the
   spec doesn't require a UI for enrollment. **Proposal:** leave
   enrollment as YAML-only for now; document the `otpauth://` URI
   shape in `docs/operator/admin-auth-setup.md`. Phase 3 only wires
   the verify side.

2. **Backward compatibility.** If an operator currently uses the
   admin port without a session (e.g. a curl from a CI script with
   no cookie), Phase 3 will start returning 401. Two mitigations:
   - **Service-account session tokens** — admins can mint a long-
     lived session token from the dashboard for CI use. Tradeoff:
     yet another credential to rotate.
   - **Interop control secret as a fallback** — non-mutating reads
     (`GET /api/...`) accept the `X-Benchmark-Secret` header as
     auth. Tradeoff: weakens the contract that the secret is
     interop-only.
   - **Proposal:** ship Phase 3 with no backward-compat hatch.
     Document the breaking change. Operators with CI scripts move
     to dashboard-issued bearer tokens (already minted as session
     records). This matches the contract's "audit-mutated CRUD"
     requirement — every mutation MUST attribute to a real actor.

3. **IP allowlist default.** Empty list today means "allow all" — is
   that the right default? Alternative: deny-all-unless-explicitly-
   allowed, which is safer but requires every operator to add their
   admin IP to YAML before first boot. **Proposal:** keep
   empty = allow-all (matches current behavior); document the
   recommended posture in the operator setup guide; add a startup
   `tracing::warn!` when the list is empty and the admin listener
   isn't on a loopback bind. Operators on `127.0.0.1:9443` don't
   need the warn.

## Implementation order

Once approved, ship in this order so each step is independently
revert-able:

1. **csrf.rs + session.rs entropy fix.** Smallest. Run existing
   admin_auth tests to confirm no regression in token shape (length
   stays the same, just the entropy source changes).
2. **TOTP wire-up in `api::login::authenticate`.** Add the TOTP step;
   add tests for happy path + TOTP-wrong + TOTP-disabled.
3. **TOTP SHA256→SHA1 migration.** Lock with RFC 6238 test vector.
4. **Admin middleware + handle_admin_request_with_actor.** Biggest
   single change. Wire IP allowlist + session check + CSRF check.
   Document open endpoints + the X-Actor strip.
5. **X-Actor strip + actor = session.user_id propagation.** Touches
   every mutation handler that consumes the actor field.
6. **Integration tests.** End-to-end auth-chain tests for each step's
   failure mode.

## Verification

Per phase + end-to-end:

- **csrf.rs + session.rs**: token uniqueness over 10k iterations (no
  collisions); proper hex length; clock skew doesn't affect output.
- **TOTP**: RFC 6238 published test vectors green; expired code
  rejected; replay rejected within window (anti-replay check).
- **Middleware**: synthetic request matrix — no cookie (401), expired
  cookie (401), wrong IP (when allowlist set, 403), missing CSRF on
  POST (403), good cookie + good CSRF (200).
- **Actor**: send `X-Actor: not-me` → audit row's actor is the real
  session user, not "not-me".
- **End-to-end**: a full login → mutation → audit-row read sequence
  with all 7 chain steps active.

## Out of scope for Phase 3

- **TOTP enrollment UI.** YAML-only for now.
- **Service-account bearer tokens.** Deferred until operators ask.
- **mTLS-only mode** (`apply_to: [admin]` with no password). Already
  works at the TLS layer; not Phase 3's surface.
- **Session-revoke UI.** SessionStore::revoke() exists; surface via
  dashboard is a separate ticket.

## Risk

This is the highest-risk phase because it touches every admin
mutation. Mitigations:

- Land each step as a separate commit so a regression bisects
  cleanly.
- Keep `handle_admin_request_with_actor` behind a feature flag /
  `cfg.admin.dashboard_auth.strict_chain: bool` for the first build,
  default `false` so the change is opt-in until verified.
- Run the existing `tests/contract/v2.3_compliance.sh` after each
  step.

Once verified, the flag default flips to `true` in a follow-up
commit.

---

**Awaiting review.** When you approve, I'll start with step 1
(csrf.rs + session.rs entropy fix) and verify before moving on.
