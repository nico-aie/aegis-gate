---
id: 2026-05-17-high-admin-bundle
date: 2026-05-17T00:00Z
severity: HIGH
area: admin · auth chain · audit
component: crates/aegis-proxy/src/admin_mutate.rs · crates/aegis-control/src/admin_auth/{totp.rs,session.rs,password.rs,rate_limit.rs} · crates/aegis-proxy/src/admin_sse.rs
interop_contract: Round 1 dashboard auth chain (defense-in-depth) · Round 1 stability
status: open
test_mode: source-review
---

# F-HIGH-admin bundle — 7 issues in the admin / auth surface

Each item compounds with the CRITICAL findings (F-CRITICAL-002 / 003 / 004 / 005) but stands as its own bug.

---

## A-01 · Mutation handlers have no request-body size limit

**Component:** every handler in [admin_mutate.rs](aegis-gate/crates/aegis-proxy/src/admin_mutate.rs) (3546 lines, ~35 handlers)

`req.into_body().collect().await` reads the whole body to memory
with no cap. Representative handlers:

- `handle_mtls_ca_bundle_put` (line 868)
- `handle_rules_post` (line 1570)
- `handle_upstreams_config_put` (line 188 ff.)
- `handle_loadmode_put` (line 1443)

The only sized handlers are in `admin_dispatch.rs` (simulate 64 KiB
at line 554, route test 4 KiB at line 619). An authenticated attacker
(or per F-CRITICAL-002, anyone) can OOM the WAF with one POST.

**Fix:** wrap each `collect()` in `http_body_util::Limited` with a
config-driven cap (e.g. 256 KiB default, 1 MiB for cert bundles):

```rust
let body = http_body_util::Limited::new(req.into_body(), MAX_ADMIN_BODY);
let bytes = body.collect().await.map_err(|_| MutationError::BodyTooLarge)?.to_bytes();
```

---

## A-02 · TOTP code uses HMAC-SHA256 while the provisioning URI claims SHA1

**Component:** [admin_auth/totp.rs:1-7, 32, 66](aegis-gate/crates/aegis-control/src/admin_auth/totp.rs#L1-L7)

The module doc says "HMAC-SHA1 for compatibility with standard
authenticator apps" but the code uses `Hmac<Sha256>`. The
provisioning URI emits `algorithm=SHA256`, but Google Authenticator
(and most older hardware tokens / Authy) default to SHA1 and ignore
the `algorithm=` parameter when generating codes. Users who scan the
QR code into one of these apps will get 6-digit codes that NEVER
verify against the WAF's SHA256 implementation.

Operators won't realise until they try to log in and discover their
TOTP doesn't work — at which point they're locked out unless they
have recovery codes (which the `admin enroll-totp` CLI prints but
which operators often discard).

**Fix:** switch to HMAC-SHA1 to match what authenticator apps
actually do:

```diff
-use hmac::{Hmac, Mac};
-use sha2::Sha256;
-type HmacSha = Hmac<Sha256>;
+use hmac::{Hmac, Mac};
+use sha1::Sha1;
+type HmacSha = Hmac<Sha1>;
```

Update the provisioning URI to emit `algorithm=SHA1` (or omit since
SHA1 is the default).

---

## A-03 · TOTP has no replay protection — used codes valid for the entire 30 s window

**Component:** [admin_auth/totp.rs:50-61](aegis-gate/crates/aegis-control/src/admin_auth/totp.rs#L50-L61)

`verify(secret, code, now)` recomputes the expected code at
`now / 30`, `(now-30) / 30`, `(now+30) / 30` (±1 step tolerance per
RFC 6238 §5.2) and string-compares. Once a code is successfully
presented, the same code remains valid for the remainder of the
30 s window. An attacker who captures the code (shoulder-surf,
HTTPS-strip on a misconfigured deploy, network logger) can replay
it for up to 30 s.

**Fix:** burn used codes per RFC 6238 §5.2. Maintain a per-user
"last used code" cache; reject if the presented code matches the
last-used value within the validity window.

```rust
struct TotpReplayGuard {
    last_used: DashMap<String, (String, Instant)>,
}
impl TotpReplayGuard {
    fn try_consume(&self, user: &str, code: &str, window: Duration) -> bool {
        let now = Instant::now();
        if let Some(prev) = self.last_used.get(user) {
            if prev.value().0 == code && now < prev.value().1 + window {
                return false;     // replay
            }
        }
        self.last_used.insert(user.to_string(), (code.to_string(), now));
        true
    }
}
```

Call `try_consume` inside `verify` after the HMAC check passes.

---

## A-04 · SSE Live Feed has no authentication; broadcast subscribers unbounded

**Component:** [admin_sse.rs:62-78](aegis-gate/crates/aegis-proxy/src/admin_sse.rs#L62-L78)

`sse_response` is constructed unconditionally — the listener
(`accept.rs:886-893`) routes `GET /dashboard/sse` to it before any
auth gate. Anyone reachable to the admin port can subscribe and
stream every audit event: mutations, detector hits, client IPs,
request IDs, mode flips, mTLS connection state.

Additionally, the `services.bus.subscribe()` call has no per-IP cap
and the broadcast channel keeps a per-receiver buffer; a fan of N
subscribers from one attacker is N×buffer memory consumed.

**Fix:** gate the SSE endpoint behind the same session middleware
that F-CRITICAL-002 introduces. Add a per-IP subscriber cap.

```rust
if req.method() == hyper::Method::GET && req.uri().path() == "/dashboard/sse" {
    if services.admin_auth.validate_session(&req).is_invalid() {
        return Ok(unauthorized());
    }
    if !services.sse_quota.try_acquire(peer.ip()) {
        return Ok(too_many_requests());
    }
    return Ok(sse_response(&services.bus, query));
}
```

Also stamp the 6 §5 headers on the SSE response (SSE is a single
long-lived response — headers ship once at start).

---

## A-05 · Session store hard-coded TTL ignores config; unbounded HashMap; no background cleanup

**Component:** [admin_auth/session.rs:30, 168-171](aegis-gate/crates/aegis-control/src/admin_auth/session.rs#L30)

`SessionStore` is constructed with hard-coded `idle_ttl = 30m,
absolute_ttl = 8h`; `cfg.admin.dashboard_auth` values are ignored.

The store is `HashMap<SessionId, SessionRecord>` with no cap and no
background cleanup task. Sessions are pruned only on `validate()`
call for that specific ID, so abandoned sessions live until process
restart.

Combined with F-CRITICAL-002 (anyone can call `POST /admin/login`
unauthenticated → creates a session), an attacker spamming logins
grows the map unbounded. Per-process memory DoS.

**Fix:**
1. Wire `cfg.admin.dashboard_auth.idle_ttl` / `absolute_ttl` to the
   `SessionStore` constructor.
2. Spawn a background `tokio::time::interval(60s)` task that walks
   the map and removes expired entries.
3. Cap the map at a configured maximum (e.g. 10 000 sessions);
   reject new sessions with 429 when full.

Bonus: `base64url_encode` at lines 168-171 is misnamed — it produces
hex (`format!("{b:02x}")`) then runs no-op `+`/`/` replacements.
Either rename to `hex_encode` or fix to produce real base64url.

---

## A-06 · Argon2 `dummy_verify` uses `hash_password` (different timing profile) instead of `verify_password` against a constant dummy hash

**Component:** [admin_auth/password.rs:10, 38-47](aegis-gate/crates/aegis-control/src/admin_auth/password.rs#L10)

To equalize timing between "user exists" and "user missing", the
login path calls `dummy_verify` when the user isn't found. The
intent: spend the same CPU as a real `verify_password`. The
implementation: call `hash_password` (which generates a salt + does
the argon2 work + base64-encodes the result).

Hashing and verifying have different cost profiles:
- `hash_password` includes salt generation + base64-encode (small
  but measurable).
- `verify_password` parses the stored hash, then does argon2 with
  the parsed salt.

A careful attacker timing thousands of login attempts can still
distinguish "user exists" (uses `verify_password`) from "user
missing" (uses `hash_password`) → user enumeration.

**Fix:** `verify_password` against a CONSTANT pre-baked dummy hash
held in a `OnceLock`:

```rust
fn dummy_verify(password: &str) {
    static DUMMY_HASH: OnceLock<String> = OnceLock::new();
    let h = DUMMY_HASH.get_or_init(|| {
        argon2::Argon2::default()
            .hash_password(b"not-a-real-password", &SaltString::generate(&mut OsRng))
            .unwrap()
            .to_string()
    });
    let _ = verify_password(h, password);     // ignore result
}
```

Now both code paths run the same `verify_password` algorithm with
the same constants.

Also document the Argon2 cost parameters explicitly (current code
uses `Argon2::default()` which is `m_cost=19456 KiB, t_cost=2,
p_cost=1` — at the OWASP 2023 minimum). Pin them in source so a
future `argon2` crate version bump doesn't silently weaken them:

```rust
let argon2 = Argon2::new(
    Algorithm::Argon2id,
    Version::V0x13,
    Params::new(19_456, 2, 1, None).unwrap(),
);
```

---

## A-07 · Login rate-limit tracker maps are unbounded → memory DoS via IP rotation

**Component:** [admin_auth/rate_limit.rs:114, 141, 145](aegis-gate/crates/aegis-control/src/admin_auth/rate_limit.rs#L114)

`LoginRateLimiter` keeps `ip_trackers` and `user_trackers` as
`HashMap<String, ...>` and inserts on every login attempt via
`entry().or_insert_with(...)`. Entries are never evicted. An
attacker who rotates source IPs (cheap on IPv6, doable on IPv4 from
a botnet) grows the map without bound.

The cleanup `prune_expired` exists but is only called from
`record_failure`, only for the IP that just failed. Aggregate
cleanup never runs.

**Fix:** spawn a background tokio task that periodically walks both
maps and removes entries whose `last_failure + lockout_window` is
in the past. Add a hard cap on map size with LRU eviction.

---

## Severity rationale

HIGH. Each compounds with F-CRITICAL-002/003/004/005 but is its own
distinct bug. Together they fill out the "admin auth chain entirely
broken" story; individually they range from "annoying memory leak"
(A-05, A-07) to "user enumeration vector" (A-06) to "TOTP can never
work" (A-02). Fixes range from 5 LoC (A-02 algorithm swap) to
~50 LoC (A-04 SSE auth gate).
