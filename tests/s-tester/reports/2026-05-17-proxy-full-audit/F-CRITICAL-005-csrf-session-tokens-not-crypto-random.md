---
id: 2026-05-17-csrf-session-tokens-not-crypto-random
date: 2026-05-17T00:00Z
severity: CRITICAL
area: admin · auth chain
component: crates/aegis-control/src/admin_auth/csrf.rs (generate_token) · admin_auth/session.rs (session id / salt)
interop_contract: Round 1 dashboard auth chain step 5 (HMAC session cookie) and step 6 (CSRF)
status: open
test_mode: source-review (spot-verified)
---

# F-CRITICAL-005 · CSRF tokens / session IDs / salts derived from `blake3(clock_nanos + counter)` — deterministic, not crypto-random

## Summary

Three security-critical token sources in the admin auth chain all
use the same insecure construction:

```rust
let now = SystemTime::now().duration_since(UNIX_EPOCH).as_nanos();
let cnt = CTR.fetch_add(1, Ordering::Relaxed);
let hash = blake3::hash(format!("csrf:{now}:{cnt}").as_bytes());
hash.to_hex()[..32].to_string()
```

NONE of them use `getrandom`, `OsRng`, or any other CSPRNG. An
attacker who can:

- Observe the WAF's wall-clock time (trivial — every HTTP `Date:`
  response header leaks it to second granularity; for finer
  granularity, time how long requests take to bracket the
  `as_nanos()` value).
- Estimate the per-process atomic counter (bounded by request count
  since boot — also bounded above by observable headers like
  `X-WAF-Request-Id` cardinality).

...can brute-force the next-issued token in tractable time.

Worse: the validation function (`csrf::validate`) is a plain string
`constant_time_eq` comparison of cookie vs header — it does NOT
check the cookie was actually issued by the server. So an attacker
who supplies their own matching `Cookie: aegis_csrf=foo` +
`X-CSRF-Token: foo` passes validation regardless of whether `foo`
is a real issued token.

In isolation this is a HIGH-severity entropy bug; combined with
F-CRITICAL-002 (no session check) it becomes CRITICAL because the
"double-submit" pattern presumes session auth in front.

**Spot-verified** at [admin_auth/csrf.rs:6-17](../../../../crates/aegis-control/src/admin_auth/csrf.rs#L6-L17):

```rust
pub fn generate_token() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    let cnt = CTR.fetch_add(1, Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let hash = blake3::hash(format!("csrf:{now}:{cnt}").as_bytes());
    hash.to_hex()[..32].to_string()
}
```

And at [admin_auth/csrf.rs:19-34](../../../../crates/aegis-control/src/admin_auth/csrf.rs#L19-L34) (`validate`): only `constant_time_eq(cookie, header)` —
no signature verification, no session linkage.

The same pattern is used in:
- `admin_auth/session.rs:156-166` — session ID + salt construction.
- `admin_dispatch.rs:1011-1018` — `X-WAF-Request-Id` derivation
  (already filed as F-HIGH-004 in the prior data-plane audit).
- `aegis-bin/src/main.rs:577-617` — TOTP secret enrollment
  (already filed as F-MEDIUM M-03 in the prior audit).

## Impact

The standalone entropy weakness:

- A determined attacker who profiles the WAF's clock + traffic
  pattern can predict the next CSRF token. With F-CRITICAL-002
  unfixed, this isn't necessary (just mint a matching pair). With
  F-CRITICAL-002 FIXED, predictable tokens become the primary
  attack vector.

- Session IDs derived the same way mean an attacker can forecast
  the next session ID range and then hijack a newly-created session
  before the legitimate user uses it.

Under Round-1 dashboard auth chain scoring, BTC may probe randomness
with a simple statistical test on observed token sequences. Even
short sequences will fail an entropy test against random.

## Suggested fix

Use `rand::rngs::OsRng` (or `getrandom::getrandom`) for every token.
Both are already in the transitive dep tree.

```diff
 pub fn generate_token() -> String {
-    use std::sync::atomic::{AtomicU64, Ordering};
-    static CTR: AtomicU64 = AtomicU64::new(0);
-    let cnt = CTR.fetch_add(1, Ordering::Relaxed);
-    let now = std::time::SystemTime::now()
-        .duration_since(std::time::UNIX_EPOCH)
-        .unwrap_or_default()
-        .as_nanos();
-    let hash = blake3::hash(format!("csrf:{now}:{cnt}").as_bytes());
-    hash.to_hex()[..32].to_string()
+    use rand::RngCore;
+    let mut buf = [0u8; 16];
+    rand::rngs::OsRng.fill_bytes(&mut buf);
+    buf.iter().map(|b| format!("{b:02x}")).collect()
 }
```

Apply the same shape to `session.rs:156-166` and to
`main.rs:577-617` (TOTP secret).

**Additional fix — actually verify CSRF cookie was server-issued.**
Sign the CSRF cookie with the same HMAC key used for session cookies,
and verify the signature on every mutation:

```rust
pub fn format_csrf_cookie(token: &str, secret: &[u8]) -> String {
    let sig = hmac_sha256(secret, token.as_bytes());
    format!("aegis_csrf={token}.{sig}; Secure; SameSite=Strict; Path=/")
}

pub fn validate(cookie_value: Option<&str>, header_value: Option<&str>, secret: &[u8]) -> CsrfResult {
    let (token, sig) = match cookie_value.and_then(|c| c.split_once('.')) {
        Some(p) => p,
        None => return CsrfResult::MissingCookie,
    };
    let expected_sig = hmac_sha256(secret, token.as_bytes());
    if !constant_time_eq(sig.as_bytes(), expected_sig.as_bytes()) {
        return CsrfResult::Invalid;     // cookie not issued by server
    }
    let header = header_value.unwrap_or("");
    if constant_time_eq(token.as_bytes(), header.as_bytes()) {
        CsrfResult::Valid
    } else {
        CsrfResult::Mismatch
    }
}
```

This stops the F-CRITICAL-002 attack of "mint your own cookie+header
pair" even before the session middleware lands.

## Verification

After the fix, repeated calls to `generate_token()` should pass a
chi-squared test for uniform distribution. A regression case in
`tests/api/`:

```rust
let tokens: Vec<_> = (0..10_000).map(|_| generate_token()).collect();
let unique: HashSet<_> = tokens.iter().collect();
assert_eq!(unique.len(), tokens.len(), "tokens not unique");
// Plus: assert each token's bytes pass a basic randomness test.
```

For the cookie-signing fix:

```sh
# Attempt to mint a fake CSRF cookie/header pair:
curl -sk -X PUT "$HOST/api/loadmode" \
    -H "Cookie: aegis_csrf=anyvalue" \
    -H "X-CSRF-Token: anyvalue" \
    -d '{"mode":"emergency"}'
# Expect 403 — invalid cookie signature.
```

## Severity rationale

CRITICAL when combined with F-CRITICAL-002. HIGH standalone. Filing
as CRITICAL because the realistic exploit chain (no session +
predictable tokens + plain-compare CSRF) makes admin auth wholly
bypassable. Trivial fix (~10 LoC per site).
