---
id: 2026-05-17-high-challenge-auth-bundle
date: 2026-05-17T00:00Z
severity: HIGH
area: security · challenge engine · auth · API security
component: crates/aegis-security/src/{challenge/*, auth/*, api_security/*}
interop_contract: official rules §5.2 #04 (Challenge Engine) · API security
status: open
test_mode: source-review
---

# F-HIGH-challenge-auth bundle — 6 issues in challenge / auth / API-security subsystems

---

## CA-01 · `ChallengeTokens::generate_nonce()` deterministic from `(ip, device, session, ts_ms)`

**Component:** [challenge/token.rs:23-30, 98-102](aegis-gate/crates/aegis-security/src/challenge/token.rs#L98-L102)

Nonce is `blake3(ip || device_fp || session || timestamp_ms)`. An
attacker observing one request can predict the nonce for the next
millisecond window from the same triple. This is the same
F-CRITICAL-005 entropy bug from the proxy audit.

The module is currently DEAD CODE (zero production callers, only
test files invoke `ChallengeTokens`; the data plane uses `PowIssuer`
directly), so impact today is zero. But: dead code with security
bugs is a maintenance landmine — a future engineer who wires it in
inherits the predictability.

**Fix:** delete the module (preferred), or replace `generate_nonce`
with `rand::rngs::OsRng.fill_bytes(&mut [u8; 16])`.

---

## CA-02 · `auth/jwt::validate` doesn't verify the signature

**Component:** [auth/jwt.rs:54-106](aegis-gate/crates/aegis-security/src/auth/jwt.rs#L54-L106)

The function is named `validate` and returns `Ok(claims)` after only
base64-decoding the payload. No HMAC/RSA signature verification.
A token with `alg: none` or a forged signature passes.

The module is documented as deferred / dead code (line 1
docstring) — but the API shape is dangerous: any future caller who
sees a `validate()` function naturally assumes it validates.

**Fix:** either delete the module or replace with a real
implementation using `jsonwebtoken` crate (already in workspace
deps per Cargo.toml):

```rust
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};

pub fn validate(token: &str, key: &DecodingKey, cfg: &JwtConfig) -> Result<Claims> {
    let mut validation = Validation::new(cfg.algorithm);
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);
    validation.set_issuer(&[&cfg.issuer]);
    validation.set_audience(&[&cfg.audience]);
    let token_data = decode::<Claims>(token, key, &validation)?;
    Ok(token_data.claims)
}
```

Pin the allowed algorithms (reject `none`, reject `HS*` when key is
RSA, etc.).

---

## CA-03 · `auth/jwt` custom base64 decoder can panic on malformed input

**Component:** [auth/jwt.rs:108-147](aegis-gate/crates/aegis-security/src/auth/jwt.rs#L108-L147)

`chars[i+1]` and `chars[i+2]/[i+3]` indexing without bounds check
before the padding-aware logic. A token where the payload length
isn't 4-aligned + padding produces index-out-of-bounds → panic.

Combined with CA-02 (dead code), impact today is zero. If ever
wired, malformed tokens crash the worker.

**Fix:** replace with `base64::engine::general_purpose::URL_SAFE_NO_PAD::decode` (the `base64` crate is already
in workspace via several deps).

---

## CA-04 · API-key compare uses `HashMap::get` (not constant-time)

**Component:** [api_security/api_keys.rs:67-69](aegis-gate/crates/aegis-security/src/api_security/api_keys.rs#L67-L69)

```rust
let hash = blake3::hash(key.as_bytes()).to_hex().to_string();
if self.keys.get(&hash).is_some() { ... }
```

`HashMap::get` uses `memcmp` short-circuit comparison internally.
For string-equal hashes the leak is sub-nanosecond, but the
contract may grade timing.

**Fix:** iterate with `subtle::ConstantTimeEq`:

```rust
use subtle::ConstantTimeEq;
let hash = blake3::hash(key.as_bytes());
let mut found = subtle::Choice::from(0u8);
for stored in self.keys.values() {
    found |= stored.as_bytes().ct_eq(hash.as_bytes());
}
found.into()
```

---

## CA-05 · `hmac_sign::verify()` has no timestamp / replay protection

**Component:** [api_security/hmac_sign.rs:1-65](aegis-gate/crates/aegis-security/src/api_security/hmac_sign.rs#L1-L65)

`HmacConfig.clock_skew_s` field exists but is never consulted in
`verify()`. A captured signed request is replayable indefinitely.
§5.7 dashboard scoring includes "HMAC signing verification:
timestamp drift bound? Replay protection?" — both missing.

**Fix:**

1. Add a `ts` field to the signed envelope (or require an `X-Timestamp` request header).
2. In `verify()`, reject if `(now - ts).abs() > cfg.clock_skew_s`.
3. Maintain a per-(api-key, nonce) replay cache with TTL = `clock_skew_s`.

---

## CA-06 · `captcha.rs::verify()` returns `Ok(true)` for all three providers

**Component:** [challenge/captcha.rs:1-18](aegis-gate/crates/aegis-security/src/challenge/captcha.rs#L1-L18)

The CAPTCHA module is a stub: `verify()` always returns `Ok(true)`
regardless of input. The doc header acknowledges it's stubbed.

The PoW path (`challenge/pow.rs`) IS the production challenge,
so impact today is zero. But: if the dashboard surfaces "CAPTCHA"
as a challenge option in the ladder and operators select it, every
CAPTCHA attempt trivially passes — false sense of security.

**Fix:** either delete the captcha module (and remove the option
from the ladder), or wire a real CAPTCHA provider (hCaptcha,
Cloudflare Turnstile, reCAPTCHA v3).

---

## Severity rationale

HIGH. CA-01/CA-02/CA-03/CA-06 are dead-code bugs (zero impact
today) but each is a security landmine if/when the code is wired.
CA-04/CA-05 are live and reachable through API-key validation +
HMAC-signed callbacks. The auth module's "validate-without-verify"
shape is particularly dangerous if any reviewer mistakes it for a
real implementation.
