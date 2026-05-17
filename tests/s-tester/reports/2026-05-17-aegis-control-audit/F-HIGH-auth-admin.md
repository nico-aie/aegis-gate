---
id: 2026-05-17-high-auth-admin-bundle
date: 2026-05-17T00:00Z
severity: HIGH
area: admin auth · interop secrets
component: crates/aegis-control/src/admin_auth/{password,session,totp,rate_limit}.rs · crates/aegis-control/src/interop/control.rs · crates/aegis-control/src/audit/sinks/syslog.rs
interop_contract: Round-1 dashboard auth chain + audit completeness
status: open
test_mode: source-review
---

# F-HIGH-auth-admin bundle — 6 issues in admin-auth and interop-secret handling (beyond F-CRITICAL-002/003/005 already filed)

---

## AA-01 · `password::generate_salt` derives from `blake3(now||counter)` not `OsRng` → defeats argon2 offline-attack resistance

**Component:** [admin_auth/password.rs:25-27](aegis-gate/crates/aegis-control/src/admin_auth/password.rs#L25-L27)

Argon2id's offline-attack resistance depends on **unpredictable
per-password salts**. Predictable salts let an attacker pre-compute
rainbow-equivalents per salt window.

Aegis derives the salt from `blake3(now_nanos || atomic_counter)`.
Same root cause as F-CRITICAL-005 in proxy audit.

If a password hash file leaks (data breach), an attacker who knows
the salt-generation time window can pre-compute argon2 outputs for
common passwords against each predictable salt, drastically reducing
the offline crack cost.

**Fix:**

```diff
 pub fn generate_salt() -> [u8; 16] {
-    let nanos = std::time::SystemTime::now()
-        .duration_since(std::time::UNIX_EPOCH)
-        .unwrap_or_default()
-        .as_nanos();
-    let cnt = COUNTER.fetch_add(1, Ordering::Relaxed);
-    let h = blake3::hash(format!("salt:{nanos}:{cnt}").as_bytes());
-    h.as_bytes()[..16].try_into().unwrap()
+    use rand::RngCore;
+    let mut salt = [0u8; 16];
+    rand::rngs::OsRng.fill_bytes(&mut salt);
+    salt
 }
```

---

## AA-02 · TOTP docstring says SHA-1 but code uses HMAC-SHA256

**Component:** [admin_auth/totp.rs:1, 66](aegis-gate/crates/aegis-control/src/admin_auth/totp.rs#L1)

Doc comment: "HMAC-SHA1 for compatibility with standard authenticator apps".

Code: `Hmac<Sha256>` (line 7). Provisioning URI advertises `algorithm=SHA256` (line 66).

Most authenticator apps (Google Authenticator, Authy classic) ignore
the `algorithm=` URI parameter and default to SHA-1 → produces codes
that NEVER verify against the server's SHA-256 implementation.

Users who scan the QR get codes that always fail; the only way to
recover is via TOTP recovery codes (if the operator kept them).

Combined with F-CRITICAL-003 in proxy audit (TOTP not wired into
login at all): even after TOTP is wired, the wrong algorithm makes
it unusable.

**Fix:** switch to HMAC-SHA1 (RFC 6238 default):

```diff
-use sha2::Sha256;
-type HmacSha = Hmac<Sha256>;
+use sha1::Sha1;
+type HmacSha = Hmac<Sha1>;
```

And `algorithm=SHA1` in the provisioning URI (or omit — SHA1 is the
default).

---

## AA-03 · `session::base64url_encode` writes HEX not base64

**Component:** [admin_auth/session.rs:168-171](aegis-gate/crates/aegis-control/src/admin_auth/session.rs#L168-L171)

Function name + module docstring (line 4: "base64url(HMAC_SHA256(...))")
say base64. The implementation writes hex via
`data.iter().map(|b| format!("{b:02x}")).collect()` then
`.replace('+', '-')` (no-op on hex output).

Functionally fine (cookie verifies via the same encoder on read) but:
- Cookie is 2x bigger than necessary (64 hex chars vs 44 base64url chars for a 32-byte HMAC).
- Function name LIES — confusing to future maintainers.
- Docstring + actual format disagree → wire-format may change accidentally.

**Fix:** either rename to `hex_encode` or implement actual base64url:

```rust
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
pub fn base64url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}
```

Rename is the smaller, safer change.

---

## AA-04 · `password.rs` Argon2 params not pinned

**Component:** [admin_auth/password.rs:8, 38](aegis-gate/crates/aegis-control/src/admin_auth/password.rs#L8)

Uses `Argon2::default()`. The `argon2` 0.5.x default is
`m_cost = 19456 KiB, t_cost = 2, p_cost = 1` — meets OWASP 2024
minimum.

But a future crate bump could lower these. The hash-stored verifier
also needs to read the params from the stored hash, so it adapts —
but new hashes get whatever the new default is.

**Fix:** pin params explicitly:

```rust
use argon2::{Algorithm, Argon2, Params, Version};

fn argon2() -> Argon2<'static> {
    let params = Params::new(19_456, 2, 1, None).expect("argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    argon2().hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| Error::HashFailed)
}
```

Document the chosen params + the OWASP year they map to in a code comment.

---

## AA-05 · `audit/sinks/syslog.rs` drops audit data on slow remote, no metric

**Component:** [audit/sinks/syslog.rs:485](aegis-gate/crates/aegis-control/src/audit/sinks/syslog.rs#L485)

On send failure the forwarder `sleep(100ms)`. Under sustained outage
to a remote syslog peer, the bus emits at full rate but the
forwarder's `rx.recv()` can't keep up → `Lagged(_)` every cycle →
data is lost.

No metric exposed; operators don't know audit is being dropped.

**Fix:** export a counter:

```rust
metrics::register_counter("waf_audit_sink_dropped_total", "Audit events dropped at sink due to backpressure", &["sink"])
    .with_label_values(&["syslog"])
    .inc_by(dropped_count);
```

And consider an alert (SLO) when this counter rises.

---

## AA-06 · interop `control.rs::secret` stored as plain `String`, not zeroized

**Component:** [interop/control.rs:226](aegis-gate/crates/aegis-control/src/interop/control.rs#L226)

The `X-Benchmark-Secret` value is stored as a plain `String`. On
process memory dump (`gcore`, container debugger, OOM core file)
the secret is exposed.

**Fix:** wrap in `secrecy::SecretString` or `zeroize::Zeroizing<String>`:

```diff
+use zeroize::Zeroizing;

 pub struct InteropControl {
-    secret: String,
+    secret: Zeroizing<String>,
     ...
 }

 fn check_auth(&self, presented: Option<&str>) -> Result<()> {
     match presented {
-        Some(s) => constant_time_eq(s.as_bytes(), self.secret.as_bytes()),
+        Some(s) => constant_time_eq(s.as_bytes(), self.secret.as_str().as_bytes()),
         None => false,
     }.then_some(()).ok_or(Error::Unauthorized)
 }
```

Same hardening for any other secret in the codebase (HMAC keys, etc.).

---

## Severity rationale

HIGH. Each is a real defense-in-depth gap. AA-01 (predictable salt)
and AA-02 (wrong TOTP algo) are the most impactful in operator-facing
auth flow. AA-05 is the biggest operational risk (silent audit data
loss).
