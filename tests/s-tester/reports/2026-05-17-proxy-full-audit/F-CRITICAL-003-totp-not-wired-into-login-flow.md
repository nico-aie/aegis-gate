---
id: 2026-05-17-totp-not-wired-into-login-flow
date: 2026-05-17T00:00Z
severity: CRITICAL
area: admin · auth chain
component: crates/aegis-control/src/api/login.rs · crates/aegis-control/src/admin_auth/totp.rs
interop_contract: Round 1 dashboard auth chain step 4 (TOTP RFC 6238)
status: open
test_mode: source-review (spot-verified)
---

# F-CRITICAL-003 · TOTP module exists, is tested, has provisioning URI — but is NEVER invoked from the login flow

## Summary

The Round-1 dashboard auth chain specifies:
*"IP allow-list → optional mTLS → argon2id password → **TOTP (RFC 6238)** → HMAC session cookie → CSRF → rate-limit"*.

Step 4 — TOTP — is completely absent from the login handler.
`authenticate()` in `api/login.rs` calls `verify_password` then
directly issues `LoginOutcome::Ok` with a session cookie. The TOTP
module at `admin_auth/totp.rs` exists, has tests, and is even
exposed as a provisioning URI for QR-code enrollment — but no code
path calls `totp::verify`.

**Spot-verified** by `grep "totp" crates/aegis-control/src/api/login.rs`:

```
4://! - [`crate::admin_auth::password::verify_password`] for the
25:use crate::admin_auth::password::{dummy_verify, verify_password};
```

Zero references to `totp::verify`. The login flow ends at
`verify_password` → `LoginOutcome::Ok`.

The dashboard's `admin enroll-totp` CLI sub-command issues a TOTP
secret + QR provisioning URI, but the issued secret is never
checked at login time.

## Observed code path

`crates/aegis-control/src/api/login.rs:119-205` (paraphrased):

```rust
pub async fn authenticate(...) -> LoginOutcome {
    // Step 1: parse body
    let req = parse_login_request(body)?;

    // Step 2: rate-limit / lockout check
    match rate_limit.check(peer_ip, &req.username) { ... }

    // Step 3: verify password (argon2id)
    let admin = match admin_identity_for(&req.username) {
        Some(a) => a,
        None => {
            dummy_verify(&req.password);     // timing-equalisation
            return LoginOutcome::Unauthorized { ... };
        }
    };

    if !verify_password(&admin.password_hash, &req.password) {
        return LoginOutcome::Unauthorized { ... };
    }

    // === MISSING STEP 4: TOTP ===
    // Nothing here.

    // Step 5: issue session cookie + CSRF cookie
    let session = session_store.create_session(...);

    LoginOutcome::Ok {
        session_cookie: format_session_cookie(&session),
        csrf_cookie:    format_csrf_cookie(&csrf),
        body:           login_ok_body(),
    }
}
```

And `crates/aegis-control/src/admin_auth/session.rs:54` initialises
the per-session struct with `totp_verified: false`, but nothing in
the codebase later flips that flag and nothing on any handler reads
it. The flag is dead.

## Repro

```sh
HOST="http://127.0.0.1:9443"

# Enroll a TOTP secret for the admin user (this works and emits a
# provisioning URI you'd put into Google Authenticator):
./target/release/waf admin enroll-totp --user admin

# Now log in WITHOUT supplying any TOTP code:
curl -sk -X POST "$HOST/admin/login" \
    -H 'content-type: application/json' \
    -d '{"username":"admin","password":"aegis-test-1234"}' -i

# Expected (per Round-1 spec): 401 / 403 with "totp required" or a
# two-step login challenge.
# Actual: 200 OK + Set-Cookie: aegis_session=... (fully privileged).
```

## Impact

- **Round 1 dashboard auth chain (Pass/Fail gate)** — step 4 of the
  defense-in-depth spec is missing. An attacker who steals the
  argon2id password hash (data breach, log leak, etc.) gets full
  admin access without needing the TOTP secret.
- **Combined with F-CRITICAL-002 (no session check)** and
  F-CRITICAL-005 (predictable session/CSRF entropy), there is
  effectively NO authentication on the admin port. The dashboard's
  TOTP enrollment UI is a security-theatre placebo.

## Suggested fix

Add the TOTP check after `verify_password` and before issuing the
session. Two viable shapes:

**Option A — single-request login with `totp_code` field** (simpler):

```diff
 pub async fn authenticate(...) -> LoginOutcome {
     let req = parse_login_request(body)?;
     ...
     if !verify_password(&admin.password_hash, &req.password) {
         return LoginOutcome::Unauthorized { ... };
     }
+    // Round-1 auth chain step 4: TOTP RFC 6238.
+    if let Some(ref totp_secret) = admin.totp_secret {
+        let code = req.totp_code.as_deref().unwrap_or("");
+        if !crate::admin_auth::totp::verify(totp_secret, code, /*now*/ now()) {
+            return LoginOutcome::Unauthorized {
+                body: error_body("invalid totp code"),
+            };
+        }
+    } else if cfg.totp_required {
+        return LoginOutcome::Unauthorized {
+            body: error_body("totp enrollment required"),
+        };
+    }
     ...
     LoginOutcome::Ok { session_cookie, csrf_cookie, body }
 }
```

Update `LoginRequest` shape to accept an optional `totp_code` string.
The dashboard's existing login form needs a 6-digit TOTP input.

**Option B — two-step login with `totp_verified: false` intermediate session** (more flexible):

1. Step 1 returns a short-lived "pre-session" cookie with
   `totp_verified=false`.
2. Step 2 (`POST /admin/login/totp`) takes the pre-session + a TOTP
   code, validates, and rotates to a real session with
   `totp_verified=true`.
3. All other endpoints require `totp_verified=true` (per the
   F-CRITICAL-002 session-validation middleware).

This requires the session struct's `totp_verified` field to actually
be checked downstream — currently dead.

## Verification

After the fix:

```sh
# Step 1 — password alone fails:
curl -sk -X POST "$HOST/admin/login" \
    -H 'content-type: application/json' \
    -d '{"username":"admin","password":"aegis-test-1234"}' -i
# Expect 401.

# Step 2 — password + valid TOTP succeeds:
totp=$(oathtool --base32 --totp "<the enrolled secret>")
curl -sk -X POST "$HOST/admin/login" \
    -H 'content-type: application/json' \
    -d "{\"username\":\"admin\",\"password\":\"aegis-test-1234\",\"totp_code\":\"$totp\"}" -i
# Expect 200 + Set-Cookie: aegis_session=...
```

Add a regression case in `tests/api/` that asserts the password-only
login is rejected with 401.

## Related findings

- F-HIGH-admin includes: TOTP code uses HMAC-SHA256 while the doc and
  provisioning URI claim SHA1 — Google Authenticator (and most
  hardware tokens) default to SHA1 and will generate codes the WAF
  rejects. Fix that BEFORE wiring TOTP in or the new TOTP step will
  be unusable.
- F-HIGH-admin also includes: TOTP has no replay protection (used
  codes can be replayed within the 30 s window).

## Severity rationale

CRITICAL. Step 4 of an explicitly-mandated 7-step auth chain is
missing. Round-1 pass/fail gate.
