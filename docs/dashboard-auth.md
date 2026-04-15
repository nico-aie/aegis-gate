# Dashboard & Admin API Authentication

Local authentication for the Aegis-Gate dashboard and admin API.
Replaces the deferred
[OIDC/SSO/RBAC design](./deferred/rbac-sso.md).

## Goals

- **Strong**: no plaintext passwords on disk, no guessable secrets,
  no framework-typical pitfalls (session fixation, CSRF, timing
  oracles).
- **Simple**: zero external dependencies. No IdP, no SAML, no
  directory service. A single admin password + optional TOTP.
- **Restrictive by default**: admin listener binds to loopback,
  IP allowlist is enforced, login is rate-limited, failed attempts
  are audited.
- **Honest**: everything is logged. Every login, logout, failure,
  lockout, password change, and token issuance produces an audit
  event on the admin chain.

## Non-Goals

- OIDC / SAML / LDAP integration (deferred — see
  [`deferred/rbac-sso.md`](./deferred/rbac-sso.md)).
- Per-user accounts, groups, or roles. v1 has **one admin
  principal**. Role separation is deferred.
- Multi-tenant per-tenant dashboards. v1 is single-tenant.

## Threat Model

| Threat                               | Mitigation                              |
|--------------------------------------|-----------------------------------------|
| Password guessing / brute force      | argon2id + per-IP + per-account rate limit + exponential backoff |
| Credential theft via disk access     | argon2id hash only; password never at rest |
| Session hijack                       | HMAC-signed cookie, `HttpOnly`, `Secure`, `SameSite=Strict`, short idle TTL |
| CSRF                                 | Double-submit token + `SameSite=Strict`  |
| Timing oracles on login              | Constant-time compare for hash + constant-time path for unknown user |
| Replay after logout                  | Server-side session revocation list (in-memory, etcd-backed for HA) |
| Stolen session cookie                | Bound to client IP + User-Agent fingerprint; mismatch = forced re-auth |
| Credential exfil via admin API       | Admin listener on loopback or IP-allowlisted interface only |
| Lost 2FA device                      | Recovery codes printed at TOTP enrollment, stored as argon2 hashes |

## Architecture

The admin listener is a separate HTTP server bound to a distinct
address from the data plane. It runs inside `aegis-control` and
shares nothing with the proxy hot path.

```
┌─────────────── aegis-control ──────────────┐
│  admin listener (9443, loopback by default)│
│     │                                       │
│     ▼                                       │
│  auth middleware                             │
│     │  ┌─────────────┐                       │
│     ├─►│ login       │── argon2id ──► etcd   │
│     │  └─────────────┘     (secret)          │
│     │  ┌─────────────┐                       │
│     ├─►│ session     │── HMAC verify         │
│     │  └─────────────┘                       │
│     │  ┌─────────────┐                       │
│     └─►│ csrf        │── double-submit       │
│        └─────────────┘                       │
│     ▼                                       │
│  axum router (dashboard + /api/*)            │
└─────────────────────────────────────────────┘
```

No request on the data-plane hot path touches any of this.

## Password Storage

- **Algorithm**: `argon2id`, v1.3.
- **Parameters**: `m = 64 MiB`, `t = 2`, `p = 1`. These target
  ~150 ms on a modern x86 core. Tuned via `waf admin benchmark-argon2`.
- **Salt**: 16 random bytes, per hash.
- **Format**: standard PHC string,
  `$argon2id$v=19$m=65536,t=2,p=1$<salt>$<hash>`.
- **Storage location**: `/aegis/secrets/admin_password` in etcd,
  ACL-gated so only the control plane role can read it. Never
  written to disk. Resolved via the `etcd` secret provider.
- **Setting**: `waf admin set-password` prompts interactively,
  hashes on the CLI host, and writes the PHC string to etcd via
  the same secret provider.

```yaml
admin:
  dashboard_auth:
    password_hash_ref: "${secret:etcd:/aegis/secrets/admin_password}"
```

## Session Token

- **Format**: HMAC-SHA256 of `session_id || issued_at || client_ip
  || ua_hash`, base64url-encoded, set as a cookie named
  `aegis_session`.
- **Cookie flags**: `HttpOnly; Secure; SameSite=Strict; Path=/;
  Max-Age=<absolute-ttl>`.
- **Signing key**: `csrf_secret_ref` resolves to a 32-byte random
  value in etcd. Rotating this key invalidates all sessions.
- **Session record** (server-side, in-memory + etcd backup for HA):
  ```rust
  struct SessionRecord {
      id: [u8; 16],
      issued_at: u64,
      last_seen: u64,
      client_ip: IpAddr,
      ua_hash: [u8; 8],
      totp_verified: bool,
      revoked: bool,
  }
  ```
- **TTLs**:
  - `session_ttl_idle`: 30 minutes. Sliding — each authenticated
    request resets the idle timer.
  - `session_ttl_absolute`: 8 hours. Hard limit; re-auth required
    regardless of activity.
- **Revocation**: `POST /admin/logout` flips `revoked` in etcd;
  all replicas see the revocation on their next request via an
  etcd watch on `/aegis/sessions/`.
- **IP / UA binding**: requests whose `client_ip || ua_hash` does
  not match the session record are rejected with 401 and audited.
  Mobile / roaming admins can opt out per-session at login with a
  `remember_device` toggle.

## CSRF Protection

- Double-submit token: on login success, the server sets a
  second cookie `aegis_csrf` (not HttpOnly) with a random
  128-bit value. Every mutating request must send the same
  value in the `X-CSRF-Token` header.
- `SameSite=Strict` on the session cookie is the primary defense;
  the double-submit catches the browser-specific edge cases where
  `SameSite` is degraded.
- Safe methods (GET, HEAD, OPTIONS) do not require the CSRF token.

## Login Flow

```
POST /admin/login
  body: { username, password, totp_code? }

1. rate-limit check (per-IP + per-username)
2. lookup current password hash from etcd
3. argon2_verify(password, hash) — constant-time
4. if totp_enabled: verify totp_code against shared secret
5. mint session_id + HMAC cookie
6. create SessionRecord in etcd
7. audit(Login, actor="admin", ip, ua, success)
8. 204 + Set-Cookie: aegis_session=...; aegis_csrf=...
```

Failure cases always run the full argon2 work to avoid leaking
"user exists" via timing. Unknown usernames hash against a fixed
dummy PHC string.

## Rate Limiting & Lockout

- **Per-IP**: max 5 login attempts per minute, sliding window,
  enforced by `CounterStore::incr_window`.
- **Per-username**: max 10 attempts per 15 minutes. After the cap,
  the account is locked for 15 minutes; subsequent correct
  passwords during lockout still fail and are audited as
  `LoginDuringLockout`.
- **Exponential backoff**: 6th, 7th, 8th attempts delay
  1 s / 2 s / 4 s before the response is sent.
- All lockouts and rate-limit rejections are audited.

## IP Allowlist

The admin listener rejects any TCP connection whose peer is not
in `admin.dashboard_auth.ip_allowlist`. Enforced at accept time,
before the HTTP layer runs. Default allowlist: `127.0.0.1/32`,
`::1/128`.

```yaml
admin:
  dashboard_auth:
    ip_allowlist:
      - "10.0.0.0/8"
      - "192.168.1.0/24"
```

For remote administration, operators either:
1. SSH-tunnel to the loopback admin port (recommended), or
2. Expose the admin listener on a private network and configure
   the allowlist for that network, or
3. Use admin mTLS (below) on a public interface.

## Admin mTLS (alternate path)

For agents and CI systems, `admin.dashboard_auth` optionally
accepts client-cert auth instead of password auth:

```yaml
admin:
  dashboard_auth:
    mtls:
      enabled: true
      ca_ref: "${secret:etcd:/aegis/secrets/admin_ca}"
      required_san: "CN=aegis-admin"
```

A connection presenting a valid client cert bypasses the
password flow and is treated as an authenticated admin session.
Still subject to the IP allowlist. Still audited. Sessions
authenticated via mTLS carry `auth_method="mtls"` in every
audit event.

## Optional TOTP (2FA)

- Standard RFC 6238 TOTP, 6 digits, 30-second step, SHA-1 HMAC.
- Shared secret stored at `/aegis/secrets/admin_totp` in etcd.
- Enabled via `admin.dashboard_auth.totp_enabled = true`.
- Enrollment: `waf admin enroll-totp` prints the provisioning URI
  and a set of 10 recovery codes (each is used once, stored as
  argon2 hashes).
- A session is not considered "fully authenticated" until TOTP is
  verified; intermediate state is tracked as `totp_verified=false`
  on the `SessionRecord`.

## Audit Events

All events go to the admin audit chain (separate from the
detection chain) under `AuditClass::Admin`.

| Event                    | Fields                                   |
|--------------------------|------------------------------------------|
| `LoginSuccess`           | actor, ip, ua, auth_method, totp_used    |
| `LoginFailure`           | ip, ua, reason (`bad_password`, `unknown_user`, `rate_limited`, `locked`, `ip_denied`, `bad_totp`) |
| `Logout`                 | actor, session_id                        |
| `SessionExpired`         | actor, session_id, reason (`idle`, `absolute`) |
| `SessionRevoked`         | actor, session_id, revoked_by            |
| `PasswordChanged`        | actor, ip                                |
| `TotpEnrolled`           | actor, ip                                |
| `TotpDisabled`           | actor, ip                                |
| `AccountLocked`          | ip_trigger, attempts, lockout_ttl        |
| `MtlsAuthAccepted`       | ip, cert_subject, cert_fingerprint       |
| `MtlsAuthRejected`       | ip, reason                               |

## CLI Commands

```sh
waf admin set-password              # interactive prompt, writes to etcd
waf admin enroll-totp               # prints QR URI + recovery codes
waf admin disable-totp              # requires current password
waf admin logout-all                # revokes every live session
waf admin benchmark-argon2          # tunes argon2id params for this host
```

See [`cli.md`](./cli.md) for the full CLI reference.

## Configuration (authoritative schema)

See `DashboardAuthConfig` in
[`../plans/shared-contract.md`](../plans/shared-contract.md) §2.6.11.

```yaml
admin:
  bind: 127.0.0.1:9443
  tls:
    cert_ref: "${secret:etcd:/aegis/secrets/admin_cert}"
    key_ref:  "${secret:etcd:/aegis/secrets/admin_key}"
  dashboard_auth:
    password_hash_ref: "${secret:etcd:/aegis/secrets/admin_password}"
    csrf_secret_ref:   "${secret:etcd:/aegis/secrets/admin_csrf}"
    session_ttl_idle: 30m
    session_ttl_absolute: 8h
    ip_allowlist:
      - "127.0.0.1/32"
      - "::1/128"
    totp_enabled: false
    login_rate_limit:
      per_ip:   { limit: 5,  window: 1m }
      per_user: { limit: 10, window: 15m }
    lockout:
      threshold: 10
      window: 15m
      duration: 15m
    mtls:
      enabled: false
```

## Performance

- argon2id verify: ~150 ms. Login is rare. Not on the data-plane
  hot path. Serialized per principal to prevent parallel-guess
  amplification.
- Session HMAC verify: ~1 µs. Runs on every authenticated admin
  request, still control plane only.
- Rate-limit check: one `CounterStore::incr_window` per login
  attempt. ~100 µs in-memory, ~500 µs against Redis.

## Upgrade Path to OIDC/RBAC

The `DashboardAuthConfig` type and the session-layer traits are
designed so a future OIDC implementation (see deferred doc) can
slot in beside the local-auth path without breaking consumers:

- The middleware checks `oidc` first if enabled, then falls back
  to the local-auth path. Both mint the same `SessionRecord`.
- Roles arrive later — v1 treats every successful login as the
  sole `admin` principal.

## Implementation Pointers

- `crates/aegis-control/src/admin/auth/password.rs` — argon2 verify + hash
- `crates/aegis-control/src/admin/auth/session.rs` — HMAC cookie + record
- `crates/aegis-control/src/admin/auth/csrf.rs` — double-submit token
- `crates/aegis-control/src/admin/auth/rate_limit.rs` — per-IP/per-user
- `crates/aegis-control/src/admin/auth/totp.rs` — RFC 6238
- `crates/aegis-control/src/admin/auth/mtls.rs` — rustls client cert
- `crates/aegis-control/src/admin/middleware.rs` — axum tower layer
