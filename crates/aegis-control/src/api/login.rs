//! `POST /admin/login` and `POST /admin/logout` (F-T1).
//!
//! Glue between the existing auth primitives:
//! - [`crate::admin_auth::password::verify_password`] for the
//!   argon2id check
//! - [`crate::admin_auth::session::SessionStore`] for HMAC-signed
//!   session cookies
//! - [`crate::admin_auth::csrf::generate_token`] +
//!   [`crate::admin_auth::csrf::format_csrf_cookie`] for the
//!   double-submit CSRF cookie
//! - [`crate::admin_auth::rate_limit::LoginRateLimiter`] for the
//!   per-IP and per-user attempt budgets + lockout
//!
//! The handler returns a `LoginOutcome` (status + cookies + body)
//! so the proxy's async wrapper can map it to a hyper `Response`
//! without re-implementing the policy.

#![allow(dead_code)]

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::admin_auth::csrf::{format_csrf_cookie, generate_token};
use crate::admin_auth::password::{dummy_verify, verify_password};
use crate::admin_auth::rate_limit::{LoginOutcome as RateOutcome, LoginRateLimiter};
use crate::admin_auth::session::{format_cookie, SessionStore as AuthSessionStore};
use crate::api::admin::{SessionInfo, SessionStore as DashboardSessionStore};

/// Request body shape. Keep the API stable across CLI / dashboard
/// callers.
#[derive(Clone, Debug, Deserialize)]
pub struct LoginRequest {
    pub user: String,
    pub password: String,
    /// 2026-05-17 F-CRITICAL-003 — required when
    /// `cfg.admin.dashboard_auth.totp_enabled = true`; omit (or
    /// pass `None`/empty) when TOTP is disabled. A missing code
    /// against a TOTP-enabled config produces the same
    /// `Unauthorized` envelope as a wrong password — no path that
    /// distinguishes the two so an attacker can't tell whether
    /// they had the password right and only need the TOTP code.
    #[serde(default)]
    pub totp_code: Option<String>,
}

/// Response body on success.
#[derive(Clone, Debug, Serialize)]
pub struct LoginResponse {
    pub ok: bool,
    pub user: String,
    pub session_idle_seconds: u64,
}

/// What a login attempt produced. The proxy maps each variant
/// onto the matching hyper response.
#[derive(Clone, Debug)]
pub enum LoginOutcome {
    /// Auth succeeded. The proxy emits 200 + the two cookies.
    Ok {
        session_cookie: String,
        csrf_cookie: String,
        body: String,
    },
    /// Wrong credentials, missing user, or any other "I don't
    /// trust you" path. Body is the documented error envelope.
    Unauthorized { body: String },
    /// Per-IP or per-user rate limiter or lockout fired. Body
    /// carries the retry-after seconds; proxy emits 429 +
    /// `Retry-After` header.
    RateLimited {
        retry_after_seconds: u64,
        body: String,
    },
    /// Body wasn't parseable. Proxy emits 400.
    BadRequest { body: String },
}

/// What a logout produced.
#[derive(Clone, Debug)]
pub enum LogoutOutcome {
    /// Session existed; proxy clears cookies + returns 204.
    Ok {
        clear_session_cookie: String,
        clear_csrf_cookie: String,
    },
    /// Cookie wasn't present or didn't validate; same response
    /// shape so logout is idempotent.
    NoSession {
        clear_session_cookie: String,
        clear_csrf_cookie: String,
    },
}

/// Identity bundle for the configured single admin (until RBAC
/// lands). The proxy builds this from
/// `cfg.admin.dashboard_auth.password_hash_ref` (+
/// `totp_secret_b32` when `totp_enabled = true`).
#[derive(Clone, Debug, Default)]
pub struct AdminIdentity {
    pub user: String,
    pub password_hash: String,
    /// 2026-05-17 F-CRITICAL-003 — operator's base32-encoded TOTP
    /// secret. Empty when TOTP is disabled. `authenticate()`
    /// decodes + verifies via `crate::admin_auth::totp::verify`.
    /// Stored decoded form lives only on the stack; we never log
    /// or audit the raw bytes.
    pub totp_secret_b32: String,
    /// 2026-05-17 F-CRITICAL-003 — operator's TOTP-enabled flag,
    /// mirrored from `cfg.admin.dashboard_auth.totp_enabled` so
    /// `authenticate()` doesn't need to take the full config.
    pub totp_enabled: bool,
}

/// Authenticate one POST /admin/login attempt.
///
/// Side-effects on success:
/// - `sessions.create(ip, user_agent)` issues a new session
///   record + cookie.
/// - `dashboard_sessions.upsert(...)` registers the session for
///   the dashboard's `/api/admin/sessions` view.
///
/// Side-effects on failure:
/// - `rate_limiter.record_failure(ip, user)` advances the
///   per-IP and per-user counters; may flip the user into lockout.
///
/// Timing: missing-user path runs `dummy_verify` so a
/// stopwatch attacker can't enumerate accounts via response time.
#[allow(clippy::too_many_arguments)]
pub fn authenticate(
    body: &str,
    admin: &AdminIdentity,
    rate_limiter: &LoginRateLimiter,
    sessions: &AuthSessionStore,
    dashboard_sessions: &DashboardSessionStore,
    ip: &str,
    user_agent: &str,
    session_idle_seconds: u64,
) -> LoginOutcome {
    let req: LoginRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            return LoginOutcome::BadRequest {
                body: error_body("invalid_json", &e.to_string()),
            };
        }
    };

    if req.user.is_empty() || req.password.is_empty() {
        return LoginOutcome::BadRequest {
            body: error_body("missing_field", "user and password are required"),
        };
    }

    // 1. Pre-flight rate limit check. Lockout wins; raw rate
    //    limit is second.
    match rate_limiter.check(ip, &req.user) {
        RateOutcome::Allowed => {}
        RateOutcome::LockedOut { remaining } => {
            return LoginOutcome::RateLimited {
                retry_after_seconds: remaining.as_secs(),
                body: error_body(
                    "locked_out",
                    "account temporarily locked after repeated failures",
                ),
            };
        }
        RateOutcome::RateLimited { retry_after } => {
            return LoginOutcome::RateLimited {
                retry_after_seconds: retry_after.as_secs(),
                body: error_body("rate_limited", "too many login attempts"),
            };
        }
    }

    // 2. Verify password. Unknown-user path runs dummy_verify so
    //    response time doesn't leak account existence.
    let ok = if req.user == admin.user {
        verify_password(&admin.password_hash, &req.password)
    } else {
        dummy_verify(&req.password);
        false
    };

    if !ok {
        rate_limiter.record_failure(ip, &req.user);
        return LoginOutcome::Unauthorized {
            body: error_body("invalid_credentials", "user or password incorrect"),
        };
    }

    // 2b. F-CRITICAL-003 (2026-05-17 s-tester audit) — when TOTP is
    //     enabled, verify the second factor. Same `Unauthorized`
    //     envelope as wrong password on any failure path (missing
    //     code, malformed code, malformed b32 secret, wrong code)
    //     so a stopwatch attacker can't distinguish password-right
    //     vs TOTP-wrong from password-wrong. The contract `actor`
    //     for repeated TOTP failures stays the same as repeated
    //     password failures — both feed `rate_limiter::record_failure`
    //     so the lockout threshold counts them together.
    if admin.totp_enabled {
        use crate::admin_auth::totp;

        let code = match req.totp_code.as_deref() {
            Some(c) if !c.is_empty() => c,
            _ => {
                rate_limiter.record_failure(ip, &req.user);
                return LoginOutcome::Unauthorized {
                    body: error_body("invalid_credentials", "user or password incorrect"),
                };
            }
        };

        let secret_bytes = match base32::decode(
            base32::Alphabet::Rfc4648 { padding: false },
            &admin.totp_secret_b32,
        ) {
            Some(b) if !b.is_empty() => b,
            _ => {
                // Config bug — secret didn't decode. Treat as auth
                // failure to operator (don't leak "your config is
                // broken" to a client) but log loudly server-side
                // so it shows up in setup-time troubleshooting.
                tracing::error!(
                    user = %req.user,
                    "admin TOTP secret failed to decode as RFC 4648 base32; reject login (re-check cfg.admin.dashboard_auth.totp_secret_b32)",
                );
                rate_limiter.record_failure(ip, &req.user);
                return LoginOutcome::Unauthorized {
                    body: error_body("invalid_credentials", "user or password incorrect"),
                };
            }
        };

        let now_s = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let cfg = totp::TotpConfig::default();
        if !totp::verify(&secret_bytes, code, now_s, &cfg) {
            rate_limiter.record_failure(ip, &req.user);
            return LoginOutcome::Unauthorized {
                body: error_body("invalid_credentials", "user or password incorrect"),
            };
        }
    }

    // 3. Success — issue session + CSRF cookies.
    rate_limiter.record_success(ip, &req.user);
    let (session_id, signed_session_value) = sessions.create(ip, user_agent);
    let session_cookie = format_cookie(
        "aegis_session",
        &signed_session_value,
        session_idle_seconds as i64,
    );
    let csrf_token = generate_token();
    let csrf_cookie = format_csrf_cookie(&csrf_token);

    // Mirror the new session into the dashboard view so
    // /api/admin/sessions reflects reality.
    dashboard_sessions.upsert(SessionInfo {
        id: session_id.clone(),
        created_at: chrono::Utc::now(),
        last_seen: chrono::Utc::now(),
        ip: ip.into(),
        user_agent: user_agent.into(),
        current: true,
    });
    dashboard_sessions.mark_current(&session_id);

    let body = LoginResponse {
        ok: true,
        user: req.user.clone(),
        session_idle_seconds,
    };
    LoginOutcome::Ok {
        session_cookie,
        csrf_cookie,
        body: serde_json::to_string(&body).unwrap_or_else(|_| "{}".into()),
    }
}

/// Process a `POST /admin/logout`. Reads the session cookie,
/// revokes the matching record in both stores, and returns
/// cookie-clearing strings the proxy emits as `Set-Cookie`.
/// Idempotent: succeeds whether or not the cookie was present.
pub fn logout(
    session_cookie: Option<&str>,
    sessions: &AuthSessionStore,
    dashboard_sessions: &DashboardSessionStore,
) -> LogoutOutcome {
    let clear_session_cookie =
        format_cookie("aegis_session", "", 0);
    let clear_csrf_cookie = if crate::admin_auth::csrf::insecure_cookies_enabled() {
        "aegis_csrf=; SameSite=Strict; Path=/; Max-Age=0".to_string()
    } else {
        "aegis_csrf=; Secure; SameSite=Strict; Path=/; Max-Age=0".to_string()
    };

    if let Some(cookie) = session_cookie {
        if let Some(rec) = sessions.validate(cookie) {
            sessions.revoke(&rec.id);
            dashboard_sessions.force_remove(&rec.id);
            return LogoutOutcome::Ok {
                clear_session_cookie,
                clear_csrf_cookie,
            };
        }
    }
    LogoutOutcome::NoSession {
        clear_session_cookie,
        clear_csrf_cookie,
    }
}

/// Single error envelope shape reused across every failure
/// branch.
fn error_body(reason: &'static str, message: &str) -> String {
    let body = serde_json::json!({
        "ok": false,
        "reason": reason,
        "message": message,
    });
    serde_json::to_string(&body).unwrap_or_else(|_| "{}".into())
}

/// Build a 32-byte session-store HMAC key by hashing the
/// configured CSRF secret. Same input → same key, so the WAF can
/// be restarted without invalidating outstanding sessions
/// (provided the secret is stable on disk).
pub fn derive_session_key(secret: &str) -> [u8; 32] {
    let hash = blake3::hash(secret.as_bytes());
    *hash.as_bytes()
}

/// Build a [`LoginRateLimiter`] from the YAML-side
/// `dashboard_auth` config. Flattens the per-IP / per-user /
/// lockout YAML into the runtime config the limiter expects.
pub fn build_rate_limiter(
    auth: &aegis_core::config::DashboardAuthConfig,
) -> Arc<LoginRateLimiter> {
    use crate::admin_auth::rate_limit::LoginRateLimitConfig;
    let cfg = LoginRateLimitConfig {
        ip_max_attempts: auth.login_rate_limit.per_ip.limit,
        ip_window: auth.login_rate_limit.per_ip.window,
        user_max_attempts: auth.login_rate_limit.per_user.limit,
        user_window: auth.login_rate_limit.per_user.window,
        lockout_threshold: auth.lockout.threshold,
        lockout_duration: auth.lockout.duration,
    };
    Arc::new(LoginRateLimiter::new(cfg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin_auth::password::hash_password;

    fn fixtures() -> (
        AdminIdentity,
        Arc<LoginRateLimiter>,
        Arc<AuthSessionStore>,
        Arc<DashboardSessionStore>,
    ) {
        let admin = AdminIdentity {
            user: "admin".into(),
            password_hash: hash_password("aegis-test-1234").unwrap(),
            ..AdminIdentity::default()
        };
        let rl = Arc::new(LoginRateLimiter::new(Default::default()));
        let key = derive_session_key("test-csrf-secret-32b");
        let sessions = Arc::new(AuthSessionStore::new(key));
        let dashboard = Arc::new(DashboardSessionStore::new());
        (admin, rl, sessions, dashboard)
    }

    fn ok_body() -> String {
        serde_json::json!({"user":"admin","password":"aegis-test-1234"}).to_string()
    }

    #[test]
    fn login_with_correct_creds_issues_session_and_csrf_cookies() {
        let (admin, rl, ss, ds) = fixtures();
        let outcome = authenticate(
            &ok_body(),
            &admin,
            &rl,
            &ss,
            &ds,
            "127.0.0.1",
            "k6/0.51.0",
            1800,
        );
        let (session, csrf, body) = match outcome {
            LoginOutcome::Ok { session_cookie, csrf_cookie, body } => {
                (session_cookie, csrf_cookie, body)
            }
            other => panic!("expected Ok, got {other:?}"),
        };
        assert!(session.starts_with("aegis_session="));
        assert!(session.contains("HttpOnly"));
        assert!(session.contains("SameSite=Strict"));
        assert!(csrf.starts_with("aegis_csrf="));
        assert!(!csrf.contains("HttpOnly"), "csrf must be JS-readable");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["user"], "admin");
        assert_eq!(v["session_idle_seconds"], 1800);
        // Dashboard view reflects the new session.
        assert_eq!(ds.list().len(), 1);
    }

    #[test]
    fn login_with_wrong_password_returns_unauthorized() {
        let (admin, rl, ss, ds) = fixtures();
        let body = serde_json::json!({"user":"admin","password":"wrong"}).to_string();
        let outcome = authenticate(&body, &admin, &rl, &ss, &ds, "127.0.0.1", "ua", 1800);
        match outcome {
            LoginOutcome::Unauthorized { body } => {
                let v: serde_json::Value = serde_json::from_str(&body).unwrap();
                assert_eq!(v["reason"], "invalid_credentials");
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
        assert_eq!(ss.active_count(), 0, "no session created on failure");
    }

    #[test]
    fn login_with_unknown_user_does_not_leak_existence() {
        let (admin, rl, ss, ds) = fixtures();
        let body = serde_json::json!({"user":"ghost","password":"whatever"}).to_string();
        let outcome = authenticate(&body, &admin, &rl, &ss, &ds, "127.0.0.1", "ua", 1800);
        // Same Unauthorized envelope as wrong password — no
        // path that reveals "no such user".
        match outcome {
            LoginOutcome::Unauthorized { body } => {
                let v: serde_json::Value = serde_json::from_str(&body).unwrap();
                assert_eq!(v["reason"], "invalid_credentials");
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn login_rejects_missing_field() {
        let (admin, rl, ss, ds) = fixtures();
        let body = serde_json::json!({"user":"admin"}).to_string();
        let outcome = authenticate(&body, &admin, &rl, &ss, &ds, "127.0.0.1", "ua", 1800);
        assert!(matches!(outcome, LoginOutcome::BadRequest { .. }));
    }

    #[test]
    fn login_rejects_invalid_json() {
        let (admin, rl, ss, ds) = fixtures();
        let outcome = authenticate("not json", &admin, &rl, &ss, &ds, "127.0.0.1", "ua", 1800);
        match outcome {
            LoginOutcome::BadRequest { body } => {
                let v: serde_json::Value = serde_json::from_str(&body).unwrap();
                assert_eq!(v["reason"], "invalid_json");
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn login_rate_limited_per_ip_after_threshold() {
        let (admin, rl, ss, ds) = fixtures();
        let bad = serde_json::json!({"user":"admin","password":"wrong"}).to_string();
        // Default config: ip_max_attempts = 5. Drive past it.
        for _ in 0..5 {
            let _ = authenticate(&bad, &admin, &rl, &ss, &ds, "10.0.0.1", "ua", 1800);
        }
        let next =
            authenticate(&bad, &admin, &rl, &ss, &ds, "10.0.0.1", "ua", 1800);
        match next {
            LoginOutcome::RateLimited {
                retry_after_seconds,
                body,
            } => {
                assert!(retry_after_seconds > 0);
                let v: serde_json::Value = serde_json::from_str(&body).unwrap();
                assert_eq!(v["reason"], "rate_limited");
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn login_lockout_after_user_threshold() {
        let (admin, rl, ss, ds) = fixtures();
        let bad = serde_json::json!({"user":"admin","password":"wrong"}).to_string();
        // Default lockout_threshold = 10. 10 wrong attempts trip it.
        // Spread across IPs so the per-IP limiter doesn't fire first.
        for i in 0..10 {
            let ip = format!("10.0.0.{i}");
            let _ = authenticate(&bad, &admin, &rl, &ss, &ds, &ip, "ua", 1800);
        }
        let next = authenticate(&bad, &admin, &rl, &ss, &ds, "10.0.0.99", "ua", 1800);
        match next {
            LoginOutcome::RateLimited { body, .. } => {
                let v: serde_json::Value = serde_json::from_str(&body).unwrap();
                assert_eq!(v["reason"], "locked_out");
            }
            other => panic!("expected lockout, got {other:?}"),
        }
    }

    #[test]
    fn login_success_clears_failure_counters() {
        let (admin, rl, ss, ds) = fixtures();
        let bad = serde_json::json!({"user":"admin","password":"wrong"}).to_string();
        for _ in 0..3 {
            let _ = authenticate(&bad, &admin, &rl, &ss, &ds, "10.0.0.5", "ua", 1800);
        }
        // Successful login MUST clear the prior failure counter so a
        // legitimate user isn't punished after fat-fingering twice.
        let outcome = authenticate(&ok_body(), &admin, &rl, &ss, &ds, "10.0.0.5", "ua", 1800);
        assert!(matches!(outcome, LoginOutcome::Ok { .. }));
        // Now drive 5 wrong attempts in a row from the same IP — the
        // limit must not fire on attempt 1 or 2 since the counter
        // was reset.
        for _ in 0..3 {
            let r = authenticate(&bad, &admin, &rl, &ss, &ds, "10.0.0.5", "ua", 1800);
            assert!(
                !matches!(r, LoginOutcome::RateLimited { .. }),
                "limit fired too early after success-reset"
            );
        }
    }

    #[test]
    fn logout_revokes_session_when_cookie_valid() {
        let (admin, rl, ss, ds) = fixtures();
        let outcome = authenticate(&ok_body(), &admin, &rl, &ss, &ds, "127.0.0.1", "ua", 1800);
        let session_value = match outcome {
            LoginOutcome::Ok { session_cookie, .. } => {
                // Extract the value between "aegis_session=" and ";"
                session_cookie
                    .strip_prefix("aegis_session=")
                    .and_then(|rest| rest.split(';').next())
                    .unwrap()
                    .to_string()
            }
            other => panic!("expected Ok, got {other:?}"),
        };
        assert_eq!(ss.active_count(), 1);
        let logout_outcome = logout(Some(&session_value), &ss, &ds);
        match logout_outcome {
            LogoutOutcome::Ok {
                clear_session_cookie,
                clear_csrf_cookie,
            } => {
                assert!(clear_session_cookie.contains("Max-Age=0"));
                assert!(clear_csrf_cookie.contains("Max-Age=0"));
            }
            other => panic!("expected Ok, got {other:?}"),
        }
        assert_eq!(ss.active_count(), 0, "session must be revoked");
    }

    #[test]
    fn logout_is_idempotent_without_cookie() {
        let (_, _, ss, ds) = fixtures();
        let outcome = logout(None, &ss, &ds);
        assert!(matches!(outcome, LogoutOutcome::NoSession { .. }));
    }

    #[test]
    fn derive_session_key_is_deterministic() {
        let a = derive_session_key("test-secret");
        let b = derive_session_key("test-secret");
        assert_eq!(a, b);
        let c = derive_session_key("other-secret");
        assert_ne!(a, c);
    }

    // ---- F-CRITICAL-003 — TOTP-enabled flow ----

    /// 32-byte all-zero secret, base32-encoded (RFC 4648, no
    /// padding). Decodes back to 32 zero bytes for the `verify`
    /// step. Picked because all-zeros is the simplest secret
    /// that survives round-trip through real base32.
    const TEST_TOTP_SECRET_B32: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn totp_admin() -> AdminIdentity {
        AdminIdentity {
            user: "admin".into(),
            password_hash: hash_password("aegis-test-1234").unwrap(),
            totp_secret_b32: TEST_TOTP_SECRET_B32.into(),
            totp_enabled: true,
        }
    }

    fn current_totp_code(secret_b32: &str) -> String {
        let secret = base32::decode(
            base32::Alphabet::Rfc4648 { padding: false },
            secret_b32,
        )
        .expect("test secret must decode");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        crate::admin_auth::totp::generate(
            &secret,
            now,
            &crate::admin_auth::totp::TotpConfig::default(),
        )
    }

    #[test]
    fn login_with_totp_enabled_requires_a_code() {
        let (_, rl, ss, ds) = fixtures();
        let admin = totp_admin();
        let body = serde_json::json!({
            "user":"admin","password":"aegis-test-1234"
        }).to_string();
        let outcome = authenticate(&body, &admin, &rl, &ss, &ds, "127.0.0.1", "ua", 1800);
        assert!(
            matches!(outcome, LoginOutcome::Unauthorized { .. }),
            "missing totp_code with totp_enabled must reject",
        );
    }

    #[test]
    fn login_with_totp_enabled_rejects_wrong_code() {
        let (_, rl, ss, ds) = fixtures();
        let admin = totp_admin();
        let body = serde_json::json!({
            "user":"admin","password":"aegis-test-1234","totp_code":"000001"
        }).to_string();
        let outcome = authenticate(&body, &admin, &rl, &ss, &ds, "127.0.0.1", "ua", 1800);
        assert!(
            matches!(outcome, LoginOutcome::Unauthorized { .. }),
            "wrong totp_code must reject",
        );
    }

    #[test]
    fn login_with_totp_enabled_accepts_current_code() {
        let (_, rl, ss, ds) = fixtures();
        let admin = totp_admin();
        let code = current_totp_code(&admin.totp_secret_b32);
        let body = serde_json::json!({
            "user":"admin",
            "password":"aegis-test-1234",
            "totp_code": code,
        }).to_string();
        let outcome = authenticate(&body, &admin, &rl, &ss, &ds, "127.0.0.1", "ua", 1800);
        match outcome {
            LoginOutcome::Ok { .. } => {}
            other => panic!("expected Ok with valid TOTP code, got {other:?}"),
        }
    }

    #[test]
    fn login_with_totp_disabled_ignores_totp_code() {
        // TOTP disabled — extra `totp_code` field is harmless.
        let (admin, rl, ss, ds) = fixtures();
        assert!(!admin.totp_enabled);
        let body = serde_json::json!({
            "user":"admin",
            "password":"aegis-test-1234",
            "totp_code":"000000",
        }).to_string();
        let outcome = authenticate(&body, &admin, &rl, &ss, &ds, "127.0.0.1", "ua", 1800);
        assert!(matches!(outcome, LoginOutcome::Ok { .. }));
    }

    #[test]
    fn login_with_totp_enabled_and_malformed_b32_secret_rejects_loudly() {
        // Config bug: operator put a non-b32 string in the
        // secret. The user-facing response is the same
        // Unauthorized as any other failure (no info leak); server
        // side a tracing::error! fires for setup-time debugging.
        let (_, rl, ss, ds) = fixtures();
        let admin = AdminIdentity {
            user: "admin".into(),
            password_hash: hash_password("aegis-test-1234").unwrap(),
            totp_secret_b32: "this is not base32!!!".into(),
            totp_enabled: true,
        };
        let body = serde_json::json!({
            "user":"admin",
            "password":"aegis-test-1234",
            "totp_code":"123456",
        }).to_string();
        let outcome = authenticate(&body, &admin, &rl, &ss, &ds, "127.0.0.1", "ua", 1800);
        assert!(matches!(outcome, LoginOutcome::Unauthorized { .. }));
    }
}
