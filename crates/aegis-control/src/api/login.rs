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
    /// `user` is the authenticated account name (TOTP-1: multi-account —
    /// the auditor must record WHICH admin logged in, not a hard-coded
    /// `admin`).
    Ok {
        user: String,
        session_cookie: String,
        csrf_cookie: String,
        body: String,
    },
    /// TOTP-2 (TF-1) — password verified but `require_totp` is on and
    /// the account has no enrolled factor. The session issued here is
    /// NOT `totp_verified`; the admin middleware restricts it to the
    /// TOTP enroll/confirm surface until a code from the authenticator
    /// app confirms enrollment. Proxy emits 200 + both cookies with the
    /// `enrollment_required` body so the login page can route to setup.
    EnrollmentRequired {
        user: String,
        session_cookie: String,
        csrf_cookie: String,
        body: String,
    },
    /// Wrong credentials, missing user, or any other "I don't
    /// trust you" path. Body is the documented error envelope.
    Unauthorized { body: String },
    /// Per-IP or per-user rate limiter or lockout fired. Body
    /// carries the retry-after seconds; proxy emits 429 +
    /// `Retry-After` header. `locked_out` distinguishes the lockout
    /// path as a typed value (AU-1: the audit bucket must not be
    /// re-parsed out of our own response body).
    RateLimited {
        retry_after_seconds: u64,
        locked_out: bool,
        body: String,
    },
    /// Body wasn't parseable. Proxy emits 400.
    BadRequest { body: String },
    /// R-1 (2026-06-19) — credentials were correct but the session record
    /// could not be persisted to the shared backend (read-only / down Redis).
    /// Proxy emits **503** so the operator sees a clear "try again" instead of
    /// a 200 + a cookie that will never validate (the silent 401 redirect loop
    /// from the Redis-hijack incident).
    StoreUnavailable { body: String },
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
    /// secret. Empty when TOTP is disabled. `authenticate().await`
    /// decodes + verifies via `crate::admin_auth::totp::verify`.
    /// Stored decoded form lives only on the stack; we never log
    /// or audit the raw bytes.
    pub totp_secret_b32: String,
    /// 2026-05-17 F-CRITICAL-003 — operator's TOTP-enabled flag,
    /// mirrored from `cfg.admin.dashboard_auth.totp_enabled` so
    /// `authenticate().await` doesn't need to take the full config.
    pub totp_enabled: bool,
    /// 2026-05-17 F-HIGH-admin — replay-protection guard for
    /// TOTP. `Arc` so the admin identity stays Clone (the proxy
    /// wraps it in an Arc<AdminIdentity> for the long-lived boot
    /// context). Single guard per identity = single guard per
    /// admin user, which matches the contract semantics (per-
    /// principal counter monotonicity). Tests build fresh
    /// guards via `AdminIdentity::default()` so consumption
    /// doesn't leak across test functions.
    pub totp_replay_guard: std::sync::Arc<crate::admin_auth::totp::TotpReplayGuard>,
}

/// TOTP-1 (TF-4) — the set of named admin accounts the login handler
/// resolves against. Replaces the single hard-coded `AdminIdentity` in
/// the auth runtime; each account keeps its own password hash, TOTP
/// state, and replay guard. All accounts are equal-privilege (no RBAC —
/// `plans/issues/FEAT-totp-google-authenticator-2026-07.md`).
#[derive(Clone, Debug, Default)]
pub struct AdminDirectory {
    accounts: Vec<std::sync::Arc<AdminIdentity>>,
    /// TOTP-2 (TF-1) — global enforcement policy: when `true` a correct
    /// password on an un-enrolled account yields an enrollment-only
    /// session, never a full one. `new()`/`single()`/`default()` leave
    /// it `false` (test/legacy shorthand); production boots read the
    /// config default (`true`) via [`AdminDirectory::from_config`].
    require_totp: bool,
    /// TOTP-3 (TF-1a) — runtime enrollment overlay. When wired, an
    /// account's effective TOTP state is the store's confirmed factor
    /// (if any) over the YAML-configured one — web enrollment without a
    /// YAML edit, fleet-wide on a shared backend.
    totp_store: Option<std::sync::Arc<crate::admin_auth::totp_store::TotpEnrollmentStore>>,
}

impl AdminDirectory {
    pub fn new(accounts: Vec<std::sync::Arc<AdminIdentity>>) -> Self {
        Self { accounts, require_totp: false, totp_store: None }
    }

    /// Wrap one identity — the single-admin shorthand (tests + legacy
    /// boot paths).
    pub fn single(identity: AdminIdentity) -> Self {
        Self {
            accounts: vec![std::sync::Arc::new(identity)],
            require_totp: false,
            totp_store: None,
        }
    }

    /// Wire the TOTP-3 runtime enrollment overlay (builder-style).
    pub fn with_totp_store(
        mut self,
        store: std::sync::Arc<crate::admin_auth::totp_store::TotpEnrollmentStore>,
    ) -> Self {
        self.totp_store = Some(store);
        self
    }

    /// The account's effective `(totp_enabled, secret_b32)`: the runtime
    /// store's confirmed factor wins over the YAML bootstrap state. An
    /// enrolled factor is honoured even under `require_totp: false` —
    /// enrollment is a promise to that operator, not something the
    /// global policy silently disables.
    pub async fn effective_totp(&self, account: &AdminIdentity) -> (bool, String) {
        if let Some(store) = &self.totp_store {
            if let Some(active) = store.active(&account.user).await {
                if active.enabled {
                    return (true, active.secret_b32);
                }
            }
        }
        (account.totp_enabled, account.totp_secret_b32.clone())
    }

    /// Set the TF-1 enforcement policy (builder-style, used by tests
    /// and `from_config`).
    pub fn with_require_totp(mut self, require_totp: bool) -> Self {
        self.require_totp = require_totp;
        self
    }

    pub fn require_totp(&self) -> bool {
        self.require_totp
    }

    /// Build from the YAML account set (legacy fields already folded in
    /// by [`aegis_core::config::DashboardAuthConfig::effective_accounts`]).
    /// One fresh replay guard per account — counter monotonicity is a
    /// per-principal contract.
    pub fn from_config(auth: &aegis_core::config::DashboardAuthConfig) -> Self {
        let accounts = auth
            .effective_accounts()
            .into_iter()
            .map(|a| {
                std::sync::Arc::new(AdminIdentity {
                    user: a.username,
                    password_hash: a.password_hash_ref,
                    totp_secret_b32: a.totp_secret_b32,
                    totp_enabled: a.totp_enabled,
                    ..AdminIdentity::default()
                })
            })
            .collect();
        Self {
            accounts,
            require_totp: auth.require_totp,
            totp_store: None,
        }
    }

    /// Resolve a submitted username. Scans the WHOLE set with a
    /// constant-time per-name compare (no early exit) so response time
    /// doesn't leak how much of a username prefix matched; the miss path
    /// then runs `dummy_verify` in `authenticate` exactly like before.
    pub fn resolve(&self, user: &str) -> Option<&std::sync::Arc<AdminIdentity>> {
        let mut found: Option<&std::sync::Arc<AdminIdentity>> = None;
        for account in &self.accounts {
            if ct_eq_names(&account.user, user) {
                found = Some(account);
            }
        }
        found
    }

    pub fn accounts(&self) -> &[std::sync::Arc<AdminIdentity>] {
        &self.accounts
    }

    /// True when at least one account has a password hash — i.e. login
    /// is reachable at all (drain-token fallback logic keys off this).
    pub fn login_enabled(&self) -> bool {
        self.accounts.iter().any(|a| !a.password_hash.trim().is_empty())
    }
}

/// Branch-free equal-length compare, same shape as `totp::ct_eq_str` —
/// usernames aren't secret, but the resolve scan must not leak match
/// position via timing.
fn ct_eq_names(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
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
pub async fn authenticate(
    body: &str,
    directory: &AdminDirectory,
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
                locked_out: true,
                body: error_body(
                    "locked_out",
                    "account temporarily locked after repeated failures",
                ),
            };
        }
        RateOutcome::RateLimited { retry_after } => {
            return LoginOutcome::RateLimited {
                retry_after_seconds: retry_after.as_secs(),
                locked_out: false,
                body: error_body("rate_limited", "too many login attempts"),
            };
        }
    }

    // 2. Resolve the account (TOTP-1: N named admins) and verify the
    //    password. Unknown-user path runs dummy_verify so response time
    //    doesn't leak account existence — same property as the old
    //    single-admin compare, now per directory entry.
    let admin = match directory.resolve(&req.user) {
        Some(account) => account,
        None => {
            dummy_verify(&req.password);
            rate_limiter.record_failure(ip, &req.user);
            return LoginOutcome::Unauthorized {
                body: error_body("invalid_credentials", "user or password incorrect"),
            };
        }
    };

    if !verify_password(&admin.password_hash, &req.password) {
        rate_limiter.record_failure(ip, &req.user);
        return LoginOutcome::Unauthorized {
            body: error_body("invalid_credentials", "user or password incorrect"),
        };
    }

    // 2a. TOTP-2 (TF-1) — enforcement. Password verified, but the policy
    //     says a password alone never grants admin access and this
    //     account has no enrolled factor: issue an ENROLLMENT-ONLY
    //     session (totp_verified=false — the middleware restricts it to
    //     POST /api/admin/totp/enroll|confirm) instead of a full one.
    //     Counts as a rate-limit success: the password WAS right, and a
    //     legitimate first login must not accrue failure strikes.
    // Effective TOTP state: the runtime enrollment overlay (TOTP-3)
    // wins over the YAML bootstrap fields.
    let (totp_enabled, totp_secret_b32) = directory.effective_totp(admin).await;

    if directory.require_totp() && !totp_enabled {
        rate_limiter.record_success(ip, &req.user);
        let (session_cookie, csrf_cookie) = match issue_session(
            sessions,
            dashboard_sessions,
            &admin.user,
            ip,
            user_agent,
            session_idle_seconds,
            false,
        )
        .await
        {
            Ok(pair) => pair,
            Err(outcome) => return outcome,
        };
        let body = serde_json::json!({
            "ok": true,
            "enrollment_required": true,
            "user": admin.user,
            "message": "TOTP enrollment required: POST /api/admin/totp/enroll, scan the QR \
                        with an authenticator app (Google Authenticator, Authy, …), then \
                        POST /api/admin/totp/confirm with a generated code",
        });
        return LoginOutcome::EnrollmentRequired {
            user: admin.user.clone(),
            session_cookie,
            csrf_cookie,
            body: body.to_string(),
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
    if totp_enabled {
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
            &totp_secret_b32,
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
        // F-HIGH-admin (2026-05-17) — replay protection. Pre-fix
        // a captured TOTP code stayed valid for the entire ±skew
        // window (~90 s with default step=30, skew=1) — a
        // shoulder-surfer or man-in-the-middle could replay it.
        // `verify_and_consume` records the matched counter on the
        // identity's per-principal guard and rejects any
        // subsequent submission of the same or earlier counter.
        if !admin.totp_replay_guard.verify_and_consume(&secret_bytes, code, now_s, &cfg) {
            rate_limiter.record_failure(ip, &req.user);
            return LoginOutcome::Unauthorized {
                body: error_body("invalid_credentials", "user or password incorrect"),
            };
        }
    }

    // 3. Success — issue session + CSRF cookies. The session is bound to
    //    the resolved account (TOTP-1) and marked fully verified: the
    //    auth policy is satisfied (TOTP checked above when enabled; no
    //    second factor demanded otherwise).
    rate_limiter.record_success(ip, &req.user);
    let (session_cookie, csrf_cookie) = match issue_session(
        sessions,
        dashboard_sessions,
        &admin.user,
        ip,
        user_agent,
        session_idle_seconds,
        true,
    )
    .await
    {
        Ok(pair) => pair,
        Err(outcome) => return outcome,
    };

    let body = LoginResponse {
        ok: true,
        user: req.user.clone(),
        session_idle_seconds,
    };
    LoginOutcome::Ok {
        user: admin.user.clone(),
        session_cookie,
        csrf_cookie,
        body: serde_json::to_string(&body).unwrap_or_else(|_| "{}".into()),
    }
}

/// Issue a session + CSRF cookie pair for `user` and mirror the record
/// into the dashboard sessions view. Shared by the full-login and the
/// TOTP-2 enrollment-required paths — the ONLY difference between them
/// is the `totp_verified` flag on the record.
///
/// R-1 (2026-06-19): a failed session-store write (read-only / down
/// shared backend) returns the 503 `StoreUnavailable` outcome rather
/// than handing back a cookie for a session that was never stored (the
/// silent 200→401 lockout from the Redis-hijack incident).
async fn issue_session(
    sessions: &AuthSessionStore,
    dashboard_sessions: &DashboardSessionStore,
    user: &str,
    ip: &str,
    user_agent: &str,
    session_idle_seconds: u64,
    totp_verified: bool,
) -> Result<(String, String), LoginOutcome> {
    let (session_id, signed_session_value) = match sessions
        .create_for_user(user, ip, user_agent, totp_verified)
        .await
    {
        Ok(pair) => pair,
        Err(e) => {
            tracing::error!(error = %e, ip, "admin login: session store write failed — returning 503");
            return Err(LoginOutcome::StoreUnavailable {
                body: error_body(
                    "session_store_unavailable",
                    "session could not be persisted; please retry",
                ),
            });
        }
    };
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
    Ok((session_cookie, csrf_cookie))
}

/// Process a `POST /admin/logout`. Reads the session cookie,
/// revokes the matching record in both stores, and returns
/// cookie-clearing strings the proxy emits as `Set-Cookie`.
/// Idempotent: succeeds whether or not the cookie was present.
pub async fn logout(
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
        if let Some(rec) = sessions.validate(cookie).await {
            sessions.revoke(&rec.id).await;
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
        AdminDirectory,
        Arc<LoginRateLimiter>,
        Arc<AuthSessionStore>,
        Arc<DashboardSessionStore>,
    ) {
        let admin = AdminDirectory::single(AdminIdentity {
            user: "admin".into(),
            password_hash: hash_password("aegis-test-1234").unwrap(),
            ..AdminIdentity::default()
        });
        let rl = Arc::new(LoginRateLimiter::new(Default::default()));
        let key = derive_session_key("test-csrf-secret-32b");
        let sessions = Arc::new(AuthSessionStore::new(key));
        let dashboard = Arc::new(DashboardSessionStore::new());
        (admin, rl, sessions, dashboard)
    }

    fn ok_body() -> String {
        serde_json::json!({"user":"admin","password":"aegis-test-1234"}).to_string()
    }

    // R-1 (2026-06-19) — correct credentials but a read-only/down session
    // backend must yield 503 StoreUnavailable, NOT a 200 + unstored cookie.
    struct FailWritesBackend;
    #[async_trait::async_trait]
    impl aegis_core::state::StateBackend for FailWritesBackend {
        async fn get(&self, _: &str) -> aegis_core::Result<Option<Vec<u8>>> {
            Ok(None)
        }
        async fn set(
            &self,
            _: &str,
            _: &[u8],
            _: std::time::Duration,
        ) -> aegis_core::Result<()> {
            Err(aegis_core::WafError::State("read only replica".into()))
        }
        async fn del(&self, _: &str) -> aegis_core::Result<()> {
            Ok(())
        }
        async fn incr_window(
            &self,
            _: &str,
            _: std::time::Duration,
            _: u64,
        ) -> aegis_core::Result<aegis_core::state::SlidingWindowResult> {
            Ok(aegis_core::state::SlidingWindowResult { count: 0, allowed: true, retry_after: None })
        }
        async fn token_bucket(&self, _: &str, _: u32, _: u32) -> aegis_core::Result<bool> {
            Ok(true)
        }
        async fn get_risk(&self, _: &aegis_core::RiskKey) -> aegis_core::Result<u32> {
            Ok(0)
        }
        async fn add_risk(&self, _: &aegis_core::RiskKey, _: i32, _: u32) -> aegis_core::Result<u32> {
            Ok(0)
        }
        async fn auto_block(
            &self,
            _: std::net::IpAddr,
            _: std::time::Duration,
        ) -> aegis_core::Result<()> {
            Ok(())
        }
        async fn is_auto_blocked(&self, _: std::net::IpAddr) -> aegis_core::Result<bool> {
            Ok(false)
        }
        async fn put_nonce(&self, _: &str, _: std::time::Duration) -> aegis_core::Result<bool> {
            Ok(true)
        }
        async fn consume_nonce(&self, _: &str) -> aegis_core::Result<bool> {
            Ok(true)
        }
    }

    #[tokio::test]
    async fn login_with_read_only_backend_returns_store_unavailable() {
        let (admin, rl, _ss, ds) = fixtures();
        let key = derive_session_key("test-csrf-secret-32b");
        let sessions = Arc::new(AuthSessionStore::with_backend(
            key,
            Arc::new(FailWritesBackend),
            chrono::Duration::minutes(30),
            chrono::Duration::hours(8),
        ));
        let outcome =
            authenticate(&ok_body(), &admin, &rl, &sessions, &ds, "127.0.0.1", "ua", 1800).await;
        assert!(
            matches!(outcome, LoginOutcome::StoreUnavailable { .. }),
            "read-only session backend must 503, not issue an unstored cookie: {outcome:?}",
        );
    }

    #[tokio::test]
    async fn login_with_correct_creds_issues_session_and_csrf_cookies() {
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
        ).await;
        let (session, csrf, body) = match outcome {
            LoginOutcome::Ok { session_cookie, csrf_cookie, body, .. } => {
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

    #[tokio::test]
    async fn login_with_wrong_password_returns_unauthorized() {
        let (admin, rl, ss, ds) = fixtures();
        let body = serde_json::json!({"user":"admin","password":"wrong"}).to_string();
        let outcome = authenticate(&body, &admin, &rl, &ss, &ds, "127.0.0.1", "ua", 1800).await;
        match outcome {
            LoginOutcome::Unauthorized { body } => {
                let v: serde_json::Value = serde_json::from_str(&body).unwrap();
                assert_eq!(v["reason"], "invalid_credentials");
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
        assert_eq!(ss.active_count().await, 0, "no session created on failure");
    }

    #[tokio::test]
    async fn login_with_unknown_user_does_not_leak_existence() {
        let (admin, rl, ss, ds) = fixtures();
        let body = serde_json::json!({"user":"ghost","password":"whatever"}).to_string();
        let outcome = authenticate(&body, &admin, &rl, &ss, &ds, "127.0.0.1", "ua", 1800).await;
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

    #[tokio::test]
    async fn login_rejects_missing_field() {
        let (admin, rl, ss, ds) = fixtures();
        let body = serde_json::json!({"user":"admin"}).to_string();
        let outcome = authenticate(&body, &admin, &rl, &ss, &ds, "127.0.0.1", "ua", 1800).await;
        assert!(matches!(outcome, LoginOutcome::BadRequest { .. }));
    }

    #[tokio::test]
    async fn login_rejects_invalid_json() {
        let (admin, rl, ss, ds) = fixtures();
        let outcome = authenticate("not json", &admin, &rl, &ss, &ds, "127.0.0.1", "ua", 1800).await;
        match outcome {
            LoginOutcome::BadRequest { body } => {
                let v: serde_json::Value = serde_json::from_str(&body).unwrap();
                assert_eq!(v["reason"], "invalid_json");
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn login_rate_limited_per_ip_after_threshold() {
        let (admin, rl, ss, ds) = fixtures();
        let bad = serde_json::json!({"user":"admin","password":"wrong"}).to_string();
        // Default config: ip_max_attempts = 5. Drive past it.
        for _ in 0..5 {
            let _ = authenticate(&bad, &admin, &rl, &ss, &ds, "10.0.0.1", "ua", 1800).await;
        }
        let next =
            authenticate(&bad, &admin, &rl, &ss, &ds, "10.0.0.1", "ua", 1800).await;
        match next {
            LoginOutcome::RateLimited {
                retry_after_seconds,
                locked_out,
                body,
            } => {
                assert!(retry_after_seconds > 0);
                assert!(!locked_out, "per-IP limit is not a lockout");
                let v: serde_json::Value = serde_json::from_str(&body).unwrap();
                assert_eq!(v["reason"], "rate_limited");
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn login_lockout_after_user_threshold() {
        let (admin, rl, ss, ds) = fixtures();
        let bad = serde_json::json!({"user":"admin","password":"wrong"}).to_string();
        // Default lockout_threshold = 10. 10 wrong attempts trip it.
        // Spread across IPs so the per-IP limiter doesn't fire first.
        for i in 0..10 {
            let ip = format!("10.0.0.{i}");
            let _ = authenticate(&bad, &admin, &rl, &ss, &ds, &ip, "ua", 1800).await;
        }
        let next = authenticate(&bad, &admin, &rl, &ss, &ds, "10.0.0.99", "ua", 1800).await;
        match next {
            LoginOutcome::RateLimited { body, .. } => {
                let v: serde_json::Value = serde_json::from_str(&body).unwrap();
                assert_eq!(v["reason"], "locked_out");
            }
            other => panic!("expected lockout, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn login_success_clears_failure_counters() {
        let (admin, rl, ss, ds) = fixtures();
        let bad = serde_json::json!({"user":"admin","password":"wrong"}).to_string();
        for _ in 0..3 {
            let _ = authenticate(&bad, &admin, &rl, &ss, &ds, "10.0.0.5", "ua", 1800).await;
        }
        // Successful login MUST clear the prior failure counter so a
        // legitimate user isn't punished after fat-fingering twice.
        let outcome = authenticate(&ok_body(), &admin, &rl, &ss, &ds, "10.0.0.5", "ua", 1800).await;
        assert!(matches!(outcome, LoginOutcome::Ok { .. }));
        // Now drive 5 wrong attempts in a row from the same IP — the
        // limit must not fire on attempt 1 or 2 since the counter
        // was reset.
        for _ in 0..3 {
            let r = authenticate(&bad, &admin, &rl, &ss, &ds, "10.0.0.5", "ua", 1800).await;
            assert!(
                !matches!(r, LoginOutcome::RateLimited { .. }),
                "limit fired too early after success-reset"
            );
        }
    }

    #[tokio::test]
    async fn logout_revokes_session_when_cookie_valid() {
        let (admin, rl, ss, ds) = fixtures();
        let outcome = authenticate(&ok_body(), &admin, &rl, &ss, &ds, "127.0.0.1", "ua", 1800).await;
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
        assert_eq!(ss.active_count().await, 1);
        let logout_outcome = logout(Some(&session_value), &ss, &ds).await;
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
        assert_eq!(ss.active_count().await, 0, "session must be revoked");
    }

    #[tokio::test]
    async fn logout_is_idempotent_without_cookie() {
        let (_, _, ss, ds) = fixtures();
        let outcome = logout(None, &ss, &ds).await;
        assert!(matches!(outcome, LogoutOutcome::NoSession { .. }));
    }

    #[tokio::test]
    async fn derive_session_key_is_deterministic() {
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

    fn totp_admin() -> AdminDirectory {
        AdminDirectory::single(AdminIdentity {
            user: "admin".into(),
            password_hash: hash_password("aegis-test-1234").unwrap(),
            totp_secret_b32: TEST_TOTP_SECRET_B32.into(),
            totp_enabled: true,
            ..AdminIdentity::default()
        })
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

    #[tokio::test]
    async fn login_with_totp_enabled_requires_a_code() {
        let (_, rl, ss, ds) = fixtures();
        let admin = totp_admin();
        let body = serde_json::json!({
            "user":"admin","password":"aegis-test-1234"
        }).to_string();
        let outcome = authenticate(&body, &admin, &rl, &ss, &ds, "127.0.0.1", "ua", 1800).await;
        assert!(
            matches!(outcome, LoginOutcome::Unauthorized { .. }),
            "missing totp_code with totp_enabled must reject",
        );
    }

    #[tokio::test]
    async fn login_with_totp_enabled_rejects_wrong_code() {
        let (_, rl, ss, ds) = fixtures();
        let admin = totp_admin();
        let body = serde_json::json!({
            "user":"admin","password":"aegis-test-1234","totp_code":"000001"
        }).to_string();
        let outcome = authenticate(&body, &admin, &rl, &ss, &ds, "127.0.0.1", "ua", 1800).await;
        assert!(
            matches!(outcome, LoginOutcome::Unauthorized { .. }),
            "wrong totp_code must reject",
        );
    }

    #[tokio::test]
    async fn login_with_totp_enabled_accepts_current_code() {
        let (_, rl, ss, ds) = fixtures();
        let admin = totp_admin();
        let code = current_totp_code(&admin.accounts()[0].totp_secret_b32);
        let body = serde_json::json!({
            "user":"admin",
            "password":"aegis-test-1234",
            "totp_code": code,
        }).to_string();
        let outcome = authenticate(&body, &admin, &rl, &ss, &ds, "127.0.0.1", "ua", 1800).await;
        match outcome {
            LoginOutcome::Ok { .. } => {}
            other => panic!("expected Ok with valid TOTP code, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn login_with_totp_disabled_ignores_totp_code() {
        // TOTP disabled — extra `totp_code` field is harmless.
        let (admin, rl, ss, ds) = fixtures();
        assert!(!admin.accounts()[0].totp_enabled);
        let body = serde_json::json!({
            "user":"admin",
            "password":"aegis-test-1234",
            "totp_code":"000000",
        }).to_string();
        let outcome = authenticate(&body, &admin, &rl, &ss, &ds, "127.0.0.1", "ua", 1800).await;
        assert!(matches!(outcome, LoginOutcome::Ok { .. }));
    }

    #[tokio::test]
    async fn login_with_totp_enabled_and_malformed_b32_secret_rejects_loudly() {
        // Config bug: operator put a non-b32 string in the
        // secret. The user-facing response is the same
        // Unauthorized as any other failure (no info leak); server
        // side a tracing::error! fires for setup-time debugging.
        let (_, rl, ss, ds) = fixtures();
        let admin = AdminDirectory::single(AdminIdentity {
            user: "admin".into(),
            password_hash: hash_password("aegis-test-1234").unwrap(),
            totp_secret_b32: "this is not base32!!!".into(),
            totp_enabled: true,
            ..AdminIdentity::default()
        });
        let body = serde_json::json!({
            "user":"admin",
            "password":"aegis-test-1234",
            "totp_code":"123456",
        }).to_string();
        let outcome = authenticate(&body, &admin, &rl, &ss, &ds, "127.0.0.1", "ua", 1800).await;
        assert!(matches!(outcome, LoginOutcome::Unauthorized { .. }));
    }

    // ---- TOTP-1 (TF-4) — multiple admin accounts ------------------------
    //
    // plans/issues/FEAT-totp-google-authenticator-2026-07.md — each admin
    // authenticates against its OWN password + TOTP state; unknown users
    // keep the dummy_verify no-leak property; lockout counters partition
    // per (ip, user) so locking alice never locks bob.

    fn two_account_directory() -> AdminDirectory {
        AdminDirectory::new(vec![
            Arc::new(AdminIdentity {
                user: "alice".into(),
                password_hash: hash_password("alice-pw-1234").unwrap(),
                ..AdminIdentity::default()
            }),
            Arc::new(AdminIdentity {
                user: "bob".into(),
                password_hash: hash_password("bob-pw-5678").unwrap(),
                totp_secret_b32: TEST_TOTP_SECRET_B32.into(),
                totp_enabled: true,
                ..AdminIdentity::default()
            }),
        ])
    }

    fn login_body(user: &str, password: &str) -> String {
        serde_json::json!({"user": user, "password": password}).to_string()
    }

    #[tokio::test]
    async fn each_account_logs_in_with_own_password() {
        let (_, rl, ss, ds) = fixtures();
        let dir = two_account_directory();
        let outcome = authenticate(
            &login_body("alice", "alice-pw-1234"),
            &dir, &rl, &ss, &ds, "127.0.0.1", "ua", 1800,
        ).await;
        assert!(matches!(outcome, LoginOutcome::Ok { .. }), "alice: {outcome:?}");

        // bob has TOTP enrolled — password + current code required.
        let code = current_totp_code(TEST_TOTP_SECRET_B32);
        let body = serde_json::json!({
            "user": "bob", "password": "bob-pw-5678", "totp_code": code,
        }).to_string();
        let outcome = authenticate(&body, &dir, &rl, &ss, &ds, "127.0.0.1", "ua", 1800).await;
        assert!(matches!(outcome, LoginOutcome::Ok { .. }), "bob: {outcome:?}");
    }

    #[tokio::test]
    async fn cross_account_password_is_rejected() {
        let (_, rl, ss, ds) = fixtures();
        let dir = two_account_directory();
        // alice's password against bob's account must never admit.
        let outcome = authenticate(
            &login_body("bob", "alice-pw-1234"),
            &dir, &rl, &ss, &ds, "127.0.0.1", "ua", 1800,
        ).await;
        assert!(matches!(outcome, LoginOutcome::Unauthorized { .. }));
    }

    #[tokio::test]
    async fn per_account_totp_only_where_enrolled() {
        let (_, rl, ss, ds) = fixtures();
        let dir = two_account_directory();
        // bob (enrolled) without a code → rejected.
        let outcome = authenticate(
            &login_body("bob", "bob-pw-5678"),
            &dir, &rl, &ss, &ds, "127.0.0.1", "ua", 1800,
        ).await;
        assert!(
            matches!(outcome, LoginOutcome::Unauthorized { .. }),
            "bob without TOTP code must reject: {outcome:?}",
        );
        // alice (not enrolled) logs in without any code.
        let outcome = authenticate(
            &login_body("alice", "alice-pw-1234"),
            &dir, &rl, &ss, &ds, "10.0.0.2", "ua", 1800,
        ).await;
        assert!(matches!(outcome, LoginOutcome::Ok { .. }));
    }

    #[tokio::test]
    async fn unknown_user_in_directory_does_not_leak_existence() {
        let (_, rl, ss, ds) = fixtures();
        let dir = two_account_directory();
        let outcome = authenticate(
            &login_body("ghost", "whatever-pw"),
            &dir, &rl, &ss, &ds, "127.0.0.1", "ua", 1800,
        ).await;
        match outcome {
            LoginOutcome::Unauthorized { body } => {
                let v: serde_json::Value = serde_json::from_str(&body).unwrap();
                assert_eq!(v["reason"], "invalid_credentials");
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn lockout_on_one_account_does_not_lock_the_other() {
        let (_, rl, ss, ds) = fixtures();
        let dir = two_account_directory();
        // Default lockout_threshold = 10; spread across IPs so the
        // per-IP limiter doesn't fire first (mirrors
        // login_lockout_after_user_threshold above).
        for i in 0..10 {
            let ip = format!("10.1.0.{i}");
            let _ = authenticate(
                &login_body("alice", "wrong-pw"),
                &dir, &rl, &ss, &ds, &ip, "ua", 1800,
            ).await;
        }
        let alice_next = authenticate(
            &login_body("alice", "alice-pw-1234"),
            &dir, &rl, &ss, &ds, "10.1.0.99", "ua", 1800,
        ).await;
        assert!(
            matches!(alice_next, LoginOutcome::RateLimited { locked_out: true, .. }),
            "alice must be locked out: {alice_next:?}",
        );
        // bob is untouched.
        let code = current_totp_code(TEST_TOTP_SECRET_B32);
        let body = serde_json::json!({
            "user": "bob", "password": "bob-pw-5678", "totp_code": code,
        }).to_string();
        let bob = authenticate(&body, &dir, &rl, &ss, &ds, "10.1.0.100", "ua", 1800).await;
        assert!(
            matches!(bob, LoginOutcome::Ok { .. }),
            "lockout on alice must not lock bob: {bob:?}",
        );
    }

    #[tokio::test]
    async fn session_record_carries_the_authenticated_username() {
        let (_, rl, ss, ds) = fixtures();
        let dir = two_account_directory();
        let outcome = authenticate(
            &login_body("alice", "alice-pw-1234"),
            &dir, &rl, &ss, &ds, "127.0.0.1", "ua", 1800,
        ).await;
        let session_value = match outcome {
            LoginOutcome::Ok { session_cookie, .. } => session_cookie
                .strip_prefix("aegis_session=")
                .and_then(|rest| rest.split(';').next())
                .unwrap()
                .to_string(),
            other => panic!("expected Ok, got {other:?}"),
        };
        let record = ss.validate(&session_value).await.expect("session must validate");
        assert_eq!(record.user, "alice", "audit identity must be per-account");
    }

    // ---- TOTP-2 (TF-1) — require_totp enforcement -----------------------
    //
    // A password alone must never grant admin access. With enforcement on
    // (the production config default) an un-enrolled account's correct
    // password yields an ENROLLMENT-ONLY session (totp_verified=false —
    // the middleware restricts it to the TOTP enroll/confirm surface),
    // never a full session.

    fn cookie_value(cookie: &str) -> String {
        cookie
            .strip_prefix("aegis_session=")
            .and_then(|rest| rest.split(';').next())
            .unwrap()
            .to_string()
    }

    fn enforced_unenrolled_directory() -> AdminDirectory {
        AdminDirectory::new(vec![Arc::new(AdminIdentity {
            user: "alice".into(),
            password_hash: hash_password("alice-pw-1234").unwrap(),
            ..AdminIdentity::default()
        })])
        .with_require_totp(true)
    }

    #[tokio::test]
    async fn require_totp_password_only_login_yields_enrollment_only_session() {
        let (_, rl, ss, ds) = fixtures();
        let dir = enforced_unenrolled_directory();
        let outcome = authenticate(
            &login_body("alice", "alice-pw-1234"),
            &dir, &rl, &ss, &ds, "127.0.0.1", "ua", 1800,
        ).await;
        let (session_cookie, body) = match outcome {
            LoginOutcome::EnrollmentRequired { session_cookie, body, .. } => {
                (session_cookie, body)
            }
            other => panic!("expected EnrollmentRequired, got {other:?}"),
        };
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["enrollment_required"], true);
        assert_eq!(v["user"], "alice");
        // The session exists but is NOT second-factor verified — the
        // middleware keys the enrollment-only restriction off this flag.
        let record = ss
            .validate(&cookie_value(&session_cookie))
            .await
            .expect("enrollment session must validate");
        assert!(!record.totp_verified, "enrollment session must not be totp_verified");
        assert_eq!(record.user, "alice");
    }

    #[tokio::test]
    async fn require_totp_wrong_password_still_unauthorized_not_enrollment() {
        // Enforcement must not turn a WRONG password into an enrollment
        // session — password verification stays the first gate.
        let (_, rl, ss, ds) = fixtures();
        let dir = enforced_unenrolled_directory();
        let outcome = authenticate(
            &login_body("alice", "wrong-pw"),
            &dir, &rl, &ss, &ds, "127.0.0.1", "ua", 1800,
        ).await;
        assert!(matches!(outcome, LoginOutcome::Unauthorized { .. }));
    }

    #[tokio::test]
    async fn require_totp_enrolled_account_stays_strict_and_fully_verified() {
        let (_, rl, ss, ds) = fixtures();
        let dir = AdminDirectory::new(vec![Arc::new(AdminIdentity {
            user: "bob".into(),
            password_hash: hash_password("bob-pw-5678").unwrap(),
            totp_secret_b32: TEST_TOTP_SECRET_B32.into(),
            totp_enabled: true,
            ..AdminIdentity::default()
        })])
        .with_require_totp(true);
        // Without a code → plain Unauthorized (never enrollment — the
        // account IS enrolled).
        let outcome = authenticate(
            &login_body("bob", "bob-pw-5678"),
            &dir, &rl, &ss, &ds, "127.0.0.1", "ua", 1800,
        ).await;
        assert!(matches!(outcome, LoginOutcome::Unauthorized { .. }));
        // With the app code → full, totp_verified session.
        let code = current_totp_code(TEST_TOTP_SECRET_B32);
        let body = serde_json::json!({
            "user": "bob", "password": "bob-pw-5678", "totp_code": code,
        }).to_string();
        let outcome = authenticate(&body, &dir, &rl, &ss, &ds, "10.0.0.3", "ua", 1800).await;
        let session_cookie = match outcome {
            LoginOutcome::Ok { session_cookie, .. } => session_cookie,
            other => panic!("expected Ok, got {other:?}"),
        };
        let record = ss
            .validate(&cookie_value(&session_cookie))
            .await
            .expect("session must validate");
        assert!(record.totp_verified, "full login must be second-factor verified");
    }

    #[tokio::test]
    async fn require_totp_false_preserves_password_only_login() {
        // Explicit opt-out (dev/CI) — today's behaviour, fully verified
        // session (the policy is satisfied because there is no policy).
        let (_, rl, ss, ds) = fixtures();
        let dir = AdminDirectory::new(vec![Arc::new(AdminIdentity {
            user: "alice".into(),
            password_hash: hash_password("alice-pw-1234").unwrap(),
            ..AdminIdentity::default()
        })])
        .with_require_totp(false);
        let outcome = authenticate(
            &login_body("alice", "alice-pw-1234"),
            &dir, &rl, &ss, &ds, "127.0.0.1", "ua", 1800,
        ).await;
        let session_cookie = match outcome {
            LoginOutcome::Ok { session_cookie, .. } => session_cookie,
            other => panic!("expected Ok, got {other:?}"),
        };
        let record = ss
            .validate(&cookie_value(&session_cookie))
            .await
            .expect("session must validate");
        assert!(
            record.totp_verified,
            "opt-out sessions must be fully admitted (not enrollment-locked)",
        );
    }
}
