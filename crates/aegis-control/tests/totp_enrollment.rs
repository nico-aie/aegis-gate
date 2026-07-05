//! TOTP-3 (TF-1a) — Google Authenticator enrollment end to end.
//! plans/issues/FEAT-totp-google-authenticator-2026-07.md
//!
//! RED-first reproducers for:
//! - `POST /api/admin/totp/enroll` payload: a GA-parseable `otpauth://`
//!   URI (SHA1/6/30), the base32 secret (manual-entry fallback), and a
//!   self-contained SVG QR (no external hosts — offline admin box).
//! - confirm step: only a code generated from the pending secret
//!   activates it; an unconfirmed secret never grants (or gates) login.
//! - login reads the runtime overlay: once confirmed, the next login
//!   REQUIRES a code from the enrolled app.
//! - pending enrollments expire.

use std::sync::Arc;

use aegis_control::admin_auth::password::hash_password;
use aegis_control::admin_auth::totp;
use aegis_control::admin_auth::totp_store::TotpEnrollmentStore;
use aegis_control::api::admin::SessionStore as DashboardSessionStore;
use aegis_control::api::login::{
    authenticate, derive_session_key, AdminDirectory, AdminIdentity, LoginOutcome,
};
use aegis_control::api::totp_enrollment::{confirm, enroll, ConfirmOutcome};
use aegis_control::admin_auth::rate_limit::LoginRateLimiter;
use aegis_control::admin_auth::session::SessionStore as AuthSessionStore;

fn now_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn code_for(secret_b32: &str) -> String {
    let secret = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret_b32)
        .expect("secret must be RFC 4648 base32");
    totp::generate(&secret, now_s(), &totp::TotpConfig::default())
}

fn login_fixtures() -> (
    Arc<LoginRateLimiter>,
    Arc<AuthSessionStore>,
    Arc<DashboardSessionStore>,
) {
    (
        Arc::new(LoginRateLimiter::new(Default::default())),
        Arc::new(AuthSessionStore::new(derive_session_key("test-csrf-secret-32b"))),
        Arc::new(DashboardSessionStore::new()),
    )
}

fn alice_identity() -> AdminIdentity {
    AdminIdentity {
        user: "alice".into(),
        password_hash: hash_password("alice-pw-1234").unwrap(),
        ..AdminIdentity::default()
    }
}

fn login_body(user: &str, password: &str) -> String {
    serde_json::json!({"user": user, "password": password}).to_string()
}

fn login_body_with_code(user: &str, password: &str, code: &str) -> String {
    serde_json::json!({"user": user, "password": password, "totp_code": code}).to_string()
}

#[tokio::test]
async fn enroll_returns_ga_uri_secret_and_self_contained_qr() {
    let store = TotpEnrollmentStore::in_memory();
    let resp = enroll(&store, "alice", "Aegis").await.expect("enroll must succeed");

    // GA-interoperable URI: SHA1 / 6 digits / 30s — the totp.rs baseline.
    assert!(
        resp.otpauth_uri.starts_with("otpauth://totp/Aegis:alice"),
        "URI must be GA-parseable: {}",
        resp.otpauth_uri,
    );
    assert!(resp.otpauth_uri.contains("algorithm=SHA1"));
    assert!(resp.otpauth_uri.contains("digits=6"));
    assert!(resp.otpauth_uri.contains("period=30"));
    assert!(resp.otpauth_uri.contains(&format!("secret={}", resp.secret_b32)));

    // Manual-entry fallback secret must round-trip as RFC 4648 base32.
    let decoded = base32::decode(
        base32::Alphabet::Rfc4648 { padding: false },
        &resp.secret_b32,
    )
    .expect("secret must decode");
    assert_eq!(decoded.len(), 32, "32-byte CSPRNG secret");

    // Self-contained SVG QR — rendered server-side, no external hosts
    // (offline admin box must work).
    assert!(resp.qr_svg.contains("<svg"), "must be inline SVG");
    // Self-contained: no fetched sub-resources. (The standard
    // `xmlns="http://www.w3.org/2000/svg"` namespace IDENTIFIER is not a
    // network reference and is allowed.)
    let without_xmlns = resp.qr_svg.replace("xmlns=\"http://www.w3.org/2000/svg\"", "");
    assert!(
        !without_xmlns.contains("http://")
            && !without_xmlns.contains("https://")
            && !without_xmlns.contains("<image")
            && !without_xmlns.contains("src="),
        "QR must not reference an external host",
    );
    assert!(resp.expires_in_seconds > 0);
}

#[tokio::test]
async fn confirm_with_generated_code_activates_and_login_then_requires_it() {
    let store = Arc::new(TotpEnrollmentStore::in_memory());
    let (rl, ss, ds) = login_fixtures();
    let dir = AdminDirectory::new(vec![Arc::new(alice_identity())])
        .with_require_totp(true)
        .with_totp_store(Arc::clone(&store));

    // Before enrollment: password-only lands in enrollment_required.
    let outcome = authenticate(
        &login_body("alice", "alice-pw-1234"),
        &dir, &rl, &ss, &ds, "127.0.0.1", "ua", 1800,
    )
    .await;
    assert!(matches!(outcome, LoginOutcome::EnrollmentRequired { .. }));

    // Enroll + confirm with a code the app would generate.
    let resp = enroll(&store, "alice", "Aegis").await.unwrap();
    let outcome = confirm(&store, "alice", &code_for(&resp.secret_b32), now_s())
        .await
        .unwrap();
    assert!(matches!(outcome, ConfirmOutcome::Activated));

    // Password-only now REJECTS (the account is enrolled — strict path).
    let outcome = authenticate(
        &login_body("alice", "alice-pw-1234"),
        &dir, &rl, &ss, &ds, "10.0.0.2", "ua", 1800,
    )
    .await;
    assert!(
        matches!(outcome, LoginOutcome::Unauthorized { .. }),
        "enrolled account without code must reject: {outcome:?}",
    );

    // Password + app code → full login.
    let outcome = authenticate(
        &login_body_with_code("alice", "alice-pw-1234", &code_for(&resp.secret_b32)),
        &dir, &rl, &ss, &ds, "10.0.0.3", "ua", 1800,
    )
    .await;
    assert!(matches!(outcome, LoginOutcome::Ok { .. }), "got {outcome:?}");
}

#[tokio::test]
async fn wrong_confirm_code_does_not_activate() {
    let store = TotpEnrollmentStore::in_memory();
    let _ = enroll(&store, "alice", "Aegis").await.unwrap();
    let outcome = confirm(&store, "alice", "000000", now_s()).await.unwrap();
    assert!(matches!(outcome, ConfirmOutcome::InvalidCode));
    assert!(
        store.active("alice").await.is_none(),
        "a wrong code must never activate the pending secret",
    );
}

#[tokio::test]
async fn unconfirmed_pending_secret_never_grants_login() {
    let store = Arc::new(TotpEnrollmentStore::in_memory());
    let (rl, ss, ds) = login_fixtures();
    let dir = AdminDirectory::new(vec![Arc::new(alice_identity())])
        .with_require_totp(true)
        .with_totp_store(Arc::clone(&store));

    let resp = enroll(&store, "alice", "Aegis").await.unwrap();
    // The operator never confirmed. A code from the PENDING secret must
    // not act as a second factor — the account is still un-enrolled, so
    // login stays in the enrollment_required state.
    let outcome = authenticate(
        &login_body_with_code("alice", "alice-pw-1234", &code_for(&resp.secret_b32)),
        &dir, &rl, &ss, &ds, "127.0.0.1", "ua", 1800,
    )
    .await;
    assert!(
        matches!(outcome, LoginOutcome::EnrollmentRequired { .. }),
        "pending (unconfirmed) secret must not unlock login: {outcome:?}",
    );
}

#[tokio::test]
async fn confirm_without_pending_enrollment_is_rejected() {
    let store = TotpEnrollmentStore::in_memory();
    let outcome = confirm(&store, "alice", "123456", now_s()).await.unwrap();
    assert!(matches!(outcome, ConfirmOutcome::NoPendingEnrollment));
}

#[tokio::test]
async fn pending_enrollment_expires() {
    let store =
        TotpEnrollmentStore::in_memory().with_pending_ttl(std::time::Duration::from_millis(30));
    let resp = enroll(&store, "alice", "Aegis").await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    let outcome = confirm(&store, "alice", &code_for(&resp.secret_b32), now_s())
        .await
        .unwrap();
    assert!(
        matches!(outcome, ConfirmOutcome::NoPendingEnrollment),
        "an expired pending enrollment must not confirm",
    );
}

#[test]
fn ascii_qr_renders_for_headless_cli_parity() {
    // TOTP-4 — `waf admin enroll-totp` prints an ASCII QR so a headless
    // setup can scan straight off the terminal, matching the web flow.
    let uri = totp::provisioning_uri("JBSWY3DPEHPK3PXP", "Aegis", "alice");
    let art = aegis_control::api::totp_enrollment::render_qr_ascii(&uri)
        .expect("ascii QR must render");
    assert!(art.lines().count() > 10, "QR art must be multi-line");
    assert!(
        art.chars().any(|c| c == '█' || c == '▀' || c == '▄' || c == '#'),
        "QR art must contain block/module characters",
    );
}

#[tokio::test]
async fn overlay_wins_over_yaml_totp_state_after_enrollment() {
    // An account bootstrapped WITHOUT TOTP in YAML gains it at runtime;
    // the store overlay must win at every subsequent login (cluster:
    // enroll on node A, login on node B — same StateBackend).
    let store = Arc::new(TotpEnrollmentStore::in_memory());
    let (rl, ss, ds) = login_fixtures();
    let dir = AdminDirectory::new(vec![Arc::new(alice_identity())])
        .with_require_totp(false) // even with enforcement off…
        .with_totp_store(Arc::clone(&store));

    let resp = enroll(&store, "alice", "Aegis").await.unwrap();
    confirm(&store, "alice", &code_for(&resp.secret_b32), now_s())
        .await
        .unwrap();

    // …an enrolled factor is still demanded (enrollment is a promise to
    // the operator, not something require_totp toggles away silently).
    let outcome = authenticate(
        &login_body("alice", "alice-pw-1234"),
        &dir, &rl, &ss, &ds, "127.0.0.1", "ua", 1800,
    )
    .await;
    assert!(
        matches!(outcome, LoginOutcome::Unauthorized { .. }),
        "enrolled account must require its code even under require_totp=false: {outcome:?}",
    );
}
