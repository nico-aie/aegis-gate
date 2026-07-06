//! TOTP-3 (TF-1a) — Google Authenticator enrollment flow bodies.
//!
//! `POST /api/admin/totp/enroll` / `POST /api/admin/totp/confirm` — the
//! proxy owns the routes (dispatch + auth middleware); this module owns
//! the payloads so they're unit-testable without hyper plumbing:
//!
//! - [`enroll`]: fresh CSPRNG secret → pending-confirm in the
//!   [`TotpEnrollmentStore`], returns the GA-compatible `otpauth://` URI
//!   (SHA1/6/30 — the `totp.rs` interop baseline, do NOT change the
//!   algorithm), the base32 secret for manual entry, and a
//!   server-rendered SVG QR (no external QR service — offline admin
//!   boxes must work).
//! - [`confirm`]: verifies a code the operator's app generated against
//!   the pending secret; only a correct code activates the factor. An
//!   unconfirmed secret never gates or grants login.

use serde::Serialize;

use crate::admin_auth::totp;
use crate::admin_auth::totp_store::TotpEnrollmentStore;

/// Response body for `POST /api/admin/totp/enroll`.
#[derive(Clone, Debug, Serialize)]
pub struct EnrollResponse {
    pub ok: bool,
    /// `otpauth://totp/<issuer>:<account>?...` — scan target for
    /// Google Authenticator / Authy / 1Password / FreeOTP / Aegis.
    pub otpauth_uri: String,
    /// Manual-entry fallback for app setups that type the secret in.
    pub secret_b32: String,
    /// Self-contained inline SVG rendering of `otpauth_uri`.
    pub qr_svg: String,
    /// How long the pending enrollment stays confirmable.
    pub expires_in_seconds: u64,
}

/// What a confirm attempt produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfirmOutcome {
    /// Code matched the pending secret — the factor is now active and
    /// every subsequent login for this account requires an app code.
    Activated,
    /// Code didn't match. The pending enrollment stays claimable so the
    /// operator can re-try without re-scanning.
    InvalidCode,
    /// Nothing pending (never enrolled, already confirmed, or the
    /// 15-minute window lapsed) — the client should re-enroll.
    NoPendingEnrollment,
}

/// Start (or restart) enrollment for `user`: stage a fresh secret and
/// build the scan payload. Restarting replaces any prior pending secret
/// — only the LAST QR shown can confirm.
pub async fn enroll(
    store: &TotpEnrollmentStore,
    user: &str,
    issuer: &str,
) -> aegis_core::Result<EnrollResponse> {
    let secret_b32 = totp::generate_secret_b32();
    store.begin_enrollment(user, &secret_b32).await?;
    let otpauth_uri = totp::provisioning_uri(&secret_b32, issuer, user);
    let qr_svg = render_qr_svg(&otpauth_uri)?;
    Ok(EnrollResponse {
        ok: true,
        otpauth_uri,
        secret_b32,
        qr_svg,
        expires_in_seconds: store.pending_ttl().as_secs(),
    })
}

/// Verify `code` against `user`'s pending secret; activate on match.
/// `now` is unix seconds (injected for testability).
pub async fn confirm(
    store: &TotpEnrollmentStore,
    user: &str,
    code: &str,
    now: u64,
) -> aegis_core::Result<ConfirmOutcome> {
    let Some(secret_b32) = store.pending_secret(user).await else {
        return Ok(ConfirmOutcome::NoPendingEnrollment);
    };
    let Some(secret) = base32::decode(
        base32::Alphabet::Rfc4648 { padding: false },
        &secret_b32,
    ) else {
        // We generated this secret ourselves — a decode failure is a
        // bug, not operator input. Fail closed.
        tracing::error!(user, "pending TOTP secret failed base32 decode (bug)");
        return Ok(ConfirmOutcome::NoPendingEnrollment);
    };
    if !totp::verify(&secret, code, now, &totp::TotpConfig::default()) {
        return Ok(ConfirmOutcome::InvalidCode);
    }
    if store.activate(user).await? {
        Ok(ConfirmOutcome::Activated)
    } else {
        // Raced with expiry between the read and the activate.
        Ok(ConfirmOutcome::NoPendingEnrollment)
    }
}

/// AM-0a — verdict for whether an enroll request may proceed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrollGate {
    /// No active factor yet — first-time enrollment, no proof required.
    FirstTime,
    /// An active factor exists and the caller proved possession of it.
    StepUpOk,
    /// An active factor exists and the caller did NOT prove possession —
    /// deny; replacing 2FA requires a current code.
    StepUpRequired,
}

/// AM-0a (review HIGH) — gate re-enrollment. Overwriting an already-active
/// factor requires proving possession of the CURRENT one (a valid live
/// code), so a hijacked fully-verified session can't silently swap an
/// operator's authenticator and lock them out. First-time enrollment (no
/// active factor) needs no proof — there's nothing to prove yet. Pure so
/// it's unit-testable without the hyper handler; `now` is unix seconds.
///
/// Note: an admin resetting *another* account's 2FA (AM-P2b
/// `/totp/reset`) is a distinct, authorised recovery action and does not
/// go through this self-service gate.
pub async fn enroll_gate(
    store: &TotpEnrollmentStore,
    user: &str,
    provided_code: Option<&str>,
    now: u64,
) -> EnrollGate {
    match store.active(user).await {
        Some(active) if active.enabled => {
            let proven = provided_code
                .filter(|c| !c.is_empty())
                .and_then(|code| {
                    base32::decode(
                        base32::Alphabet::Rfc4648 { padding: false },
                        &active.secret_b32,
                    )
                    .filter(|s| !s.is_empty())
                    .map(|secret| totp::verify(&secret, code, now, &totp::TotpConfig::default()))
                })
                .unwrap_or(false);
            if proven {
                EnrollGate::StepUpOk
            } else {
                EnrollGate::StepUpRequired
            }
        }
        _ => EnrollGate::FirstTime,
    }
}

/// TOTP-4 — terminal QR for CLI parity (`waf admin enroll-totp` /
/// `create-account --with-totp`): headless setups scan straight off
/// the terminal, matching the web flow. Unicode half-block rendering
/// (▀▄█) keeps the art compact enough for a QR that encodes a full
/// `otpauth://` URI.
pub fn render_qr_ascii(data: &str) -> aegis_core::Result<String> {
    let code = qrcode::QrCode::new(data.as_bytes()).map_err(|e| {
        aegis_core::WafError::State(format!("QR encode failed: {e}"))
    })?;
    Ok(code
        .render::<qrcode::render::unicode::Dense1x2>()
        .quiet_zone(true)
        .build())
}

/// Render `data` as a self-contained SVG QR. Pure-Rust `qrcode` crate,
/// no raster/image dependency, no external host.
fn render_qr_svg(data: &str) -> aegis_core::Result<String> {
    let code = qrcode::QrCode::new(data.as_bytes()).map_err(|e| {
        aegis_core::WafError::State(format!("QR encode failed: {e}"))
    })?;
    Ok(code
        .render::<qrcode::render::svg::Color<'_>>()
        .min_dimensions(240, 240)
        .quiet_zone(true)
        .build())
}

#[cfg(test)]
mod enroll_gate_tests {
    // AM-0a — re-enrollment step-up. Overwriting an active factor requires a
    // valid CURRENT code; first-time enrollment does not.
    use super::*;
    use crate::admin_auth::totp;

    fn code_now(secret_b32: &str, now: u64) -> String {
        let secret =
            base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret_b32).unwrap();
        totp::generate(&secret, now, &totp::TotpConfig::default())
    }

    async fn store_with_active(user: &str) -> (TotpEnrollmentStore, String) {
        let store = TotpEnrollmentStore::in_memory();
        let secret = totp::generate_secret_b32();
        store.begin_enrollment(user, &secret).await.unwrap();
        assert!(store.activate(user).await.unwrap());
        (store, secret)
    }

    #[tokio::test]
    async fn first_time_enrollment_needs_no_proof() {
        let store = TotpEnrollmentStore::in_memory();
        assert_eq!(
            enroll_gate(&store, "alice", None, 1_000_000).await,
            EnrollGate::FirstTime,
        );
    }

    #[tokio::test]
    async fn reenroll_without_code_is_denied() {
        let (store, _secret) = store_with_active("alice").await;
        assert_eq!(
            enroll_gate(&store, "alice", None, 1_000_000).await,
            EnrollGate::StepUpRequired,
        );
    }

    #[tokio::test]
    async fn reenroll_with_wrong_code_is_denied() {
        let (store, _secret) = store_with_active("alice").await;
        assert_eq!(
            enroll_gate(&store, "alice", Some("000000"), 1_000_000).await,
            EnrollGate::StepUpRequired,
        );
    }

    #[tokio::test]
    async fn reenroll_with_current_code_is_allowed() {
        let (store, secret) = store_with_active("alice").await;
        let now = 1_000_000;
        let code = code_now(&secret, now);
        assert_eq!(
            enroll_gate(&store, "alice", Some(&code), now).await,
            EnrollGate::StepUpOk,
        );
    }
}
