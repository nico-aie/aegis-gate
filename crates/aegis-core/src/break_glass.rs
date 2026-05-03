//! MTLS-T9 — break-glass emergency mTLS bypass.
//!
//! Triggered by `AEGIS_MTLS_BREAK_GLASS=1` at process boot.
//! Downgrades the **admin plane's** effective `client_auth.mode`
//! to `Optional` so an operator who has lost their client cert
//! (lost laptop, expired cert, CA rotation gone wrong) can still
//! reach the dashboard to recover.
//!
//! ## Design constraints
//!
//! - **Boot-only**: a runtime override would defeat the
//!   purpose — an attacker who can flip a runtime flag could
//!   also disable mTLS entirely. The decision lives at process
//!   start, never a hot reload, never a dashboard endpoint.
//! - **Loud**: warnings every 60s on stderr + an audit event
//!   on the chain so the trail can't be missed.
//! - **Admin only**: data-plane listeners stay strict. The
//!   recovery surface is the dashboard, not the data path.
//! - **Documented exit**: `unset AEGIS_MTLS_BREAK_GLASS && systemctl
//!   restart aegis-gate` returns to the configured mode.
//!
//! ## What it does NOT do
//!
//! - Does not bypass admin password / TOTP. Break-glass is a TLS
//!   transport relaxation; the dashboard's session-cookie auth
//!   still gates every endpoint.
//! - Does not change the CA bundle or allowed_sans. If a cert
//!   IS presented, it's still validated.
//! - Does not affect data-plane mTLS. Apps continue to enforce
//!   their per-route `auth_required` lists.

use std::sync::atomic::{AtomicBool, Ordering};

const ENV_VAR: &str = "AEGIS_MTLS_BREAK_GLASS";

/// One-shot capture of the env-var state at boot. Subsequent
/// calls reuse the cached value so a `set_var` in tests
/// doesn't change the answer mid-run.
static BREAK_GLASS_ACTIVE: AtomicBool = AtomicBool::new(false);
static BREAK_GLASS_INITIALISED: AtomicBool = AtomicBool::new(false);

/// Initialise from the environment. Idempotent — first call
/// captures, subsequent calls are no-ops.
///
/// Returns the captured value so the boot path can log it
/// without a second env read.
pub fn init_from_env() -> bool {
    let active = matches!(
        std::env::var(ENV_VAR).as_deref(),
        Ok("1") | Ok("true") | Ok("yes"),
    );
    if !BREAK_GLASS_INITIALISED.swap(true, Ordering::AcqRel) {
        BREAK_GLASS_ACTIVE.store(active, Ordering::Release);
    }
    BREAK_GLASS_ACTIVE.load(Ordering::Acquire)
}

/// True iff break-glass was set at process start. Hot-path
/// safe (one atomic load, no env access).
pub fn is_active() -> bool {
    if !BREAK_GLASS_INITIALISED.load(Ordering::Acquire) {
        // Lazy init for tests + bundles that don't go through
        // `aegis-proxy::run`. Production always runs through
        // `init_from_env` early in boot.
        let _ = init_from_env();
    }
    BREAK_GLASS_ACTIVE.load(Ordering::Acquire)
}

/// Reset for tests. NEVER call from production — not
/// `pub` outside the crate.
#[doc(hidden)]
#[cfg(test)]
pub fn _reset_for_test() {
    BREAK_GLASS_INITIALISED.store(false, Ordering::Release);
    BREAK_GLASS_ACTIVE.store(false, Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Env-var tests must serialise — concurrent set_var/remove_var
    // would race with the static cache.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn unset_env_means_inactive() {
        let _g = ENV_LOCK.lock().unwrap();
        _reset_for_test();
        unsafe { std::env::remove_var(ENV_VAR); }
        assert!(!init_from_env());
        assert!(!is_active());
    }

    #[test]
    fn env_one_activates() {
        let _g = ENV_LOCK.lock().unwrap();
        _reset_for_test();
        unsafe { std::env::set_var(ENV_VAR, "1"); }
        assert!(init_from_env());
        assert!(is_active());
        unsafe { std::env::remove_var(ENV_VAR); }
    }

    #[test]
    fn env_true_also_activates() {
        let _g = ENV_LOCK.lock().unwrap();
        _reset_for_test();
        unsafe { std::env::set_var(ENV_VAR, "true"); }
        assert!(init_from_env());
        unsafe { std::env::remove_var(ENV_VAR); }
    }

    #[test]
    fn env_garbage_stays_inactive() {
        let _g = ENV_LOCK.lock().unwrap();
        _reset_for_test();
        unsafe { std::env::set_var(ENV_VAR, "maybe"); }
        assert!(!init_from_env());
        unsafe { std::env::remove_var(ENV_VAR); }
    }

    #[test]
    fn second_init_is_a_noop() {
        let _g = ENV_LOCK.lock().unwrap();
        _reset_for_test();
        unsafe { std::env::set_var(ENV_VAR, "1"); }
        let first = init_from_env();
        // Flip env to off and try again — captured value wins.
        unsafe { std::env::set_var(ENV_VAR, "0"); }
        let second = init_from_env();
        assert_eq!(first, second);
        assert!(is_active(), "first init's value persists");
        unsafe { std::env::remove_var(ENV_VAR); }
    }
}
