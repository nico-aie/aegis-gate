//! AM-P2b — admin account-management operations: list / create / reset
//! password / reset 2FA / delete, over the runtime [`AdminAccountStore`]
//! overlay. Equal-privilege model (no RBAC): any admin may manage accounts;
//! the guards here (last-admin, no-self-target) are what keep that safe.
//!
//! These are (almost) pure helpers over the stores so they're unit-testable
//! without hyper. The proxy owns the routes, the auth gate (session + CSRF +
//! write scope), the acting-actor header, and audit emission.
//!
//! **No secrets leave here.** [`AccountView`] carries metadata only — never a
//! password hash or TOTP secret.

use std::collections::{BTreeSet, HashMap};

use serde::Serialize;

use crate::admin_auth::password::hash_password;
use crate::admin_auth::session::SessionStore as AuthSessionStore;
use crate::admin_auth::totp_store::TotpEnrollmentStore;
use crate::api::login::AdminDirectory;

/// Minimum admin password length (matches `api::admin::handle_password_change`).
pub const MIN_PASSWORD_LEN: usize = 12;

/// Non-secret account metadata for the management UI.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct AccountView {
    pub username: String,
    /// `"bootstrap"` (YAML seed) or `"runtime"` (created/overridden via API).
    pub source: &'static str,
    pub totp_enrolled: bool,
    pub disabled: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CreateError {
    /// No runtime account store wired (single-node build without a backend).
    Unavailable,
    InvalidUsername,
    Duplicate,
    WeakPassword,
    Store(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum MutateError {
    Unavailable,
    NotFound,
    /// The acting admin targeted their own account — use the self-service
    /// endpoints (which require step-up) instead.
    SelfTarget,
    /// Would remove the last login-eligible admin (→ lockout).
    LastAdmin,
    WeakPassword,
    Store(String),
}

/// Live (login-eligible) usernames = YAML seed minus tombstones, plus
/// runtime-active accounts.
pub async fn live_usernames(directory: &AdminDirectory) -> BTreeSet<String> {
    let mut set: BTreeSet<String> = directory.accounts().iter().map(|a| a.user.clone()).collect();
    if let Some(store) = directory.account_store() {
        for rec in store.list().await {
            if rec.is_active() {
                set.insert(rec.username);
            } else {
                set.remove(&rec.username);
            }
        }
    }
    set
}

/// The merged account list (YAML seed with the runtime overlay applied), each
/// annotated with its source + whether 2FA is enrolled. Sorted by username.
pub async fn list_accounts(
    directory: &AdminDirectory,
    totp_store: &TotpEnrollmentStore,
) -> Vec<AccountView> {
    let runtime: HashMap<String, _> = match directory.account_store() {
        Some(store) => store
            .list()
            .await
            .into_iter()
            .map(|r| (r.username.clone(), r))
            .collect(),
        None => HashMap::new(),
    };
    let mut views: Vec<AccountView> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();

    for acct in directory.accounts() {
        let uname = &acct.user;
        seen.insert(uname.clone());
        if let Some(rec) = runtime.get(uname) {
            if !rec.is_active() {
                continue; // tombstoned — hidden from the seed
            }
        }
        let source = if runtime.contains_key(uname) { "runtime" } else { "bootstrap" };
        views.push(AccountView {
            username: uname.clone(),
            source,
            totp_enrolled: is_enrolled(totp_store, uname).await,
            disabled: false,
        });
    }
    for (uname, rec) in &runtime {
        if seen.contains(uname) || !rec.is_active() {
            continue;
        }
        views.push(AccountView {
            username: uname.clone(),
            source: "runtime",
            totp_enrolled: is_enrolled(totp_store, uname).await,
            disabled: rec.disabled,
        });
    }
    views.sort_by(|a, b| a.username.cmp(&b.username));
    views
}

async fn is_enrolled(totp_store: &TotpEnrollmentStore, user: &str) -> bool {
    totp_store.active(user).await.map(|a| a.enabled).unwrap_or(false)
}

/// Create a new runtime admin account. New accounts have no 2FA factor, so
/// under `require_totp` they enrol at first login.
pub async fn create_account(
    directory: &AdminDirectory,
    username: &str,
    password: &str,
) -> Result<(), CreateError> {
    let Some(store) = directory.account_store() else {
        return Err(CreateError::Unavailable);
    };
    if !aegis_core::config::is_valid_admin_username(username) {
        return Err(CreateError::InvalidUsername);
    }
    if password.len() < MIN_PASSWORD_LEN {
        return Err(CreateError::WeakPassword);
    }
    if live_usernames(directory).await.contains(username) {
        return Err(CreateError::Duplicate);
    }
    let hash = hash_password(password).map_err(|e| CreateError::Store(e.to_string()))?;
    store
        .upsert(username, &hash)
        .await
        .map_err(|e| CreateError::Store(e.to_string()))
}

/// Admin-reset another account's password (no old-password check — this is an
/// admin override). Revokes that account's sessions so old cookies die.
pub async fn reset_password(
    directory: &AdminDirectory,
    sessions: &AuthSessionStore,
    target: &str,
    actor: &str,
    new_password: &str,
) -> Result<(), MutateError> {
    let Some(store) = directory.account_store() else {
        return Err(MutateError::Unavailable);
    };
    if target == actor {
        return Err(MutateError::SelfTarget);
    }
    if new_password.len() < MIN_PASSWORD_LEN {
        return Err(MutateError::WeakPassword);
    }
    if !live_usernames(directory).await.contains(target) {
        return Err(MutateError::NotFound);
    }
    let hash = hash_password(new_password).map_err(|e| MutateError::Store(e.to_string()))?;
    // upsert overrides a YAML-seeded account too (resolve then returns the
    // runtime record with the new hash).
    store
        .upsert(target, &hash)
        .await
        .map_err(|e| MutateError::Store(e.to_string()))?;
    sessions.revoke_user(target, None).await;
    Ok(())
}

/// Admin-reset another account's 2FA (lost-device recovery). Clears the active
/// factor so the target re-enrols at next login, and revokes their sessions.
pub async fn reset_totp(
    directory: &AdminDirectory,
    totp_store: &TotpEnrollmentStore,
    sessions: &AuthSessionStore,
    target: &str,
    actor: &str,
) -> Result<(), MutateError> {
    if directory.account_store().is_none() {
        return Err(MutateError::Unavailable);
    }
    if target == actor {
        return Err(MutateError::SelfTarget);
    }
    if !live_usernames(directory).await.contains(target) {
        return Err(MutateError::NotFound);
    }
    totp_store
        .clear(target)
        .await
        .map_err(|e| MutateError::Store(e.to_string()))?;
    sessions.revoke_user(target, None).await;
    Ok(())
}

/// Delete an account. YAML-seeded accounts are tombstoned (the boot file can't
/// be edited at runtime); runtime-only accounts are hard-removed. Purges the
/// 2FA factor + sessions. Refuses to remove the last live admin.
pub async fn delete_account(
    directory: &AdminDirectory,
    totp_store: &TotpEnrollmentStore,
    sessions: &AuthSessionStore,
    target: &str,
    actor: &str,
) -> Result<(), MutateError> {
    let Some(store) = directory.account_store() else {
        return Err(MutateError::Unavailable);
    };
    if target == actor {
        return Err(MutateError::SelfTarget);
    }
    let live = live_usernames(directory).await;
    if !live.contains(target) {
        return Err(MutateError::NotFound);
    }
    if live.len() <= 1 {
        return Err(MutateError::LastAdmin);
    }
    let is_yaml = directory.accounts().iter().any(|a| a.user == target);
    if is_yaml {
        store
            .tombstone(target)
            .await
            .map_err(|e| MutateError::Store(e.to_string()))?;
    } else {
        store
            .remove(target)
            .await
            .map_err(|e| MutateError::Store(e.to_string()))?;
    }
    let _ = totp_store.clear(target).await;
    sessions.revoke_user(target, None).await;
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub enum SelfPwError {
    Unavailable,
    NotFound,
    WeakPassword,
    SameAsCurrent,
    CurrentIncorrect,
    Store(String),
}

/// AM-P2d — self-service password change. Unlike the admin reset, this
/// verifies the CURRENT password (so a hijacked session can't rotate the
/// password without knowing the old one) and keeps the caller's own session
/// (`keep_session_id`) while revoking their others.
pub async fn change_own_password(
    directory: &AdminDirectory,
    sessions: &AuthSessionStore,
    actor: &str,
    current: &str,
    new: &str,
    keep_session_id: Option<&str>,
) -> Result<(), SelfPwError> {
    let Some(store) = directory.account_store() else {
        return Err(SelfPwError::Unavailable);
    };
    if new.len() < MIN_PASSWORD_LEN {
        return Err(SelfPwError::WeakPassword);
    }
    if current == new {
        return Err(SelfPwError::SameAsCurrent);
    }
    let Some(identity) = directory.resolve(actor).await else {
        return Err(SelfPwError::NotFound);
    };
    if !crate::admin_auth::password::verify_password(&identity.password_hash, current) {
        return Err(SelfPwError::CurrentIncorrect);
    }
    let hash = hash_password(new).map_err(|e| SelfPwError::Store(e.to_string()))?;
    store
        .upsert(actor, &hash)
        .await
        .map_err(|e| SelfPwError::Store(e.to_string()))?;
    sessions.revoke_user(actor, keep_session_id).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin_auth::account_store::AdminAccountStore;
    use crate::admin_auth::password::hash_password;
    use crate::api::login::AdminIdentity;
    use std::sync::Arc;

    fn dir_with(seed: &[&str]) -> (AdminDirectory, Arc<AdminAccountStore>) {
        let store = Arc::new(AdminAccountStore::in_memory());
        let accounts: Vec<Arc<AdminIdentity>> = seed
            .iter()
            .map(|u| {
                Arc::new(AdminIdentity {
                    user: (*u).into(),
                    password_hash: hash_password("seed-password-123").unwrap(),
                    ..AdminIdentity::default()
                })
            })
            .collect();
        let dir = AdminDirectory::new(accounts).with_account_store(Arc::clone(&store));
        (dir, store)
    }

    fn sessions() -> AuthSessionStore {
        AuthSessionStore::new([3u8; 32])
    }
    fn totp() -> TotpEnrollmentStore {
        TotpEnrollmentStore::in_memory()
    }

    #[tokio::test]
    async fn create_rejects_bad_username_dup_and_weak_password() {
        let (dir, _s) = dir_with(&["admin"]);
        assert_eq!(
            create_account(&dir, "bad name", "long-enough-pw-123").await,
            Err(CreateError::InvalidUsername)
        );
        assert_eq!(
            create_account(&dir, "newbie", "short").await,
            Err(CreateError::WeakPassword)
        );
        assert_eq!(
            create_account(&dir, "admin", "long-enough-pw-123").await,
            Err(CreateError::Duplicate)
        );
        assert!(create_account(&dir, "alice", "long-enough-pw-123").await.is_ok());
        // Now a live account → duplicate on re-create.
        assert_eq!(
            create_account(&dir, "alice", "long-enough-pw-123").await,
            Err(CreateError::Duplicate)
        );
    }

    #[tokio::test]
    async fn list_reflects_seed_runtime_and_tombstone() {
        let (dir, store) = dir_with(&["admin"]);
        create_account(&dir, "alice", "long-enough-pw-123").await.unwrap();
        let views = list_accounts(&dir, &totp()).await;
        let names: Vec<_> = views.iter().map(|v| v.username.as_str()).collect();
        assert_eq!(names, vec!["admin", "alice"]);
        assert_eq!(views[0].source, "bootstrap");
        assert_eq!(views[1].source, "runtime");
        // Tombstone the seed admin → drops out of the list.
        store.tombstone("admin").await.unwrap();
        let views = list_accounts(&dir, &totp()).await;
        assert_eq!(
            views.iter().map(|v| v.username.as_str()).collect::<Vec<_>>(),
            vec!["alice"]
        );
    }

    #[tokio::test]
    async fn reset_password_guards_self_notfound_and_weak() {
        let (dir, _s) = dir_with(&["admin"]);
        create_account(&dir, "alice", "long-enough-pw-123").await.unwrap();
        let sess = sessions();
        assert_eq!(
            reset_password(&dir, &sess, "admin", "admin", "long-enough-pw-123").await,
            Err(MutateError::SelfTarget)
        );
        assert_eq!(
            reset_password(&dir, &sess, "ghost", "admin", "long-enough-pw-123").await,
            Err(MutateError::NotFound)
        );
        assert_eq!(
            reset_password(&dir, &sess, "alice", "admin", "short").await,
            Err(MutateError::WeakPassword)
        );
        assert!(reset_password(&dir, &sess, "alice", "admin", "brand-new-pw-456").await.is_ok());
    }

    #[tokio::test]
    async fn reset_totp_clears_the_factor() {
        let (dir, _s) = dir_with(&["admin"]);
        create_account(&dir, "alice", "long-enough-pw-123").await.unwrap();
        let tstore = totp();
        // Enrol alice.
        let secret = crate::admin_auth::totp::generate_secret_b32();
        tstore.begin_enrollment("alice", &secret).await.unwrap();
        tstore.activate("alice").await.unwrap();
        assert!(is_enrolled(&tstore, "alice").await);
        // Admin resets it.
        assert!(reset_totp(&dir, &tstore, &sessions(), "alice", "admin").await.is_ok());
        assert!(!is_enrolled(&tstore, "alice").await, "factor cleared → re-enrol next login");
    }

    #[tokio::test]
    async fn delete_enforces_last_admin_and_self_guards() {
        let (dir, store) = dir_with(&["admin"]);
        let tstore = totp();
        let sess = sessions();
        // Only one live admin → can't delete anyone (self-guard first, then last-admin).
        assert_eq!(
            delete_account(&dir, &tstore, &sess, "admin", "admin").await,
            Err(MutateError::SelfTarget)
        );
        create_account(&dir, "alice", "long-enough-pw-123").await.unwrap();
        // Delete runtime-only alice (as admin) → hard remove.
        assert!(delete_account(&dir, &tstore, &sess, "alice", "admin").await.is_ok());
        assert!(store.get("alice").await.is_none(), "runtime-only delete hard-removes");
        // Recreate, then last-admin guard: deleting the seed admin as alice
        // would still leave alice, so it's allowed; but deleting alice as admin
        // when alice is the only *other* live account is fine too. Prove the
        // guard by collapsing to one: tombstone admin, then deleting alice
        // (as someone else) must refuse.
        create_account(&dir, "alice", "long-enough-pw-123").await.unwrap();
        store.tombstone("admin").await.unwrap(); // now only alice is live
        assert_eq!(
            delete_account(&dir, &tstore, &sess, "alice", "root").await,
            Err(MutateError::LastAdmin)
        );
    }

    #[tokio::test]
    async fn change_own_password_verifies_current_and_rejects_reuse() {
        let (dir, _s) = dir_with(&["admin"]);
        create_account(&dir, "alice", "alice-old-pw-123").await.unwrap();
        let sess = sessions();
        // Wrong current password → rejected.
        assert_eq!(
            change_own_password(&dir, &sess, "alice", "wrong", "alice-new-pw-456", None).await,
            Err(SelfPwError::CurrentIncorrect)
        );
        // New == current → rejected.
        assert_eq!(
            change_own_password(&dir, &sess, "alice", "alice-old-pw-123", "alice-old-pw-123", None).await,
            Err(SelfPwError::SameAsCurrent)
        );
        // Too short → rejected.
        assert_eq!(
            change_own_password(&dir, &sess, "alice", "alice-old-pw-123", "short", None).await,
            Err(SelfPwError::WeakPassword)
        );
        // Correct current + valid new → ok, and the new password now verifies.
        assert!(change_own_password(&dir, &sess, "alice", "alice-old-pw-123", "alice-new-pw-456", None)
            .await
            .is_ok());
        let id = dir.resolve("alice").await.unwrap();
        assert!(crate::admin_auth::password::verify_password(&id.password_hash, "alice-new-pw-456"));
    }

    #[tokio::test]
    async fn delete_tombstones_yaml_seed_but_removes_runtime() {
        let (dir, store) = dir_with(&["admin", "keep"]);
        let tstore = totp();
        let sess = sessions();
        // Seed admin → tombstone (still gettable as deleted).
        assert!(delete_account(&dir, &tstore, &sess, "admin", "keep").await.is_ok());
        assert!(store.get("admin").await.unwrap().deleted, "seed delete is a tombstone");
    }
}
