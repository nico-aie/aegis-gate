//! AM-P2a — runtime admin-account store (create / reset / delete an admin
//! without a YAML edit or a restart).
//!
//! Mirrors [`super::totp_store::TotpEnrollmentStore`]: a shared
//! [`StateBackend`] when wired (Redis hash `control:waf:admin:accounts` —
//! fleet-wide + restart-durable, one field per username), else a local map
//! for tests / single-process fixtures.
//!
//! Accounts are durable, config-class identity: they live under
//! `control:waf:*`, which `reset_state`'s ephemeral patterns exclude, so a
//! state wipe never deletes admins (→ permanent lockout).
//!
//! Precedence with the YAML-seeded `accounts:` block is resolved by
//! [`crate::api::login::AdminDirectory`]: a store record overlays the YAML
//! seed by username, and a **tombstone** (`deleted: true`) hides a
//! YAML-seeded account without a file edit. TOTP factors are NOT stored here
//! — they stay in [`super::totp_store::TotpEnrollmentStore`], keyed by the
//! same username, so a runtime-created account enrols exactly like a
//! YAML-seeded one.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use aegis_core::state::StateBackend;

/// Durable hash holding one field per runtime-managed username.
const ACCOUNTS_HASH_KEY: &str = "control:waf:admin:accounts";

/// A runtime-managed admin account, or a tombstone hiding a YAML-seeded one.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimeAccount {
    pub username: String,
    /// argon2id PHC hash. Empty for a tombstone.
    #[serde(default)]
    pub password_hash: String,
    #[serde(default)]
    pub disabled: bool,
    /// Tombstone marker — hides a YAML-seeded account of the same username
    /// (there's no way to delete a line from the boot YAML at runtime).
    #[serde(default)]
    pub deleted: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl RuntimeAccount {
    /// A live, login-eligible account (not a tombstone, not disabled).
    pub fn is_active(&self) -> bool {
        !self.deleted && !self.disabled
    }
}

/// Runtime admin-account store. Manual `Debug` — never print password hashes.
pub struct AdminAccountStore {
    backend: Option<Arc<dyn StateBackend>>,
    local: Mutex<HashMap<String, RuntimeAccount>>,
}

impl std::fmt::Debug for AdminAccountStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminAccountStore")
            .field("backend", &self.backend.is_some())
            .finish_non_exhaustive()
    }
}

impl Default for AdminAccountStore {
    fn default() -> Self {
        Self::in_memory()
    }
}

impl AdminAccountStore {
    /// Local-only store — tests + single-process fixtures.
    pub fn in_memory() -> Self {
        Self { backend: None, local: Mutex::new(HashMap::new()) }
    }

    /// Shared store backed by the same [`StateBackend`] as sessions / TOTP —
    /// Redis in cluster mode (fleet-wide + durable). Production boot path.
    pub fn with_backend(backend: Arc<dyn StateBackend>) -> Self {
        Self { backend: Some(backend), local: Mutex::new(HashMap::new()) }
    }

    /// One record by username (including tombstones). `None` = never managed
    /// at runtime (defer to the YAML seed).
    pub async fn get(&self, user: &str) -> Option<RuntimeAccount> {
        if self.backend.is_some() {
            self.list().await.into_iter().find(|r| r.username == user)
        } else {
            self.local.lock().unwrap().get(user).cloned()
        }
    }

    /// All records, including tombstones — the directory overlay filters.
    pub async fn list(&self) -> Vec<RuntimeAccount> {
        if let Some(b) = &self.backend {
            match b.hscan(ACCOUNTS_HASH_KEY).await {
                Ok(pairs) => pairs
                    .into_iter()
                    .filter_map(|(_, bytes)| serde_json::from_slice(&bytes).ok())
                    .collect(),
                Err(_) => Vec::new(),
            }
        } else {
            self.local.lock().unwrap().values().cloned().collect()
        }
    }

    async fn put(&self, account: &RuntimeAccount) -> aegis_core::Result<()> {
        if let Some(b) = &self.backend {
            let bytes = serde_json::to_vec(account).unwrap_or_default();
            b.hset_multi(ACCOUNTS_HASH_KEY, &[(account.username.clone(), bytes)])
                .await
        } else {
            self.local
                .lock()
                .unwrap()
                .insert(account.username.clone(), account.clone());
            Ok(())
        }
    }

    /// Create or replace a runtime account (clears any prior tombstone).
    pub async fn upsert(&self, username: &str, password_hash: &str) -> aegis_core::Result<()> {
        let now = chrono::Utc::now();
        let created_at = self.get(username).await.map(|r| r.created_at).unwrap_or(now);
        self.put(&RuntimeAccount {
            username: username.to_string(),
            password_hash: password_hash.to_string(),
            disabled: false,
            deleted: false,
            created_at,
            updated_at: now,
        })
        .await
    }

    /// Reset an existing runtime account's password. `false` = no live
    /// runtime record for `username` (caller may need to materialise a
    /// YAML-seeded account into the store first).
    pub async fn set_password(
        &self,
        username: &str,
        password_hash: &str,
    ) -> aegis_core::Result<bool> {
        let Some(mut rec) = self.get(username).await else {
            return Ok(false);
        };
        if rec.deleted {
            return Ok(false);
        }
        rec.password_hash = password_hash.to_string();
        rec.updated_at = chrono::Utc::now();
        self.put(&rec).await?;
        Ok(true)
    }

    /// Tombstone a username — hides a YAML-seeded account of the same name
    /// without a file edit. Idempotent.
    pub async fn tombstone(&self, username: &str) -> aegis_core::Result<()> {
        let now = chrono::Utc::now();
        let created_at = self.get(username).await.map(|r| r.created_at).unwrap_or(now);
        self.put(&RuntimeAccount {
            username: username.to_string(),
            password_hash: String::new(),
            disabled: true,
            deleted: true,
            created_at,
            updated_at: now,
        })
        .await
    }

    /// Hard-remove a runtime-only account's field. Use when there is no
    /// YAML seed to hide (a tombstone would just be dead weight).
    pub async fn remove(&self, username: &str) -> aegis_core::Result<()> {
        if let Some(b) = &self.backend {
            b.hdel(ACCOUNTS_HASH_KEY, &[username.to_string()]).await
        } else {
            self.local.lock().unwrap().remove(username);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn upsert_then_get_roundtrips() {
        let store = AdminAccountStore::in_memory();
        store.upsert("alice", "$argon2id$alice").await.unwrap();
        let rec = store.get("alice").await.unwrap();
        assert_eq!(rec.username, "alice");
        assert_eq!(rec.password_hash, "$argon2id$alice");
        assert!(rec.is_active());
    }

    #[tokio::test]
    async fn tombstone_marks_inactive_but_is_still_gettable() {
        let store = AdminAccountStore::in_memory();
        store.upsert("bob", "$argon2id$bob").await.unwrap();
        store.tombstone("bob").await.unwrap();
        let rec = store.get("bob").await.unwrap();
        assert!(rec.deleted, "tombstone must be visible so the overlay can hide the seed");
        assert!(!rec.is_active());
    }

    #[tokio::test]
    async fn upsert_after_tombstone_revives_and_preserves_created_at() {
        let store = AdminAccountStore::in_memory();
        store.upsert("carol", "$argon2id$c1").await.unwrap();
        let created = store.get("carol").await.unwrap().created_at;
        store.tombstone("carol").await.unwrap();
        store.upsert("carol", "$argon2id$c2").await.unwrap();
        let rec = store.get("carol").await.unwrap();
        assert!(rec.is_active());
        assert_eq!(rec.password_hash, "$argon2id$c2");
        assert_eq!(rec.created_at, created, "created_at must survive tombstone→revive");
    }

    #[tokio::test]
    async fn set_password_requires_a_live_record() {
        let store = AdminAccountStore::in_memory();
        assert!(!store.set_password("ghost", "$argon2id$x").await.unwrap());
        store.upsert("dan", "$argon2id$d1").await.unwrap();
        assert!(store.set_password("dan", "$argon2id$d2").await.unwrap());
        assert_eq!(store.get("dan").await.unwrap().password_hash, "$argon2id$d2");
        store.tombstone("dan").await.unwrap();
        assert!(!store.set_password("dan", "$argon2id$d3").await.unwrap());
    }

    #[tokio::test]
    async fn remove_drops_the_field_entirely() {
        let store = AdminAccountStore::in_memory();
        store.upsert("eve", "$argon2id$e").await.unwrap();
        store.remove("eve").await.unwrap();
        assert!(store.get("eve").await.is_none());
    }

    #[tokio::test]
    async fn debug_never_prints_hashes() {
        let store = AdminAccountStore::in_memory();
        store.upsert("frank", "$argon2id$SECRETHASH").await.unwrap();
        assert!(!format!("{store:?}").contains("SECRETHASH"));
    }
}
