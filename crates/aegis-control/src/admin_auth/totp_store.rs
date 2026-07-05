//! TOTP-3 (TF-1a) — runtime TOTP enrollment state, per admin account.
//!
//! Two kinds of state, storage chosen per the decision in
//! `plans/issues/FEAT-totp-google-authenticator-2026-07.md`:
//!
//! - **Active factors** (`secret_b32`, enabled) — durable hash
//!   `control:waf:admin:totp`, field = username (`hset_multi`/`hscan`,
//!   the same pattern as `control:waf:incidents`). On Redis this is
//!   fleet-wide + restart-durable: enroll on node A, log in on node B.
//! - **Pending enrollments** (secret issued, QR shown, code not yet
//!   confirmed) — TTL key `control:waf:admin:totp:pending:<user>`
//!   (default 15 min). A pending secret is NOT a second factor: login
//!   ignores it until the confirm step proves the operator's app
//!   actually scanned it.
//!
//! Mirrors [`super::session::SessionStore`]'s storage shape: a shared
//! [`StateBackend`] when wired (Redis fleet-wide / in-memory backend),
//! else local maps (aegis-control tests + fixtures). On the standalone
//! `in_memory` backend the state lives for the process lifetime only —
//! the YAML `accounts[].totp_secret_b32` (via CLI enrollment) stays the
//! durable bootstrap there.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use aegis_core::state::StateBackend;

/// Durable hash key holding one field per enrolled username.
const ACTIVE_HASH_KEY: &str = "control:waf:admin:totp";
/// Per-user pending-enrollment key prefix (TTL'd).
const PENDING_KEY_PREFIX: &str = "control:waf:admin:totp:pending:";
/// How long an issued-but-unconfirmed secret stays claimable.
const DEFAULT_PENDING_TTL: Duration = Duration::from_secs(15 * 60);

/// An account's confirmed, active TOTP factor.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActiveTotp {
    pub secret_b32: String,
    pub enabled: bool,
    /// RFC 3339 activation timestamp (audit/debug surface only).
    pub activated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PendingTotp {
    secret_b32: String,
}

/// Runtime TOTP state store. See the module doc for the storage story.
///
/// Manual `Debug`: the maps hold shared secrets — never print them.
pub struct TotpEnrollmentStore {
    backend: Option<Arc<dyn StateBackend>>,
    local_active: Mutex<HashMap<String, ActiveTotp>>,
    /// Local pending entries carry their own deadline (the backend path
    /// delegates expiry to the key TTL instead).
    local_pending: Mutex<HashMap<String, (PendingTotp, Instant)>>,
    pending_ttl: Duration,
}

impl std::fmt::Debug for TotpEnrollmentStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpEnrollmentStore")
            .field("backend", &self.backend.is_some())
            .field("pending_ttl", &self.pending_ttl)
            .finish_non_exhaustive()
    }
}

impl TotpEnrollmentStore {
    /// Local-only store — aegis-control tests + single-process fixtures.
    pub fn in_memory() -> Self {
        Self {
            backend: None,
            local_active: Mutex::new(HashMap::new()),
            local_pending: Mutex::new(HashMap::new()),
            pending_ttl: DEFAULT_PENDING_TTL,
        }
    }

    /// Shared store backed by the same [`StateBackend`] as admin
    /// sessions — Redis in cluster mode (fleet-wide + durable), the
    /// in-memory backend on standalone. Production boot path.
    pub fn with_backend(backend: Arc<dyn StateBackend>) -> Self {
        Self {
            backend: Some(backend),
            local_active: Mutex::new(HashMap::new()),
            local_pending: Mutex::new(HashMap::new()),
            pending_ttl: DEFAULT_PENDING_TTL,
        }
    }

    /// Shorten the pending-confirm window (tests).
    pub fn with_pending_ttl(mut self, ttl: Duration) -> Self {
        self.pending_ttl = ttl;
        self
    }

    pub fn pending_ttl(&self) -> Duration {
        self.pending_ttl
    }

    fn pending_key(user: &str) -> String {
        format!("{PENDING_KEY_PREFIX}{user}")
    }

    /// Stage a fresh secret for `user`, replacing any prior pending
    /// enrollment. Not a factor until [`Self::activate`] — login ignores
    /// pending secrets entirely.
    pub async fn begin_enrollment(
        &self,
        user: &str,
        secret_b32: &str,
    ) -> aegis_core::Result<()> {
        let pending = PendingTotp { secret_b32: secret_b32.into() };
        if let Some(b) = &self.backend {
            let bytes = serde_json::to_vec(&pending).unwrap_or_default();
            b.set(&Self::pending_key(user), &bytes, self.pending_ttl).await?;
        } else {
            self.local_pending.lock().unwrap().insert(
                user.to_string(),
                (pending, Instant::now() + self.pending_ttl),
            );
        }
        Ok(())
    }

    /// The staged-but-unconfirmed secret for `user`, if it hasn't
    /// expired.
    pub async fn pending_secret(&self, user: &str) -> Option<String> {
        if let Some(b) = &self.backend {
            let bytes = b.get(&Self::pending_key(user)).await.ok()??;
            let pending: PendingTotp = serde_json::from_slice(&bytes).ok()?;
            Some(pending.secret_b32)
        } else {
            let mut map = self.local_pending.lock().unwrap();
            match map.get(user) {
                Some((_, deadline)) if Instant::now() > *deadline => {
                    map.remove(user);
                    None
                }
                Some((pending, _)) => Some(pending.secret_b32.clone()),
                None => None,
            }
        }
    }

    /// Promote the pending secret to the account's active factor and
    /// drop the pending entry. Returns `false` when there was no live
    /// pending enrollment (expired / never started). The CODE check
    /// lives in `api::totp_enrollment::confirm` — this is pure storage.
    pub async fn activate(&self, user: &str) -> aegis_core::Result<bool> {
        let Some(secret_b32) = self.pending_secret(user).await else {
            return Ok(false);
        };
        let active = ActiveTotp {
            secret_b32,
            enabled: true,
            activated_at: chrono::Utc::now(),
        };
        if let Some(b) = &self.backend {
            let bytes = serde_json::to_vec(&active).unwrap_or_default();
            b.hset_multi(ACTIVE_HASH_KEY, &[(user.to_string(), bytes)]).await?;
            let _ = b.del(&Self::pending_key(user)).await;
        } else {
            self.local_active.lock().unwrap().insert(user.to_string(), active);
            self.local_pending.lock().unwrap().remove(user);
        }
        Ok(true)
    }

    /// The account's confirmed factor, if any. Login overlays this over
    /// the YAML-configured state (store wins when present).
    pub async fn active(&self, user: &str) -> Option<ActiveTotp> {
        if let Some(b) = &self.backend {
            // The admin set is a handful of entries — scanning the hash
            // is one round-trip and avoids needing an HGET on the trait.
            let pairs = b.hscan(ACTIVE_HASH_KEY).await.ok()?;
            for (field, bytes) in pairs {
                if field == user {
                    return serde_json::from_slice(&bytes).ok();
                }
            }
            None
        } else {
            self.local_active.lock().unwrap().get(user).cloned()
        }
    }
}
