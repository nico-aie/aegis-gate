//! `/api/admin/*` self-service (D-M4-T4.7..T4.10).
//!
//! Password change, TOTP, sessions, policy, break-glass,
//! integrations. Most actions delegate to the existing `admin_auth`
//! module; this layer is just the JSON-shape adapter + the
//! in-memory state for break-glass + sessions until the etcd-backed
//! cluster runtime lands.


use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize)]
pub struct PasswordChangeRequest {
    pub current: String,
    pub new: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct PasswordChangeResponse {
    pub ok: bool,
    pub error: Option<String>,
}

/// Verify a password change. The `verify_current` closure verifies
/// the supplied current password against the stored hash;
/// `apply_new` stores the new hash; `invalidate_sessions` is called
/// after a successful password change to drop every existing admin
/// session. This indirection keeps `aegis-control` independent of
/// the secret-provider plumbing.
///
/// **2026-05-11 PR #8 (CTL-20)** — session invalidation was missing
/// from the original signature, leaving stolen session cookies
/// valid after a password reset. The `invalidate_sessions` closure
/// is now mandatory; production callers should hand it a closure
/// that wipes the [`crate::admin_auth::session::AuthSessionStore`]
/// for the user. Test bundles can pass `|| {}` if they're just
/// exercising the validation surface.
pub fn handle_password_change<V, A, I>(
    req: &PasswordChangeRequest,
    verify_current: V,
    apply_new: A,
    invalidate_sessions: I,
) -> PasswordChangeResponse
where
    V: FnOnce(&str) -> bool,
    A: FnOnce(&str) -> Result<(), String>,
    I: FnOnce(),
{
    if req.new.len() < 12 {
        return PasswordChangeResponse {
            ok: false,
            error: Some("new password must be ≥ 12 chars".into()),
        };
    }
    if req.current == req.new {
        return PasswordChangeResponse {
            ok: false,
            error: Some("new password equals current".into()),
        };
    }
    if !verify_current(&req.current) {
        return PasswordChangeResponse {
            ok: false,
            error: Some("current password incorrect".into()),
        };
    }
    match apply_new(&req.new) {
        Ok(()) => {
            // Invalidate sessions AFTER the new hash is persisted so
            // a hash-store failure doesn't strand the operator with
            // no way back in.
            invalidate_sessions();
            PasswordChangeResponse {
                ok: true,
                error: None,
            }
        }
        Err(e) => PasswordChangeResponse {
            ok: false,
            error: Some(e),
        },
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionInfo {
    pub id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    pub ip: String,
    pub user_agent: String,
    pub current: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionsResponse {
    pub sessions: Vec<SessionInfo>,
}

#[derive(Default)]
struct SessionStoreState {
    sessions: HashMap<String, SessionInfo>,
    current_id: Option<String>,
}

#[derive(Clone, Default)]
pub struct SessionStore {
    inner: Arc<Mutex<SessionStoreState>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upsert(&self, mut info: SessionInfo) {
        let mut s = self.inner.lock().expect("session store poisoned");
        if let Some(curr) = &s.current_id {
            info.current = info.id == *curr;
        }
        s.sessions.insert(info.id.clone(), info);
    }

    pub fn mark_current(&self, id: &str) {
        let mut s = self.inner.lock().expect("session store poisoned");
        s.current_id = Some(id.into());
        for (sid, sess) in s.sessions.iter_mut() {
            sess.current = sid == id;
        }
    }

    pub fn list(&self) -> Vec<SessionInfo> {
        let s = self.inner.lock().expect("session store poisoned");
        let mut v: Vec<SessionInfo> = s.sessions.values().cloned().collect();
        v.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        v
    }

    /// Returns `true` if the session existed and was not the current
    /// one. Revoking the current session via this endpoint is rejected
    /// (use `/admin/logout` instead) to prevent foot-gun.
    pub fn revoke(&self, id: &str) -> Result<(), String> {
        let mut s = self.inner.lock().expect("session store poisoned");
        if s.current_id.as_deref() == Some(id) {
            return Err("cannot revoke current session via this endpoint".into());
        }
        if s.sessions.remove(id).is_none() {
            return Err(format!("unknown session: {id}"));
        }
        Ok(())
    }

    /// Remove a session unconditionally — used by `/admin/logout`,
    /// which is the documented escape hatch when an operator
    /// needs to invalidate their *own* current session.
    /// Returns `true` if a row was removed.
    pub fn force_remove(&self, id: &str) -> bool {
        let mut s = self.inner.lock().expect("session store poisoned");
        if s.current_id.as_deref() == Some(id) {
            s.current_id = None;
        }
        s.sessions.remove(id).is_some()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct BreakGlassResponse {
    pub active: bool,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct BreakGlassRequest {
    /// Free-form reason — surfaced in the audit chain + the dashboard
    /// banner.
    pub reason: String,
    /// TTL in seconds. Clamped to [60, 3600].
    pub ttl_seconds: u64,
}

#[derive(Default)]
struct BreakGlassState {
    active_until: Option<chrono::DateTime<chrono::Utc>>,
    reason: Option<String>,
}

#[derive(Clone, Default)]
pub struct BreakGlass {
    inner: Arc<Mutex<BreakGlassState>>,
}

impl BreakGlass {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enable(&self, req: BreakGlassRequest) -> BreakGlassResponse {
        let ttl = req.ttl_seconds.clamp(60, 3600) as i64;
        let until = chrono::Utc::now() + chrono::Duration::seconds(ttl);
        let mut s = self.inner.lock().expect("break glass poisoned");
        s.active_until = Some(until);
        s.reason = Some(req.reason.clone());
        BreakGlassResponse {
            active: true,
            expires_at: Some(until),
            reason: Some(req.reason),
        }
    }

    pub fn disable(&self) {
        let mut s = self.inner.lock().expect("break glass poisoned");
        s.active_until = None;
        s.reason = None;
    }

    pub fn snapshot(&self) -> BreakGlassResponse {
        let s = self.inner.lock().expect("break glass poisoned");
        match s.active_until {
            Some(t) if t > chrono::Utc::now() => BreakGlassResponse {
                active: true,
                expires_at: Some(t),
                reason: s.reason.clone(),
            },
            _ => BreakGlassResponse {
                active: false,
                expires_at: None,
                reason: None,
            },
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct IntegrationsResponse {
    pub grafana_url: Option<String>,
    pub alertmanager_url: Option<String>,
    pub gitops_repo: Option<String>,
    pub prometheus_url: Option<String>,
}

impl IntegrationsResponse {
    /// Constructed from the live config on every read — these are
    /// pure config mirrors, no separate state.
    pub fn from_config(cfg: &aegis_core::config::WafConfig) -> Self {
        // Optional fields not yet on AdminConfig — return None for
        // now; future config additions populate them.
        let _ = cfg;
        Self {
            grafana_url: None,
            alertmanager_url: None,
            gitops_repo: None,
            prometheus_url: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_too_short_rejected() {
        let invalidated = std::cell::Cell::new(false);
        let r = handle_password_change(
            &PasswordChangeRequest {
                current: "abcdefghijkl".into(),
                new: "short".into(),
            },
            |_| true,
            |_| Ok(()),
            || invalidated.set(true),
        );
        assert!(!r.ok);
        assert!(r.error.unwrap().contains("12"));
        // CTL-20 — sessions must NOT be invalidated on a failed change.
        assert!(!invalidated.get());
    }

    #[test]
    fn password_same_as_current_rejected() {
        let invalidated = std::cell::Cell::new(false);
        let r = handle_password_change(
            &PasswordChangeRequest {
                current: "current-password-1".into(),
                new: "current-password-1".into(),
            },
            |_| true,
            |_| Ok(()),
            || invalidated.set(true),
        );
        assert!(!r.ok);
        assert!(!invalidated.get());
    }

    #[test]
    fn password_wrong_current_rejected() {
        let invalidated = std::cell::Cell::new(false);
        let r = handle_password_change(
            &PasswordChangeRequest {
                current: "wrong".into(),
                new: "new-password-99".into(),
            },
            |_| false,
            |_| Ok(()),
            || invalidated.set(true),
        );
        assert!(!r.ok);
        assert!(!invalidated.get());
    }

    #[test]
    fn password_change_succeeds_when_inputs_valid() {
        let invalidated = std::cell::Cell::new(false);
        let r = handle_password_change(
            &PasswordChangeRequest {
                current: "current-password-1".into(),
                new: "new-password-9999".into(),
            },
            |_| true,
            |_| Ok(()),
            || invalidated.set(true),
        );
        assert!(r.ok);
        // CTL-20 — sessions MUST be invalidated on a successful change.
        assert!(invalidated.get(), "session invalidation closure was not called");
    }

    #[test]
    fn password_change_does_not_invalidate_when_apply_fails() {
        // CTL-20 — if the hash store rejects the new password,
        // sessions stay intact so the operator isn't stranded.
        let invalidated = std::cell::Cell::new(false);
        let r = handle_password_change(
            &PasswordChangeRequest {
                current: "current-password-1".into(),
                new: "new-password-9999".into(),
            },
            |_| true,
            |_| Err("hash store unavailable".into()),
            || invalidated.set(true),
        );
        assert!(!r.ok);
        assert!(!invalidated.get());
    }

    fn session(id: &str) -> SessionInfo {
        SessionInfo {
            id: id.into(),
            created_at: chrono::Utc::now(),
            last_seen: chrono::Utc::now(),
            ip: "1.1.1.1".into(),
            user_agent: "test".into(),
            current: false,
        }
    }

    #[test]
    fn session_store_revoke_rejects_current() {
        let s = SessionStore::new();
        s.upsert(session("a"));
        s.upsert(session("b"));
        s.mark_current("a");
        assert!(s.revoke("a").is_err());
        assert_eq!(s.list().len(), 2);
    }

    #[test]
    fn session_store_revoke_removes_other() {
        let s = SessionStore::new();
        s.upsert(session("a"));
        s.upsert(session("b"));
        s.mark_current("a");
        s.revoke("b").unwrap();
        assert_eq!(s.list().len(), 1);
    }

    #[test]
    fn break_glass_enables_with_clamped_ttl() {
        let bg = BreakGlass::new();
        let r = bg.enable(BreakGlassRequest {
            reason: "incident-1234".into(),
            ttl_seconds: 99_999,
        });
        assert!(r.active);
        // Clamped to 3600s (1h).
        let until = r.expires_at.unwrap();
        let cap = chrono::Utc::now() + chrono::Duration::seconds(3600);
        assert!(until <= cap + chrono::Duration::seconds(2));
    }

    #[test]
    fn break_glass_disable_clears_state() {
        let bg = BreakGlass::new();
        bg.enable(BreakGlassRequest {
            reason: "x".into(),
            ttl_seconds: 600,
        });
        bg.disable();
        let s = bg.snapshot();
        assert!(!s.active);
        assert!(s.expires_at.is_none());
    }

    #[test]
    fn break_glass_snapshot_inactive_after_expiry() {
        let bg = BreakGlass::new();
        // ttl_seconds clamps to 60 minimum; manipulate state directly
        // for the test by enabling then forcing the timestamp into
        // the past.
        bg.enable(BreakGlassRequest {
            reason: "x".into(),
            ttl_seconds: 60,
        });
        {
            let mut s = bg.inner.lock().unwrap();
            s.active_until = Some(chrono::Utc::now() - chrono::Duration::seconds(1));
        }
        assert!(!bg.snapshot().active);
    }
}
