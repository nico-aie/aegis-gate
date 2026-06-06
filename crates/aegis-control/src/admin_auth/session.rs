//! HMAC session cookie + server-side `SessionRecord`.
//!
//! Cookie: `<id>.<hex(HMAC_SHA256(key, id||issued_at||ip||ua_hash))>`.
//! The `id` is a 122-bit UUID (the real bearer secret); the HMAC binds the
//! cookie's integrity so a leaked-id-only can't be forged into a valid cookie.
//! Flags: HttpOnly; Secure; SameSite=Strict (see [`format_cookie`]).
//!
//! **Storage:** records persist through a shared [`StateBackend`] when one is
//! wired (`with_backend`) — Redis in a multi-node deploy (records are
//! fleet-wide + auto-expire via the key TTL), or the auto-reaped in-memory
//! backend. With no backend (`new` / `with_ttls`, used by tests + the
//! aegis-control default fixtures) records live in a local map — single-node,
//! pruned lazily on validate.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use aegis_core::state::StateBackend;

type HmacSha256 = Hmac<Sha256>;

/// Key namespace for session records in the shared backend.
const KEY_PREFIX: &str = "adminsess:";

/// Session record (server-side; serialized into the shared backend).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionRecord {
    pub id: String,
    pub issued_at: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub ip: String,
    pub ua_hash: String,
    pub totp_verified: bool,
}

/// Session store. Records live in a shared [`StateBackend`] when one is wired
/// (multi-node + auto-reaped), else in a local map (single-node fallback).
pub struct SessionStore {
    key: [u8; 32],
    /// Shared store (Redis / in-mem backend). `None` ⇒ local-map fallback.
    backend: Option<Arc<dyn StateBackend>>,
    /// Local fallback when `backend` is `None`.
    local: Mutex<HashMap<String, SessionRecord>>,
    idle_ttl: Duration,
    absolute_ttl: Duration,
}

impl SessionStore {
    /// Local-only store, default TTLs (idle 30m / absolute 8h). For tests +
    /// the aegis-control default fixtures.
    pub fn new(key: [u8; 32]) -> Self {
        Self::with_ttls(key, Duration::minutes(30), Duration::hours(8))
    }

    /// Local-only store with explicit TTLs.
    pub fn with_ttls(key: [u8; 32], idle_ttl: Duration, absolute_ttl: Duration) -> Self {
        Self {
            key,
            backend: None,
            local: Mutex::new(HashMap::new()),
            idle_ttl,
            absolute_ttl,
        }
    }

    /// Shared store backed by `backend` (Redis ⇒ fleet-wide + restart-durable;
    /// any backend ⇒ records auto-expire at the idle TTL, which also reaps
    /// abandoned sessions). Production boot path (`accept.rs`) uses this.
    pub fn with_backend(
        key: [u8; 32],
        backend: Arc<dyn StateBackend>,
        idle_ttl: Duration,
        absolute_ttl: Duration,
    ) -> Self {
        Self {
            key,
            backend: Some(backend),
            local: Mutex::new(HashMap::new()),
            idle_ttl,
            absolute_ttl,
        }
    }

    fn skey(id: &str) -> String {
        format!("{KEY_PREFIX}{id}")
    }

    fn idle_std(&self) -> std::time::Duration {
        self.idle_ttl.to_std().unwrap_or(std::time::Duration::from_secs(1800))
    }

    async fn put_record(&self, record: &SessionRecord) {
        if let Some(b) = &self.backend {
            let bytes = serde_json::to_vec(record).unwrap_or_default();
            // Idle TTL on the key auto-expires (and reaps) abandoned sessions;
            // absolute TTL is enforced on read from `issued_at`.
            let _ = b.set(&Self::skey(&record.id), &bytes, self.idle_std()).await;
        } else {
            self.local
                .lock()
                .unwrap()
                .insert(record.id.clone(), record.clone());
        }
    }

    async fn get_record(&self, id: &str) -> Option<SessionRecord> {
        if let Some(b) = &self.backend {
            let bytes = b.get(&Self::skey(id)).await.ok()??;
            serde_json::from_slice(&bytes).ok()
        } else {
            self.local.lock().unwrap().get(id).cloned()
        }
    }

    async fn del_record(&self, id: &str) -> bool {
        if let Some(b) = &self.backend {
            let existed = b.get(&Self::skey(id)).await.ok().flatten().is_some();
            let _ = b.del(&Self::skey(id)).await;
            existed
        } else {
            self.local.lock().unwrap().remove(id).is_some()
        }
    }

    /// Create a new session; returns `(id, signed cookie value)`.
    pub async fn create(&self, ip: &str, user_agent: &str) -> (String, String) {
        let id = generate_id();
        let now = Utc::now();
        let ua_hash = blake3::hash(user_agent.as_bytes()).to_hex().to_string();
        let record = SessionRecord {
            id: id.clone(),
            issued_at: now,
            last_seen: now,
            ip: ip.into(),
            ua_hash: ua_hash.clone(),
            totp_verified: false,
        };
        self.put_record(&record).await;
        let cookie = self.sign_cookie(&id, now.timestamp(), ip, &ua_hash);
        (id, cookie)
    }

    /// Validate a session cookie. Returns the record when the cookie's HMAC is
    /// valid and the session is within both TTLs (and slides the idle window).
    pub async fn validate(&self, cookie: &str) -> Option<SessionRecord> {
        let id = cookie.split('.').next()?;
        let mut record = self.get_record(id).await?;

        // Verify HMAC over the record's own fields.
        let expected = self.sign_cookie(
            &record.id,
            record.issued_at.timestamp(),
            &record.ip,
            &record.ua_hash,
        );
        if !constant_time_eq(cookie.as_bytes(), expected.as_bytes()) {
            return None;
        }

        let now = Utc::now();
        if now - record.issued_at > self.absolute_ttl || now - record.last_seen > self.idle_ttl {
            self.del_record(id).await;
            return None;
        }

        // Slide the idle window (re-stores with a fresh idle TTL).
        record.last_seen = now;
        self.put_record(&record).await;
        Some(record)
    }

    /// Revoke a session by ID. Returns whether it existed.
    pub async fn revoke(&self, session_id: &str) -> bool {
        self.del_record(session_id).await
    }

    /// Mark a session TOTP-verified (the step-up second factor succeeded).
    pub async fn mark_totp_verified(&self, session_id: &str) -> bool {
        if let Some(mut record) = self.get_record(session_id).await {
            record.totp_verified = true;
            self.put_record(&record).await;
            true
        } else {
            false
        }
    }

    /// Active session count (best-effort; SCAN on the shared backend).
    pub async fn active_count(&self) -> usize {
        if let Some(b) = &self.backend {
            b.scan_prefix(KEY_PREFIX).await.map(|v| v.len()).unwrap_or(0)
        } else {
            self.local.lock().unwrap().len()
        }
    }

    fn sign_cookie(&self, id: &str, issued_ts: i64, ip: &str, ua_hash: &str) -> String {
        let payload = format!("{id}||{issued_ts}||{ip}||{ua_hash}");
        let mut mac = HmacSha256::new_from_slice(&self.key).unwrap();
        mac.update(payload.as_bytes());
        let encoded = hex_encode(&mac.finalize().into_bytes());
        format!("{id}.{encoded}")
    }
}

/// Format the `Set-Cookie` header value. `Secure` is included unless the
/// dev-only `AEGIS_INSECURE_COOKIES=1` opt-out is set (plain-HTTP admin
/// listener; the Makefile `run-dev` target sets it).
pub fn format_cookie(name: &str, value: &str, max_age_s: i64) -> String {
    let secure = if crate::admin_auth::csrf::insecure_cookies_enabled() {
        ""
    } else {
        "Secure; "
    };
    format!("{name}={value}; HttpOnly; {secure}SameSite=Strict; Path=/; Max-Age={max_age_s}")
}

fn generate_id() -> String {
    // UUID v4 (getrandom) — 122 bits of CSPRNG entropy per call.
    uuid::Uuid::new_v4().simple().to_string()
}

/// Lowercase hex of the HMAC digest (URL-safe by construction: no `+`/`/`/`=`).
fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: [u8; 32] = [1u8; 32];

    #[tokio::test]
    async fn create_and_validate_session() {
        let store = SessionStore::new(TEST_KEY);
        let (id, cookie) = store.create("1.2.3.4", "Mozilla/5.0").await;
        assert!(!id.is_empty());
        assert!(cookie.contains('.'));
        let record = store.validate(&cookie).await.unwrap();
        assert_eq!(record.ip, "1.2.3.4");
        assert!(!record.totp_verified);
        assert_eq!(store.active_count().await, 1);
    }

    #[tokio::test]
    async fn rejects_garbage_and_tampered() {
        let store = SessionStore::new(TEST_KEY);
        assert!(store.validate("garbage").await.is_none());
        let (_, cookie) = store.create("1.2.3.4", "ua").await;
        assert!(store.validate(&format!("{cookie}X")).await.is_none());
    }

    #[tokio::test]
    async fn revoke_session() {
        let store = SessionStore::new(TEST_KEY);
        let (id, cookie) = store.create("1.2.3.4", "ua").await;
        assert!(store.revoke(&id).await);
        assert!(store.validate(&cookie).await.is_none());
        assert!(!store.revoke("no-such-id").await);
    }

    #[tokio::test]
    async fn mark_totp_verified() {
        let store = SessionStore::new(TEST_KEY);
        let (id, cookie) = store.create("1.2.3.4", "ua").await;
        assert!(store.mark_totp_verified(&id).await);
        assert!(store.validate(&cookie).await.unwrap().totp_verified);
    }

    #[tokio::test]
    async fn unique_session_ids() {
        let store = SessionStore::new(TEST_KEY);
        let (id1, _) = store.create("1.2.3.4", "ua").await;
        let (id2, _) = store.create("1.2.3.4", "ua").await;
        assert_ne!(id1, id2);
    }

    #[tokio::test]
    async fn honors_idle_ttl() {
        let store = SessionStore::with_ttls(TEST_KEY, Duration::seconds(1), Duration::hours(1));
        let (id, cookie) = store.create("1.2.3.4", "ua").await;
        {
            let mut g = store.local.lock().unwrap();
            g.get_mut(&id).unwrap().last_seen = Utc::now() - Duration::seconds(5);
        }
        assert!(store.validate(&cookie).await.is_none(), "expired idle not rejected");
    }

    #[tokio::test]
    async fn honors_absolute_ttl() {
        let store = SessionStore::with_ttls(TEST_KEY, Duration::hours(1), Duration::seconds(1));
        let (id, cookie) = store.create("1.2.3.4", "ua").await;
        {
            let mut g = store.local.lock().unwrap();
            g.get_mut(&id).unwrap().issued_at = Utc::now() - Duration::seconds(5);
        }
        assert!(store.validate(&cookie).await.is_none(), "absolute TTL not enforced");
    }

    #[tokio::test]
    async fn session_ids_are_unpredictable_across_many_calls() {
        let store = SessionStore::new(TEST_KEY);
        let mut set = std::collections::HashSet::new();
        for _ in 0..2_000 {
            let (id, _) = store.create("1.2.3.4", "ua").await;
            assert!(set.insert(id), "session id collision");
        }
    }

    #[test]
    fn format_cookie_flags() {
        let c = format_cookie("aegis_session", "val123", 1800);
        assert!(c.contains("HttpOnly"));
        assert!(c.contains("Secure"));
        assert!(c.contains("SameSite=Strict"));
        assert!(c.contains("Max-Age=1800"));
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"short", b"longer"));
    }
}
