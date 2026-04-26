/// HMAC session cookie + SessionRecord.
///
/// Cookie: `aegis_session = base64url(HMAC_SHA256(key, id||issued_at||ip||ua_hash))`
/// Flags: HttpOnly; Secure; SameSite=Strict
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Mutex;

type HmacSha256 = Hmac<Sha256>;

/// Session record stored server-side.
#[derive(Clone, Debug)]
pub struct SessionRecord {
    pub id: String,
    pub issued_at: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub ip: String,
    pub ua_hash: String,
    pub totp_verified: bool,
}

/// Session store (in-memory; production uses etcd/Redis).
pub struct SessionStore {
    key: [u8; 32],
    sessions: Mutex<HashMap<String, SessionRecord>>,
    idle_ttl: Duration,
    absolute_ttl: Duration,
}

impl SessionStore {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            sessions: Mutex::new(HashMap::new()),
            idle_ttl: Duration::minutes(30),
            absolute_ttl: Duration::hours(8),
        }
    }

    /// Create a new session and return the cookie value.
    pub fn create(&self, ip: &str, user_agent: &str) -> (String, String) {
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

        let cookie = self.sign_cookie(&id, now.timestamp(), ip, &ua_hash);
        self.sessions.lock().unwrap().insert(id.clone(), record);
        (id, cookie)
    }

    /// Validate a session cookie. Returns the session record if valid.
    pub fn validate(&self, cookie: &str) -> Option<SessionRecord> {
        let (id, issued_ts, ip, ua_hash) = self.parse_cookie(cookie)?;
        let mut sessions = self.sessions.lock().unwrap();
        let record = sessions.get_mut(&id)?;

        // Verify HMAC.
        let expected = self.sign_cookie(&id, issued_ts, &ip, &ua_hash);
        if !constant_time_eq(cookie.as_bytes(), expected.as_bytes()) {
            return None;
        }

        let now = Utc::now();

        // Check absolute TTL.
        if now - record.issued_at > self.absolute_ttl {
            sessions.remove(&id);
            return None;
        }

        // Check idle TTL.
        if now - record.last_seen > self.idle_ttl {
            sessions.remove(&id);
            return None;
        }

        record.last_seen = now;
        Some(record.clone())
    }

    /// Revoke a session by ID.
    pub fn revoke(&self, session_id: &str) -> bool {
        self.sessions.lock().unwrap().remove(session_id).is_some()
    }

    /// Mark a session as TOTP-verified.
    pub fn mark_totp_verified(&self, session_id: &str) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(record) = sessions.get_mut(session_id) {
            record.totp_verified = true;
            true
        } else {
            false
        }
    }

    /// Active session count.
    pub fn active_count(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    fn sign_cookie(&self, id: &str, issued_ts: i64, ip: &str, ua_hash: &str) -> String {
        let payload = format!("{id}||{issued_ts}||{ip}||{ua_hash}");
        let mut mac = HmacSha256::new_from_slice(&self.key).unwrap();
        mac.update(payload.as_bytes());
        let result = mac.finalize().into_bytes();
        let encoded = base64url_encode(&result);
        format!("{id}.{encoded}")
    }

    fn parse_cookie(&self, cookie: &str) -> Option<(String, i64, String, String)> {
        let parts: Vec<&str> = cookie.splitn(2, '.').collect();
        if parts.len() != 2 {
            return None;
        }
        let id = parts[0];
        let sessions = self.sessions.lock().unwrap();
        let record = sessions.get(id)?;
        Some((
            id.into(),
            record.issued_at.timestamp(),
            record.ip.clone(),
            record.ua_hash.clone(),
        ))
    }
}

/// Format the Set-Cookie header value.
pub fn format_cookie(name: &str, value: &str, max_age_s: i64) -> String {
    format!(
        "{name}={value}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={max_age_s}"
    )
}

fn generate_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    let cnt = CTR.fetch_add(1, Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let hash = blake3::hash(format!("{now}:{cnt}").as_bytes());
    hash.to_hex()[..24].to_string()
}

fn base64url_encode(data: &[u8]) -> String {
    let b64: String = data.iter().map(|b| format!("{b:02x}")).collect();
    b64.replace('+', "-").replace('/', "_").trim_end_matches('=').to_string()
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

    #[test]
    fn create_session() {
        let store = SessionStore::new(TEST_KEY);
        let (id, cookie) = store.create("1.2.3.4", "Mozilla/5.0");
        assert!(!id.is_empty());
        assert!(cookie.contains('.'));
        assert_eq!(store.active_count(), 1);
    }

    #[test]
    fn validate_valid_session() {
        let store = SessionStore::new(TEST_KEY);
        let (_, cookie) = store.create("1.2.3.4", "Mozilla/5.0");
        let record = store.validate(&cookie).unwrap();
        assert_eq!(record.ip, "1.2.3.4");
        assert!(!record.totp_verified);
    }

    #[test]
    fn validate_invalid_cookie() {
        let store = SessionStore::new(TEST_KEY);
        assert!(store.validate("garbage").is_none());
    }

    #[test]
    fn validate_tampered_cookie() {
        let store = SessionStore::new(TEST_KEY);
        let (_, cookie) = store.create("1.2.3.4", "Mozilla/5.0");
        let tampered = format!("{cookie}X");
        assert!(store.validate(&tampered).is_none());
    }

    #[test]
    fn revoke_session() {
        let store = SessionStore::new(TEST_KEY);
        let (id, cookie) = store.create("1.2.3.4", "Mozilla/5.0");
        assert!(store.revoke(&id));
        assert!(store.validate(&cookie).is_none());
        assert_eq!(store.active_count(), 0);
    }

    #[test]
    fn revoke_nonexistent() {
        let store = SessionStore::new(TEST_KEY);
        assert!(!store.revoke("no-such-id"));
    }

    #[test]
    fn mark_totp_verified() {
        let store = SessionStore::new(TEST_KEY);
        let (id, cookie) = store.create("1.2.3.4", "Mozilla/5.0");
        assert!(store.mark_totp_verified(&id));
        let record = store.validate(&cookie).unwrap();
        assert!(record.totp_verified);
    }

    #[test]
    fn unique_session_ids() {
        let store = SessionStore::new(TEST_KEY);
        let (id1, _) = store.create("1.2.3.4", "ua");
        let (id2, _) = store.create("1.2.3.4", "ua");
        assert_ne!(id1, id2);
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
    fn constant_time_eq_same() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn constant_time_eq_different() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn constant_time_eq_different_len() {
        assert!(!constant_time_eq(b"short", b"longer"));
    }
}
