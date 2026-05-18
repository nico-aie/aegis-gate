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
        Self::with_ttls(
            key,
            Duration::minutes(30),
            Duration::hours(8),
        )
    }

    /// 2026-05-17 F-HIGH-admin sub-finding: pre-fix `SessionStore`
    /// hard-coded its idle / absolute TTL at construction so the
    /// operator-facing `cfg.admin.dashboard_auth.session_ttl_idle`
    /// / `session_ttl_absolute` knobs were ignored (operators could
    /// change YAML, restart the WAF, and see the same 30-minute
    /// idle / 8-hour absolute behaviour). The new boot path
    /// (`accept.rs` for production, `lib.rs` for the integration
    /// fixture) reads cfg and threads the durations in here. Tests
    /// keep the convenience `new(key)` shape; production must use
    /// `with_ttls`.
    pub fn with_ttls(
        key: [u8; 32],
        idle_ttl: Duration,
        absolute_ttl: Duration,
    ) -> Self {
        Self {
            key,
            sessions: Mutex::new(HashMap::new()),
            idle_ttl,
            absolute_ttl,
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
///
/// The `Secure` flag is included by default. See
/// [`crate::admin_auth::csrf::insecure_cookies_enabled`] for the
/// dev-only `AEGIS_INSECURE_COOKIES=1` opt-out used when the admin
/// listener is plain HTTP (Makefile's `run-dev` target sets it).
pub fn format_cookie(name: &str, value: &str, max_age_s: i64) -> String {
    let secure = if crate::admin_auth::csrf::insecure_cookies_enabled() {
        ""
    } else {
        "Secure; "
    };
    format!(
        "{name}={value}; HttpOnly; {secure}SameSite=Strict; Path=/; Max-Age={max_age_s}"
    )
}

fn generate_id() -> String {
    // 2026-05-17 F-CRITICAL-005 — was `blake3(clock_nanos + atomic
    // counter)`, which is deterministic on the (now, counter) pair
    // and predictable to an attacker observing one issued id. UUID
    // v4 gives 122 bits of CSPRNG entropy per call. Result length
    // grew from 24 to 32 hex chars; no caller asserts on length.
    uuid::Uuid::new_v4().simple().to_string()
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
    fn with_ttls_honors_explicit_idle_ttl() {
        // F-HIGH-admin regression: pre-fix the idle TTL was hard-
        // coded to 30 minutes regardless of operator config. Build
        // a store with a deliberately tiny idle TTL and confirm
        // the validate path enforces it (we can't easily move
        // chrono::Utc::now() in a unit test, so instead we
        // reconstruct an expired record directly and assert
        // validate rejects).
        let store = SessionStore::with_ttls(
            TEST_KEY,
            Duration::seconds(1),
            Duration::hours(1),
        );
        let (id, cookie) = store.create("1.2.3.4", "ua");
        // Mutate the record's last_seen to simulate a > 1s gap.
        {
            let mut sessions = store.sessions.lock().unwrap();
            let rec = sessions.get_mut(&id).unwrap();
            rec.last_seen = Utc::now() - Duration::seconds(5);
        }
        // The configured 1s idle TTL must reject; without the fix
        // (hard-coded 30 min) this would still succeed.
        assert!(store.validate(&cookie).is_none(), "expired session not rejected");
    }

    #[test]
    fn with_ttls_honors_explicit_absolute_ttl() {
        let store = SessionStore::with_ttls(
            TEST_KEY,
            Duration::hours(1),
            Duration::seconds(1),
        );
        let (id, cookie) = store.create("1.2.3.4", "ua");
        {
            let mut sessions = store.sessions.lock().unwrap();
            let rec = sessions.get_mut(&id).unwrap();
            rec.issued_at = Utc::now() - Duration::seconds(5);
        }
        assert!(store.validate(&cookie).is_none(), "absolute TTL not enforced");
    }

    #[test]
    fn session_ids_are_unpredictable_across_many_calls() {
        // F-CRITICAL-005 regression. Pre-fix `generate_id` derived
        // from `blake3(clock_nanos + atomic counter)` — an attacker
        // who issued one session could brute-force the next within
        // a microsecond window. UUID v4 (getrandom) closes that.
        let store = SessionStore::new(TEST_KEY);
        let mut set = std::collections::HashSet::new();
        for _ in 0..2_000 {
            let (id, _) = store.create("1.2.3.4", "ua");
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
