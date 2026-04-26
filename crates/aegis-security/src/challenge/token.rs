use aegis_core::decision::ChallengeLevel;
use aegis_core::risk::RiskKey;
use aegis_core::state::StateBackend;

use std::time::Duration;

/// Challenge token issuer and verifier using HMAC-signed blake3 tokens.
pub struct ChallengeTokens {
    /// Secret key for HMAC signing.
    key: [u8; 32],
    /// Nonce TTL in seconds.
    nonce_ttl_s: u64,
}

impl ChallengeTokens {
    pub fn new(key: [u8; 32], nonce_ttl_s: u64) -> Self {
        Self { key, nonce_ttl_s }
    }

    /// Issue a challenge token for a given risk key and challenge level.
    ///
    /// Format: `{nonce}:{level_byte}:{mac}`
    pub fn issue(&self, key: &RiskKey, level: ChallengeLevel) -> String {
        let nonce = generate_nonce(key);
        let level_byte = level_to_byte(level);
        let payload = format!("{nonce}:{level_byte}");
        let mac = self.sign(payload.as_bytes());
        format!("{payload}:{mac}")
    }

    /// Verify a challenge token.
    ///
    /// Returns the challenge level if valid, or an error.
    /// Consumes the nonce to prevent replay.
    pub async fn verify(
        &self,
        state: &dyn StateBackend,
        token: &str,
    ) -> Result<ChallengeLevel, TokenError> {
        let parts: Vec<&str> = token.split(':').collect();
        if parts.len() != 3 {
            return Err(TokenError::Malformed);
        }

        let nonce = parts[0];
        let level_byte: u8 = parts[1].parse().map_err(|_| TokenError::Malformed)?;
        let claimed_mac = parts[2];

        // Verify MAC.
        let payload = format!("{nonce}:{level_byte}");
        let expected_mac = self.sign(payload.as_bytes());
        if !constant_time_eq(claimed_mac, &expected_mac) {
            return Err(TokenError::InvalidSignature);
        }

        // Verify level byte is valid.
        let level = byte_to_level(level_byte).ok_or(TokenError::InvalidLevel)?;

        // Consume nonce (single-use).
        let nonce_key = format!("nonce:{nonce}");
        let consumed = state.consume_nonce(&nonce_key).await.map_err(|_| TokenError::StateError)?;
        if !consumed {
            return Err(TokenError::ReplayDetected);
        }

        Ok(level)
    }

    /// Store the nonce before issuing.
    pub async fn store_nonce(
        &self,
        state: &dyn StateBackend,
        key: &RiskKey,
    ) -> aegis_core::Result<()> {
        let nonce = generate_nonce(key);
        let nonce_key = format!("nonce:{nonce}");
        let ttl = Duration::from_secs(self.nonce_ttl_s);
        state.put_nonce(&nonce_key, ttl).await?;
        Ok(())
    }

    fn sign(&self, data: &[u8]) -> String {
        let mut hasher = blake3::Hasher::new_keyed(&self.key);
        hasher.update(data);
        hasher.finalize().to_hex()[..32].to_string()
    }
}

#[derive(Debug, PartialEq)]
pub enum TokenError {
    Malformed,
    InvalidSignature,
    InvalidLevel,
    ReplayDetected,
    StateError,
}

fn generate_nonce(key: &RiskKey) -> String {
    let input = format!("{}:{:?}:{:?}:{}", key.ip, key.device_fp, key.session, timestamp_ms());
    let hash = blake3::hash(input.as_bytes());
    hash.to_hex()[..24].to_string()
}

fn timestamp_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn level_to_byte(level: ChallengeLevel) -> u8 {
    match level {
        ChallengeLevel::Js => 1,
        ChallengeLevel::Pow => 2,
        ChallengeLevel::Captcha => 3,
    }
}

fn byte_to_level(byte: u8) -> Option<ChallengeLevel> {
    match byte {
        1 => Some(ChallengeLevel::Js),
        2 => Some(ChallengeLevel::Pow),
        3 => Some(ChallengeLevel::Captcha),
        _ => None,
    }
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::Mutex;

    struct MockState {
        nonces: Mutex<HashMap<String, bool>>,
    }

    impl MockState {
        fn new() -> Self {
            Self { nonces: Mutex::new(HashMap::new()) }
        }
    }

    #[async_trait::async_trait]
    impl StateBackend for MockState {
        async fn get(&self, _k: &str) -> aegis_core::Result<Option<Vec<u8>>> { Ok(None) }
        async fn set(&self, _k: &str, _v: &[u8], _t: Duration) -> aegis_core::Result<()> { Ok(()) }
        async fn del(&self, _k: &str) -> aegis_core::Result<()> { Ok(()) }
        async fn incr_window(&self, _k: &str, _w: Duration, _l: u64) -> aegis_core::Result<aegis_core::SlidingWindowResult> {
            Ok(aegis_core::SlidingWindowResult { count: 0, allowed: true, retry_after: None })
        }
        async fn token_bucket(&self, _k: &str, _r: u32, _b: u32) -> aegis_core::Result<bool> { Ok(true) }
        async fn get_risk(&self, _k: &aegis_core::RiskKey) -> aegis_core::Result<u32> { Ok(0) }
        async fn add_risk(&self, _k: &aegis_core::RiskKey, _d: i32, _m: u32) -> aegis_core::Result<u32> { Ok(0) }
        async fn auto_block(&self, _ip: IpAddr, _t: Duration) -> aegis_core::Result<()> { Ok(()) }
        async fn is_auto_blocked(&self, _ip: IpAddr) -> aegis_core::Result<bool> { Ok(false) }
        async fn put_nonce(&self, nonce: &str, _t: Duration) -> aegis_core::Result<bool> {
            let mut map = self.nonces.lock().unwrap();
            Ok(map.insert(nonce.into(), true).is_none())
        }
        async fn consume_nonce(&self, nonce: &str) -> aegis_core::Result<bool> {
            let mut map = self.nonces.lock().unwrap();
            Ok(map.remove(nonce).is_some())
        }
    }

    fn test_key() -> RiskKey {
        RiskKey {
            ip: "10.0.0.1".parse().unwrap(),
            device_fp: Some("fp".into()),
            session: Some("sess".into()),
            tenant_id: None,
        }
    }

    #[test]
    fn issue_produces_valid_format() {
        let tokens = ChallengeTokens::new([42u8; 32], 300);
        let key = test_key();
        let token = tokens.issue(&key, ChallengeLevel::Js);
        let parts: Vec<&str> = token.split(':').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].len(), 24); // nonce
        assert_eq!(parts[1], "1");       // Js level
        assert_eq!(parts[2].len(), 32); // mac
    }

    #[tokio::test]
    async fn verify_valid_token() {
        let state = MockState::new();
        let tokens = ChallengeTokens::new([42u8; 32], 300);
        let key = test_key();

        // Store nonce first, then issue.
        tokens.store_nonce(&state, &key).await.unwrap();
        let token = tokens.issue(&key, ChallengeLevel::Pow);

        let result = tokens.verify(&state, &token).await;
        assert!(matches!(result, Ok(ChallengeLevel::Pow)));
    }

    #[tokio::test]
    async fn replay_rejected() {
        let state = MockState::new();
        let tokens = ChallengeTokens::new([42u8; 32], 300);
        let key = test_key();

        tokens.store_nonce(&state, &key).await.unwrap();
        let token = tokens.issue(&key, ChallengeLevel::Js);

        // First verify succeeds.
        tokens.verify(&state, &token).await.unwrap();

        // Second verify fails (nonce consumed).
        let result = tokens.verify(&state, &token).await;
        assert_eq!(result.unwrap_err(), TokenError::ReplayDetected);
    }

    #[tokio::test]
    async fn tampered_mac_rejected() {
        let state = MockState::new();
        let tokens = ChallengeTokens::new([42u8; 32], 300);
        let key = test_key();

        tokens.store_nonce(&state, &key).await.unwrap();
        let token = tokens.issue(&key, ChallengeLevel::Js);

        // Tamper with the mac.
        let parts: Vec<&str> = token.split(':').collect();
        let tampered = format!("{}:{}:00000000000000000000000000000000", parts[0], parts[1]);

        let result = tokens.verify(&state, &tampered).await;
        assert_eq!(result.unwrap_err(), TokenError::InvalidSignature);
    }

    #[tokio::test]
    async fn downgrade_attempt_rejected() {
        let state = MockState::new();
        let tokens = ChallengeTokens::new([42u8; 32], 300);
        let key = test_key();

        tokens.store_nonce(&state, &key).await.unwrap();
        let token = tokens.issue(&key, ChallengeLevel::Captcha);

        // Try to change level from 3 (Captcha) to 1 (Js) → MAC mismatch.
        let parts: Vec<&str> = token.split(':').collect();
        let downgrade = format!("{}:1:{}", parts[0], parts[2]);

        let result = tokens.verify(&state, &downgrade).await;
        assert_eq!(result.unwrap_err(), TokenError::InvalidSignature);
    }

    #[test]
    fn malformed_token_rejected() {
        let tokens = ChallengeTokens::new([42u8; 32], 300);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let state = MockState::new();
        let result = rt.block_on(tokens.verify(&state, "garbage"));
        assert_eq!(result.unwrap_err(), TokenError::Malformed);
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("ab", "abc"));
    }
}
