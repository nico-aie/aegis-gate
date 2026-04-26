/// API key management with scopes and rate limits.
use std::collections::HashMap;

/// An API key consumer.
#[derive(Clone, Debug)]
pub struct ApiKeyEntry {
    pub consumer_id: String,
    pub key_hash: String,
    pub scopes: Vec<String>,
    pub rate_limit: Option<u64>,
    pub revoked: bool,
}

/// API key store.
pub struct ApiKeyStore {
    keys: HashMap<String, ApiKeyEntry>,
}

/// API key verification result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApiKeyResult {
    Valid { consumer_id: String },
    Revoked,
    NotFound,
    ScopeMismatch { required: String },
    MissingKey,
}

impl ApiKeyStore {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Register a key (hashed with blake3 for storage).
    pub fn add_key(&mut self, raw_key: &str, consumer_id: &str, scopes: Vec<String>, rate_limit: Option<u64>) {
        let hash = blake3::hash(raw_key.as_bytes()).to_hex().to_string();
        self.keys.insert(hash.clone(), ApiKeyEntry {
            consumer_id: consumer_id.into(),
            key_hash: hash,
            scopes,
            rate_limit,
            revoked: false,
        });
    }

    /// Revoke a key by raw key.
    pub fn revoke(&mut self, raw_key: &str) {
        let hash = blake3::hash(raw_key.as_bytes()).to_hex().to_string();
        if let Some(entry) = self.keys.get_mut(&hash) {
            entry.revoked = true;
        }
    }

    /// Verify an API key with optional scope check.
    ///
    /// Extracts key from `Authorization: Bearer <key>` or a raw key string.
    pub fn verify(&self, raw_key: Option<&str>, required_scope: Option<&str>) -> ApiKeyResult {
        let key = match raw_key {
            Some(k) => k,
            None => return ApiKeyResult::MissingKey,
        };

        // Strip "Bearer " prefix if present.
        let actual_key = key.strip_prefix("Bearer ").unwrap_or(key);
        let hash = blake3::hash(actual_key.as_bytes()).to_hex().to_string();

        match self.keys.get(&hash) {
            None => ApiKeyResult::NotFound,
            Some(entry) if entry.revoked => ApiKeyResult::Revoked,
            Some(entry) => {
                if let Some(scope) = required_scope {
                    if !entry.scopes.contains(&scope.to_string()) {
                        return ApiKeyResult::ScopeMismatch {
                            required: scope.into(),
                        };
                    }
                }
                ApiKeyResult::Valid {
                    consumer_id: entry.consumer_id.clone(),
                }
            }
        }
    }

    pub fn key_count(&self) -> usize {
        self.keys.len()
    }
}

impl Default for ApiKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_key() {
        let mut store = ApiKeyStore::new();
        store.add_key("my-secret-key", "consumer-1", vec!["read".into(), "write".into()], None);
        let result = store.verify(Some("my-secret-key"), None);
        assert_eq!(result, ApiKeyResult::Valid { consumer_id: "consumer-1".into() });
    }

    #[test]
    fn valid_key_with_bearer() {
        let mut store = ApiKeyStore::new();
        store.add_key("my-secret-key", "consumer-1", vec!["read".into()], None);
        let result = store.verify(Some("Bearer my-secret-key"), None);
        assert_eq!(result, ApiKeyResult::Valid { consumer_id: "consumer-1".into() });
    }

    #[test]
    fn revoked_key() {
        let mut store = ApiKeyStore::new();
        store.add_key("my-key", "consumer-1", vec![], None);
        store.revoke("my-key");
        assert_eq!(store.verify(Some("my-key"), None), ApiKeyResult::Revoked);
    }

    #[test]
    fn unknown_key() {
        let store = ApiKeyStore::new();
        assert_eq!(store.verify(Some("unknown"), None), ApiKeyResult::NotFound);
    }

    #[test]
    fn missing_key() {
        let store = ApiKeyStore::new();
        assert_eq!(store.verify(None, None), ApiKeyResult::MissingKey);
    }

    #[test]
    fn scope_match() {
        let mut store = ApiKeyStore::new();
        store.add_key("key1", "c1", vec!["read".into(), "write".into()], None);
        assert_eq!(store.verify(Some("key1"), Some("read")), ApiKeyResult::Valid { consumer_id: "c1".into() });
    }

    #[test]
    fn scope_mismatch() {
        let mut store = ApiKeyStore::new();
        store.add_key("key1", "c1", vec!["read".into()], None);
        let result = store.verify(Some("key1"), Some("admin"));
        assert_eq!(result, ApiKeyResult::ScopeMismatch { required: "admin".into() });
    }

    #[test]
    fn key_count() {
        let mut store = ApiKeyStore::new();
        store.add_key("k1", "c1", vec![], None);
        store.add_key("k2", "c2", vec![], None);
        assert_eq!(store.key_count(), 2);
    }
}
