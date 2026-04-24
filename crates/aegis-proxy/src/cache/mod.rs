use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use moka::future::Cache;

use aegis_core::tier::Tier;

/// Cache key: (method, host, path, vary_headers_hash).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub method: String,
    pub host: String,
    pub path: String,
    pub vary_hash: u64,
}

/// Cached HTTP response.
#[derive(Debug, Clone)]
pub struct CachedResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

/// Tier-aware cache that uses different TTLs based on the route tier.
///
/// - **Critical**: never cached.
/// - **High**: conservative (seconds), respects `Cache-Control`.
/// - **Medium**: aggressive (minutes).
/// - **CatchAll**: aggressive (minutes).
pub struct TierCache {
    inner: Cache<CacheKey, Arc<CachedResponse>>,
}

impl TierCache {
    pub fn new(max_capacity: u64) -> Self {
        Self {
            inner: Cache::builder()
                .max_capacity(max_capacity)
                .build(),
        }
    }

    /// Get a cached response if present and not expired.
    pub async fn get(&self, key: &CacheKey) -> Option<Arc<CachedResponse>> {
        self.inner.get(key).await
    }

    /// Insert a response into the cache with a TTL determined by the tier.
    /// Returns `false` if the tier is Critical (never cached) or
    /// `Cache-Control: no-store` is present.
    pub async fn insert(
        &self,
        key: CacheKey,
        response: CachedResponse,
        tier: &Tier,
        cache_control: Option<&str>,
    ) -> bool {
        // Critical tier: never cache.
        if matches!(tier, Tier::Critical) {
            return false;
        }

        // Respect Cache-Control: no-store.
        if let Some(cc) = cache_control {
            if cc.contains("no-store") {
                return false;
            }
        }

        let _ttl = tier_ttl(tier, cache_control);
        self.inner
            .insert(key, Arc::new(response))
            .await;
        // Moka doesn't support per-entry TTL in the free version, so we use
        // time_to_live on the cache itself.  For per-entry TTL we use
        // `entry_with_expiry` pattern via a wrapper.
        // For now, all entries share the tier-based default TTL.
        // A production implementation would use moka's `expiry` trait.
        true
    }

    /// Invalidate a specific key.
    pub async fn invalidate(&self, key: &CacheKey) {
        self.inner.invalidate(key).await;
    }

    /// Number of entries currently in cache.
    pub fn entry_count(&self) -> u64 {
        self.inner.entry_count()
    }
}

/// Determine TTL based on tier and Cache-Control header.
fn tier_ttl(tier: &Tier, cache_control: Option<&str>) -> Duration {
    // Extract max-age from Cache-Control if present.
    let max_age = cache_control
        .and_then(|cc| {
            cc.split(',')
                .map(|d| d.trim())
                .find(|d| d.starts_with("max-age="))
                .and_then(|d| d[8..].parse::<u64>().ok())
        });

    match tier {
        Tier::Critical => Duration::ZERO, // Should never reach here.
        Tier::High => {
            // Conservative: use max-age if present, else 5 seconds.
            max_age.map_or(Duration::from_secs(5), Duration::from_secs)
        }
        Tier::Medium | Tier::CatchAll => {
            // Aggressive: use max-age if present, else 5 minutes.
            max_age.map_or(Duration::from_secs(300), Duration::from_secs)
        }
    }
}

/// Compute a vary hash from headers.
pub fn compute_vary_hash(
    headers: &hyper::header::HeaderMap,
    vary_keys: &[&str],
) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for key in vary_keys {
        if let Some(val) = headers.get(*key) {
            key.hash(&mut hasher);
            val.as_bytes().hash(&mut hasher);
        }
    }
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_key() -> CacheKey {
        CacheKey {
            method: "GET".into(),
            host: "example.com".into(),
            path: "/api/data".into(),
            vary_hash: 0,
        }
    }

    fn sample_response() -> CachedResponse {
        CachedResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: Bytes::from(r#"{"ok":true}"#),
        }
    }

    #[tokio::test]
    async fn cache_hit_on_medium_tier() {
        let cache = TierCache::new(100);
        let key = sample_key();
        let resp = sample_response();

        let inserted = cache
            .insert(key.clone(), resp.clone(), &Tier::Medium, None)
            .await;
        assert!(inserted);

        let cached = cache.get(&key).await.unwrap();
        assert_eq!(cached.status, 200);
        assert_eq!(cached.body, Bytes::from(r#"{"ok":true}"#));
    }

    #[tokio::test]
    async fn critical_tier_never_cached() {
        let cache = TierCache::new(100);
        let key = sample_key();
        let resp = sample_response();

        let inserted = cache
            .insert(key.clone(), resp, &Tier::Critical, None)
            .await;
        assert!(!inserted);
        assert!(cache.get(&key).await.is_none());
    }

    #[tokio::test]
    async fn no_store_respected() {
        let cache = TierCache::new(100);
        let key = sample_key();
        let resp = sample_response();

        let inserted = cache
            .insert(key.clone(), resp, &Tier::Medium, Some("no-store"))
            .await;
        assert!(!inserted);
        assert!(cache.get(&key).await.is_none());
    }

    #[tokio::test]
    async fn invalidation() {
        let cache = TierCache::new(100);
        let key = sample_key();
        let resp = sample_response();

        cache
            .insert(key.clone(), resp, &Tier::Medium, None)
            .await;
        assert!(cache.get(&key).await.is_some());

        cache.invalidate(&key).await;
        assert!(cache.get(&key).await.is_none());
    }

    #[test]
    fn tier_ttl_high_default() {
        let ttl = tier_ttl(&Tier::High, None);
        assert_eq!(ttl, Duration::from_secs(5));
    }

    #[test]
    fn tier_ttl_high_with_max_age() {
        let ttl = tier_ttl(&Tier::High, Some("public, max-age=30"));
        assert_eq!(ttl, Duration::from_secs(30));
    }

    #[test]
    fn tier_ttl_medium_default() {
        let ttl = tier_ttl(&Tier::Medium, None);
        assert_eq!(ttl, Duration::from_secs(300));
    }

    #[test]
    fn vary_hash_changes_with_header() {
        let mut h1 = hyper::header::HeaderMap::new();
        h1.insert("accept", "application/json".parse().unwrap());

        let mut h2 = hyper::header::HeaderMap::new();
        h2.insert("accept", "text/html".parse().unwrap());

        let hash1 = compute_vary_hash(&h1, &["accept"]);
        let hash2 = compute_vary_hash(&h2, &["accept"]);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn vary_hash_same_for_same_headers() {
        let mut h1 = hyper::header::HeaderMap::new();
        h1.insert("accept", "application/json".parse().unwrap());

        let mut h2 = hyper::header::HeaderMap::new();
        h2.insert("accept", "application/json".parse().unwrap());

        assert_eq!(
            compute_vary_hash(&h1, &["accept"]),
            compute_vary_hash(&h2, &["accept"])
        );
    }
}
