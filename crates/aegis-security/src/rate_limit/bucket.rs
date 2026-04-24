use aegis_core::state::StateBackend;

/// Try to take a token from a token bucket.
///
/// - `rate_per_s`: refill rate (tokens per second).
/// - `burst`: maximum bucket capacity.
///
/// Returns `true` if the token was granted.
pub async fn take(
    state: &dyn StateBackend,
    key: &str,
    rate_per_s: u32,
    burst: u32,
) -> aegis_core::Result<bool> {
    state.token_bucket(key, rate_per_s, burst).await
}

/// Build a token-bucket key.
pub fn build_key(scope: &str, id: &str, discriminator: &str) -> String {
    format!("tb:{scope}:{id}:{discriminator}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    struct MockBucket {
        buckets: Mutex<HashMap<String, (f64, Instant)>>,
    }

    impl MockBucket {
        fn new() -> Self {
            Self {
                buckets: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl StateBackend for MockBucket {
        async fn get(&self, _k: &str) -> aegis_core::Result<Option<Vec<u8>>> { Ok(None) }
        async fn set(&self, _k: &str, _v: &[u8], _t: Duration) -> aegis_core::Result<()> { Ok(()) }
        async fn del(&self, _k: &str) -> aegis_core::Result<()> { Ok(()) }
        async fn incr_window(&self, _k: &str, _w: Duration, _l: u64) -> aegis_core::Result<aegis_core::SlidingWindowResult> {
            Ok(aegis_core::SlidingWindowResult { count: 0, allowed: true, retry_after: None })
        }
        async fn token_bucket(&self, key: &str, rate_per_s: u32, burst: u32) -> aegis_core::Result<bool> {
            let mut map = self.buckets.lock().unwrap();
            let now = Instant::now();
            let entry = map
                .entry(key.to_string())
                .or_insert((f64::from(burst), now));
            let elapsed = now.duration_since(entry.1).as_secs_f64();
            entry.0 = (entry.0 + elapsed * f64::from(rate_per_s)).min(f64::from(burst));
            entry.1 = now;
            if entry.0 >= 1.0 {
                entry.0 -= 1.0;
                Ok(true)
            } else {
                Ok(false)
            }
        }
        async fn get_risk(&self, _k: &aegis_core::RiskKey) -> aegis_core::Result<u32> { Ok(0) }
        async fn add_risk(&self, _k: &aegis_core::RiskKey, _d: i32, _m: u32) -> aegis_core::Result<u32> { Ok(0) }
        async fn auto_block(&self, _ip: std::net::IpAddr, _t: Duration) -> aegis_core::Result<()> { Ok(()) }
        async fn is_auto_blocked(&self, _ip: std::net::IpAddr) -> aegis_core::Result<bool> { Ok(false) }
        async fn put_nonce(&self, _n: &str, _t: Duration) -> aegis_core::Result<bool> { Ok(true) }
        async fn consume_nonce(&self, _n: &str) -> aegis_core::Result<bool> { Ok(true) }
    }

    #[tokio::test]
    async fn burst_consumed_instantly() {
        let state = Arc::new(MockBucket::new());
        let key = build_key("global", "api", "user1");
        // Burst of 5 — first 5 should succeed.
        for _ in 0..5 {
            assert!(take(state.as_ref(), &key, 1, 5).await.unwrap());
        }
        // 6th should fail.
        assert!(!take(state.as_ref(), &key, 1, 5).await.unwrap());
    }

    #[tokio::test]
    async fn refill_after_wait() {
        let state = Arc::new(MockBucket::new());
        let key = build_key("global", "api", "user2");
        // Exhaust burst.
        for _ in 0..3 {
            take(state.as_ref(), &key, 10, 3).await.unwrap();
        }
        assert!(!take(state.as_ref(), &key, 10, 3).await.unwrap());
        // Wait for refill (simulated by sleeping).
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(take(state.as_ref(), &key, 10, 3).await.unwrap());
    }

    #[tokio::test]
    async fn different_keys_independent() {
        let state = Arc::new(MockBucket::new());
        let k1 = build_key("global", "api", "a");
        let k2 = build_key("global", "api", "b");
        // Exhaust k1.
        for _ in 0..2 {
            take(state.as_ref(), &k1, 1, 2).await.unwrap();
        }
        assert!(!take(state.as_ref(), &k1, 1, 2).await.unwrap());
        // k2 should still work.
        assert!(take(state.as_ref(), &k2, 1, 2).await.unwrap());
    }

    #[test]
    fn key_format() {
        assert_eq!(build_key("route", "r1", "ip"), "tb:route:r1:ip");
    }
}
