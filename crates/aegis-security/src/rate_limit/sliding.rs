use std::time::Duration;

use aegis_core::state::StateBackend;
use aegis_core::SlidingWindowResult;

/// Decision from rate-limit check.
#[derive(Debug, Clone)]
pub struct RateDecision {
    pub allowed: bool,
    pub count: u64,
    pub limit: u64,
    pub retry_after_s: Option<u32>,
}

/// Check sliding-window rate limit.
///
/// Key format: `rl:{scope}:{id}:{bucket}` — the caller builds the full key.
pub async fn check(
    state: &dyn StateBackend,
    key: &str,
    limit: u64,
    window_s: u32,
) -> aegis_core::Result<RateDecision> {
    let window = Duration::from_secs(u64::from(window_s));
    let result: SlidingWindowResult = state.incr_window(key, window, limit).await?;

    Ok(RateDecision {
        allowed: result.allowed,
        count: result.count,
        limit,
        retry_after_s: result.retry_after.map(|d| d.as_secs() as u32),
    })
}

/// Build a rate-limit key for a given scope, rule id, and discriminator.
pub fn build_key(scope: &str, rule_id: &str, discriminator: &str) -> String {
    format!("rl:{scope}:{rule_id}:{discriminator}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::state::StateBackend;
    use std::sync::Arc;

    // Use the in-memory backend from aegis-proxy for testing.
    // Since we can't depend on aegis-proxy, we create a minimal mock.
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::Instant;

    struct MockState {
        windows: Mutex<HashMap<String, (u64, Instant)>>,
    }

    impl MockState {
        fn new() -> Self {
            Self {
                windows: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl StateBackend for MockState {
        async fn get(&self, _key: &str) -> aegis_core::Result<Option<Vec<u8>>> {
            Ok(None)
        }
        async fn set(&self, _key: &str, _val: &[u8], _ttl: Duration) -> aegis_core::Result<()> {
            Ok(())
        }
        async fn del(&self, _key: &str) -> aegis_core::Result<()> {
            Ok(())
        }
        async fn incr_window(
            &self,
            key: &str,
            window: Duration,
            limit: u64,
        ) -> aegis_core::Result<SlidingWindowResult> {
            let mut map = self.windows.lock().unwrap();
            let now = Instant::now();
            let entry = map.entry(key.to_string()).or_insert((0, now));
            if now.duration_since(entry.1) > window {
                entry.0 = 0;
                entry.1 = now;
            }
            entry.0 += 1;
            let count = entry.0;
            let allowed = count <= limit;
            let retry_after = if allowed {
                None
            } else {
                Some(window.saturating_sub(now.duration_since(entry.1)))
            };
            Ok(SlidingWindowResult {
                count,
                allowed,
                retry_after,
            })
        }
        async fn token_bucket(&self, _key: &str, _rate: u32, _burst: u32) -> aegis_core::Result<bool> {
            Ok(true)
        }
        async fn get_risk(&self, _key: &aegis_core::RiskKey) -> aegis_core::Result<u32> {
            Ok(0)
        }
        async fn add_risk(&self, _key: &aegis_core::RiskKey, _delta: i32, _max: u32) -> aegis_core::Result<u32> {
            Ok(0)
        }
        async fn auto_block(&self, _ip: std::net::IpAddr, _ttl: Duration) -> aegis_core::Result<()> {
            Ok(())
        }
        async fn is_auto_blocked(&self, _ip: std::net::IpAddr) -> aegis_core::Result<bool> {
            Ok(false)
        }
        async fn put_nonce(&self, _nonce: &str, _ttl: Duration) -> aegis_core::Result<bool> {
            Ok(true)
        }
        async fn consume_nonce(&self, _nonce: &str) -> aegis_core::Result<bool> {
            Ok(true)
        }
    }

    #[tokio::test]
    async fn under_limit_allowed() {
        let state = Arc::new(MockState::new());
        let key = build_key("global", "r1", "1.2.3.4");
        let d = check(state.as_ref(), &key, 10, 60).await.unwrap();
        assert!(d.allowed);
        assert_eq!(d.count, 1);
    }

    #[tokio::test]
    async fn exceed_limit_denied() {
        let state = Arc::new(MockState::new());
        let key = build_key("global", "r1", "1.2.3.4");
        for _ in 0..5 {
            check(state.as_ref(), &key, 5, 60).await.unwrap();
        }
        let d = check(state.as_ref(), &key, 5, 60).await.unwrap();
        assert!(!d.allowed);
        assert_eq!(d.count, 6);
    }

    #[tokio::test]
    async fn different_keys_independent() {
        let state = Arc::new(MockState::new());
        let k1 = build_key("global", "r1", "1.1.1.1");
        let k2 = build_key("global", "r1", "2.2.2.2");
        for _ in 0..5 {
            check(state.as_ref(), &k1, 5, 60).await.unwrap();
        }
        let d = check(state.as_ref(), &k2, 5, 60).await.unwrap();
        assert!(d.allowed);
    }

    #[tokio::test]
    async fn concurrent_callers() {
        let state = Arc::new(MockState::new());
        let key = build_key("global", "r1", "flood");
        let limit = 100u64;
        let mut handles = vec![];
        for _ in 0..200 {
            let s = state.clone();
            let k = key.clone();
            handles.push(tokio::spawn(async move {
                check(s.as_ref(), &k, limit, 60).await.unwrap()
            }));
        }
        let mut allowed = 0u64;
        let mut denied = 0u64;
        for h in handles {
            let d = h.await.unwrap();
            if d.allowed {
                allowed += 1;
            } else {
                denied += 1;
            }
        }
        assert_eq!(allowed, limit);
        assert_eq!(denied, 100);
    }

    #[test]
    fn build_key_format() {
        let k = build_key("route", "sqli-block", "10.0.0.1");
        assert_eq!(k, "rl:route:sqli-block:10.0.0.1");
    }
}
