use std::net::IpAddr;
use std::time::Duration;

use crate::error::Result;
use crate::risk::RiskKey;

pub struct SlidingWindowResult {
    pub count: u64,
    pub allowed: bool,
    pub retry_after: Option<Duration>,
}

#[async_trait::async_trait]
pub trait StateBackend: Send + Sync + 'static {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    async fn set(&self, key: &str, val: &[u8], ttl: Duration) -> Result<()>;
    async fn del(&self, key: &str) -> Result<()>;

    async fn incr_window(
        &self,
        key: &str,
        window: Duration,
        limit: u64,
    ) -> Result<SlidingWindowResult>;

    async fn token_bucket(
        &self,
        key: &str,
        rate_per_s: u32,
        burst: u32,
    ) -> Result<bool>;

    async fn get_risk(&self, key: &RiskKey) -> Result<u32>;
    async fn add_risk(&self, key: &RiskKey, delta: i32, max: u32) -> Result<u32>;

    async fn auto_block(&self, ip: IpAddr, ttl: Duration) -> Result<()>;
    async fn is_auto_blocked(&self, ip: IpAddr) -> Result<bool>;

    async fn put_nonce(&self, nonce: &str, ttl: Duration) -> Result<bool>;
    async fn consume_nonce(&self, nonce: &str) -> Result<bool>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sliding_window_result_fields() {
        let r = SlidingWindowResult {
            count: 5,
            allowed: true,
            retry_after: None,
        };
        assert_eq!(r.count, 5);
        assert!(r.allowed);
        assert!(r.retry_after.is_none());
    }

    #[test]
    fn sliding_window_exceeded() {
        let r = SlidingWindowResult {
            count: 101,
            allowed: false,
            retry_after: Some(Duration::from_secs(30)),
        };
        assert!(!r.allowed);
        assert_eq!(r.retry_after.unwrap().as_secs(), 30);
    }
}
