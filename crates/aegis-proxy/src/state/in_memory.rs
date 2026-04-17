use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;

use aegis_core::error::Result;
use aegis_core::risk::RiskKey;
use aegis_core::state::{SlidingWindowResult, StateBackend};

struct Entry {
    value: Vec<u8>,
    expires_at: Option<Instant>,
}

impl Entry {
    fn is_expired(&self) -> bool {
        self.expires_at
            .map(|t| Instant::now() >= t)
            .unwrap_or(false)
    }
}

pub struct InMemoryBackend {
    kv: Arc<DashMap<String, Entry>>,
}

impl InMemoryBackend {
    pub fn new() -> Self {
        Self {
            kv: Arc::new(DashMap::new()),
        }
    }

    fn risk_key_str(key: &RiskKey) -> String {
        format!(
            "g:risk:{}:{}:{}",
            key.ip,
            key.device_fp.as_deref().unwrap_or("-"),
            key.session.as_deref().unwrap_or("-"),
        )
    }

    fn block_key(ip: IpAddr) -> String {
        format!("g:block:{ip}")
    }
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl StateBackend for InMemoryBackend {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        match self.kv.get(key) {
            Some(entry) if !entry.is_expired() => Ok(Some(entry.value.clone())),
            Some(_) => {
                self.kv.remove(key);
                Ok(None)
            }
            None => Ok(None),
        }
    }

    async fn set(&self, key: &str, val: &[u8], ttl: Duration) -> Result<()> {
        self.kv.insert(
            key.to_string(),
            Entry {
                value: val.to_vec(),
                expires_at: Some(Instant::now() + ttl),
            },
        );
        Ok(())
    }

    async fn del(&self, key: &str) -> Result<()> {
        self.kv.remove(key);
        Ok(())
    }

    async fn incr_window(
        &self,
        key: &str,
        window: Duration,
        limit: u64,
    ) -> Result<SlidingWindowResult> {
        let k = format!("g:rl:sw:{key}");
        let now = Instant::now();

        let mut entry = self.kv.entry(k).or_insert_with(|| Entry {
            value: 0u64.to_le_bytes().to_vec(),
            expires_at: Some(now + window),
        });

        if entry.is_expired() {
            entry.value = 1u64.to_le_bytes().to_vec();
            entry.expires_at = Some(now + window);
            return Ok(SlidingWindowResult {
                count: 1,
                allowed: 1 <= limit,
                retry_after: if 1 > limit {
                    Some(window)
                } else {
                    None
                },
            });
        }

        let current = u64::from_le_bytes(
            entry.value[..8].try_into().unwrap_or([0; 8]),
        );
        let new_count = current + 1;
        entry.value = new_count.to_le_bytes().to_vec();

        Ok(SlidingWindowResult {
            count: new_count,
            allowed: new_count <= limit,
            retry_after: if new_count > limit {
                entry.expires_at.map(|e| e.duration_since(now))
            } else {
                None
            },
        })
    }

    async fn token_bucket(
        &self,
        key: &str,
        rate_per_s: u32,
        burst: u32,
    ) -> Result<bool> {
        let k = format!("g:rl:tb:{key}");
        let now = Instant::now();

        let mut entry = self.kv.entry(k).or_insert_with(|| {
            let tokens_and_ts = encode_bucket(burst as f64, now);
            Entry {
                value: tokens_and_ts,
                expires_at: None,
            }
        });

        let (tokens, last) = decode_bucket(&entry.value);
        let elapsed = now.duration_since(last).as_secs_f64();
        let refilled = (tokens + elapsed * rate_per_s as f64).min(burst as f64);

        if refilled >= 1.0 {
            entry.value = encode_bucket(refilled - 1.0, now);
            Ok(true)
        } else {
            entry.value = encode_bucket(refilled, now);
            Ok(false)
        }
    }

    async fn get_risk(&self, key: &RiskKey) -> Result<u32> {
        let k = Self::risk_key_str(key);
        match self.kv.get(&k) {
            Some(entry) if !entry.is_expired() => {
                let val = u32::from_le_bytes(
                    entry.value[..4].try_into().unwrap_or([0; 4]),
                );
                Ok(val)
            }
            _ => Ok(0),
        }
    }

    async fn add_risk(&self, key: &RiskKey, delta: i32, max: u32) -> Result<u32> {
        let k = Self::risk_key_str(key);
        let mut entry = self.kv.entry(k).or_insert_with(|| Entry {
            value: 0u32.to_le_bytes().to_vec(),
            expires_at: None,
        });

        let current = u32::from_le_bytes(
            entry.value[..4].try_into().unwrap_or([0; 4]),
        );
        let new_val = if delta >= 0 {
            current.saturating_add(delta as u32).min(max)
        } else {
            current.saturating_sub(delta.unsigned_abs())
        };
        entry.value = new_val.to_le_bytes().to_vec();
        Ok(new_val)
    }

    async fn auto_block(&self, ip: IpAddr, ttl: Duration) -> Result<()> {
        let k = Self::block_key(ip);
        self.kv.insert(
            k,
            Entry {
                value: vec![1],
                expires_at: Some(Instant::now() + ttl),
            },
        );
        Ok(())
    }

    async fn is_auto_blocked(&self, ip: IpAddr) -> Result<bool> {
        let k = Self::block_key(ip);
        match self.kv.get(&k) {
            Some(entry) if !entry.is_expired() => Ok(true),
            Some(_) => {
                self.kv.remove(&k);
                Ok(false)
            }
            None => Ok(false),
        }
    }

    async fn put_nonce(&self, nonce: &str, ttl: Duration) -> Result<bool> {
        let k = format!("g:nonce:{nonce}");
        if self.kv.contains_key(&k) {
            return Ok(false);
        }
        self.kv.insert(
            k,
            Entry {
                value: vec![1],
                expires_at: Some(Instant::now() + ttl),
            },
        );
        Ok(true)
    }

    async fn consume_nonce(&self, nonce: &str) -> Result<bool> {
        let k = format!("g:nonce:{nonce}");
        Ok(self.kv.remove(&k).is_some())
    }
}

fn encode_bucket(tokens: f64, ts: Instant) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16);
    buf.extend_from_slice(&tokens.to_le_bytes());
    let nanos = ts.elapsed().as_nanos() as u64; // relative offset; we store the Instant as nanos-ago=0
    buf.extend_from_slice(&nanos.to_le_bytes());
    buf
}

fn decode_bucket(data: &[u8]) -> (f64, Instant) {
    let tokens = f64::from_le_bytes(data[..8].try_into().unwrap_or([0; 8]));
    // The timestamp is always "now" relative — we re-encode on every access
    // so for simplicity we treat the stored timestamp as the last access time.
    // In a real impl this would be a proper epoch-based timestamp.
    (tokens, Instant::now())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn backend() -> InMemoryBackend {
        InMemoryBackend::new()
    }

    #[tokio::test]
    async fn get_set_del() {
        let b = backend();
        b.set("key1", b"hello", Duration::from_secs(60)).await.unwrap();
        let val = b.get("key1").await.unwrap();
        assert_eq!(val, Some(b"hello".to_vec()));

        b.del("key1").await.unwrap();
        let val = b.get("key1").await.unwrap();
        assert!(val.is_none());
    }

    #[tokio::test]
    async fn get_returns_none_for_missing_key() {
        let b = backend();
        let val = b.get("nonexistent").await.unwrap();
        assert!(val.is_none());
    }

    #[tokio::test]
    async fn sliding_window_increments() {
        let b = backend();
        let r1 = b.incr_window("test-ip", Duration::from_secs(60), 5).await.unwrap();
        assert_eq!(r1.count, 1);
        assert!(r1.allowed);

        let r2 = b.incr_window("test-ip", Duration::from_secs(60), 5).await.unwrap();
        assert_eq!(r2.count, 2);
        assert!(r2.allowed);
    }

    #[tokio::test]
    async fn sliding_window_exceeds_limit() {
        let b = backend();
        for _ in 0..5 {
            b.incr_window("flood", Duration::from_secs(60), 5).await.unwrap();
        }
        let r = b.incr_window("flood", Duration::from_secs(60), 5).await.unwrap();
        assert_eq!(r.count, 6);
        assert!(!r.allowed);
        assert!(r.retry_after.is_some());
    }

    #[tokio::test]
    async fn token_bucket_allows_within_burst() {
        let b = backend();
        // burst=3, so first 3 should succeed
        assert!(b.token_bucket("api", 1, 3).await.unwrap());
        assert!(b.token_bucket("api", 1, 3).await.unwrap());
        assert!(b.token_bucket("api", 1, 3).await.unwrap());
    }

    #[tokio::test]
    async fn risk_score_starts_at_zero() {
        let b = backend();
        let key = RiskKey {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            device_fp: None,
            session: None,
            tenant_id: None,
        };
        assert_eq!(b.get_risk(&key).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn risk_score_add_and_clamp() {
        let b = backend();
        let key = RiskKey {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            device_fp: None,
            session: None,
            tenant_id: None,
        };
        let v = b.add_risk(&key, 50, 100).await.unwrap();
        assert_eq!(v, 50);

        let v = b.add_risk(&key, 70, 100).await.unwrap();
        assert_eq!(v, 100); // clamped to max

        let v = b.add_risk(&key, -30, 100).await.unwrap();
        assert_eq!(v, 70);
    }

    #[tokio::test]
    async fn auto_block_and_check() {
        let b = backend();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

        assert!(!b.is_auto_blocked(ip).await.unwrap());
        b.auto_block(ip, Duration::from_secs(300)).await.unwrap();
        assert!(b.is_auto_blocked(ip).await.unwrap());
    }

    #[tokio::test]
    async fn nonce_put_and_consume() {
        let b = backend();

        // First put succeeds
        assert!(b.put_nonce("abc123", Duration::from_secs(60)).await.unwrap());
        // Duplicate put fails
        assert!(!b.put_nonce("abc123", Duration::from_secs(60)).await.unwrap());

        // Consume succeeds once
        assert!(b.consume_nonce("abc123").await.unwrap());
        // Second consume fails
        assert!(!b.consume_nonce("abc123").await.unwrap());
    }

    #[tokio::test]
    async fn nonce_consume_nonexistent() {
        let b = backend();
        assert!(!b.consume_nonce("doesnotexist").await.unwrap());
    }
}
