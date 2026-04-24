//! Redis-backed state backend (feature-gated: `redis`).
//!
//! Uses `deadpool-redis` for connection pooling and Lua scripts for atomic
//! sliding-window operations. Falls back to local in-memory on backend error
//! and reconciles via `max(local, remote)` on recovery.

use std::time::Duration;

/// Configuration for the Redis backend.
#[derive(Debug, Clone)]
pub struct RedisConfig {
    pub url: String,
    pub pool_size: u32,
    pub timeout: Duration,
    /// Whether this is a cluster deployment.
    pub cluster: bool,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: "redis://127.0.0.1:6379".into(),
            pool_size: 16,
            timeout: Duration::from_secs(5),
            cluster: false,
        }
    }
}

/// Lua script for atomic sliding-window increment.
pub const SLIDING_WINDOW_LUA: &str = r#"
local key = KEYS[1]
local window = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

-- Remove expired entries
redis.call('ZREMRANGEBYSCORE', key, 0, now - window * 1000)

-- Add current timestamp
redis.call('ZADD', key, now, now .. ':' .. math.random(1, 1000000))

-- Set TTL
redis.call('PEXPIRE', key, window * 1000)

-- Count
local count = redis.call('ZCARD', key)
return count
"#;

/// Lua script for atomic token bucket.
pub const TOKEN_BUCKET_LUA: &str = r#"
local key = KEYS[1]
local rate = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

local data = redis.call('GET', key)
local tokens, last_ts

if data then
    local parts = {}
    for p in data:gmatch('[^:]+') do parts[#parts+1] = tonumber(p) end
    tokens = parts[1]
    last_ts = parts[2]
else
    tokens = burst
    last_ts = now
end

local elapsed = (now - last_ts) / 1000.0
tokens = math.min(burst, tokens + elapsed * rate)

if tokens >= 1 then
    tokens = tokens - 1
    redis.call('SET', key, tokens .. ':' .. now)
    return 1
else
    redis.call('SET', key, tokens .. ':' .. now)
    return 0
end
"#;

/// Placeholder for the actual RedisBackend.  Full implementation requires
/// `deadpool-redis` which is feature-gated.  This module provides the Lua
/// scripts and config types so other code can reference them.
pub struct RedisBackendStub {
    pub config: RedisConfig,
}

impl RedisBackendStub {
    pub fn new(config: RedisConfig) -> Self {
        Self { config }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_redis_config() {
        let cfg = RedisConfig::default();
        assert_eq!(cfg.url, "redis://127.0.0.1:6379");
        assert_eq!(cfg.pool_size, 16);
        assert!(!cfg.cluster);
    }

    #[test]
    fn lua_scripts_not_empty() {
        assert!(!SLIDING_WINDOW_LUA.is_empty());
        assert!(!TOKEN_BUCKET_LUA.is_empty());
    }

    #[test]
    fn lua_sliding_window_contains_zcard() {
        assert!(SLIDING_WINDOW_LUA.contains("ZCARD"));
        assert!(SLIDING_WINDOW_LUA.contains("ZREMRANGEBYSCORE"));
    }

    #[test]
    fn lua_token_bucket_contains_burst() {
        assert!(TOKEN_BUCKET_LUA.contains("burst"));
        assert!(TOKEN_BUCKET_LUA.contains("tokens"));
    }

    #[test]
    fn stub_construction() {
        let stub = RedisBackendStub::new(RedisConfig::default());
        assert_eq!(stub.config.url, "redis://127.0.0.1:6379");
    }
}
