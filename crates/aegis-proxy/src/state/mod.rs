pub mod in_memory;
pub mod reconcile;
pub mod redis;
pub mod rehydrate;

pub use in_memory::InMemoryBackend;
pub use reconcile::ReconcilingBackend;
pub use rehydrate::{rehydrate, RehydrateResult};

// Re-export the real Redis backend only when the feature is on.
#[cfg(feature = "redis")]
pub use redis::RedisBackend;

// The config + Lua script constants are public regardless of
// feature so other crates can reference them (e.g. for tooling
// or for the future redis_cluster backend).
pub use redis::{RedisConfig, ADD_RISK_LUA, SLIDING_WINDOW_LUA, TOKEN_BUCKET_LUA};
