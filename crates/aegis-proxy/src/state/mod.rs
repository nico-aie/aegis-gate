pub mod in_memory;
pub mod reconcile;
pub mod redis;
pub mod rehydrate;

// Redis-backed FleetBus (cluster Phase 2 event fanout) — feature-gated
// since it depends on the `redis` crate.
#[cfg(feature = "redis")]
pub mod fleet_redis;

pub use in_memory::InMemoryBackend;
pub use reconcile::ReconcilingBackend;
pub use rehydrate::{rehydrate, RehydrateResult};

// Re-export the real Redis backend only when the feature is on.
#[cfg(feature = "redis")]
pub use redis::RedisBackend;

#[cfg(feature = "redis")]
pub use fleet_redis::RedisFleetBus;

// The config + Lua script constants are public regardless of
// feature so other crates can reference them (e.g. for tooling
// or for the future redis_cluster backend).
pub use redis::{RedisConfig, ADD_RISK_LUA, SLIDING_WINDOW_LUA, TOKEN_BUCKET_LUA};
