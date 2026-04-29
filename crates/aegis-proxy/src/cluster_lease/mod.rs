//! Distributed lease implementations (B1-T3).
//!
//! Backends:
//!
//! - [`InProcessLease`] — single-node default. Pure
//!   `Mutex<HashMap>`; identical observable semantics to a
//!   1-replica Redis lease so unit tests on this impl exercise
//!   the same contract a multi-node deployment will see.
//! - [`RedisLease`] — feature-gated `aegis-proxy/redis`. Uses
//!   `SET NX PX <ttl_ms>` for `acquire` and Lua CAS for `renew` /
//!   `release` so only the holder can mutate a key.
//!
//! See [`heartbeat::spawn_heartbeat`] for the standard pattern
//! that gates a leader-only task on continuous renewal.

pub mod heartbeat;
pub mod in_process;
pub mod runner;

#[cfg(feature = "redis")]
pub mod redis;

pub use heartbeat::{spawn_heartbeat, HeartbeatHandle};
pub use in_process::InProcessLease;
pub use runner::{run_with_lease, spawn_with_lease};

#[cfg(feature = "redis")]
pub use redis::RedisLease;
