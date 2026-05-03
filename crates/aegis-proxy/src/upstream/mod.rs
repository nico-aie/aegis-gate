pub mod lb;
pub mod health;
pub mod circuit;
pub mod forward;
pub mod registry;
pub mod tls;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// Runtime representation of an upstream member.
#[derive(Debug)]
pub struct Member {
    pub addr: SocketAddr,
    pub weight: u32,
    pub zone: Option<String>,
    pub healthy: AtomicBool,
    pub inflight: AtomicU64,
    /// FIX 2026-05-03 — explicit Host-header override mirroring
    /// `MemberConfig.host_header`. When `Some(host)`,
    /// `forward()` sends `Host: <host>` upstream instead of
    /// rewriting it to `<addr>` — required for vhost-routed
    /// backends.
    pub host_override: Option<String>,
}

impl Member {
    pub fn new(addr: SocketAddr, weight: u32, zone: Option<String>) -> Self {
        Self {
            addr,
            weight,
            zone,
            healthy: AtomicBool::new(true),
            inflight: AtomicU64::new(0),
            host_override: None,
        }
    }

    pub fn with_host_override(
        addr: SocketAddr,
        weight: u32,
        zone: Option<String>,
        host_override: Option<String>,
    ) -> Self {
        Self {
            addr,
            weight,
            zone,
            healthy: AtomicBool::new(true),
            inflight: AtomicU64::new(0),
            host_override,
        }
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }
}

/// A pool of upstream members with a configured load-balancing strategy.
#[derive(Debug)]
pub struct Pool {
    pub name: String,
    pub members: Vec<Arc<Member>>,
    pub strategy: lb::LbStrategy,
    /// UP-T1 — per-pool connection-pool tuning. Threaded into
    /// [`forward::forward`] so each call uses the same pooled
    /// `Client` for that signature.
    pub connection: aegis_core::config::ConnectionPoolConfig,
}
