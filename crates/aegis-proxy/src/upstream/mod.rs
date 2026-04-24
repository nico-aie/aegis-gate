pub mod lb;
pub mod health;
pub mod circuit;
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
}

impl Member {
    pub fn new(addr: SocketAddr, weight: u32, zone: Option<String>) -> Self {
        Self {
            addr,
            weight,
            zone,
            healthy: AtomicBool::new(true),
            inflight: AtomicU64::new(0),
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
}
