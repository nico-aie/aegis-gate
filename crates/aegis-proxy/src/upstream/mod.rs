pub mod lb;
pub mod health;
pub mod circuit;
pub mod dns_refresh;
pub mod dns_resolve;
pub mod forward;
pub mod identity;
pub mod mtls_failures;
pub mod pinned_resolver;
pub mod probe;
pub mod registry;
pub mod rotation;
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

    /// RAII guard for the per-member `inflight` counter
    /// (F-CRITICAL-008, 2026-05-17 s-tester audit).
    ///
    /// Pre-fix the proxy + data-plane forward paths manually called
    /// `inflight.fetch_add(1)` before the upstream `.await` and
    /// `inflight.fetch_sub(1)` after. A cancellation or panic
    /// between those points leaked the counter, permanently biasing
    /// `LeastConn` / `P2C` load balancers against the affected pool
    /// member. `inflight_guard()` returns a guard whose `Drop` runs
    /// the decrement regardless of how the surrounding future exits
    /// (await cancellation, panic, early return).
    pub fn inflight_guard(self: &Arc<Self>) -> InflightGuard {
        self.inflight.fetch_add(1, Ordering::Relaxed);
        InflightGuard { member: Arc::clone(self) }
    }
}

/// RAII handle that decrements `Member.inflight` on drop. Issued by
/// [`Member::inflight_guard`]. See that fn's doc for the bug this
/// closed.
pub struct InflightGuard {
    member: Arc<Member>,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.member.inflight.fetch_sub(1, Ordering::Relaxed);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn member() -> Arc<Member> {
        Arc::new(Member::new(
            "127.0.0.1:9999".parse().unwrap(),
            1,
            None,
        ))
    }

    #[test]
    fn inflight_guard_increments_on_create_and_decrements_on_drop() {
        let m = member();
        assert_eq!(m.inflight.load(Ordering::Relaxed), 0);
        {
            let _g = m.inflight_guard();
            assert_eq!(m.inflight.load(Ordering::Relaxed), 1);
        }
        // Guard dropped → counter decremented.
        assert_eq!(m.inflight.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn inflight_guard_decrements_on_unwind() {
        // Regression for F-CRITICAL-008: pre-fix, a panic inside
        // the forward.await dropped the future and leaked the
        // counter. The guard's Drop runs even on panic-unwind, so
        // a `catch_unwind` here lets us assert it.
        let m = member();
        let m_clone = Arc::clone(&m);
        let result = std::panic::catch_unwind(move || {
            let _g = m_clone.inflight_guard();
            assert_eq!(m_clone.inflight.load(Ordering::Relaxed), 1);
            panic!("simulated forward panic");
        });
        assert!(result.is_err());
        // Counter must be back to zero despite the panic.
        assert_eq!(m.inflight.load(Ordering::Relaxed), 0);
    }
}
