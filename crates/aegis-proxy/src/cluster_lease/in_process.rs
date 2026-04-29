//! In-process [`LeaseStore`] — single-node default.
//!
//! Backed by a `Mutex<HashMap>` keyed on lease key. Used directly
//! in single-node deployments and as a parity reference for the
//! Redis-backed impl.
//!
//! The observable contract matches the Redis impl exactly:
//!
//! - `acquire` returns `Some` on first take or when we already
//!   hold the lease (renews TTL); `None` if another node holds
//!   it and the TTL has not expired.
//! - `renew` returns `false` when we lost the lease (e.g. TTL
//!   expired and another node took it).
//! - `release` is a no-op if we no longer hold the lease.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aegis_core::cluster::{LeaseHandle, LeaseStore, NodeId};
use aegis_core::error::Result;

/// Per-key state inside the in-process lease store.
struct Slot {
    holder: NodeId,
    expires_at: Instant,
    fence: u64,
}

/// In-process [`LeaseStore`].
///
/// Cheap to clone — internal state is `Arc`-shared so the
/// "shared store" pattern used by the test suite (multiple nodes
/// against one map) maps onto multiple `InProcessLease` clones.
pub struct InProcessLease {
    self_id: NodeId,
    leases: Arc<Mutex<HashMap<String, Slot>>>,
    fence: Arc<AtomicU64>,
}

impl Clone for InProcessLease {
    fn clone(&self) -> Self {
        Self {
            self_id: self.self_id.clone(),
            leases: self.leases.clone(),
            fence: self.fence.clone(),
        }
    }
}

impl InProcessLease {
    /// New independent lease store. Two `InProcessLease`s built
    /// with `new` do **not** share state — use
    /// [`InProcessLease::cloned_with_node`] when modeling
    /// multiple nodes pointing at the same map.
    pub fn new(self_id: NodeId) -> Self {
        Self {
            self_id,
            leases: Arc::new(Mutex::new(HashMap::new())),
            fence: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Build a sibling that shares this store but identifies as a
    /// different node. Used in tests and in the rare case where a
    /// process needs to manage leases under multiple identities.
    pub fn cloned_with_node(&self, node: NodeId) -> Self {
        Self {
            self_id: node,
            leases: self.leases.clone(),
            fence: self.fence.clone(),
        }
    }

    /// Identity this store acquires leases as.
    pub fn self_id(&self) -> &NodeId {
        &self.self_id
    }

    fn next_fence(&self) -> u64 {
        // Always advance — fence semantics demand monotonicity
        // even across release+re-acquire by the same node.
        self.fence.fetch_add(1, Ordering::Relaxed) + 1
    }
}

#[async_trait::async_trait]
impl LeaseStore for InProcessLease {
    async fn acquire(
        &self,
        key: &str,
        ttl: Duration,
    ) -> Result<Option<LeaseHandle>> {
        let mut leases = self.leases.lock().expect("lease mutex poisoned");
        let now = Instant::now();

        if let Some(slot) = leases.get(key) {
            if slot.holder == self.self_id {
                // We hold it — refresh TTL but keep the original
                // fence so renews don't drift.
                let fence = slot.fence;
                let new_slot = Slot {
                    holder: self.self_id.clone(),
                    expires_at: now + ttl,
                    fence,
                };
                leases.insert(key.to_string(), new_slot);
                return Ok(Some(LeaseHandle {
                    key: key.to_string(),
                    holder: self.self_id.clone(),
                    fence,
                }));
            }
            if now < slot.expires_at {
                // Another node holds it.
                return Ok(None);
            }
            // Expired — fall through to take.
        }

        let fence = self.next_fence();
        leases.insert(
            key.to_string(),
            Slot {
                holder: self.self_id.clone(),
                expires_at: now + ttl,
                fence,
            },
        );
        Ok(Some(LeaseHandle {
            key: key.to_string(),
            holder: self.self_id.clone(),
            fence,
        }))
    }

    async fn renew(&self, lease: &LeaseHandle, ttl: Duration) -> Result<bool> {
        let mut leases = self.leases.lock().expect("lease mutex poisoned");
        let now = Instant::now();

        match leases.get(&lease.key) {
            Some(slot)
                if slot.holder == lease.holder
                    && slot.fence == lease.fence
                    && now < slot.expires_at =>
            {
                // Still ours — extend TTL.
                let fence = slot.fence;
                leases.insert(
                    lease.key.clone(),
                    Slot {
                        holder: lease.holder.clone(),
                        expires_at: now + ttl,
                        fence,
                    },
                );
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn release(&self, lease: &LeaseHandle) -> Result<()> {
        let mut leases = self.leases.lock().expect("lease mutex poisoned");
        // CAS-style remove: only delete if still ours.
        if let Some(slot) = leases.get(&lease.key) {
            if slot.holder == lease.holder && slot.fence == lease.fence {
                leases.remove(&lease.key);
            }
        }
        Ok(())
    }

    async fn holder(&self, key: &str) -> Result<Option<NodeId>> {
        let leases = self.leases.lock().expect("lease mutex poisoned");
        Ok(leases.get(key).and_then(|slot| {
            if Instant::now() < slot.expires_at {
                Some(slot.holder.clone())
            } else {
                None
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease(name: &str) -> InProcessLease {
        InProcessLease::new(NodeId::new(name))
    }

    #[tokio::test]
    async fn acquire_first_returns_handle() {
        let l = lease("node-1");
        let h = l.acquire("acme", Duration::from_secs(10)).await.unwrap();
        assert!(h.is_some());
        let h = h.unwrap();
        assert_eq!(h.key, "acme");
        assert_eq!(h.holder, NodeId::new("node-1"));
    }

    #[tokio::test]
    async fn acquire_blocked_by_holder() {
        let a = lease("node-1");
        let b = a.cloned_with_node(NodeId::new("node-2"));

        assert!(a.acquire("acme", Duration::from_secs(10)).await.unwrap().is_some());
        assert!(b.acquire("acme", Duration::from_secs(10)).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn acquire_refresh_keeps_same_fence() {
        let l = lease("node-1");
        let h1 = l.acquire("acme", Duration::from_secs(10)).await.unwrap().unwrap();
        let h2 = l.acquire("acme", Duration::from_secs(10)).await.unwrap().unwrap();
        assert_eq!(h1.fence, h2.fence, "self-refresh must not advance fence");
    }

    #[tokio::test]
    async fn renew_returns_true_for_holder() {
        let l = lease("node-1");
        let h = l.acquire("acme", Duration::from_secs(10)).await.unwrap().unwrap();
        assert!(l.renew(&h, Duration::from_secs(10)).await.unwrap());
    }

    #[tokio::test]
    async fn renew_returns_false_after_release() {
        let l = lease("node-1");
        let h = l.acquire("acme", Duration::from_secs(10)).await.unwrap().unwrap();
        l.release(&h).await.unwrap();
        assert!(!l.renew(&h, Duration::from_secs(10)).await.unwrap());
    }

    #[tokio::test]
    async fn release_with_stale_handle_is_noop() {
        // Release CAS is on the handle, not the calling store —
        // matching the Redis impl. So a forged handle (wrong
        // holder OR wrong fence) must NOT delete the lease, even
        // if it's called from a store that happens to be the
        // current holder.
        let l = lease("node-1");
        let real = l.acquire("acme", Duration::from_secs(10)).await.unwrap().unwrap();

        let stale = LeaseHandle {
            key: real.key.clone(),
            holder: NodeId::new("node-2"), // wrong holder
            fence: real.fence,
        };
        l.release(&stale).await.unwrap();
        assert_eq!(
            l.holder("acme").await.unwrap().unwrap(),
            NodeId::new("node-1"),
            "release with wrong holder must be a no-op",
        );

        let stale_fence = LeaseHandle {
            key: real.key.clone(),
            holder: real.holder.clone(),
            fence: real.fence + 999, // wrong fence
        };
        l.release(&stale_fence).await.unwrap();
        assert_eq!(
            l.holder("acme").await.unwrap().unwrap(),
            NodeId::new("node-1"),
            "release with wrong fence must be a no-op",
        );

        // The real handle does succeed.
        l.release(&real).await.unwrap();
        assert!(l.holder("acme").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn expired_lease_can_be_taken_by_another() {
        let a = InProcessLease::new(NodeId::new("node-1"));
        let b = a.cloned_with_node(NodeId::new("node-2"));

        // 1ms TTL
        assert!(a.acquire("acme", Duration::from_millis(1)).await.unwrap().is_some());
        tokio::time::sleep(Duration::from_millis(10)).await;
        let h_b = b.acquire("acme", Duration::from_secs(10)).await.unwrap();
        assert!(h_b.is_some(), "expired lease should be reacquirable");
        assert_eq!(h_b.unwrap().holder, NodeId::new("node-2"));
    }

    #[tokio::test]
    async fn fence_advances_across_takeovers() {
        let a = InProcessLease::new(NodeId::new("node-1"));
        let b = a.cloned_with_node(NodeId::new("node-2"));

        let h1 = a.acquire("acme", Duration::from_millis(1)).await.unwrap().unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        let h2 = b.acquire("acme", Duration::from_secs(10)).await.unwrap().unwrap();
        assert!(
            h2.fence > h1.fence,
            "fence must increase on takeover: h1={} h2={}",
            h1.fence,
            h2.fence,
        );
    }

    #[tokio::test]
    async fn three_nodes_only_one_winner() {
        let a = InProcessLease::new(NodeId::new("node-1"));
        let b = a.cloned_with_node(NodeId::new("node-2"));
        let c = a.cloned_with_node(NodeId::new("node-3"));

        let mut winners = 0;
        for store in [&a, &b, &c] {
            if store
                .acquire("gitops", Duration::from_secs(10))
                .await
                .unwrap()
                .is_some()
            {
                winners += 1;
            }
        }
        assert_eq!(winners, 1);
    }

    #[tokio::test]
    async fn holder_returns_none_when_unheld() {
        let l = lease("node-1");
        assert!(l.holder("never-acquired").await.unwrap().is_none());
    }
}
