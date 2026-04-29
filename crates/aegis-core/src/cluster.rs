//! Cluster contracts.
//!
//! Two surfaces:
//!
//! 1. [`ClusterMembership`] — peer awareness (who's alive). The
//!    `aegis-proxy` crate carries the in-process / future-SWIM
//!    impl.
//! 2. [`LeaseStore`] — distributed leader lease. The Redis-backed
//!    impl ([`aegis-proxy::cluster_lease::RedisLease`]) gates
//!    leader-only tasks (ACME, GitOps, threat-intel, witness
//!    export) on a Redis `SET NX PX` lease.
//!
//! These are distinct so the two evolve independently — a cluster
//! can use Redis for leases without needing SWIM membership, and
//! vice-versa.

use std::time::{Duration, Instant};

use crate::error::Result;

// ---------------------------------------------------------------------------
// Membership
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct NodeInfo {
    pub id: String,
    pub zone: Option<String>,
    pub version: String,
    pub load: u32,
    pub started_at: chrono::DateTime<chrono::Utc>,
}

/// Legacy single-method lease type returned by
/// [`ClusterMembership::acquire_lease`]. Retained for the
/// existing membership API; new code should use [`LeaseStore`]
/// + [`LeaseHandle`].
pub struct Lease {
    pub key: String,
    pub expires_at: Instant,
}

#[async_trait::async_trait]
pub trait ClusterMembership: Send + Sync + 'static {
    fn self_node(&self) -> &NodeInfo;
    async fn peers(&self) -> Vec<NodeInfo>;
    async fn acquire_lease(&self, key: &str, ttl: Duration) -> Result<Option<Lease>>;
}

// ---------------------------------------------------------------------------
// Distributed lease (B1-T3)
// ---------------------------------------------------------------------------

/// Identity of a cluster node. Stable across reconnections, scoped
/// to one process. Use a UUID, hostname-PID combo, or a config-set
/// identifier — anything globally unique within the cluster.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodeId(pub String);

impl NodeId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Handle to a held lease. Returned by
/// [`LeaseStore::acquire`]; passed back to `renew` and `release`
/// so a node can only operate on a lease it actually owns.
///
/// `fence` is a monotonically-increasing fencing token —
/// downstream code (e.g. ACME issuance) can stamp side-effects
/// with this token to detect stale-leader writes after a
/// partition heals.
#[derive(Clone, Debug)]
pub struct LeaseHandle {
    pub key: String,
    pub holder: NodeId,
    pub fence: u64,
}

/// Distributed lease store.
///
/// Implementations:
///
/// - `aegis-proxy::cluster_lease::InProcessLease` — single-node
///   default (replaces the in-process `acquire_lease` on
///   `InProcessCluster`).
/// - `aegis-proxy::cluster_lease::RedisLease` — feature-gated
///   `aegis-proxy/redis`; uses `SET NX PX` for acquire and a Lua
///   CAS script for `renew` / `release` so only the holder can
///   mutate a key.
///
/// **Failure semantics.** If a backend op fails (network, Redis
/// down), `renew` returns `Ok(false)` to signal "lease lost" so
/// the caller stops the gated task. `acquire` returns `Err` only
/// for misconfiguration; transient unreachability returns
/// `Ok(None)`.
#[async_trait::async_trait]
pub trait LeaseStore: Send + Sync + 'static {
    /// Try to take the lease named `key` for `ttl`. Returns
    /// `Some(handle)` if acquired (or already held by us),
    /// `None` if another node holds it.
    async fn acquire(&self, key: &str, ttl: Duration) -> Result<Option<LeaseHandle>>;

    /// Refresh `lease`'s TTL. Returns `true` if we still hold
    /// it, `false` if we lost it (e.g. partition expired our
    /// lease and another node took it).
    async fn renew(&self, lease: &LeaseHandle, ttl: Duration) -> Result<bool>;

    /// Voluntarily release the lease. No-op if we no longer hold
    /// it.
    async fn release(&self, lease: &LeaseHandle) -> Result<()>;

    /// Observability — who currently holds `key`? Returns `None`
    /// if no live holder.
    async fn holder(&self, key: &str) -> Result<Option<NodeId>>;

    /// The identity *this* store acquires leases under. Used by
    /// admin observability surfaces (carry-over 3, post
    /// 2026-04-29 cluster smoke) to render
    /// `is_leader = self_id() == holder("leader:cluster")`.
    /// Default impl returns "unknown" so existing concrete
    /// stores compile without change; in-tree impls override.
    fn self_id(&self) -> NodeId {
        NodeId::new("unknown")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_info_fields() {
        let n = NodeInfo {
            id: "node-1".into(),
            zone: Some("us-east-1a".into()),
            version: "0.1.0".into(),
            load: 42,
            started_at: chrono::Utc::now(),
        };
        assert_eq!(n.id, "node-1");
        assert_eq!(n.load, 42);
    }

    #[test]
    fn lease_has_expiry() {
        let l = Lease {
            key: "leader/threat-intel".into(),
            expires_at: Instant::now() + Duration::from_secs(30),
        };
        assert!(l.expires_at > Instant::now());
    }

    #[test]
    fn node_info_is_clone() {
        let n = NodeInfo {
            id: "node-2".into(),
            zone: None,
            version: "0.1.0".into(),
            load: 0,
            started_at: chrono::Utc::now(),
        };
        let n2 = n.clone();
        assert_eq!(n.id, n2.id);
    }

    #[test]
    fn node_id_round_trips() {
        let id = NodeId::new("waf-0");
        assert_eq!(id.as_str(), "waf-0");
        assert_eq!(format!("{id}"), "waf-0");
        assert_eq!(id.clone(), id);
    }

    #[test]
    fn lease_handle_carries_fence() {
        let h = LeaseHandle {
            key: "acme".into(),
            holder: NodeId::new("waf-0"),
            fence: 7,
        };
        assert_eq!(h.fence, 7);
        assert_eq!(h.holder.as_str(), "waf-0");
    }
}
