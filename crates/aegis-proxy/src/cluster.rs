//! Cluster membership and leader lease.
//!
//! Default: SWIM gossip (via `foca`).
//! Alternate: Redis-backed registry (`nodes:*` keys with TTL heartbeat).
//! `acquire_lease(key, ttl)` ensures only one node runs ACME, GitOps, etc.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Identity of a cluster node.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodeId(pub String);

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// State of a peer as seen by this node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    Alive,
    Suspect,
    Down,
}

/// In-process cluster membership for testing and single-node deployment.
pub struct InProcessCluster {
    self_id: NodeId,
    peers: Arc<Mutex<HashMap<NodeId, PeerState>>>,
    leases: Arc<Mutex<HashMap<String, (NodeId, Instant)>>>,
    lease_ttl: Duration,
}

impl InProcessCluster {
    pub fn new(self_id: NodeId, lease_ttl: Duration) -> Self {
        Self {
            self_id,
            peers: Arc::new(Mutex::new(HashMap::new())),
            leases: Arc::new(Mutex::new(HashMap::new())),
            lease_ttl,
        }
    }

    /// Register a peer as alive.
    pub fn add_peer(&self, id: NodeId) {
        self.peers.lock().unwrap().insert(id, PeerState::Alive);
    }

    /// Mark a peer as suspect.
    pub fn suspect_peer(&self, id: &NodeId) {
        if let Some(state) = self.peers.lock().unwrap().get_mut(id) {
            *state = PeerState::Suspect;
        }
    }

    /// Mark a peer as down and remove it.
    pub fn remove_peer(&self, id: &NodeId) {
        self.peers.lock().unwrap().remove(id);
    }

    /// List alive peers.
    pub fn peers(&self) -> Vec<(NodeId, PeerState)> {
        self.peers
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect()
    }

    /// Number of alive peers (excluding self).
    pub fn peer_count(&self) -> usize {
        self.peers
            .lock()
            .unwrap()
            .values()
            .filter(|s| matches!(s, PeerState::Alive))
            .count()
    }

    /// Try to acquire a named lease.  Returns `true` if this node now holds it.
    pub fn acquire_lease(&self, key: &str) -> bool {
        let mut leases = self.leases.lock().unwrap();
        let now = Instant::now();

        if let Some((holder, expires)) = leases.get(key) {
            if *holder == self.self_id {
                // Refresh our own lease.
                leases.insert(key.to_string(), (self.self_id.clone(), now + self.lease_ttl));
                return true;
            }
            if now < *expires {
                return false; // Another node holds it.
            }
        }

        // Lease is free or expired — acquire.
        leases.insert(key.to_string(), (self.self_id.clone(), now + self.lease_ttl));
        true
    }

    /// Check who holds a lease.
    pub fn lease_holder(&self, key: &str) -> Option<NodeId> {
        let leases = self.leases.lock().unwrap();
        leases.get(key).and_then(|(id, expires)| {
            if Instant::now() < *expires {
                Some(id.clone())
            } else {
                None
            }
        })
    }

    pub fn self_id(&self) -> &NodeId {
        &self.self_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cluster(name: &str) -> InProcessCluster {
        InProcessCluster::new(NodeId(name.into()), Duration::from_secs(10))
    }

    #[test]
    fn add_and_list_peers() {
        let c = cluster("node-1");
        c.add_peer(NodeId("node-2".into()));
        c.add_peer(NodeId("node-3".into()));
        assert_eq!(c.peer_count(), 2);
    }

    #[test]
    fn suspect_and_remove() {
        let c = cluster("node-1");
        c.add_peer(NodeId("node-2".into()));
        c.suspect_peer(&NodeId("node-2".into()));
        let peers = c.peers();
        assert_eq!(peers[0].1, PeerState::Suspect);

        c.remove_peer(&NodeId("node-2".into()));
        assert_eq!(c.peer_count(), 0);
    }

    #[test]
    fn lease_acquired_by_first_node() {
        let c1 = cluster("node-1");
        assert!(c1.acquire_lease("acme"));
        assert_eq!(c1.lease_holder("acme").unwrap(), NodeId("node-1".into()));
    }

    #[test]
    fn lease_blocked_by_holder() {
        let c1 = cluster("node-1");
        let c2 = InProcessCluster {
            self_id: NodeId("node-2".into()),
            peers: Arc::new(Mutex::new(HashMap::new())),
            leases: c1.leases.clone(), // shared lease store
            lease_ttl: Duration::from_secs(10),
        };

        assert!(c1.acquire_lease("acme"));
        assert!(!c2.acquire_lease("acme")); // blocked
    }

    #[test]
    fn lease_refreshed_by_holder() {
        let c1 = cluster("node-1");
        assert!(c1.acquire_lease("acme"));
        assert!(c1.acquire_lease("acme")); // refresh succeeds
    }

    #[test]
    fn expired_lease_can_be_taken() {
        let c1 = InProcessCluster::new(
            NodeId("node-1".into()),
            Duration::from_millis(1), // very short TTL
        );
        let c2 = InProcessCluster {
            self_id: NodeId("node-2".into()),
            peers: Arc::new(Mutex::new(HashMap::new())),
            leases: c1.leases.clone(),
            lease_ttl: Duration::from_secs(10),
        };

        assert!(c1.acquire_lease("acme"));
        // Wait for expiry.
        std::thread::sleep(Duration::from_millis(10));
        assert!(c2.acquire_lease("acme"));
        assert_eq!(c2.lease_holder("acme").unwrap(), NodeId("node-2".into()));
    }

    #[test]
    fn three_node_cluster_single_lease_holder() {
        let shared_leases = Arc::new(Mutex::new(HashMap::new()));
        let nodes: Vec<_> = (1..=3)
            .map(|i| InProcessCluster {
                self_id: NodeId(format!("node-{i}")),
                peers: Arc::new(Mutex::new(HashMap::new())),
                leases: shared_leases.clone(),
                lease_ttl: Duration::from_secs(10),
            })
            .collect();

        // All try to acquire the same lease.
        let mut winners = 0;
        for node in &nodes {
            if node.acquire_lease("gitops") {
                winners += 1;
            }
        }
        // Exactly one winner.
        assert_eq!(winners, 1);

        // Verify the lease holder is consistent.
        let holder = nodes[0].lease_holder("gitops").unwrap();
        for node in &nodes {
            assert_eq!(node.lease_holder("gitops").unwrap(), holder);
        }
    }
}
