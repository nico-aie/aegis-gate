use crate::error::Result;

#[derive(Clone, Debug)]
pub struct NodeInfo {
    pub id: String,
    pub zone: Option<String>,
    pub version: String,
    pub load: u32,
    pub started_at: chrono::DateTime<chrono::Utc>,
}

pub struct Lease {
    pub key: String,
    pub expires_at: std::time::Instant,
}

#[async_trait::async_trait]
pub trait ClusterMembership: Send + Sync + 'static {
    fn self_node(&self) -> &NodeInfo;
    async fn peers(&self) -> Vec<NodeInfo>;
    async fn acquire_lease(
        &self,
        key: &str,
        ttl: std::time::Duration,
    ) -> Result<Option<Lease>>;
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
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(30),
        };
        assert!(l.expires_at > std::time::Instant::now());
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
}
