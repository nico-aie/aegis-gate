use crate::error::Result;

#[derive(Clone, Debug)]
pub struct MemberAddr {
    pub addr: std::net::SocketAddr,
    pub zone: Option<String>,
    pub weight: u32,
}

#[async_trait::async_trait]
pub trait ServiceDiscovery: Send + Sync + 'static {
    async fn subscribe(
        &self,
        pool: &str,
    ) -> Result<tokio::sync::watch::Receiver<Vec<MemberAddr>>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn member_addr_fields() {
        let m = MemberAddr {
            addr: "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
            zone: Some("zone-a".into()),
            weight: 10,
        };
        assert_eq!(m.addr.port(), 8080);
        assert_eq!(m.weight, 10);
    }

    #[test]
    fn member_addr_is_clone() {
        let m = MemberAddr {
            addr: "10.0.0.1:80".parse().unwrap(),
            zone: None,
            weight: 1,
        };
        let m2 = m.clone();
        assert_eq!(m.addr, m2.addr);
    }
}
