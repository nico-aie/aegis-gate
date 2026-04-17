use std::net::IpAddr;

#[derive(Clone, Hash, Eq, PartialEq, Debug)]
pub struct RiskKey {
    pub ip: IpAddr,
    pub device_fp: Option<String>,
    pub session: Option<String>,
    pub tenant_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::Ipv4Addr;

    #[test]
    fn risk_key_equality() {
        let k1 = RiskKey {
            ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            device_fp: Some("fp123".into()),
            session: Some("sess-abc".into()),
            tenant_id: None,
        };
        let k2 = RiskKey {
            ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            device_fp: Some("fp123".into()),
            session: Some("sess-abc".into()),
            tenant_id: None,
        };
        assert_eq!(k1, k2);
    }

    #[test]
    fn risk_key_hash_stability() {
        let k1 = RiskKey {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            device_fp: None,
            session: None,
            tenant_id: None,
        };
        let k2 = k1.clone();
        let mut set = HashSet::new();
        set.insert(k1);
        assert!(set.contains(&k2));
    }

    #[test]
    fn risk_key_different_ips_not_equal() {
        let k1 = RiskKey {
            ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            device_fp: None,
            session: None,
            tenant_id: None,
        };
        let k2 = RiskKey {
            ip: IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
            device_fp: None,
            session: None,
            tenant_id: None,
        };
        assert_ne!(k1, k2);
    }
}
