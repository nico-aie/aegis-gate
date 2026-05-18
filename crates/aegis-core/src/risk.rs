use std::net::IpAddr;

#[derive(Clone, Hash, Eq, PartialEq, Debug)]
pub struct RiskKey {
    pub ip: IpAddr,
    pub device_fp: Option<String>,
    pub session: Option<String>,
    pub tenant_id: Option<String>,
}

impl RiskKey {
    /// 2026-05-18 F-CRITICAL-001 (security audit, Phase E) — the
    /// "legacy" / IP-only constructor. Used when the data plane
    /// doesn't have device-fingerprint or session info available
    /// (e.g. anonymous public endpoints, pre-session-warmup). All
    /// `Option` axes stay `None`.
    ///
    /// Composite-key construction (with `device_fp` from JA4 + UA
    /// hash, `session` from cookie / JWT-sub, `tenant_id` from
    /// route metadata) is a separate site-specific constructor —
    /// callers build a `RiskKey { … }` literal there. This helper
    /// is the bridge for the migration from IP-only to composite.
    pub fn from_ip(ip: IpAddr) -> Self {
        Self {
            ip,
            device_fp: None,
            session: None,
            tenant_id: None,
        }
    }
}

impl From<IpAddr> for RiskKey {
    fn from(ip: IpAddr) -> Self {
        Self::from_ip(ip)
    }
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
