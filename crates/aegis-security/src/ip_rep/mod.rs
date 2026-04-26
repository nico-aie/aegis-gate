pub mod asn;
pub mod xff;

use std::net::IpAddr;

use ipnet::IpNet;

/// IP reputation list types.
#[derive(Clone, Debug)]
pub struct IpLists {
    pub whitelist: Vec<IpNet>,
    pub blacklist: Vec<IpNet>,
    pub trusted_proxies: Vec<IpNet>,
}

impl Default for IpLists {
    fn default() -> Self {
        Self {
            whitelist: Vec::new(),
            blacklist: Vec::new(),
            trusted_proxies: vec![
                "127.0.0.0/8".parse().unwrap(),
                "10.0.0.0/8".parse().unwrap(),
                "172.16.0.0/12".parse().unwrap(),
                "192.168.0.0/16".parse().unwrap(),
                "::1/128".parse().unwrap(),
                "fc00::/7".parse().unwrap(),
            ],
        }
    }
}

/// IP classification result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IpClassification {
    Whitelisted,
    Blacklisted,
    TrustedProxy,
    Unknown,
}

impl IpLists {
    /// Classify an IP address.
    pub fn classify(&self, ip: IpAddr) -> IpClassification {
        if self.whitelist.iter().any(|net| net.contains(&ip)) {
            return IpClassification::Whitelisted;
        }
        if self.blacklist.iter().any(|net| net.contains(&ip)) {
            return IpClassification::Blacklisted;
        }
        if self.trusted_proxies.iter().any(|net| net.contains(&ip)) {
            return IpClassification::TrustedProxy;
        }
        IpClassification::Unknown
    }

    /// Resolve the real client IP from peer + XFF using trusted proxy list.
    pub fn resolve_client_ip(&self, peer: IpAddr, xff: Option<&str>) -> IpAddr {
        xff::resolve_client_ip(peer, xff, &self.trusted_proxies)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitelist_takes_priority() {
        let mut lists = IpLists::default();
        lists.whitelist.push("1.2.3.0/24".parse().unwrap());
        lists.blacklist.push("1.2.3.0/24".parse().unwrap());
        assert_eq!(lists.classify("1.2.3.4".parse().unwrap()), IpClassification::Whitelisted);
    }

    #[test]
    fn blacklist_detected() {
        let mut lists = IpLists::default();
        lists.blacklist.push("198.51.100.0/24".parse().unwrap());
        assert_eq!(lists.classify("198.51.100.5".parse().unwrap()), IpClassification::Blacklisted);
    }

    #[test]
    fn trusted_proxy_detected() {
        let lists = IpLists::default();
        assert_eq!(lists.classify("10.0.0.1".parse().unwrap()), IpClassification::TrustedProxy);
        assert_eq!(lists.classify("127.0.0.1".parse().unwrap()), IpClassification::TrustedProxy);
    }

    #[test]
    fn unknown_ip() {
        let lists = IpLists::default();
        assert_eq!(lists.classify("8.8.8.8".parse().unwrap()), IpClassification::Unknown);
    }

    #[test]
    fn resolve_with_xff() {
        let lists = IpLists::default();
        let client = lists.resolve_client_ip("10.0.0.1".parse().unwrap(), Some("203.0.113.50"));
        assert_eq!(client, "203.0.113.50".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn resolve_untrusted_peer_ignores_xff() {
        let lists = IpLists::default();
        let peer: IpAddr = "8.8.8.8".parse().unwrap();
        let client = lists.resolve_client_ip(peer, Some("1.2.3.4"));
        assert_eq!(client, peer);
    }

    #[test]
    fn ipv6_blacklist() {
        let mut lists = IpLists::default();
        lists.blacklist.push("2001:db8::/32".parse().unwrap());
        assert_eq!(lists.classify("2001:db8::1".parse().unwrap()), IpClassification::Blacklisted);
    }

    #[test]
    fn empty_lists_all_unknown() {
        let lists = IpLists {
            whitelist: vec![],
            blacklist: vec![],
            trusted_proxies: vec![],
        };
        assert_eq!(lists.classify("10.0.0.1".parse().unwrap()), IpClassification::Unknown);
    }
}
