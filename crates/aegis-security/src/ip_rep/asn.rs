use std::net::IpAddr;

/// ASN category for an IP address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AsnCategory {
    Residential,
    Hosting,
    Vpn,
    Tor,
    Bogon,
    Unknown,
}

/// Risk delta per ASN category.
#[derive(Clone, Debug)]
pub struct AsnRiskConfig {
    pub hosting_delta: i32,
    pub vpn_delta: i32,
    pub tor_delta: i32,
    pub bogon_delta: i32,
    pub residential_delta: i32,
}

impl Default for AsnRiskConfig {
    fn default() -> Self {
        Self {
            hosting_delta: 10,
            vpn_delta: 5,
            tor_delta: 15,
            bogon_delta: 20,
            residential_delta: 0,
        }
    }
}

/// ASN classifier trait — abstracts the MaxMind DB lookup.
pub trait AsnClassifier: Send + Sync {
    fn classify(&self, ip: IpAddr) -> AsnCategory;
    fn asn_number(&self, ip: IpAddr) -> Option<u32>;
    fn asn_org(&self, ip: IpAddr) -> Option<String>;
}

/// In-memory ASN classifier with known ASN ranges.
///
/// In production, this would wrap a MaxMind GeoLite2-ASN mmdb reader.
/// For now, it uses a configurable set of known ASN → category mappings.
pub struct StaticAsnClassifier {
    /// Known hosting ASNs.
    pub hosting_asns: Vec<u32>,
    /// Known VPN ASNs.
    pub vpn_asns: Vec<u32>,
    /// Known Tor exit node IPs (simplified).
    pub tor_exits: Vec<IpAddr>,
    /// Bogon ranges.
    pub bogon_ranges: Vec<ipnet::IpNet>,
}

impl Default for StaticAsnClassifier {
    fn default() -> Self {
        Self {
            hosting_asns: vec![
                16509,  // AWS
                14618,  // AWS
                15169,  // Google Cloud
                8075,   // Microsoft Azure
                13335,  // Cloudflare
                20940,  // Akamai
                63949,  // Linode
                14061,  // DigitalOcean
                16276,  // OVH
                24940,  // Hetzner
            ],
            vpn_asns: vec![
                9009,   // M247 (NordVPN, etc.)
                60068,  // Datacamp / CDN77
                212238, // Datacamp
                209854, // Private Internet Access
            ],
            tor_exits: Vec::new(),
            bogon_ranges: vec![
                "0.0.0.0/8".parse().unwrap(),
                "100.64.0.0/10".parse().unwrap(),
                "169.254.0.0/16".parse().unwrap(),
                "192.0.0.0/24".parse().unwrap(),
                "192.0.2.0/24".parse().unwrap(),
                "198.18.0.0/15".parse().unwrap(),
                "198.51.100.0/24".parse().unwrap(),
                "203.0.113.0/24".parse().unwrap(),
                "224.0.0.0/4".parse().unwrap(),
                "240.0.0.0/4".parse().unwrap(),
            ],
        }
    }
}

impl AsnClassifier for StaticAsnClassifier {
    fn classify(&self, ip: IpAddr) -> AsnCategory {
        // Check Tor first.
        if self.tor_exits.contains(&ip) {
            return AsnCategory::Tor;
        }

        // Check bogon.
        if self.bogon_ranges.iter().any(|net| net.contains(&ip)) {
            return AsnCategory::Bogon;
        }

        // In production, do mmdb lookup to get ASN, then categorize.
        // Here, we return Unknown since we don't have the mmdb.
        AsnCategory::Unknown
    }

    fn asn_number(&self, _ip: IpAddr) -> Option<u32> {
        // Would be populated by mmdb lookup.
        None
    }

    fn asn_org(&self, _ip: IpAddr) -> Option<String> {
        None
    }
}

impl StaticAsnClassifier {
    /// Classify by ASN number directly (for when mmdb lookup provides the ASN).
    pub fn classify_asn(&self, asn: u32) -> AsnCategory {
        if self.hosting_asns.contains(&asn) {
            return AsnCategory::Hosting;
        }
        if self.vpn_asns.contains(&asn) {
            return AsnCategory::Vpn;
        }
        AsnCategory::Residential
    }
}

impl AsnRiskConfig {
    pub fn risk_delta(&self, category: &AsnCategory) -> i32 {
        match category {
            AsnCategory::Residential => self.residential_delta,
            AsnCategory::Hosting => self.hosting_delta,
            AsnCategory::Vpn => self.vpn_delta,
            AsnCategory::Tor => self.tor_delta,
            AsnCategory::Bogon => self.bogon_delta,
            AsnCategory::Unknown => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosting_asn_classified() {
        let c = StaticAsnClassifier::default();
        assert_eq!(c.classify_asn(16509), AsnCategory::Hosting); // AWS
        assert_eq!(c.classify_asn(15169), AsnCategory::Hosting); // Google
        assert_eq!(c.classify_asn(14061), AsnCategory::Hosting); // DigitalOcean
    }

    #[test]
    fn vpn_asn_classified() {
        let c = StaticAsnClassifier::default();
        assert_eq!(c.classify_asn(9009), AsnCategory::Vpn);  // M247
        assert_eq!(c.classify_asn(60068), AsnCategory::Vpn); // CDN77
    }

    #[test]
    fn residential_asn_classified() {
        let c = StaticAsnClassifier::default();
        assert_eq!(c.classify_asn(7922), AsnCategory::Residential);  // Comcast
        assert_eq!(c.classify_asn(701), AsnCategory::Residential);   // Verizon
    }

    #[test]
    fn bogon_ip_detected() {
        let c = StaticAsnClassifier::default();
        assert_eq!(c.classify("0.0.0.1".parse().unwrap()), AsnCategory::Bogon);
        assert_eq!(c.classify("169.254.1.1".parse().unwrap()), AsnCategory::Bogon);
        assert_eq!(c.classify("203.0.113.1".parse().unwrap()), AsnCategory::Bogon);
        assert_eq!(c.classify("240.0.0.1".parse().unwrap()), AsnCategory::Bogon);
    }

    #[test]
    fn tor_exit_detected() {
        let mut c = StaticAsnClassifier::default();
        c.tor_exits.push("198.51.100.50".parse().unwrap());
        // Note: this IP is also in bogon range, but tor check runs first.
        assert_eq!(c.classify("198.51.100.50".parse().unwrap()), AsnCategory::Tor);
    }

    #[test]
    fn normal_ip_unknown() {
        let c = StaticAsnClassifier::default();
        assert_eq!(c.classify("8.8.8.8".parse().unwrap()), AsnCategory::Unknown);
    }

    #[test]
    fn risk_deltas() {
        let cfg = AsnRiskConfig::default();
        assert_eq!(cfg.risk_delta(&AsnCategory::Hosting), 10);
        assert_eq!(cfg.risk_delta(&AsnCategory::Tor), 15);
        assert_eq!(cfg.risk_delta(&AsnCategory::Bogon), 20);
        assert_eq!(cfg.risk_delta(&AsnCategory::Residential), 0);
        assert_eq!(cfg.risk_delta(&AsnCategory::Unknown), 0);
    }

    #[test]
    fn custom_risk_config() {
        let cfg = AsnRiskConfig {
            hosting_delta: 20,
            vpn_delta: 15,
            tor_delta: 30,
            bogon_delta: 50,
            residential_delta: -5,
        };
        assert_eq!(cfg.risk_delta(&AsnCategory::Hosting), 20);
        assert_eq!(cfg.risk_delta(&AsnCategory::Residential), -5);
    }
}
