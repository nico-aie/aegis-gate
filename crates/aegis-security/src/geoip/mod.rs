//! GeoIP lookup surface.
//!
//! Provides a small [`GeoIpLookup`] trait so the rule engine
//! (and any future module that wants country/ASN) can resolve
//! a peer IP to an ISO-3166 alpha-2 country code or an
//! autonomous-system number without depending directly on
//! MaxMind's reader.
//!
//! The concrete [`reader::MaxMindReader`] implementation lives
//! behind the `geoip` Cargo feature so default builds don't
//! pull `maxminddb`.

use std::net::IpAddr;

#[cfg(feature = "geoip")]
pub mod reader;

#[cfg(feature = "geoip")]
pub use reader::MaxMindReader;

/// Read-only GeoIP lookup. Implementations are
/// [`Send`] + [`Sync`] so they can sit behind an `Arc` and
/// outlive a request.
pub trait GeoIpLookup: Send + Sync {
    /// Resolve `ip` to its ISO-3166 alpha-2 country code (e.g.
    /// `"US"`). Returns `None` if the IP is unknown to the
    /// reader, or if no country DB is configured.
    fn country(&self, ip: IpAddr) -> Option<String>;

    /// Resolve `ip` to its autonomous-system number. Returns
    /// `None` if the IP is unknown, or if no ASN DB is
    /// configured.
    fn asn(&self, ip: IpAddr) -> Option<u32>;
}

/// In-memory lookup useful for tests and dev environments.
/// Maps fixed IPs (or fixed `/24` prefixes for ASN) to
/// pre-canned country/ASN values. Not intended for production.
#[derive(Default)]
pub struct StaticGeoIp {
    /// Exact-IP → ISO country code.
    pub countries: std::collections::HashMap<IpAddr, String>,
    /// Exact-IP → ASN.
    pub asns: std::collections::HashMap<IpAddr, u32>,
}

impl StaticGeoIp {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_country(mut self, ip: &str, code: &str) -> Self {
        if let Ok(addr) = ip.parse() {
            self.countries.insert(addr, code.to_string());
        }
        self
    }

    pub fn with_asn(mut self, ip: &str, asn: u32) -> Self {
        if let Ok(addr) = ip.parse() {
            self.asns.insert(addr, asn);
        }
        self
    }
}

impl GeoIpLookup for StaticGeoIp {
    fn country(&self, ip: IpAddr) -> Option<String> {
        self.countries.get(&ip).cloned()
    }

    fn asn(&self, ip: IpAddr) -> Option<u32> {
        self.asns.get(&ip).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_lookup_returns_configured_country() {
        let g = StaticGeoIp::new().with_country("1.2.3.4", "US");
        assert_eq!(g.country("1.2.3.4".parse().unwrap()).as_deref(), Some("US"));
    }

    #[test]
    fn static_lookup_returns_none_for_unknown_ip() {
        let g = StaticGeoIp::new();
        assert!(g.country("9.9.9.9".parse().unwrap()).is_none());
        assert!(g.asn("9.9.9.9".parse().unwrap()).is_none());
    }

    #[test]
    fn static_lookup_returns_configured_asn() {
        let g = StaticGeoIp::new().with_asn("8.8.8.8", 15169);
        assert_eq!(g.asn("8.8.8.8".parse().unwrap()), Some(15169));
    }

    #[test]
    fn static_lookup_silently_drops_invalid_ip() {
        let g = StaticGeoIp::new()
            .with_country("not-an-ip", "US")
            .with_asn("also-not-an-ip", 42);
        assert!(g.countries.is_empty());
        assert!(g.asns.is_empty());
    }

    #[test]
    fn static_lookup_supports_ipv6() {
        let g = StaticGeoIp::new().with_country("2001:db8::1", "DE");
        assert_eq!(
            g.country("2001:db8::1".parse().unwrap()).as_deref(),
            Some("DE")
        );
    }

    #[test]
    fn indicator_count_defaults_to_none() {
        // PE-2 — implementations that can't count loaded indicators
        // report None (rendered as null on the wire), never a fake 0.
        let g = StaticGeoIp::new().with_country("1.2.3.4", "US");
        assert_eq!(g.indicator_count(), None);
    }
}
