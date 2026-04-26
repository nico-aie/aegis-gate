// Admin mTLS client certificate authentication.
//
// Valid client cert (matching SAN) bypasses password flow; session still issued.
// Still subject to IP allowlist.

/// mTLS config.
#[derive(Clone, Debug, Default)]
pub struct MtlsConfig {
    pub enabled: bool,
    pub ca_ref: String,
    pub allowed_sans: Vec<String>,
}

/// mTLS auth result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MtlsResult {
    Authenticated { subject: String },
    RejectedSan { presented: String },
    NoCertPresented,
    Disabled,
}

/// Verify a client certificate's SAN against allowed list.
pub fn verify_client_cert(
    config: &MtlsConfig,
    cert_san: Option<&str>,
) -> MtlsResult {
    if !config.enabled {
        return MtlsResult::Disabled;
    }

    let san = match cert_san {
        Some(s) => s,
        None => return MtlsResult::NoCertPresented,
    };

    if config.allowed_sans.iter().any(|allowed| allowed == san) {
        MtlsResult::Authenticated {
            subject: san.into(),
        }
    } else {
        MtlsResult::RejectedSan {
            presented: san.into(),
        }
    }
}

/// IP allowlist check for admin endpoint.
pub fn check_ip_allowlist(client_ip: &str, allowlist: &[ipnet::IpNet]) -> bool {
    if allowlist.is_empty() {
        return true; // No allowlist = all allowed.
    }
    let ip: std::net::IpAddr = match client_ip.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    allowlist.iter().any(|net| net.contains(&ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_config() -> MtlsConfig {
        MtlsConfig {
            enabled: true,
            ca_ref: "${secret:file:/etc/aegis/admin-ca.pem}".into(),
            allowed_sans: vec!["admin@aegis.local".into(), "ops@aegis.local".into()],
        }
    }

    // mTLS tests.
    #[test]
    fn mtls_disabled() {
        let cfg = MtlsConfig::default();
        assert_eq!(verify_client_cert(&cfg, Some("admin")), MtlsResult::Disabled);
    }

    #[test]
    fn mtls_no_cert() {
        let cfg = enabled_config();
        assert_eq!(verify_client_cert(&cfg, None), MtlsResult::NoCertPresented);
    }

    #[test]
    fn mtls_valid_san() {
        let cfg = enabled_config();
        let result = verify_client_cert(&cfg, Some("admin@aegis.local"));
        assert_eq!(
            result,
            MtlsResult::Authenticated {
                subject: "admin@aegis.local".into()
            }
        );
    }

    #[test]
    fn mtls_valid_second_san() {
        let cfg = enabled_config();
        let result = verify_client_cert(&cfg, Some("ops@aegis.local"));
        assert!(matches!(result, MtlsResult::Authenticated { .. }));
    }

    #[test]
    fn mtls_rejected_san() {
        let cfg = enabled_config();
        let result = verify_client_cert(&cfg, Some("evil@attacker.com"));
        assert_eq!(
            result,
            MtlsResult::RejectedSan {
                presented: "evil@attacker.com".into()
            }
        );
    }

    // IP allowlist tests.
    #[test]
    fn allowlist_empty_allows_all() {
        assert!(check_ip_allowlist("1.2.3.4", &[]));
    }

    #[test]
    fn allowlist_allows_matching_ip() {
        let nets: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        assert!(check_ip_allowlist("10.1.2.3", &nets));
    }

    #[test]
    fn allowlist_rejects_non_matching() {
        let nets: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        assert!(!check_ip_allowlist("192.168.1.1", &nets));
    }

    #[test]
    fn allowlist_exact_ip() {
        let nets: Vec<ipnet::IpNet> = vec!["192.168.1.100/32".parse().unwrap()];
        assert!(check_ip_allowlist("192.168.1.100", &nets));
        assert!(!check_ip_allowlist("192.168.1.101", &nets));
    }

    #[test]
    fn allowlist_ipv6() {
        let nets: Vec<ipnet::IpNet> = vec!["::1/128".parse().unwrap()];
        assert!(check_ip_allowlist("::1", &nets));
        assert!(!check_ip_allowlist("::2", &nets));
    }

    #[test]
    fn allowlist_multiple_nets() {
        let nets: Vec<ipnet::IpNet> = vec![
            "10.0.0.0/8".parse().unwrap(),
            "172.16.0.0/12".parse().unwrap(),
        ];
        assert!(check_ip_allowlist("10.1.1.1", &nets));
        assert!(check_ip_allowlist("172.20.1.1", &nets));
        assert!(!check_ip_allowlist("8.8.8.8", &nets));
    }

    #[test]
    fn allowlist_invalid_ip() {
        let nets: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        assert!(!check_ip_allowlist("not-an-ip", &nets));
    }
}
