use std::net::IpAddr;

use ipnet::IpNet;

/// Walk X-Forwarded-For right-to-left through trusted proxies to find the real client IP.
///
/// Rules:
///   - If the TCP peer is not in `trusted`, return the peer (ignore XFF entirely).
///   - Walk XFF from right to left; skip entries in `trusted`.
///   - First non-trusted entry is the client IP.
///   - If all XFF entries are trusted, return the leftmost XFF entry.
///   - If XFF is missing/empty, return the peer.
pub fn resolve_client_ip(
    peer: IpAddr,
    xff_header: Option<&str>,
    trusted: &[IpNet],
) -> IpAddr {
    // If peer is not trusted, ignore XFF entirely.
    if !is_trusted(peer, trusted) {
        return peer;
    }

    let xff = match xff_header {
        Some(h) if !h.trim().is_empty() => h,
        _ => return peer,
    };

    let addrs: Vec<&str> = xff.split(',').map(|s| s.trim()).collect();

    // Walk right-to-left.
    for addr_str in addrs.iter().rev() {
        if let Ok(ip) = addr_str.parse::<IpAddr>() {
            if !is_trusted(ip, trusted) {
                return ip;
            }
        } else {
            // Unparseable entry → treat as client (defensive).
            return peer;
        }
    }

    // All entries were trusted → use leftmost.
    if let Some(first) = addrs.first() {
        if let Ok(ip) = first.parse::<IpAddr>() {
            return ip;
        }
    }

    peer
}

fn is_trusted(ip: IpAddr, trusted: &[IpNet]) -> bool {
    trusted.iter().any(|net| net.contains(&ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trusted_nets() -> Vec<IpNet> {
        vec![
            "10.0.0.0/8".parse().unwrap(),
            "172.16.0.0/12".parse().unwrap(),
            "192.168.0.0/16".parse().unwrap(),
            "127.0.0.0/8".parse().unwrap(),
        ]
    }

    #[test]
    fn no_xff_returns_peer() {
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(resolve_client_ip(peer, None, &trusted_nets()), peer);
    }

    #[test]
    fn empty_xff_returns_peer() {
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(resolve_client_ip(peer, Some(""), &trusted_nets()), peer);
    }

    #[test]
    fn untrusted_peer_ignores_xff() {
        let peer: IpAddr = "8.8.8.8".parse().unwrap();
        let xff = "1.2.3.4, 10.0.0.1";
        assert_eq!(resolve_client_ip(peer, Some(xff), &trusted_nets()), peer);
    }

    #[test]
    fn spoofed_xff_through_untrusted_peer() {
        let peer: IpAddr = "203.0.113.50".parse().unwrap();
        let xff = "10.0.0.1, 192.168.1.1";
        // Peer is untrusted → XFF ignored.
        assert_eq!(resolve_client_ip(peer, Some(xff), &trusted_nets()), peer);
    }

    #[test]
    fn single_xff_client() {
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let xff = "203.0.113.50";
        assert_eq!(
            resolve_client_ip(peer, Some(xff), &trusted_nets()),
            "203.0.113.50".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn multi_hop_xff() {
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let xff = "203.0.113.50, 10.0.0.2, 10.0.0.3";
        // Walk R→L: 10.0.0.3 (trusted), 10.0.0.2 (trusted), 203.0.113.50 (not trusted) → client.
        assert_eq!(
            resolve_client_ip(peer, Some(xff), &trusted_nets()),
            "203.0.113.50".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn all_trusted_xff_returns_leftmost() {
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let xff = "10.0.0.5, 10.0.0.6, 10.0.0.7";
        assert_eq!(
            resolve_client_ip(peer, Some(xff), &trusted_nets()),
            "10.0.0.5".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn xff_with_spaces() {
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let xff = "  203.0.113.50 ,  10.0.0.2 ";
        assert_eq!(
            resolve_client_ip(peer, Some(xff), &trusted_nets()),
            "203.0.113.50".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn ipv6_xff() {
        let trusted = vec!["::1/128".parse().unwrap(), "fc00::/7".parse().unwrap()];
        let peer: IpAddr = "::1".parse().unwrap();
        let xff = "2001:db8::1, fc00::2";
        assert_eq!(
            resolve_client_ip(peer, Some(xff), &trusted),
            "2001:db8::1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn garbage_xff_entry_returns_peer() {
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let xff = "not-an-ip, 10.0.0.2";
        // Unparseable → defensive return peer.
        assert_eq!(resolve_client_ip(peer, Some(xff), &trusted_nets()), peer);
    }
}
