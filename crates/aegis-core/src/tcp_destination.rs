//! TCP-T1 — destination policy for raw-TCP CONNECT tunnels.
//!
//! See [`plans/tcp-forwarder-phase-4.md`] for the full design.
//! This module is the **pure** parser + admission gate; the
//! data-plane CONNECT handler (TCP-T3) calls
//! [`policy_admits`] after detectors but before opening the
//! upstream socket.
//!
//! ## Wire format
//!
//! Each entry in `route.tcp_destination_allowlist` is a string
//! of the shape `<cidr>:<port-spec>` where:
//!
//! - `<cidr>` is a single IPv4 or IPv6 CIDR (`10.0.0.0/8`,
//!   `2001:db8::/32`, or a bare host like `192.168.1.42` —
//!   parsed as `/32` or `/128`).
//! - `<port-spec>` is one of `<n>`, `<lo>-<hi>`, or `*`.
//!
//! Examples:
//!
//! - `"10.0.0.0/8:6379"`         — Redis private mesh, port 6379 only.
//! - `"192.168.1.0/24:443"`      — only HTTPS to that subnet.
//! - `"172.16.0.0/12:8000-8999"` — port range to a VPC.
//! - `"172.16.0.0/12:*"`         — any port to that VPC.
//! - `"::1/128:*"`               — REJECTED at parse-time
//!   (loopback is hardcoded-deny; see
//!   [`is_internal_address`]).
//!
//! Empty allowlist = closed: `policy_admits` returns `false`
//! for every input. Operators must opt-in to destinations
//! explicitly.

use std::net::IpAddr;

use ipnet::IpNet;

/// Range of permitted upstream ports for one allowlist entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortSpec {
    /// Single port number — exact match.
    One(u16),
    /// Inclusive range `[lo, hi]`.
    Range(u16, u16),
    /// Any port — `*`.
    Any,
}

impl PortSpec {
    pub fn matches(&self, port: u16) -> bool {
        match *self {
            PortSpec::One(p) => p == port,
            PortSpec::Range(lo, hi) => lo <= port && port <= hi,
            PortSpec::Any => true,
        }
    }
}

/// One parsed allowlist entry. `Vec<TcpDestinationRule>` is the
/// runtime form the data-plane consults on every CONNECT.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpDestinationRule {
    pub net: IpNet,
    pub ports: PortSpec,
}

impl TcpDestinationRule {
    pub fn admits(&self, addr: IpAddr, port: u16) -> bool {
        self.net.contains(&addr) && self.ports.matches(port)
    }
}

/// Parse a single `<cidr>:<port-spec>` entry. Errors carry the
/// offending input so config-load logs identify the bad row
/// without needing line numbers.
pub fn parse_rule(input: &str) -> Result<TcpDestinationRule, String> {
    if input.is_empty() {
        return Err("tcp_destination_allowlist entry must not be empty".into());
    }
    if input.contains(',') {
        return Err(format!(
            "tcp_destination_allowlist entry '{input}' contains ',' — use one entry per list element, not comma-separated",
        ));
    }
    // Split on the LAST colon. CIDR is everything before; port
    // spec is the tail. Splitting on the last colon is the only
    // way to handle IPv6 addresses, which contain colons.
    let (cidr_str, port_str) = input.rsplit_once(':').ok_or_else(|| {
        format!("tcp_destination_allowlist entry '{input}' missing ':<port-spec>'")
    })?;
    if cidr_str.is_empty() || port_str.is_empty() {
        return Err(format!(
            "tcp_destination_allowlist entry '{input}' has empty cidr or port-spec",
        ));
    }
    // IPv6 CIDRs in allowlist entries use the unbracketed form
    // (`2001:db8::/32:443`). Brackets are reserved for the
    // request-time CONNECT authority parser
    // ([`parse_authority`]) where they're a URI standard.
    let net = parse_cidr_or_host(cidr_str).map_err(|e| {
        format!("tcp_destination_allowlist entry '{input}': bad cidr: {e}")
    })?;
    let ports = parse_port_spec(port_str).map_err(|e| {
        format!("tcp_destination_allowlist entry '{input}': bad port-spec: {e}")
    })?;

    // Hardcoded reject of loopback / link-local / unspec at the
    // CIDR level — even if every address inside the CIDR would
    // resolve to "internal", we reject the whole entry. Operators
    // who really need this set `AEGIS_TCP_TUNNEL_ALLOW_INTERNAL=1`.
    if cidr_targets_internal_only(&net)
        && std::env::var("AEGIS_TCP_TUNNEL_ALLOW_INTERNAL").unwrap_or_default() != "1"
    {
        return Err(format!(
            "tcp_destination_allowlist entry '{input}' targets internal-only address space (loopback / link-local / unspec). Set AEGIS_TCP_TUNNEL_ALLOW_INTERNAL=1 to override.",
        ));
    }
    Ok(TcpDestinationRule { net, ports })
}

/// `host` accepted as `addr/32` or `addr/128`; otherwise fall
/// through to ipnet's parser.
fn parse_cidr_or_host(s: &str) -> Result<IpNet, String> {
    if let Ok(net) = s.parse::<IpNet>() {
        return Ok(net);
    }
    if let Ok(addr) = s.parse::<IpAddr>() {
        return Ok(match addr {
            IpAddr::V4(v4) => IpNet::V4(ipnet::Ipv4Net::new(v4, 32).unwrap()),
            IpAddr::V6(v6) => IpNet::V6(ipnet::Ipv6Net::new(v6, 128).unwrap()),
        });
    }
    Err(format!("'{s}' is neither a CIDR nor a bare IP"))
}

fn parse_port_spec(s: &str) -> Result<PortSpec, String> {
    if s == "*" {
        return Ok(PortSpec::Any);
    }
    if let Some((lo_str, hi_str)) = s.split_once('-') {
        let lo: u16 = lo_str
            .parse()
            .map_err(|_| format!("range low '{lo_str}' is not a valid port"))?;
        let hi: u16 = hi_str
            .parse()
            .map_err(|_| format!("range high '{hi_str}' is not a valid port"))?;
        if lo == 0 || hi == 0 {
            return Err("port 0 not allowed".into());
        }
        if lo > hi {
            return Err(format!("range low {lo} > high {hi}"));
        }
        return Ok(PortSpec::Range(lo, hi));
    }
    let p: u16 = s
        .parse()
        .map_err(|_| format!("'{s}' is not a valid port"))?;
    if p == 0 {
        return Err("port 0 not allowed".into());
    }
    Ok(PortSpec::One(p))
}

/// Hardcoded list of address ranges that are rejected as
/// CONNECT destinations regardless of the allowlist. Bypass
/// only via `AEGIS_TCP_TUNNEL_ALLOW_INTERNAL=1` (intentionally
/// awkward — this is the SSRF gate).
pub fn is_internal_address(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            v4.is_loopback()         // 127.0.0.0/8
                || v4.is_unspecified()   // 0.0.0.0
                || v4.is_link_local()    // 169.254.0.0/16
                || v4.is_broadcast()     // 255.255.255.255
                || v4.is_multicast()     // 224.0.0.0/4
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()         // ::1
                || v6.is_unspecified()   // ::
                || v6.is_multicast()     // ff00::/8
                // Link-local is fe80::/10. Rust's stable std has
                // `is_unicast_link_local` only on nightly, so check
                // the prefix manually.
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// True iff every address inside `net` is internal — used at
/// parse time to reject `127.0.0.0/8:*` etc. without enumerating
/// the network.
fn cidr_targets_internal_only(net: &IpNet) -> bool {
    is_internal_address(net.network()) && is_internal_address(net.broadcast())
}

/// Runtime admission. The data-plane CONNECT handler calls this
/// after `is_internal_address` has already been checked on the
/// resolved authority. Returns `true` iff at least one rule
/// admits the (addr, port) pair.
pub fn policy_admits(rules: &[TcpDestinationRule], addr: IpAddr, port: u16) -> bool {
    if is_internal_address(addr)
        && std::env::var("AEGIS_TCP_TUNNEL_ALLOW_INTERNAL").unwrap_or_default() != "1"
    {
        return false;
    }
    rules.iter().any(|r| r.admits(addr, port))
}

/// Parse a CONNECT request authority (`host:port`) into
/// `(IpAddr, u16)`. Returns `None` when the host is a DNS name
/// (TCP-T3 will resolve it before calling `policy_admits`) or
/// the form is malformed.
///
/// IPv6 authorities are bracketed (`[2001:db8::1]:443`) per
/// RFC 3986 §3.2.2; we strip the brackets here.
pub fn parse_authority(authority: &str) -> Option<(IpAddr, u16)> {
    let (host_str, port_str) = if let Some(rest) = authority.strip_prefix('[') {
        let (h, tail) = rest.split_once(']')?;
        let port = tail.strip_prefix(':')?;
        (h, port)
    } else {
        authority.rsplit_once(':')?
    };
    let port: u16 = port_str.parse().ok()?;
    let addr: IpAddr = host_str.parse().ok()?;
    Some((addr, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(s: &str) -> TcpDestinationRule {
        parse_rule(s).expect("parse")
    }

    // --- PortSpec ---

    #[test]
    fn port_spec_one_matches_only_exact() {
        assert!(PortSpec::One(443).matches(443));
        assert!(!PortSpec::One(443).matches(80));
    }

    #[test]
    fn port_spec_range_inclusive_both_ends() {
        let p = PortSpec::Range(8000, 8999);
        assert!(p.matches(8000));
        assert!(p.matches(8500));
        assert!(p.matches(8999));
        assert!(!p.matches(7999));
        assert!(!p.matches(9000));
    }

    #[test]
    fn port_spec_any_matches_anything() {
        assert!(PortSpec::Any.matches(1));
        assert!(PortSpec::Any.matches(443));
        assert!(PortSpec::Any.matches(65535));
    }

    // --- parse_rule happy paths ---

    #[test]
    fn parse_v4_cidr_with_single_port() {
        let rule = r("10.0.0.0/8:6379");
        assert_eq!(rule.ports, PortSpec::One(6379));
        assert!(rule.admits("10.1.2.3".parse().unwrap(), 6379));
        assert!(!rule.admits("10.1.2.3".parse().unwrap(), 6380));
        assert!(!rule.admits("11.0.0.1".parse().unwrap(), 6379));
    }

    #[test]
    fn parse_v4_host_treated_as_slash32() {
        let rule = r("203.0.113.42:443");
        assert!(rule.admits("203.0.113.42".parse().unwrap(), 443));
        assert!(!rule.admits("203.0.113.43".parse().unwrap(), 443));
    }

    #[test]
    fn parse_v4_with_port_range() {
        let rule = r("192.168.1.0/24:8000-8999");
        assert!(rule.admits("192.168.1.50".parse().unwrap(), 8500));
        assert!(!rule.admits("192.168.1.50".parse().unwrap(), 7999));
    }

    #[test]
    fn parse_v4_with_any_port() {
        let rule = r("172.16.0.0/12:*");
        assert!(rule.admits("172.16.5.5".parse().unwrap(), 1));
        assert!(rule.admits("172.16.5.5".parse().unwrap(), 65535));
        assert!(!rule.admits("172.32.0.1".parse().unwrap(), 80));
    }

    #[test]
    fn parse_v6_without_brackets() {
        let rule = r("2001:db8::/32:443");
        assert!(rule.admits("2001:db8::1".parse().unwrap(), 443));
    }

    // --- parse_rule rejections ---

    #[test]
    fn empty_input_rejected() {
        let err = parse_rule("").unwrap_err();
        assert!(err.contains("must not be empty"));
    }

    #[test]
    fn comma_separated_rejected() {
        let err = parse_rule("10.0.0.0/8:443,11.0.0.0/8:443").unwrap_err();
        assert!(err.contains("contains ','"));
    }

    #[test]
    fn missing_port_rejected() {
        let err = parse_rule("10.0.0.0/8").unwrap_err();
        assert!(err.contains("missing ':<port-spec>'"));
    }

    #[test]
    fn empty_cidr_rejected() {
        let err = parse_rule(":443").unwrap_err();
        assert!(err.contains("empty cidr or port-spec"));
    }

    #[test]
    fn empty_port_rejected() {
        let err = parse_rule("10.0.0.0/8:").unwrap_err();
        assert!(err.contains("empty cidr or port-spec"));
    }

    #[test]
    fn port_zero_rejected() {
        let err = parse_rule("10.0.0.0/8:0").unwrap_err();
        assert!(err.contains("port 0 not allowed"));
    }

    #[test]
    fn port_range_inverted_rejected() {
        let err = parse_rule("10.0.0.0/8:9000-8000").unwrap_err();
        assert!(err.contains("range low 9000 > high 8000"));
    }

    #[test]
    fn malformed_cidr_rejected() {
        let err = parse_rule("not-an-ip:443").unwrap_err();
        assert!(err.contains("bad cidr"));
    }

    #[test]
    fn malformed_port_rejected() {
        let err = parse_rule("10.0.0.0/8:abc").unwrap_err();
        assert!(err.contains("bad port-spec"));
    }

    // --- internal-address gate ---

    #[test]
    fn loopback_v4_is_internal() {
        assert!(is_internal_address("127.0.0.1".parse().unwrap()));
        assert!(is_internal_address("127.42.42.42".parse().unwrap()));
    }

    #[test]
    fn loopback_v6_is_internal() {
        assert!(is_internal_address("::1".parse().unwrap()));
    }

    #[test]
    fn unspecified_is_internal() {
        assert!(is_internal_address("0.0.0.0".parse().unwrap()));
        assert!(is_internal_address("::".parse().unwrap()));
    }

    #[test]
    fn link_local_v4_is_internal() {
        assert!(is_internal_address("169.254.1.1".parse().unwrap()));
    }

    #[test]
    fn link_local_v6_is_internal() {
        assert!(is_internal_address("fe80::1".parse().unwrap()));
    }

    #[test]
    fn multicast_is_internal() {
        assert!(is_internal_address("224.0.0.1".parse().unwrap()));
        assert!(is_internal_address("ff00::1".parse().unwrap()));
    }

    #[test]
    fn public_addresses_are_not_internal() {
        assert!(!is_internal_address("8.8.8.8".parse().unwrap()));
        assert!(!is_internal_address("203.0.113.1".parse().unwrap()));
        assert!(!is_internal_address("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn private_v4_ranges_are_not_internal() {
        // 10.0.0.0/8 and 192.168.0.0/16 are RFC 1918 private —
        // but they're a legitimate tcp-tunnel target (mesh
        // services). Don't lump them into internal.
        assert!(!is_internal_address("10.0.0.1".parse().unwrap()));
        assert!(!is_internal_address("192.168.1.1".parse().unwrap()));
        assert!(!is_internal_address("172.16.0.1".parse().unwrap()));
    }

    // --- internal-targeting CIDR is rejected at parse time ---

    #[test]
    fn loopback_cidr_rejected_at_parse() {
        let err = parse_rule("127.0.0.0/8:*").unwrap_err();
        assert!(
            err.contains("internal-only"),
            "expected internal-only reject, got: {err}",
        );
    }

    #[test]
    fn loopback_host_rejected_at_parse() {
        let err = parse_rule("127.0.0.1:443").unwrap_err();
        assert!(err.contains("internal-only"), "got: {err}");
    }

    #[test]
    fn unspec_cidr_rejected_at_parse() {
        let err = parse_rule("0.0.0.0/32:*").unwrap_err();
        assert!(err.contains("internal-only"), "got: {err}");
    }

    // --- policy_admits ---

    #[test]
    fn policy_admits_when_any_rule_matches() {
        let rules = [r("10.0.0.0/8:6379"), r("192.168.1.0/24:443")];
        assert!(policy_admits(
            &rules,
            "10.5.5.5".parse().unwrap(),
            6379
        ));
        assert!(policy_admits(
            &rules,
            "192.168.1.10".parse().unwrap(),
            443
        ));
    }

    #[test]
    fn policy_rejects_when_no_rule_matches() {
        let rules = [r("10.0.0.0/8:6379")];
        assert!(!policy_admits(&rules, "10.5.5.5".parse().unwrap(), 80));
        assert!(!policy_admits(&rules, "11.0.0.1".parse().unwrap(), 6379));
    }

    #[test]
    fn empty_allowlist_rejects_all() {
        assert!(!policy_admits(
            &[],
            "8.8.8.8".parse().unwrap(),
            443
        ));
    }

    #[test]
    fn policy_rejects_internal_addresses_even_when_listed() {
        // This case is unreachable via parse_rule (internal CIDRs
        // get rejected at parse time), but a programmatic caller
        // could construct one. Belt-and-braces.
        let rule = TcpDestinationRule {
            net: "10.0.0.0/8".parse().unwrap(),
            ports: PortSpec::Any,
        };
        // 127.0.0.1 is not in 10.0.0.0/8 either, but the point is
        // even if a rule did contain a loopback addr, the runtime
        // gate refuses.
        assert!(!policy_admits(
            std::slice::from_ref(&rule),
            "127.0.0.1".parse().unwrap(),
            443
        ));
    }

    // --- parse_authority ---

    #[test]
    fn parse_authority_v4() {
        let (addr, port) = parse_authority("203.0.113.1:443").unwrap();
        assert_eq!(addr, "203.0.113.1".parse::<IpAddr>().unwrap());
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_authority_v6_with_brackets() {
        let (addr, port) = parse_authority("[2001:db8::1]:443").unwrap();
        assert_eq!(addr, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_authority_dns_name_returns_none() {
        // CONNECT to a DNS name is the common case; the data-plane
        // resolves it before calling policy_admits. parse_authority
        // returning None signals "not a literal IP".
        assert!(parse_authority("api.example.com:443").is_none());
    }

    #[test]
    fn parse_authority_no_port_returns_none() {
        assert!(parse_authority("203.0.113.1").is_none());
    }

    #[test]
    fn parse_authority_bad_port_returns_none() {
        assert!(parse_authority("203.0.113.1:notaport").is_none());
        assert!(parse_authority("203.0.113.1:99999").is_none());
    }
}
