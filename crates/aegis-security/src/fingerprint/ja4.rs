/// JA4 TLS fingerprint parser.
///
/// JA4 format: {q}{version}{sni}{cipher_count}{ext_count}_{cipher_hash}_{ext_hash}
///
///   - q: 't' (TCP) or 'q' (QUIC)
///   - version: TLS version as 2-char string (12, 13, etc.)
///   - sni: 'd' (domain SNI) or 'i' (IP SNI) or 'x' (no SNI)
///   - cipher_count: 2-digit hex
///   - ext_count: 2-digit hex
///   - cipher_hash: truncated blake3 of sorted cipher list
///   - ext_hash: truncated blake3 of sorted extension list
///
/// SNI type for JA4.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SniType {
    Domain,
    Ip,
    None,
}

/// Protocol type for JA4.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtoType {
    Tcp,
    Quic,
}

/// Compute a JA4 fingerprint.
pub fn compute(
    proto: ProtoType,
    tls_version: u16,
    sni: SniType,
    cipher_suites: &[u16],
    extensions: &[u16],
) -> String {
    let q = match proto {
        ProtoType::Tcp => 't',
        ProtoType::Quic => 'q',
    };
    let ver = match tls_version {
        0x0301 => "10",
        0x0302 => "11",
        0x0303 => "12",
        0x0304 => "13",
        _ => "00",
    };
    let sni_char = match sni {
        SniType::Domain => 'd',
        SniType::Ip => 'i',
        SniType::None => 'x',
    };

    let cipher_count = cipher_suites.len().min(99);
    let ext_count = extensions.len().min(99);

    // Sort cipher suites and extensions for stability.
    let mut sorted_ciphers: Vec<u16> = cipher_suites.to_vec();
    sorted_ciphers.sort_unstable();
    let mut sorted_exts: Vec<u16> = extensions.to_vec();
    sorted_exts.sort_unstable();

    let cipher_str = sorted_ciphers
        .iter()
        .map(|c| format!("{c:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let ext_str = sorted_exts
        .iter()
        .map(|e| format!("{e:04x}"))
        .collect::<Vec<_>>()
        .join(",");

    let cipher_hash = truncated_hash(&cipher_str);
    let ext_hash = truncated_hash(&ext_str);

    format!(
        "{q}{ver}{sni_char}{cipher_count:02x}{ext_count:02x}_{cipher_hash}_{ext_hash}"
    )
}

/// Compute a salted JA4 fingerprint.
pub fn compute_salted(
    proto: ProtoType,
    tls_version: u16,
    sni: SniType,
    cipher_suites: &[u16],
    extensions: &[u16],
    salt: &[u8; 32],
) -> String {
    let raw = compute(proto, tls_version, sni, cipher_suites, extensions);
    let mut hasher = blake3::Hasher::new_keyed(salt);
    hasher.update(raw.as_bytes());
    hasher.finalize().to_hex().to_string()
}

fn truncated_hash(input: &str) -> String {
    let hash = blake3::hash(input.as_bytes());
    hash.to_hex()[..12].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Chrome TLS 1.3 via TCP with domain SNI.
    fn chrome_params() -> (ProtoType, u16, SniType, Vec<u16>, Vec<u16>) {
        (
            ProtoType::Tcp,
            0x0304,
            SniType::Domain,
            vec![4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392],
            vec![0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 21],
        )
    }

    // Firefox TLS 1.3 via TCP with domain SNI.
    fn firefox_params() -> (ProtoType, u16, SniType, Vec<u16>, Vec<u16>) {
        (
            ProtoType::Tcp,
            0x0304,
            SniType::Domain,
            vec![4865, 4867, 4866, 49195, 49199, 52393, 52392, 49196, 49200],
            vec![0, 23, 65281, 10, 11, 35, 16, 5, 34, 51, 43, 13, 45, 28, 21],
        )
    }

    // Curl TLS 1.2 via TCP.
    fn curl_params() -> (ProtoType, u16, SniType, Vec<u16>, Vec<u16>) {
        (
            ProtoType::Tcp,
            0x0303,
            SniType::Domain,
            vec![49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53, 10],
            vec![0, 23, 65281, 10, 11, 35, 16, 5, 13],
        )
    }

    // Python-requests TLS 1.2 via TCP.
    fn python_params() -> (ProtoType, u16, SniType, Vec<u16>, Vec<u16>) {
        (
            ProtoType::Tcp,
            0x0303,
            SniType::Domain,
            vec![49195, 49196, 52393, 49199, 49200, 52392, 49171, 49172, 156, 157, 47, 53],
            vec![0, 23, 65281, 10, 11, 35, 16, 5, 13, 18],
        )
    }

    #[test]
    fn ja4_deterministic() {
        let (p, v, s, c, e) = chrome_params();
        let a = compute(p, v, s, &c, &e);
        let b = compute(p, v, s, &c, &e);
        assert_eq!(a, b);
    }

    #[test]
    fn ja4_chrome_vs_firefox_differ() {
        let (p1, v1, s1, c1, e1) = chrome_params();
        let (p2, v2, s2, c2, e2) = firefox_params();
        let a = compute(p1, v1, s1, &c1, &e1);
        let b = compute(p2, v2, s2, &c2, &e2);
        // Same ciphers (sorted) but different extensions → should differ.
        assert_ne!(a, b);
    }

    #[test]
    fn ja4_chrome_vs_curl_differ() {
        let (p1, v1, s1, c1, e1) = chrome_params();
        let (p2, v2, s2, c2, e2) = curl_params();
        let a = compute(p1, v1, s1, &c1, &e1);
        let b = compute(p2, v2, s2, &c2, &e2);
        assert_ne!(a, b);
    }

    #[test]
    fn ja4_firefox_vs_python_differ() {
        let (p1, v1, s1, c1, e1) = firefox_params();
        let (p2, v2, s2, c2, e2) = python_params();
        let a = compute(p1, v1, s1, &c1, &e1);
        let b = compute(p2, v2, s2, &c2, &e2);
        assert_ne!(a, b);
    }

    #[test]
    fn ja4_format_structure() {
        let (p, v, s, c, e) = chrome_params();
        let fp = compute(p, v, s, &c, &e);
        // Format: {q}{ver}{sni}{cc}{ec}_{cipher_hash}_{ext_hash}
        let parts: Vec<&str> = fp.split('_').collect();
        assert_eq!(parts.len(), 3);
        // q(1) + ver(2) + sni(1) + cc(2hex) + ec(2hex) = 8 chars
        assert_eq!(parts[0].len(), 8);
        assert!(parts[0].starts_with('t'));
        assert_eq!(parts[1].len(), 12); // truncated hash
        assert_eq!(parts[2].len(), 12);
    }

    #[test]
    fn ja4_quic_vs_tcp_differ() {
        let (_, v, s, c, e) = chrome_params();
        let tcp = compute(ProtoType::Tcp, v, s, &c, &e);
        let quic = compute(ProtoType::Quic, v, s, &c, &e);
        assert_ne!(tcp, quic);
        assert!(tcp.starts_with('t'));
        assert!(quic.starts_with('q'));
    }

    #[test]
    fn ja4_sni_variants() {
        let c = &[4865u16, 4866];
        let e = &[0u16, 23];
        let domain = compute(ProtoType::Tcp, 0x0304, SniType::Domain, c, e);
        let ip = compute(ProtoType::Tcp, 0x0304, SniType::Ip, c, e);
        let none = compute(ProtoType::Tcp, 0x0304, SniType::None, c, e);
        assert_ne!(domain, ip);
        assert_ne!(domain, none);
        assert_ne!(ip, none);
    }

    #[test]
    fn ja4_salted_differs() {
        let (p, v, s, c, e) = chrome_params();
        let raw = compute(p, v, s, &c, &e);
        let salt = [99u8; 32];
        let salted = compute_salted(p, v, s, &c, &e, &salt);
        assert_ne!(raw, salted);
    }

    #[test]
    fn ja4_different_salts_differ() {
        let (p, v, s, c, e) = chrome_params();
        let s1 = [1u8; 32];
        let s2 = [2u8; 32];
        let a = compute_salted(p, v, s, &c, &e, &s1);
        let b = compute_salted(p, v, s, &c, &e, &s2);
        assert_ne!(a, b);
    }
}
