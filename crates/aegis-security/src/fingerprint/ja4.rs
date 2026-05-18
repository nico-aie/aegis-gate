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

    // 2026-05-18 (QC Sprint 2.1 — F-CRITICAL-011): strip GREASE
    // values before hashing. Chrome (and other browsers) rotate
    // a GREASE marker into a random slot of the cipher / extension
    // list on every TLS handshake — without stripping, every
    // connection from the same Chrome install produces a
    // different JA4 cipher_hash / ext_hash and the fingerprint
    // can't be used for device-stability checks (e.g. the
    // F-CRITICAL-010 device→IP reverse map). Per draft-ietf-tls-
    // grease-04 / RFC 8701, GREASE values match the pattern
    // `0x?A?A` where each nibble is 'A' — testable as
    // `(v & 0x0F0F) == 0x0A0A`.
    //
    // **No sort.** The pre-fix code did `.sort_unstable()` after
    // collecting, on the rationale of "stability across handshake
    // re-orderings". But the JA4 spec calls for ORIGINAL ORDER —
    // the cipher list's order IS the fingerprint signal. Sorting
    // collapsed legitimate client-distinguishing reorderings into
    // a single hash. After this fix, cipher_hash / ext_hash
    // distinguish clients that reorder their ClientHello lists.
    let cipher_count = cipher_suites.iter().filter(|c| !is_grease(**c)).count().min(99);
    let ext_count = extensions.iter().filter(|e| !is_grease(**e)).count().min(99);

    let cipher_str = cipher_suites
        .iter()
        .filter(|c| !is_grease(**c))
        .map(|c| format!("{c:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let ext_str = extensions
        .iter()
        .filter(|e| !is_grease(**e))
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

/// 2026-05-18 (QC Sprint 2.1 — F-CRITICAL-011): GREASE marker
/// predicate per RFC 8701. Chrome and other modern browsers
/// rotate one GREASE value into the cipher / extension lists on
/// every handshake; the JA4 spec calls for filtering them out so
/// the fingerprint is stable across connections.
///
/// GREASE values are `0x?A?A` where the top nibble of each byte
/// is `A` — testable as `(v & 0x0F0F) == 0x0A0A`. That covers
/// `0x0A0A`, `0x1A1A`, …, `0xFAFA` (16 reserved values).
#[inline]
pub(crate) fn is_grease(v: u16) -> bool {
    (v & 0x0F0F) == 0x0A0A
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

    // ---- 2026-05-18 QC Sprint 2.1 — F-CRITICAL-011 ----

    /// GREASE predicate covers all 16 reserved values from RFC 8701.
    #[test]
    fn is_grease_matches_rfc_8701_values() {
        // All 16 reserved GREASE values.
        for hi in 0..=15 {
            let v = ((hi << 4) | 0x0A) as u16;
            let v = (v << 8) | v;
            assert!(
                is_grease(v),
                "expected 0x{v:04x} to be GREASE",
            );
        }
        // Non-GREASE values.
        for v in [0x1301u16, 0x1303, 0x002b, 0x000a, 0xc02b, 0xc02f] {
            assert!(!is_grease(v), "expected 0x{v:04x} NOT to be GREASE");
        }
    }

    /// The KEY regression test for F-CRITICAL-011: Chrome's
    /// per-handshake GREASE rotation must NOT change the JA4.
    /// Same client, two handshakes with different GREASE slots →
    /// identical fingerprint.
    #[test]
    fn ja4_stable_under_chrome_grease_rotation() {
        // Chrome ClientHello with GREASE 0x0A0A in different slots.
        let ciphers_a: Vec<u16> = vec![
            0x0A0A, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f,
            0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035,
        ];
        // Same handshake, GREASE rotated to a different position +
        // value (0x1A1A this time).
        let ciphers_b: Vec<u16> = vec![
            0x1301, 0x1302, 0x1A1A, 0x1303, 0xc02b, 0xc02f,
            0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035,
        ];
        let exts: Vec<u16> = vec![
            0x002b, 0x002d, 0x0033, 0x000a, 0x000b, 0x0017,
            0xff01, 0x0005,
        ];
        let a = compute(ProtoType::Tcp, 0x0304, SniType::Domain, &ciphers_a, &exts);
        let b = compute(ProtoType::Tcp, 0x0304, SniType::Domain, &ciphers_b, &exts);
        assert_eq!(a, b, "GREASE rotation must not change JA4 (got {a} vs {b})");
    }

    /// Same rationale for the extension list.
    #[test]
    fn ja4_stable_under_grease_in_extensions() {
        let ciphers: Vec<u16> = vec![0x1301, 0x1302, 0x1303];
        let exts_a: Vec<u16> = vec![0x0A0A, 0x002b, 0x002d, 0x0033];
        let exts_b: Vec<u16> = vec![0x002b, 0x4A4A, 0x002d, 0x0033];
        let a = compute(ProtoType::Tcp, 0x0304, SniType::Domain, &ciphers, &exts_a);
        let b = compute(ProtoType::Tcp, 0x0304, SniType::Domain, &ciphers, &exts_b);
        assert_eq!(a, b);
    }

    /// Counter-test: NON-GREASE reordering DOES change the JA4.
    /// The pre-fix code sorted ciphers, which masked legitimate
    /// client-distinguishing reorderings.
    #[test]
    fn ja4_changes_when_non_grease_ciphers_reorder() {
        let ciphers_a: Vec<u16> = vec![0x1301, 0x1302, 0x1303];
        let ciphers_b: Vec<u16> = vec![0x1303, 0x1302, 0x1301]; // reversed
        let exts: Vec<u16> = vec![0x002b];
        let a = compute(ProtoType::Tcp, 0x0304, SniType::Domain, &ciphers_a, &exts);
        let b = compute(ProtoType::Tcp, 0x0304, SniType::Domain, &ciphers_b, &exts);
        assert_ne!(
            a, b,
            "non-GREASE cipher reordering should differentiate JA4 \
             (the pre-fix sort_unstable collapsed this signal)",
        );
    }

    /// GREASE count is excluded from the cipher_count / ext_count
    /// fields. Chrome with 17 ciphers (1 GREASE + 16 real) reports
    /// 10 (0x10 = 16) not 11.
    #[test]
    fn ja4_count_excludes_grease() {
        let ciphers: Vec<u16> =
            vec![0x0A0A, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f];
        let exts: Vec<u16> = vec![0x002b];
        let fp = compute(ProtoType::Tcp, 0x0304, SniType::Domain, &ciphers, &exts);
        // Format: q ver sni cipher_count ext_count _ cipher_hash _ ext_hash
        // → "t13d05" not "t13d06".
        assert!(
            fp.starts_with("t13d05"),
            "cipher_count must exclude GREASE (got prefix in {fp})",
        );
    }
}
