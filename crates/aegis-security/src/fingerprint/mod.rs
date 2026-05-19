pub mod device_ip_tracker;
pub mod h2;
pub mod ja3;
pub mod ja4;

pub use device_ip_tracker::DeviceIpTracker;

use aegis_core::TlsFingerprint;

/// Compute a composite device ID from available fingerprint data.
///
/// Uses blake3 keyed hash over (TLS fp, H2 fp, UA, header order) with deployment salt.
pub fn device_id(
    fp: &TlsFingerprint,
    h2: Option<&str>,
    ua: Option<&str>,
    header_order: &[String],
    salt: &[u8; 32],
) -> String {
    let mut hasher = blake3::Hasher::new_keyed(salt);
    hasher.update(fp.ja3.as_bytes());
    hasher.update(b"|");
    hasher.update(fp.ja4.as_bytes());
    hasher.update(b"|");
    hasher.update(h2.unwrap_or("").as_bytes());
    hasher.update(b"|");
    hasher.update(ua.unwrap_or("").as_bytes());
    hasher.update(b"|");
    for h in header_order {
        hasher.update(h.as_bytes());
        hasher.update(b",");
    }
    hasher.finalize().to_hex().to_string()
}

/// 2026-05-19 — short device-fingerprint hash for the
/// [`aegis_core::risk::RiskKey::device_fp`] axis. Distinct from
/// [`device_id`] above: this one is purpose-built for the
/// composite RiskKey, takes only `(ja4, ua)`, and returns a
/// 16-hex-character (64-bit) prefix of blake3.
///
/// Why no salt: the value is only ever used as an in-memory
/// HashMap key + the first 8 chars are surfaced through
/// `RiskSnapshot` to operators. A 64-bit unkeyed digest is
/// collision-safe at our scale (≪ 2³² distinct device shapes
/// per cluster lifetime) and lets two operators staring at the
/// same JA4+UA pair on different deployments compare notes
/// without the salt-swap mismatch the `device_id` helper has.
///
/// Why include `ua`: the same JA4 is shared across many distinct
/// browsers (Chrome 120 on macOS, Chrome 120 on Linux, …). The
/// UA disambiguates them without re-deriving JA4. Pass `None` if
/// the request didn't ship a User-Agent header — the hash stays
/// stable, both branches still bucket-isolate from non-UA-less
/// peers because the JA4 alone differs.
///
/// Why NO ip: the IP is already a separate axis on `RiskKey`.
/// Including it here would re-collapse buckets onto the IP axis
/// — defeating the whole point of the composite key.
pub fn device_fp_hash(ja4: &str, ua: Option<&str>) -> String {
    let mut h = blake3::Hasher::new();
    h.update(ja4.as_bytes());
    // Domain separator prevents any pathological "ja4 || ua" pair
    // from colliding with a different "ja4' || ua'" pair via
    // shifting the boundary.
    h.update(b"\0");
    h.update(ua.unwrap_or("").as_bytes());
    // 16 hex chars = 64 bits. Plenty of entropy for collision
    // resistance at any cluster scale; short enough that the
    // dashboard can render it inline.
    h.finalize().to_hex().to_string()[..16].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::TlsFingerprint;

    fn make_fp(ja3: &str, ja4: &str) -> TlsFingerprint {
        TlsFingerprint {
            ja3: ja3.into(),
            ja4: ja4.into(),
        }
    }

    #[test]
    fn device_id_deterministic() {
        let fp = make_fp("abc", "def");
        let salt = [1u8; 32];
        let a = device_id(&fp, Some("h2fp"), Some("Chrome"), &["accept".into(), "host".into()], &salt);
        let b = device_id(&fp, Some("h2fp"), Some("Chrome"), &["accept".into(), "host".into()], &salt);
        assert_eq!(a, b);
    }

    #[test]
    fn device_id_different_tls_differ() {
        let salt = [1u8; 32];
        let headers: Vec<String> = vec!["accept".into()];
        let a = device_id(&make_fp("abc", "def"), Some("h2"), Some("UA"), &headers, &salt);
        let b = device_id(&make_fp("xyz", "def"), Some("h2"), Some("UA"), &headers, &salt);
        assert_ne!(a, b);
    }

    #[test]
    fn device_id_different_h2_differ() {
        let fp = make_fp("abc", "def");
        let salt = [1u8; 32];
        let headers: Vec<String> = vec![];
        let a = device_id(&fp, Some("h2_chrome"), Some("UA"), &headers, &salt);
        let b = device_id(&fp, Some("h2_tonic"), Some("UA"), &headers, &salt);
        assert_ne!(a, b);
    }

    #[test]
    fn device_id_different_ua_differ() {
        let fp = make_fp("abc", "def");
        let salt = [1u8; 32];
        let headers: Vec<String> = vec![];
        let a = device_id(&fp, None, Some("Chrome/120"), &headers, &salt);
        let b = device_id(&fp, None, Some("Firefox/121"), &headers, &salt);
        assert_ne!(a, b);
    }

    #[test]
    fn device_id_different_salt_differ() {
        let fp = make_fp("abc", "def");
        let s1 = [1u8; 32];
        let s2 = [2u8; 32];
        let headers: Vec<String> = vec![];
        let a = device_id(&fp, None, None, &headers, &s1);
        let b = device_id(&fp, None, None, &headers, &s2);
        assert_ne!(a, b);
    }

    #[test]
    fn device_id_header_order_matters() {
        let fp = make_fp("abc", "def");
        let salt = [1u8; 32];
        let a = device_id(&fp, None, None, &["accept".into(), "host".into()], &salt);
        let b = device_id(&fp, None, None, &["host".into(), "accept".into()], &salt);
        assert_ne!(a, b);
    }

    #[test]
    fn device_id_none_fields_stable() {
        let fp = make_fp("abc", "def");
        let salt = [1u8; 32];
        let headers: Vec<String> = vec![];
        let a = device_id(&fp, None, None, &headers, &salt);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn device_id_hash_length() {
        let fp = make_fp("abc", "def");
        let salt = [1u8; 32];
        let id = device_id(&fp, Some("h2"), Some("ua"), &["accept".into()], &salt);
        assert_eq!(id.len(), 64); // blake3 hex
    }

    // ---- device_fp_hash (2026-05-19) ----

    #[test]
    fn device_fp_hash_length() {
        // 64-bit / 16 hex chars — the contract.
        let h = device_fp_hash("t13d1516h2_8daaf6152771_b0da82dd1658", Some("Mozilla/5.0"));
        assert_eq!(h.len(), 16);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn device_fp_hash_deterministic() {
        let a = device_fp_hash("ja4-x", Some("UA-1"));
        let b = device_fp_hash("ja4-x", Some("UA-1"));
        assert_eq!(a, b, "same inputs must yield same hash");
    }

    #[test]
    fn device_fp_hash_distinguishes_ja4() {
        let a = device_fp_hash("ja4-x", Some("UA"));
        let b = device_fp_hash("ja4-y", Some("UA"));
        assert_ne!(a, b);
    }

    #[test]
    fn device_fp_hash_distinguishes_ua() {
        // Two browsers with the same JA4 must hash differently
        // when their UA strings differ.
        let a = device_fp_hash("same-ja4", Some("Chrome/120 macOS"));
        let b = device_fp_hash("same-ja4", Some("Chrome/120 Linux"));
        assert_ne!(a, b);
    }

    #[test]
    fn device_fp_hash_no_ua_is_stable() {
        // The None branch hashes to a stable value (distinct from
        // any populated UA hash). Two requests from the same JA4
        // with no UA bucket together.
        let a = device_fp_hash("ja4-x", None);
        let b = device_fp_hash("ja4-x", None);
        assert_eq!(a, b);
        let c = device_fp_hash("ja4-x", Some(""));
        // Empty UA hashes the same as no UA — `unwrap_or("")`.
        assert_eq!(a, c);
    }

    #[test]
    fn device_fp_hash_domain_separator_prevents_boundary_collision() {
        // Without a domain separator, "ab"+"cd" and "a"+"bcd" would
        // hash identically (both concatenate to "abcd"). The
        // `\0` separator splits them.
        let a = device_fp_hash("ab", Some("cd"));
        let b = device_fp_hash("a", Some("bcd"));
        assert_ne!(a, b);
    }
}
