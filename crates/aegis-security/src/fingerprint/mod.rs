pub mod h2;
pub mod ja3;
pub mod ja4;

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
}
