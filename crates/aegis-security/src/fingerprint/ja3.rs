/// JA3 TLS fingerprint parser.
///
/// JA3 = MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
/// We use blake3 instead of MD5 for security.
///
/// Parse a JA3 fingerprint from raw ClientHello fields.
///
/// Fields:
/// - `tls_version`: e.g. 771 for TLS 1.2
/// - `cipher_suites`: list of cipher suite IDs
/// - `extensions`: list of extension IDs
/// - `elliptic_curves`: list of supported groups
/// - `ec_point_formats`: list of EC point format IDs
pub fn compute(
    tls_version: u16,
    cipher_suites: &[u16],
    extensions: &[u16],
    elliptic_curves: &[u16],
    ec_point_formats: &[u8],
) -> String {
    let raw = format!(
        "{},{},{},{},{}",
        tls_version,
        join_u16(cipher_suites),
        join_u16(extensions),
        join_u16(elliptic_curves),
        join_u8(ec_point_formats),
    );
    let hash = blake3::hash(raw.as_bytes());
    hash.to_hex().to_string()
}

/// Compute a salted JA3.
pub fn compute_salted(
    tls_version: u16,
    cipher_suites: &[u16],
    extensions: &[u16],
    elliptic_curves: &[u16],
    ec_point_formats: &[u8],
    salt: &[u8; 32],
) -> String {
    let raw = format!(
        "{},{},{},{},{}",
        tls_version,
        join_u16(cipher_suites),
        join_u16(extensions),
        join_u16(elliptic_curves),
        join_u8(ec_point_formats),
    );
    let mut hasher = blake3::Hasher::new_keyed(salt);
    hasher.update(raw.as_bytes());
    hasher.finalize().to_hex().to_string()
}

fn join_u16(vals: &[u16]) -> String {
    vals.iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

fn join_u8(vals: &[u8]) -> String {
    vals.iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Typical Chrome TLS 1.2 fields (simplified).
    const CHROME_VERSION: u16 = 771;
    const CHROME_CIPHERS: &[u16] = &[4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53];
    const CHROME_EXTENSIONS: &[u16] = &[0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 21];
    const CHROME_CURVES: &[u16] = &[29, 23, 24];
    const CHROME_POINTS: &[u8] = &[0];

    // Typical curl TLS 1.2 fields (simplified).
    const CURL_VERSION: u16 = 771;
    const CURL_CIPHERS: &[u16] = &[49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53, 10];
    const CURL_EXTENSIONS: &[u16] = &[0, 23, 65281, 10, 11, 35, 16, 5, 13];
    const CURL_CURVES: &[u16] = &[29, 23, 24];
    const CURL_POINTS: &[u8] = &[0];

    // Firefox TLS 1.3 (simplified).
    const FF_VERSION: u16 = 772;
    const FF_CIPHERS: &[u16] = &[4865, 4867, 4866, 49195, 49199, 52393, 52392, 49196, 49200, 49162, 49161, 49171, 49172, 156, 157, 47, 53];
    const FF_EXTENSIONS: &[u16] = &[0, 23, 65281, 10, 11, 35, 16, 5, 34, 51, 43, 13, 45, 28, 21];
    const FF_CURVES: &[u16] = &[29, 23, 24, 256, 257];
    const FF_POINTS: &[u8] = &[0];

    // Python requests (simplified).
    const PY_VERSION: u16 = 771;
    const PY_CIPHERS: &[u16] = &[49195, 49196, 52393, 49199, 49200, 52392, 49171, 49172, 156, 157, 47, 53];
    const PY_EXTENSIONS: &[u16] = &[0, 23, 65281, 10, 11, 35, 16, 5, 13, 18];
    const PY_CURVES: &[u16] = &[29, 23, 24];
    const PY_POINTS: &[u8] = &[0];

    #[test]
    fn ja3_deterministic() {
        let a = compute(CHROME_VERSION, CHROME_CIPHERS, CHROME_EXTENSIONS, CHROME_CURVES, CHROME_POINTS);
        let b = compute(CHROME_VERSION, CHROME_CIPHERS, CHROME_EXTENSIONS, CHROME_CURVES, CHROME_POINTS);
        assert_eq!(a, b);
    }

    #[test]
    fn ja3_chrome_vs_curl_differ() {
        let chrome = compute(CHROME_VERSION, CHROME_CIPHERS, CHROME_EXTENSIONS, CHROME_CURVES, CHROME_POINTS);
        let curl = compute(CURL_VERSION, CURL_CIPHERS, CURL_EXTENSIONS, CURL_CURVES, CURL_POINTS);
        assert_ne!(chrome, curl);
    }

    #[test]
    fn ja3_chrome_vs_firefox_differ() {
        let chrome = compute(CHROME_VERSION, CHROME_CIPHERS, CHROME_EXTENSIONS, CHROME_CURVES, CHROME_POINTS);
        let ff = compute(FF_VERSION, FF_CIPHERS, FF_EXTENSIONS, FF_CURVES, FF_POINTS);
        assert_ne!(chrome, ff);
    }

    #[test]
    fn ja3_firefox_vs_python_differ() {
        let ff = compute(FF_VERSION, FF_CIPHERS, FF_EXTENSIONS, FF_CURVES, FF_POINTS);
        let py = compute(PY_VERSION, PY_CIPHERS, PY_EXTENSIONS, PY_CURVES, PY_POINTS);
        assert_ne!(ff, py);
    }

    #[test]
    fn ja3_hash_length_is_64() {
        let h = compute(CHROME_VERSION, CHROME_CIPHERS, CHROME_EXTENSIONS, CHROME_CURVES, CHROME_POINTS);
        assert_eq!(h.len(), 64); // blake3 hex = 64 chars
    }

    #[test]
    fn ja3_salted_differs_from_unsalted() {
        let unsalted = compute(CHROME_VERSION, CHROME_CIPHERS, CHROME_EXTENSIONS, CHROME_CURVES, CHROME_POINTS);
        let salt = [42u8; 32];
        let salted = compute_salted(CHROME_VERSION, CHROME_CIPHERS, CHROME_EXTENSIONS, CHROME_CURVES, CHROME_POINTS, &salt);
        assert_ne!(unsalted, salted);
    }

    #[test]
    fn ja3_different_salts_differ() {
        let s1 = [1u8; 32];
        let s2 = [2u8; 32];
        let a = compute_salted(CHROME_VERSION, CHROME_CIPHERS, CHROME_EXTENSIONS, CHROME_CURVES, CHROME_POINTS, &s1);
        let b = compute_salted(CHROME_VERSION, CHROME_CIPHERS, CHROME_EXTENSIONS, CHROME_CURVES, CHROME_POINTS, &s2);
        assert_ne!(a, b);
    }

    #[test]
    fn ja3_empty_fields() {
        let h = compute(771, &[], &[], &[], &[]);
        assert_eq!(h.len(), 64);
    }
}
