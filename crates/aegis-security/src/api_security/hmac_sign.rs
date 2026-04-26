/// HMAC request signing verification (SigV4-style).
use std::collections::BTreeMap;

/// HMAC signature config.
#[derive(Clone, Debug)]
pub struct HmacConfig {
    pub clock_skew_s: u64,
}

impl Default for HmacConfig {
    fn default() -> Self {
        Self { clock_skew_s: 300 }
    }
}

/// Compute canonical string for signing.
pub fn canonical_string(
    method: &str,
    path: &str,
    headers: &BTreeMap<String, String>,
    body_hash: &str,
) -> String {
    let canonical_headers: String = headers
        .iter()
        .map(|(k, v)| format!("{}:{}", k.to_lowercase(), v.trim()))
        .collect::<Vec<_>>()
        .join("\n");
    let signed_headers: String = headers
        .keys()
        .map(|k| k.to_lowercase())
        .collect::<Vec<_>>()
        .join(";");
    format!("{method}\n{path}\n{canonical_headers}\n{signed_headers}\n{body_hash}")
}

/// Sign a canonical string with a secret key.
pub fn sign(canonical: &str, secret: &[u8; 32]) -> String {
    let mut hasher = blake3::Hasher::new_keyed(secret);
    hasher.update(canonical.as_bytes());
    hasher.finalize().to_hex().to_string()
}

/// Verify a request signature.
pub fn verify(
    method: &str,
    path: &str,
    headers: &BTreeMap<String, String>,
    body_hash: &str,
    claimed_signature: &str,
    secret: &[u8; 32],
) -> bool {
    let canonical = canonical_string(method, path, headers, body_hash);
    let expected = sign(&canonical, secret);
    constant_time_eq(&expected, claimed_signature)
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret() -> [u8; 32] {
        [42u8; 32]
    }

    fn test_headers() -> BTreeMap<String, String> {
        let mut h = BTreeMap::new();
        h.insert("host".into(), "api.example.com".into());
        h.insert("content-type".into(), "application/json".into());
        h
    }

    #[test]
    fn valid_signature_passes() {
        let headers = test_headers();
        let body_hash = blake3::hash(b"{}").to_hex().to_string();
        let canonical = canonical_string("POST", "/api/v1/data", &headers, &body_hash);
        let sig = sign(&canonical, &test_secret());
        assert!(verify("POST", "/api/v1/data", &headers, &body_hash, &sig, &test_secret()));
    }

    #[test]
    fn tampered_body_rejected() {
        let headers = test_headers();
        let original_hash = blake3::hash(b"{}").to_hex().to_string();
        let canonical = canonical_string("POST", "/api/v1/data", &headers, &original_hash);
        let sig = sign(&canonical, &test_secret());

        // Verify with different body hash.
        let tampered_hash = blake3::hash(b"{\"admin\":true}").to_hex().to_string();
        assert!(!verify("POST", "/api/v1/data", &headers, &tampered_hash, &sig, &test_secret()));
    }

    #[test]
    fn tampered_path_rejected() {
        let headers = test_headers();
        let body_hash = blake3::hash(b"{}").to_hex().to_string();
        let canonical = canonical_string("POST", "/api/v1/data", &headers, &body_hash);
        let sig = sign(&canonical, &test_secret());
        assert!(!verify("POST", "/api/v1/admin", &headers, &body_hash, &sig, &test_secret()));
    }

    #[test]
    fn wrong_secret_rejected() {
        let headers = test_headers();
        let body_hash = blake3::hash(b"{}").to_hex().to_string();
        let canonical = canonical_string("POST", "/api/v1/data", &headers, &body_hash);
        let sig = sign(&canonical, &test_secret());
        let wrong_secret = [99u8; 32];
        assert!(!verify("POST", "/api/v1/data", &headers, &body_hash, &sig, &wrong_secret));
    }

    #[test]
    fn deterministic_signature() {
        let headers = test_headers();
        let body_hash = blake3::hash(b"test").to_hex().to_string();
        let c1 = canonical_string("GET", "/path", &headers, &body_hash);
        let c2 = canonical_string("GET", "/path", &headers, &body_hash);
        assert_eq!(sign(&c1, &test_secret()), sign(&c2, &test_secret()));
    }

    #[test]
    fn canonical_header_ordering() {
        let mut h1 = BTreeMap::new();
        h1.insert("b-header".into(), "2".into());
        h1.insert("a-header".into(), "1".into());
        // BTreeMap sorts by key, so order is deterministic.
        let c = canonical_string("GET", "/", &h1, "hash");
        assert!(c.contains("a-header:1\nb-header:2"));
    }
}
