use std::net::SocketAddr;

/// HMAC-signed session affinity cookie.
///
/// The `AG_SID` cookie encodes the chosen upstream member address so that
/// subsequent requests from the same client are routed to the same member.
/// If the member is drained or unhealthy, the cookie is re-issued.
const COOKIE_NAME: &str = "AG_SID";

/// Session affinity configuration.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// HMAC secret for signing the cookie value.
    pub hmac_secret: Vec<u8>,
    /// Cookie `Path` attribute.
    pub cookie_path: String,
    /// Cookie `Max-Age` in seconds.
    pub max_age: u64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            hmac_secret: b"default-secret-change-me".to_vec(),
            cookie_path: "/".into(),
            max_age: 86400,
        }
    }
}

/// Encode a member address into a signed cookie value.
pub fn encode_cookie(addr: &SocketAddr, secret: &[u8]) -> String {
    let payload = addr.to_string();
    let sig = simple_hmac(payload.as_bytes(), secret);
    format!("{payload}.{sig}")
}

/// Decode and verify a cookie value, returning the member address.
pub fn decode_cookie(value: &str, secret: &[u8]) -> Option<SocketAddr> {
    let dot = value.rfind('.')?;
    let payload = &value[..dot];
    let sig = &value[dot + 1..];

    let expected = simple_hmac(payload.as_bytes(), secret);
    if !constant_time_eq(sig.as_bytes(), expected.as_bytes()) {
        return None;
    }

    payload.parse().ok()
}

/// Build a `Set-Cookie` header value for the affinity cookie.
pub fn build_set_cookie(addr: &SocketAddr, cfg: &SessionConfig) -> String {
    let value = encode_cookie(addr, &cfg.hmac_secret);
    format!(
        "{COOKIE_NAME}={value}; Path={}; Max-Age={}; HttpOnly; SameSite=Lax",
        cfg.cookie_path, cfg.max_age
    )
}

/// Extract the `AG_SID` value from request cookies.
pub fn extract_session_cookie(headers: &hyper::header::HeaderMap) -> Option<String> {
    for value in headers.get_all(hyper::header::COOKIE) {
        if let Ok(s) = value.to_str() {
            for pair in s.split(';') {
                let pair = pair.trim();
                if let Some(rest) = pair.strip_prefix("AG_SID=") {
                    return Some(rest.to_string());
                }
            }
        }
    }
    None
}

/// Simple HMAC-like hash using blake3 keyed mode (truncated hex).
fn simple_hmac(data: &[u8], key: &[u8]) -> String {
    // Use blake3 in keyed mode. Key must be exactly 32 bytes — pad/truncate.
    let mut key_arr = [0u8; 32];
    let len = key.len().min(32);
    key_arr[..len].copy_from_slice(&key[..len]);

    let hash = blake3::keyed_hash(&key_arr, data);
    let hex = hash.to_hex();
    hex[..16].to_string() // 16 hex chars = 64 bits, sufficient for cookie sig
}

/// Constant-time comparison to avoid timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn test_secret() -> Vec<u8> {
        b"test-secret-32-bytes-paddedXXXX".to_vec()
    }

    #[test]
    fn encode_decode_roundtrip() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let secret = test_secret();
        let cookie = encode_cookie(&addr, &secret);
        let decoded = decode_cookie(&cookie, &secret).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn tampered_cookie_rejected() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let secret = test_secret();
        let cookie = encode_cookie(&addr, &secret);
        // Tamper with the payload.
        let tampered = cookie.replace("127.0.0.1", "10.0.0.1");
        assert!(decode_cookie(&tampered, &secret).is_none());
    }

    #[test]
    fn wrong_secret_rejected() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let cookie = encode_cookie(&addr, &test_secret());
        assert!(decode_cookie(&cookie, b"wrong-secret-xxxxxxxxxxxxXXXXX").is_none());
    }

    #[test]
    fn build_set_cookie_format() {
        let addr: SocketAddr = "10.0.0.5:3000".parse().unwrap();
        let cfg = SessionConfig::default();
        let header = build_set_cookie(&addr, &cfg);
        assert!(header.starts_with("AG_SID="));
        assert!(header.contains("Path=/"));
        assert!(header.contains("HttpOnly"));
        assert!(header.contains("SameSite=Lax"));
        assert!(header.contains("Max-Age=86400"));
    }

    #[test]
    fn extract_cookie_from_headers() {
        let mut headers = hyper::header::HeaderMap::new();
        let cookie_val = encode_cookie(
            &"127.0.0.1:8080".parse().unwrap(),
            &test_secret(),
        );
        headers.insert(
            hyper::header::COOKIE,
            format!("other=foo; AG_SID={cookie_val}; bar=baz")
                .parse()
                .unwrap(),
        );
        let extracted = extract_session_cookie(&headers).unwrap();
        assert_eq!(extracted, cookie_val);
    }

    #[test]
    fn extract_cookie_missing() {
        let headers = hyper::header::HeaderMap::new();
        assert!(extract_session_cookie(&headers).is_none());
    }

    #[test]
    fn sticky_session_100_requests() {
        let addr: SocketAddr = "10.0.0.1:9090".parse().unwrap();
        let secret = test_secret();
        let cookie = encode_cookie(&addr, &secret);

        for _ in 0..100 {
            let decoded = decode_cookie(&cookie, &secret).unwrap();
            assert_eq!(decoded, addr);
        }
    }
}
