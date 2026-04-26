/// ICAP antivirus integration (RFC 3507 stub).
///
/// ICAP mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IcapMode {
    Reqmod,
    Respmod,
}

/// ICAP scan result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScanResult {
    Clean,
    Infected { threat_name: String },
    Error { message: String },
    Timeout,
}

/// ICAP client trait.
#[async_trait::async_trait]
pub trait IcapClient: Send + Sync {
    async fn scan(
        &self,
        mode: IcapMode,
        body: &[u8],
    ) -> aegis_core::Result<ScanResult>;
}

/// Stub ICAP client for testing.
pub struct StubIcapClient {
    eicar_detect: bool,
}

impl StubIcapClient {
    pub fn new(eicar_detect: bool) -> Self {
        Self { eicar_detect }
    }
}

/// EICAR test string.
const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

#[async_trait::async_trait]
impl IcapClient for StubIcapClient {
    async fn scan(
        &self,
        _mode: IcapMode,
        body: &[u8],
    ) -> aegis_core::Result<ScanResult> {
        if self.eicar_detect && body.windows(EICAR.len()).any(|w| w == EICAR) {
            return Ok(ScanResult::Infected {
                threat_name: "EICAR-Test-File".into(),
            });
        }
        Ok(ScanResult::Clean)
    }
}

/// Check if body should be scanned based on content hash cache.
pub fn should_scan(body_hash: &str, clean_cache: &std::collections::HashSet<String>) -> bool {
    !clean_cache.contains(body_hash)
}

/// Compute body hash for caching.
pub fn body_hash(body: &[u8]) -> String {
    blake3::hash(body).to_hex()[..16].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[tokio::test]
    async fn clean_body_passes() {
        let client = StubIcapClient::new(true);
        let result = client.scan(IcapMode::Reqmod, b"Hello World").await.unwrap();
        assert_eq!(result, ScanResult::Clean);
    }

    #[tokio::test]
    async fn eicar_detected() {
        let client = StubIcapClient::new(true);
        let result = client.scan(IcapMode::Reqmod, EICAR).await.unwrap();
        assert!(matches!(result, ScanResult::Infected { .. }));
        if let ScanResult::Infected { threat_name } = result {
            assert_eq!(threat_name, "EICAR-Test-File");
        }
    }

    #[tokio::test]
    async fn eicar_in_larger_body() {
        let client = StubIcapClient::new(true);
        let mut body = b"prefix".to_vec();
        body.extend_from_slice(EICAR);
        body.extend_from_slice(b"suffix");
        let result = client.scan(IcapMode::Reqmod, &body).await.unwrap();
        assert!(matches!(result, ScanResult::Infected { .. }));
    }

    #[tokio::test]
    async fn respmod_mode_works() {
        let client = StubIcapClient::new(true);
        let result = client.scan(IcapMode::Respmod, b"safe content").await.unwrap();
        assert_eq!(result, ScanResult::Clean);
    }

    #[test]
    fn clean_cache_skips_scan() {
        let hash = body_hash(b"already scanned");
        let mut cache = HashSet::new();
        cache.insert(hash.clone());
        assert!(!should_scan(&hash, &cache));
    }

    #[test]
    fn unknown_hash_needs_scan() {
        let cache = HashSet::new();
        assert!(should_scan("new_hash", &cache));
    }

    #[test]
    fn body_hash_deterministic() {
        let a = body_hash(b"test data");
        let b = body_hash(b"test data");
        assert_eq!(a, b);
    }

    #[test]
    fn body_hash_different_data() {
        let a = body_hash(b"data1");
        let b = body_hash(b"data2");
        assert_ne!(a, b);
    }
}
