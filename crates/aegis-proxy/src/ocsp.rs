//! OCSP stapling background task.
//!
//! For each certificate, fetches the OCSP response from the CA's OCSP
//! responder URL (extracted from the cert's Authority Information Access
//! extension), caches it to disk, and populates `CertifiedKey::ocsp`.
//! Refreshes before `nextUpdate`.

use std::path::PathBuf;
use std::time::Duration;

/// Configuration for the OCSP stapling task.
#[derive(Debug, Clone)]
pub struct OcspConfig {
    /// Directory to cache OCSP responses.
    pub cache_dir: PathBuf,
    /// How often to check for OCSP response freshness.
    pub poll_interval: Duration,
    /// Timeout for OCSP HTTP requests.
    pub request_timeout: Duration,
}

impl Default for OcspConfig {
    fn default() -> Self {
        Self {
            cache_dir: PathBuf::from("/var/lib/aegis/ocsp"),
            poll_interval: Duration::from_secs(3600),     // 1 hour
            request_timeout: Duration::from_secs(10),
        }
    }
}

/// Cached OCSP response for a single certificate.
#[derive(Debug, Clone)]
pub struct OcspResponse {
    /// DER-encoded OCSP response bytes.
    pub der: Vec<u8>,
    /// When this response was fetched.
    pub fetched_at: std::time::Instant,
    /// Suggested refresh time (from nextUpdate or half-life heuristic).
    pub refresh_after: Duration,
}

impl OcspResponse {
    /// Whether this response should be refreshed.
    pub fn needs_refresh(&self) -> bool {
        self.fetched_at.elapsed() >= self.refresh_after
    }
}

/// Write an OCSP response to the cache directory.
pub fn cache_response(
    cache_dir: &std::path::Path,
    cert_fingerprint: &str,
    der: &[u8],
) -> std::io::Result<()> {
    std::fs::create_dir_all(cache_dir)?;
    let path = cache_dir.join(format!("{cert_fingerprint}.ocsp"));
    std::fs::write(path, der)
}

/// Read a cached OCSP response from disk.
pub fn read_cached_response(
    cache_dir: &std::path::Path,
    cert_fingerprint: &str,
) -> Option<Vec<u8>> {
    let path = cache_dir.join(format!("{cert_fingerprint}.ocsp"));
    std::fs::read(path).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn default_config() {
        let cfg = OcspConfig::default();
        assert_eq!(cfg.poll_interval, Duration::from_secs(3600));
        assert_eq!(cfg.request_timeout, Duration::from_secs(10));
    }

    #[test]
    fn response_needs_refresh() {
        let resp = OcspResponse {
            der: vec![1, 2, 3],
            fetched_at: std::time::Instant::now() - Duration::from_secs(7200),
            refresh_after: Duration::from_secs(3600),
        };
        assert!(resp.needs_refresh());
    }

    #[test]
    fn response_fresh() {
        let resp = OcspResponse {
            der: vec![1, 2, 3],
            fetched_at: std::time::Instant::now(),
            refresh_after: Duration::from_secs(3600),
        };
        assert!(!resp.needs_refresh());
    }

    #[test]
    fn cache_roundtrip() {
        let dir = TempDir::new().unwrap();
        let der = b"fake-ocsp-response";

        cache_response(dir.path(), "abc123", der).unwrap();
        let read = read_cached_response(dir.path(), "abc123").unwrap();
        assert_eq!(read, der);
    }

    #[test]
    fn missing_cache_returns_none() {
        let dir = TempDir::new().unwrap();
        assert!(read_cached_response(dir.path(), "nonexistent").is_none());
    }
}
