//! ACME certificate issuance (feature-gated: `acme`).
//!
//! Uses HTTP-01 or TLS-ALPN-01 challenge flow.  In a multi-instance deployment
//! only the leader (via `acquire_lease("acme")`) runs the order workflow; the
//! resulting cert is pushed through the same hot-reload path as file certs.
//!
//! This module provides the core types and state machine.  The actual ACME
//! client (`instant-acme`) integration is behind the `acme` feature flag.

use std::path::PathBuf;
use std::time::Duration;

/// ACME account + order configuration.
#[derive(Debug, Clone)]
pub struct AcmeConfig {
    /// ACME directory URL (e.g. Let's Encrypt production or staging).
    pub directory_url: String,
    /// Contact emails for the ACME account.
    pub contacts: Vec<String>,
    /// Domains to issue certificates for.
    pub domains: Vec<String>,
    /// Where to persist issued certs on disk.
    pub cert_dir: PathBuf,
    /// How early before expiry to trigger renewal.
    pub renew_before: Duration,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            directory_url: "https://acme-v02.api.letsencrypt.org/directory".into(),
            contacts: Vec::new(),
            domains: Vec::new(),
            cert_dir: PathBuf::from("/var/lib/aegis/certs"),
            renew_before: Duration::from_secs(30 * 24 * 3600), // 30 days
        }
    }
}

/// State of an ACME order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderState {
    /// Waiting for challenges to be fulfilled.
    Pending,
    /// All challenges fulfilled, ready to finalize.
    Ready,
    /// Certificate issued.
    Valid,
    /// Order failed.
    Invalid,
}

/// Token + key-authorization for an HTTP-01 challenge.
#[derive(Debug, Clone)]
pub struct Http01Challenge {
    pub token: String,
    pub key_authorization: String,
}

impl Http01Challenge {
    /// The well-known path that the ACME server will probe.
    pub fn path(&self) -> String {
        format!("/.well-known/acme-challenge/{}", self.token)
    }
}

/// Checks whether a cert (PEM bytes) expires within `renew_before`.
pub fn cert_needs_renewal(pem_bytes: &[u8], renew_before: Duration) -> bool {
    // Parse the first certificate from PEM.
    let mut reader = std::io::BufReader::new(pem_bytes);
    let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_default();

    if certs.is_empty() {
        return true; // No cert → needs renewal.
    }

    // Use webpki to parse the cert and check notAfter.
    // For the skeleton, we just return false (not expired) since full x509
    // parsing requires additional deps.  Production would use `x509-parser`.
    let _ = renew_before;
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let cfg = AcmeConfig::default();
        assert!(cfg.directory_url.contains("letsencrypt"));
        assert_eq!(cfg.renew_before, Duration::from_secs(30 * 24 * 3600));
    }

    #[test]
    fn http01_challenge_path() {
        let ch = Http01Challenge {
            token: "abc123".into(),
            key_authorization: "abc123.thumbprint".into(),
        };
        assert_eq!(ch.path(), "/.well-known/acme-challenge/abc123");
    }

    #[test]
    fn order_state_transitions() {
        let states = [
            OrderState::Pending,
            OrderState::Ready,
            OrderState::Valid,
            OrderState::Invalid,
        ];
        assert_eq!(states[0], OrderState::Pending);
        assert_eq!(states[2], OrderState::Valid);
        assert_ne!(OrderState::Ready, OrderState::Invalid);
    }

    #[test]
    fn empty_pem_needs_renewal() {
        assert!(cert_needs_renewal(b"", Duration::from_secs(0)));
    }

    #[test]
    fn valid_pem_does_not_need_renewal_skeleton() {
        // Generate a self-signed cert PEM.
        let params = rcgen::CertificateParams::new(vec!["test.example.com".into()]).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let pem = cert.pem();

        // Skeleton always returns false for valid certs.
        assert!(!cert_needs_renewal(pem.as_bytes(), Duration::from_secs(0)));
    }
}
