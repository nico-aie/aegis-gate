//! MTLS-T10 — CA bundle validation + preview helpers.
//!
//! The dashboard's CA Bundle Upload card pastes (or selects) a
//! PEM and POSTs the raw bytes here. The server:
//!
//!   1. Parses the PEM,
//!   2. Builds a per-cert summary (subject, fingerprint, expiry),
//!   3. Returns the summary + a `valid` flag the dashboard
//!      renders before the operator commits.
//!
//! No raw bytes ever land in the audit chain — only the metadata
//! summary the operator can also see in the UI.
//!
//! This module is the **pure** parser; the audit-mutated PUT
//! handler in `aegis-proxy::admin_mutate` calls it.

use serde::Serialize;
use sha2::Digest;
use x509_parser::prelude::*;

/// One trust anchor's metadata.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct CertPreview {
    /// X.509 Subject DN as a one-line string (`CN=test-ca,O=...`).
    pub subject: String,
    /// X.509 Issuer DN (matches `subject` for self-signed CAs).
    pub issuer: String,
    /// SHA-256 fingerprint of the DER bytes, hex-encoded with
    /// colon separators every two hex chars (`AB:12:34:...`).
    pub fingerprint_sha256: String,
    /// Not-after (expiry) as RFC 3339 UTC. None when the cert
    /// is malformed enough that the parser can't read the
    /// validity field.
    pub not_after: Option<String>,
    /// Days from now until `not_after`. Negative when the cert
    /// is already expired (the parser still accepts it; the
    /// dashboard renders the row in red).
    pub days_to_expiry: Option<i64>,
    /// True iff `not_after` is in the past as of parse time.
    pub expired: bool,
    /// True iff this cert has the BasicConstraints CA:TRUE
    /// extension. Trust bundles should be all-CAs; the
    /// dashboard warns when they're not.
    pub is_ca: bool,
}

/// Wire shape of `PUT /api/mtls/ca-bundle`'s success response.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct PreviewResponse {
    /// True when every cert parsed cleanly. False when the PEM
    /// had at least one malformed block; `errors` carries the
    /// reasons.
    pub valid: bool,
    /// Number of CERTIFICATE blocks the parser saw (including
    /// malformed ones).
    pub blocks_seen: usize,
    /// Per-cert summary, in the order they appeared in the PEM.
    pub certificates: Vec<CertPreview>,
    /// Per-block error messages (empty when `valid: true`).
    pub errors: Vec<String>,
}

/// Parse a PEM bundle and return the preview shape.
///
/// `now_unix_seconds` is injected for testability so the
/// `days_to_expiry` math can be deterministic in unit tests.
/// Production callers pass `chrono::Utc::now().timestamp()`.
pub fn parse_and_preview(pem: &[u8], now_unix_seconds: i64) -> PreviewResponse {
    if pem.is_empty() {
        return PreviewResponse {
            valid: false,
            blocks_seen: 0,
            certificates: Vec::new(),
            errors: vec!["empty input".into()],
        };
    }

    let mut reader = std::io::BufReader::new(pem);
    let blocks: Vec<Result<rustls_pki_types::CertificateDer<'static>, _>> =
        rustls_pemfile::certs(&mut reader).collect();

    let mut certificates = Vec::with_capacity(blocks.len());
    let mut errors = Vec::new();

    for (i, block) in blocks.iter().enumerate() {
        match block {
            Err(e) => errors.push(format!("block {}: {}", i + 1, e)),
            Ok(der) => match parse_one(der.as_ref(), now_unix_seconds) {
                Ok(p) => certificates.push(p),
                Err(e) => errors.push(format!("block {}: {}", i + 1, e)),
            },
        }
    }

    if blocks.is_empty() {
        errors.push("no CERTIFICATE blocks found".into());
    }

    PreviewResponse {
        valid: errors.is_empty(),
        blocks_seen: blocks.len(),
        certificates,
        errors,
    }
}

fn parse_one(der: &[u8], now: i64) -> Result<CertPreview, String> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| format!("X.509 parse: {e}"))?;

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();

    let mut hasher = sha2::Sha256::new();
    hasher.update(der);
    let digest = hasher.finalize();
    let fingerprint_sha256 = digest
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":");

    let not_after_secs = cert.validity().not_after.timestamp();
    let not_after = chrono::DateTime::<chrono::Utc>::from_timestamp(not_after_secs, 0)
        .map(|dt| dt.to_rfc3339());
    let days_to_expiry = Some((not_after_secs - now) / 86_400);
    let expired = not_after_secs <= now;

    // BasicConstraints CA flag.
    let is_ca = cert
        .basic_constraints()
        .ok()
        .flatten()
        .map(|ext| ext.value.ca)
        .unwrap_or(false);

    Ok(CertPreview {
        subject,
        issuer,
        fingerprint_sha256,
        not_after,
        days_to_expiry,
        expired,
        is_ca,
    })
}

/// Compact diff of two preview lists keyed by fingerprint —
/// what's added, removed, kept. Used by the audit emitter to
/// record exactly what the operator changed without storing
/// raw certs.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct PreviewDiff {
    pub added: Vec<CertPreview>,
    pub removed: Vec<CertPreview>,
    pub kept: Vec<CertPreview>,
}

pub fn diff_previews(before: &[CertPreview], after: &[CertPreview]) -> PreviewDiff {
    use std::collections::HashSet;
    let before_fps: HashSet<&str> = before.iter().map(|c| c.fingerprint_sha256.as_str()).collect();
    let after_fps: HashSet<&str> = after.iter().map(|c| c.fingerprint_sha256.as_str()).collect();
    PreviewDiff {
        added: after
            .iter()
            .filter(|c| !before_fps.contains(c.fingerprint_sha256.as_str()))
            .cloned()
            .collect(),
        removed: before
            .iter()
            .filter(|c| !after_fps.contains(c.fingerprint_sha256.as_str()))
            .cloned()
            .collect(),
        kept: before
            .iter()
            .filter(|c| after_fps.contains(c.fingerprint_sha256.as_str()))
            .cloned()
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_ca_pem(common_name: &str) -> Vec<u8> {
        let mut params = rcgen::CertificateParams::new(vec![common_name.into()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        // rcgen 0.13 leaves the X.509 Subject DN empty unless the
        // distinguished_name is populated explicitly. Mirror the
        // SAN value into CN so `cert.subject().to_string()` is
        // stable + assertable in tests.
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, common_name);
        params.distinguished_name = dn;
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        cert.pem().into_bytes()
    }

    #[test]
    fn empty_input_is_invalid() {
        let r = parse_and_preview(b"", 1700000000);
        assert!(!r.valid);
        assert_eq!(r.blocks_seen, 0);
        assert!(r.certificates.is_empty());
        assert!(r.errors[0].contains("empty"));
    }

    #[test]
    fn no_certificate_blocks_is_invalid() {
        let r = parse_and_preview(b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----", 1700000000);
        assert!(!r.valid);
        assert_eq!(r.blocks_seen, 0);
        assert!(r.errors.iter().any(|e| e.contains("no CERTIFICATE")));
    }

    #[test]
    fn valid_ca_parses_and_reports_metadata() {
        let pem = make_test_ca_pem("test-ca-1");
        let r = parse_and_preview(&pem, chrono::Utc::now().timestamp());
        assert!(r.valid, "errors: {:?}", r.errors);
        assert_eq!(r.certificates.len(), 1);
        let c = &r.certificates[0];
        assert!(c.subject.contains("test-ca-1"));
        assert_eq!(c.fingerprint_sha256.len(), 95); // 32 bytes × 2 hex + 31 colons
        assert!(c.is_ca, "BasicConstraints CA:TRUE expected");
        assert!(!c.expired);
        assert!(c.days_to_expiry.unwrap() > 0);
    }

    #[test]
    fn fingerprint_is_stable_for_same_cert() {
        let pem = make_test_ca_pem("stable-ca");
        let r1 = parse_and_preview(&pem, 1700000000);
        let r2 = parse_and_preview(&pem, 1700000000);
        assert_eq!(
            r1.certificates[0].fingerprint_sha256,
            r2.certificates[0].fingerprint_sha256,
        );
    }

    #[test]
    fn fingerprint_differs_for_different_certs() {
        let pem_a = make_test_ca_pem("ca-a");
        let pem_b = make_test_ca_pem("ca-b");
        let r_a = parse_and_preview(&pem_a, 1700000000);
        let r_b = parse_and_preview(&pem_b, 1700000000);
        assert_ne!(
            r_a.certificates[0].fingerprint_sha256,
            r_b.certificates[0].fingerprint_sha256,
        );
    }

    #[test]
    fn diff_classifies_added_removed_kept() {
        let pem_a = make_test_ca_pem("ca-a");
        let pem_b = make_test_ca_pem("ca-b");
        let pem_c = make_test_ca_pem("ca-c");
        let now = chrono::Utc::now().timestamp();
        let prev = [
            parse_and_preview(&pem_a, now).certificates.remove(0),
            parse_and_preview(&pem_b, now).certificates.remove(0),
        ];
        let next = [
            // a kept
            parse_and_preview(&pem_a, now).certificates.remove(0),
            // c added (b removed)
            parse_and_preview(&pem_c, now).certificates.remove(0),
        ];
        let d = diff_previews(&prev, &next);
        assert_eq!(d.added.len(), 1);
        assert_eq!(d.removed.len(), 1);
        assert_eq!(d.kept.len(), 1);
        assert!(d.added[0].subject.contains("ca-c"));
        assert!(d.removed[0].subject.contains("ca-b"));
        assert!(d.kept[0].subject.contains("ca-a"));
    }

    #[test]
    fn multiple_certs_in_one_pem_all_parse() {
        let mut pem = Vec::new();
        pem.extend_from_slice(&make_test_ca_pem("multi-1"));
        pem.extend_from_slice(&make_test_ca_pem("multi-2"));
        pem.extend_from_slice(&make_test_ca_pem("multi-3"));
        let r = parse_and_preview(&pem, chrono::Utc::now().timestamp());
        assert!(r.valid, "errors: {:?}", r.errors);
        assert_eq!(r.certificates.len(), 3);
    }
}
