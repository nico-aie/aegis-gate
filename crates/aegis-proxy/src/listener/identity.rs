//! MTLS-T3 — populate [`ClientIdentity`] for every accepted
//! TLS handshake.
//!
//! The data-plane accept loop calls
//! [`extract_identity_from_handshake`] right after
//! `tokio_rustls::TlsAcceptor::accept` returns. Output is
//! threaded through `ProxyContext` into the per-request
//! handler, where T4 will gate decisions on it.
//!
//! ## Why this lives outside the verifier
//!
//! `WebPkiClientVerifier` (MTLS-T2) decides whether a chain is
//! trusted; it does **not** expose what's in the leaf SAN. We
//! parse the leaf with `x509-parser` after the handshake
//! completes so the policy layer (T4) can read SAN strings,
//! SPIFFE URIs, and a stable fingerprint.
//!
//! ## Identity-shape decisions
//!
//! - **First URI-SAN starting with `spiffe://`** → [`ClientIdentity::Spiffe`].
//!   SPIFFE IDs are URI SANs by spec, so an explicit URI scheme
//!   check beats heuristics on the rest of the URI shape.
//! - **Otherwise**, first non-empty SAN in priority order
//!   `URI > DNS > email` → [`ClientIdentity::Mtls`]. URI is
//!   first so non-SPIFFE URI SANs (e.g.
//!   `urn:my-co:service:payments`) carry through; DNS is the
//!   common case for service-to-service certs.
//! - **No leaf cert** (Optional mode admitted a no-cert
//!   handshake) → [`ClientIdentity::Anonymous`].
//! - **Leaf cert that fails to parse** → `Anonymous`. The
//!   verifier accepted it, so we trust the chain, but a
//!   malformed leaf shouldn't crash the proxy. Operators see
//!   the failure in the `tracing::warn` line.
//!
//! ## Fingerprint
//!
//! Hex-encoded SHA-256 of the leaf DER. Stable across
//! handshakes from the same cert; useful for pinning, audit,
//! and per-identity rate-limit keys (T4).

use sha2::{Digest, Sha256};
use x509_parser::prelude::FromDer;

use aegis_core::ClientIdentity;

/// Parse the peer's leaf cert (if any) into a
/// [`ClientIdentity`]. Pass the `Vec<CertificateDer<'static>>`
/// returned by `tokio_rustls::server::TlsStream::get_ref().1.peer_certificates()`.
///
/// `chain_ok` reflects the verifier outcome from MTLS-T2 —
/// `true` for `Required` mode (only verified chains reach this
/// point), `true` for `Optional` mode when a cert is present
/// (verifier still ran), `false` when the verifier was bypassed
/// (e.g. test scaffolding). Callers that have direct access to
/// the verifier outcome can pass it explicitly; the data-plane
/// boot wires `true` because the verifier ran.
pub fn extract_identity_from_peer_certs(
    peer_certs: Option<&[rustls_pki_types::CertificateDer<'static>]>,
    chain_ok: bool,
) -> ClientIdentity {
    extract_identity_with_allowlist(peer_certs, chain_ok, None)
}

/// MTLS-T7 — same as [`extract_identity_from_peer_certs`] but
/// gates on the live SAN allowlist. When the store is `Some`
/// AND non-empty AND the parsed SAN doesn't match any pattern,
/// the result is downgraded to `ClientIdentity::Anonymous`
/// (the verifier accepted the chain — we just narrowed the
/// principal set). Empty store admits everything (back-compat).
pub fn extract_identity_with_allowlist(
    peer_certs: Option<&[rustls_pki_types::CertificateDer<'static>]>,
    chain_ok: bool,
    allowed_sans: Option<&aegis_control::api::mtls::AllowedSansStore>,
) -> ClientIdentity {
    let identity = extract_identity_inner(peer_certs, chain_ok);
    match (&identity, allowed_sans) {
        // Anonymous — nothing to gate.
        (ClientIdentity::Anonymous, _) => identity,
        // No allowlist configured — admit.
        (_, None) => identity,
        (_, Some(store)) => {
            let principal = identity.principal().unwrap_or("");
            if store.admits(principal) {
                identity
            } else {
                tracing::debug!(
                    principal = %principal,
                    "client cert SAN not in allowlist; downgraded to Anonymous",
                );
                ClientIdentity::Anonymous
            }
        }
    }
}

fn extract_identity_inner(
    peer_certs: Option<&[rustls_pki_types::CertificateDer<'static>]>,
    chain_ok: bool,
) -> ClientIdentity {
    let leaf = match peer_certs.and_then(|certs| certs.first()) {
        Some(c) => c,
        None => return ClientIdentity::Anonymous,
    };

    let fingerprint = sha256_hex(leaf);

    let parsed = match x509_parser::certificate::X509Certificate::from_der(leaf) {
        Ok((_, p)) => p,
        Err(e) => {
            // The verifier already accepted this chain — a parse
            // failure here is genuinely surprising. Log + fall back
            // to Anonymous so a malformed (but trusted) leaf can't
            // crash the proxy.
            tracing::warn!(
                error = %e,
                fingerprint = %fingerprint,
                "leaf cert parse failed after verifier accepted the chain",
            );
            return ClientIdentity::Anonymous;
        }
    };

    let sans = collect_sans(&parsed);

    // Priority 1: SPIFFE — first URI-SAN with the `spiffe://`
    // scheme. SPIFFE IDs are URI SANs per spec, so the scheme
    // check is the load-bearing test.
    if let Some(uri) = sans.iter().find_map(|s| match s {
        SanValue::Uri(u) if u.starts_with("spiffe://") => Some(u.clone()),
        _ => None,
    }) {
        let td = parse_spiffe_trust_domain(&uri).to_string();
        return ClientIdentity::Spiffe { uri, td };
    }

    // Priority 2: first non-SPIFFE URI / DNS / email SAN.
    // Order chosen so explicit URI-SAN (which is rare but
    // intentional when present) wins over DNS, and email is
    // the last fallback.
    let san = sans
        .iter()
        .find_map(|s| match s {
            SanValue::Uri(u) => Some(u.clone()),
            _ => None,
        })
        .or_else(|| {
            sans.iter().find_map(|s| match s {
                SanValue::Dns(d) => Some(d.clone()),
                _ => None,
            })
        })
        .or_else(|| {
            sans.iter().find_map(|s| match s {
                SanValue::Email(e) => Some(e.clone()),
                _ => None,
            })
        });

    match san {
        Some(san) => ClientIdentity::Mtls {
            san,
            fingerprint,
            chain_ok,
        },
        None => {
            // Cert with no useful SAN — common SubjectCN-only
            // certs land here. Fall back to Subject CN if
            // present; otherwise mark anonymous (the verifier
            // accepted the chain, but we have nothing
            // operator-facing to display).
            if let Some(cn) = parsed
                .subject()
                .iter_common_name()
                .next()
                .and_then(|cn| cn.as_str().ok())
                .map(|s| s.to_string())
            {
                ClientIdentity::Mtls {
                    san: cn,
                    fingerprint,
                    chain_ok,
                }
            } else {
                ClientIdentity::Anonymous
            }
        }
    }
}

#[derive(Debug, Clone)]
enum SanValue {
    Dns(String),
    Email(String),
    Uri(String),
}

/// Walk every `subjectAltName` extension on the cert and yield
/// SAN values in document order. Returns an empty `Vec` for
/// certs without a SAN extension or with only IP / RID / etc
/// SANs (uncommon for service certs).
fn collect_sans(cert: &x509_parser::certificate::X509Certificate<'_>) -> Vec<SanValue> {
    use x509_parser::extensions::{GeneralName, ParsedExtension};

    let mut out = Vec::new();
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in &san.general_names {
                match name {
                    GeneralName::DNSName(d) => out.push(SanValue::Dns(d.to_string())),
                    GeneralName::RFC822Name(e) => out.push(SanValue::Email(e.to_string())),
                    GeneralName::URI(u) => out.push(SanValue::Uri(u.to_string())),
                    // IP / RegisteredID / DirectoryName / etc.
                    // not surfaced today — the data-plane policy
                    // layer reads SAN strings only.
                    _ => {}
                }
            }
        }
    }
    out
}

/// Pull the trust-domain prefix out of a SPIFFE URI. Format is
/// `spiffe://<td>[/path]`; we keep just the host segment so the
/// audit emits a stable label across path-suffix variants.
fn parse_spiffe_trust_domain(uri: &str) -> &str {
    // Strip the scheme.
    let after_scheme = uri.strip_prefix("spiffe://").unwrap_or(uri);
    // First path segment is the trust domain; the rest is the
    // workload path.
    after_scheme.split_once('/').map(|(td, _)| td).unwrap_or(after_scheme)
}

/// SHA-256 of a byte slice, lowercase hex. Used to fingerprint
/// leaf cert DER for the audit chain.
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest.iter() {
        use std::fmt::Write;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls_pki_types::CertificateDer;

    /// Issue a self-signed leaf with the given SAN list. Returns
    /// the DER bytes. We bypass the WebPki verifier path entirely
    /// — the parser doesn't care that the cert is self-signed.
    fn issue_leaf_with_sans(sans: Vec<rcgen::SanType>) -> Vec<u8> {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = sans;
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        cert.der().to_vec()
    }

    fn issue_leaf_with_cn(cn: &str) -> Vec<u8> {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, cn);
        params.distinguished_name = dn;
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        cert.der().to_vec()
    }

    fn der_to_certs(der: Vec<u8>) -> Vec<CertificateDer<'static>> {
        vec![CertificateDer::from(der)]
    }

    #[test]
    fn anonymous_when_no_peer_certs() {
        // `peer_certificates()` returns `None` when no client
        // cert was offered (common in `Optional` mode).
        let id = extract_identity_from_peer_certs(None, false);
        assert_eq!(id, ClientIdentity::Anonymous);
    }

    #[test]
    fn anonymous_when_peer_cert_list_is_empty() {
        // Edge case — `Some(&[])` is treated identically to
        // `None`. Defensive against rustls API future changes.
        let empty: Vec<CertificateDer<'static>> = vec![];
        let id = extract_identity_from_peer_certs(Some(&empty), false);
        assert_eq!(id, ClientIdentity::Anonymous);
    }

    #[test]
    fn dns_san_lands_in_mtls_san_field() {
        let der = issue_leaf_with_sans(vec![rcgen::SanType::DnsName(
            "service.example.com".try_into().unwrap(),
        )]);
        let certs = der_to_certs(der);
        let id = extract_identity_from_peer_certs(Some(&certs), true);
        match id {
            ClientIdentity::Mtls { san, fingerprint, chain_ok } => {
                assert_eq!(san, "service.example.com");
                assert_eq!(fingerprint.len(), 64, "SHA-256 hex is 64 chars");
                assert!(chain_ok);
            }
            other => panic!("expected Mtls, got {other:?}"),
        }
    }

    #[test]
    fn email_san_lands_in_mtls_san_field() {
        let der = issue_leaf_with_sans(vec![rcgen::SanType::Rfc822Name(
            "ops@example.com".try_into().unwrap(),
        )]);
        let certs = der_to_certs(der);
        let id = extract_identity_from_peer_certs(Some(&certs), true);
        match id {
            ClientIdentity::Mtls { san, .. } => {
                assert_eq!(san, "ops@example.com");
            }
            other => panic!("expected Mtls, got {other:?}"),
        }
    }

    #[test]
    fn spiffe_uri_san_lands_in_spiffe_variant_with_trust_domain() {
        let der = issue_leaf_with_sans(vec![rcgen::SanType::URI(
            "spiffe://prod.example.com/payments-api"
                .try_into()
                .unwrap(),
        )]);
        let certs = der_to_certs(der);
        let id = extract_identity_from_peer_certs(Some(&certs), true);
        match id {
            ClientIdentity::Spiffe { uri, td } => {
                assert_eq!(uri, "spiffe://prod.example.com/payments-api");
                assert_eq!(td, "prod.example.com");
            }
            other => panic!("expected Spiffe, got {other:?}"),
        }
    }

    #[test]
    fn non_spiffe_uri_san_lands_in_mtls_with_full_uri() {
        // URI scheme other than `spiffe://` should NOT trigger
        // the Spiffe variant — it's just a generic mTLS principal.
        let der = issue_leaf_with_sans(vec![rcgen::SanType::URI(
            "urn:my-co:service:payments".try_into().unwrap(),
        )]);
        let certs = der_to_certs(der);
        let id = extract_identity_from_peer_certs(Some(&certs), true);
        match id {
            ClientIdentity::Mtls { san, .. } => {
                assert_eq!(san, "urn:my-co:service:payments");
            }
            other => panic!("expected Mtls (non-SPIFFE URI), got {other:?}"),
        }
    }

    #[test]
    fn spiffe_san_wins_over_other_sans() {
        // Multi-SAN cert: a DNS SAN, an email SAN, and a SPIFFE
        // URI. The SPIFFE URI must win regardless of SAN order
        // in the cert.
        let der = issue_leaf_with_sans(vec![
            rcgen::SanType::DnsName("backup.example.com".try_into().unwrap()),
            rcgen::SanType::Rfc822Name("ops@example.com".try_into().unwrap()),
            rcgen::SanType::URI(
                "spiffe://td.example/svc".try_into().unwrap(),
            ),
        ]);
        let certs = der_to_certs(der);
        let id = extract_identity_from_peer_certs(Some(&certs), true);
        match id {
            ClientIdentity::Spiffe { uri, td } => {
                assert_eq!(uri, "spiffe://td.example/svc");
                assert_eq!(td, "td.example");
            }
            other => panic!("expected Spiffe to win, got {other:?}"),
        }
    }

    #[test]
    fn dns_san_wins_over_email_when_no_uri() {
        let der = issue_leaf_with_sans(vec![
            rcgen::SanType::Rfc822Name("ops@example.com".try_into().unwrap()),
            rcgen::SanType::DnsName("svc.example.com".try_into().unwrap()),
        ]);
        let certs = der_to_certs(der);
        let id = extract_identity_from_peer_certs(Some(&certs), true);
        match id {
            ClientIdentity::Mtls { san, .. } => {
                assert_eq!(san, "svc.example.com");
            }
            other => panic!("expected Mtls/DNS, got {other:?}"),
        }
    }

    #[test]
    fn cn_fallback_when_no_san_extension() {
        let der = issue_leaf_with_cn("legacy-client");
        let certs = der_to_certs(der);
        let id = extract_identity_from_peer_certs(Some(&certs), true);
        match id {
            ClientIdentity::Mtls { san, .. } => {
                assert_eq!(san, "legacy-client");
            }
            other => panic!("expected Mtls/CN fallback, got {other:?}"),
        }
    }

    #[test]
    fn fingerprint_is_stable_across_calls() {
        // Same DER → same hex SHA-256 every time. Operators
        // pin on this; instability would break audit pinning.
        let der = issue_leaf_with_sans(vec![rcgen::SanType::DnsName(
            "service.example.com".try_into().unwrap(),
        )]);
        let certs1 = der_to_certs(der.clone());
        let certs2 = der_to_certs(der);
        let id1 = extract_identity_from_peer_certs(Some(&certs1), true);
        let id2 = extract_identity_from_peer_certs(Some(&certs2), true);
        match (id1, id2) {
            (
                ClientIdentity::Mtls { fingerprint: a, .. },
                ClientIdentity::Mtls { fingerprint: b, .. },
            ) => assert_eq!(a, b),
            _ => panic!("expected two Mtls identities"),
        }
    }

    #[test]
    fn fingerprint_differs_for_different_certs() {
        let der1 = issue_leaf_with_sans(vec![rcgen::SanType::DnsName(
            "a.example.com".try_into().unwrap(),
        )]);
        let der2 = issue_leaf_with_sans(vec![rcgen::SanType::DnsName(
            "b.example.com".try_into().unwrap(),
        )]);
        let certs1 = der_to_certs(der1);
        let certs2 = der_to_certs(der2);
        let id1 = extract_identity_from_peer_certs(Some(&certs1), true);
        let id2 = extract_identity_from_peer_certs(Some(&certs2), true);
        match (id1, id2) {
            (
                ClientIdentity::Mtls { fingerprint: a, .. },
                ClientIdentity::Mtls { fingerprint: b, .. },
            ) => assert_ne!(a, b, "different DER must produce different fingerprints"),
            _ => panic!("expected two Mtls identities"),
        }
    }

    #[test]
    fn chain_ok_propagates_through() {
        let der = issue_leaf_with_sans(vec![rcgen::SanType::DnsName(
            "svc.example.com".try_into().unwrap(),
        )]);
        let certs = der_to_certs(der);

        let ok = extract_identity_from_peer_certs(Some(&certs), true);
        let bad = extract_identity_from_peer_certs(Some(&certs), false);
        match (ok, bad) {
            (
                ClientIdentity::Mtls { chain_ok: true, .. },
                ClientIdentity::Mtls { chain_ok: false, .. },
            ) => {}
            other => panic!("chain_ok must round-trip — got {other:?}"),
        }
    }

    #[test]
    fn parse_spiffe_trust_domain_with_path() {
        assert_eq!(
            parse_spiffe_trust_domain("spiffe://prod.example/payments"),
            "prod.example",
        );
    }

    #[test]
    fn parse_spiffe_trust_domain_no_path() {
        // Trust-domain-only SPIFFE URIs are valid.
        assert_eq!(
            parse_spiffe_trust_domain("spiffe://prod.example"),
            "prod.example",
        );
    }

    #[test]
    fn parse_spiffe_trust_domain_handles_nested_path() {
        // Multiple `/` segments — only the first determines the
        // trust domain.
        assert_eq!(
            parse_spiffe_trust_domain("spiffe://td/svc/sub/leaf"),
            "td",
        );
    }

    #[test]
    fn malformed_leaf_falls_back_to_anonymous() {
        // 8 bytes of garbage isn't a valid X.509 cert — parser
        // returns Err. The function logs + returns Anonymous
        // rather than crashing.
        let bogus = vec![CertificateDer::from(vec![0u8; 8])];
        let id = extract_identity_from_peer_certs(Some(&bogus), true);
        assert_eq!(id, ClientIdentity::Anonymous);
    }

    // ---------------- MTLS-T7 — SAN allowlist gate ----------------

    #[test]
    fn allowlist_none_passes_through() {
        // Back-compat: extract_identity_from_peer_certs goes
        // through the new path with allowlist = None and must
        // produce the same result.
        let der = issue_leaf_with_sans(vec![rcgen::SanType::DnsName(
            "svc.example.com".try_into().unwrap(),
        )]);
        let certs = der_to_certs(der);
        let id = extract_identity_with_allowlist(Some(&certs), true, None);
        match id {
            ClientIdentity::Mtls { san, .. } => assert_eq!(san, "svc.example.com"),
            other => panic!("expected Mtls, got {other:?}"),
        }
    }

    #[test]
    fn allowlist_empty_admits_any_san() {
        // Empty list = no gate. Same shape as `None`.
        use aegis_control::api::mtls::AllowedSansStore;
        let store = AllowedSansStore::from(Vec::<String>::new());
        let der = issue_leaf_with_sans(vec![rcgen::SanType::DnsName(
            "svc.example.com".try_into().unwrap(),
        )]);
        let certs = der_to_certs(der);
        let id = extract_identity_with_allowlist(Some(&certs), true, Some(&store));
        assert!(matches!(id, ClientIdentity::Mtls { .. }));
    }

    #[test]
    fn allowlist_admits_matching_san() {
        use aegis_control::api::mtls::AllowedSansStore;
        let store = AllowedSansStore::from(vec!["svc.example.com".into()]);
        let der = issue_leaf_with_sans(vec![rcgen::SanType::DnsName(
            "svc.example.com".try_into().unwrap(),
        )]);
        let certs = der_to_certs(der);
        let id = extract_identity_with_allowlist(Some(&certs), true, Some(&store));
        match id {
            ClientIdentity::Mtls { san, .. } => assert_eq!(san, "svc.example.com"),
            other => panic!("expected Mtls, got {other:?}"),
        }
    }

    #[test]
    fn allowlist_downgrades_unmatched_san_to_anonymous() {
        use aegis_control::api::mtls::AllowedSansStore;
        let store = AllowedSansStore::from(vec!["allowed.example.com".into()]);
        let der = issue_leaf_with_sans(vec![rcgen::SanType::DnsName(
            "rogue.example.com".try_into().unwrap(),
        )]);
        let certs = der_to_certs(der);
        let id = extract_identity_with_allowlist(Some(&certs), true, Some(&store));
        // Verifier accepted the chain (chain_ok = true) but
        // the SAN isn't on the allowlist → Anonymous.
        assert_eq!(id, ClientIdentity::Anonymous);
    }

    #[test]
    fn allowlist_admits_wildcard_subdomain() {
        use aegis_control::api::mtls::AllowedSansStore;
        let store = AllowedSansStore::from(vec!["*.example.com".into()]);
        let der = issue_leaf_with_sans(vec![rcgen::SanType::DnsName(
            "svc.example.com".try_into().unwrap(),
        )]);
        let certs = der_to_certs(der);
        let id = extract_identity_with_allowlist(Some(&certs), true, Some(&store));
        assert!(matches!(id, ClientIdentity::Mtls { .. }));
    }

    #[test]
    fn allowlist_with_anonymous_passes_through() {
        // Anonymous identity has no SAN to match — the gate
        // doesn't apply (skipping it would be a security bug
        // by promoting Anonymous to Mtls). Result stays
        // Anonymous regardless of the allowlist contents.
        use aegis_control::api::mtls::AllowedSansStore;
        let store = AllowedSansStore::from(vec!["anything".into()]);
        let id = extract_identity_with_allowlist(None, false, Some(&store));
        assert_eq!(id, ClientIdentity::Anonymous);
    }

    #[test]
    fn allowlist_admits_spiffe_uri_on_match() {
        use aegis_control::api::mtls::AllowedSansStore;
        let store = AllowedSansStore::from(vec![
            "spiffe://prod.example.com/payments-api".into(),
        ]);
        let der = issue_leaf_with_sans(vec![rcgen::SanType::URI(
            "spiffe://prod.example.com/payments-api".try_into().unwrap(),
        )]);
        let certs = der_to_certs(der);
        let id = extract_identity_with_allowlist(Some(&certs), true, Some(&store));
        match id {
            ClientIdentity::Spiffe { uri, .. } => {
                assert_eq!(uri, "spiffe://prod.example.com/payments-api");
            }
            other => panic!("expected Spiffe, got {other:?}"),
        }
    }
}
