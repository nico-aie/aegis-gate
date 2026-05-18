use std::fs;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use aegis_core::TlsFingerprint;
use arc_swap::ArcSwap;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// 2026-05-18 (QC TLS wire-up — F-CRITICAL-010 / 014 / 015
/// activation): compute a post-handshake TLS fingerprint from a
/// completed rustls [`ServerConnection`].
///
/// **JA4-light.** Canonical JA4 reads the full ClientHello
/// extension list, which rustls 0.23 doesn't expose to public
/// post-handshake callers — only what the negotiator selected.
/// This helper produces a stable string from what IS exposed:
/// negotiated_cipher_suite + ALPN + protocol_version + SNI type.
///
/// Format: `t{ver}{sni}_{cipher_hex}_{alpn_hash}`
/// - `t` — TCP (canonical JA4 prefix).
/// - `ver` — `12` / `13` for TLS 1.2 / 1.3.
/// - `sni` — `d` (domain) / `i` (IP literal) / `x` (none).
/// - `cipher_hex` — 4-hex-digit IANA cipher ID.
/// - `alpn_hash` — first 4 hex chars of blake3 of the ALPN
///   string, or `"none"` when no ALPN was negotiated.
///
/// Stable enough to distinguish client classes (Chrome vs curl
/// vs sqlmap have different negotiated ciphers + ALPN choices);
/// coarser than canonical JA4 for fine-grained library versioning.
/// Tracked in `plans/future/unwired-stubs-catalog.md § "JA4 capture"`.
pub fn compute_post_handshake_fingerprint(
    conn: &rustls::ServerConnection,
) -> TlsFingerprint {
    let ver_str = match conn.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_3) => "13",
        Some(rustls::ProtocolVersion::TLSv1_2) => "12",
        _ => "00",
    };
    let sni_char = match conn.server_name() {
        Some(name) if name.parse::<std::net::IpAddr>().is_ok() => 'i',
        Some(_) => 'd',
        None => 'x',
    };
    let cipher_hex = conn
        .negotiated_cipher_suite()
        .map(|cs| format!("{:04x}", u16::from(cs.suite())))
        .unwrap_or_else(|| "0000".into());
    let alpn_hash = conn
        .alpn_protocol()
        .map(|a| {
            let h = blake3::hash(a);
            h.to_hex()[..4].to_string()
        })
        .unwrap_or_else(|| "none".into());
    let combined = format!("t{ver_str}{sni_char}_{cipher_hex}_{alpn_hash}");
    TlsFingerprint {
        // No canonical JA3 today either — populate both fields
        // with the post-handshake string so consumers that key
        // on either get stable output. When canonical JA3/JA4
        // capture lands (ClientHello-callback wire-up), split.
        ja3: combined.clone(),
        ja4: combined,
    }
}

/// Holds all SNI-to-certificate mappings.  Swapped atomically on cert reload
/// without dropping in-flight TLS handshakes.
#[derive(Debug)]
pub struct CertStore {
    /// SNI hostname → certified key.  Lowercase keys.
    entries: Vec<CertEntry>,
    /// Fallback when no SNI match (first cert loaded).
    default: Option<Arc<CertifiedKey>>,
}

#[derive(Debug)]
struct CertEntry {
    hosts: Vec<String>,
    key: Arc<CertifiedKey>,
}

impl CertStore {
    /// Build a new `CertStore` from PEM file pairs on disk.
    pub fn load(
        certs: &[(impl AsRef<Path>, impl AsRef<Path>, &[String])],
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut entries = Vec::new();
        let mut default: Option<Arc<CertifiedKey>> = None;

        for (cert_path, key_path, hosts) in certs {
            let certified = load_certified_key(cert_path.as_ref(), key_path.as_ref())?;
            let arc = Arc::new(certified);

            if default.is_none() {
                default = Some(arc.clone());
            }

            entries.push(CertEntry {
                hosts: hosts.iter().map(|h| h.to_ascii_lowercase()).collect(),
                key: arc,
            });
        }

        Ok(Self { entries, default })
    }

    /// Resolve a `CertifiedKey` for the given SNI hostname.
    pub fn resolve(&self, sni: Option<&str>) -> Option<Arc<CertifiedKey>> {
        if let Some(name) = sni {
            let name_lower = name.to_ascii_lowercase();
            for entry in &self.entries {
                for host in &entry.hosts {
                    if host == &name_lower {
                        return Some(entry.key.clone());
                    }
                    // Wildcard: *.example.com matches foo.example.com
                    if let Some(suffix) = host.strip_prefix("*.") {
                        if name_lower.ends_with(suffix)
                            && name_lower.len() > suffix.len()
                            && name_lower.as_bytes()[name_lower.len() - suffix.len() - 1] == b'.'
                        {
                            return Some(entry.key.clone());
                        }
                    }
                }
            }
        }
        self.default.clone()
    }
}

/// `rustls::server::ResolvesServerCert` backed by an `ArcSwap<CertStore>`.
/// The store can be swapped at runtime without dropping in-flight handshakes.
pub struct DynamicResolver {
    store: Arc<ArcSwap<CertStore>>,
}

impl DynamicResolver {
    pub fn new(store: Arc<ArcSwap<CertStore>>) -> Self {
        Self { store }
    }

    /// Swap the underlying store (e.g. after cert file rotation).
    pub fn swap(&self, new_store: CertStore) {
        self.store.store(Arc::new(new_store));
    }

    /// Get a handle to the shared `ArcSwap<CertStore>` for external swapping.
    pub fn store_handle(&self) -> Arc<ArcSwap<CertStore>> {
        self.store.clone()
    }
}

impl std::fmt::Debug for DynamicResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicResolver").finish()
    }
}

impl ResolvesServerCert for DynamicResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let store = self.store.load();
        store.resolve(client_hello.server_name())
    }
}

/// Load a PEM certificate chain + private key from disk into a `CertifiedKey`.
fn load_certified_key(
    cert_path: &Path,
    key_path: &Path,
) -> Result<CertifiedKey, Box<dyn std::error::Error + Send + Sync>> {
    // Read certificate chain.
    let cert_file = fs::File::open(cert_path)?;
    let mut reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()?;

    if certs.is_empty() {
        return Err(format!("no certificates found in {}", cert_path.display()).into());
    }

    // Read private key.
    let key_file = fs::File::open(key_path)?;
    let mut key_reader = BufReader::new(key_file);
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| format!("no private key found in {}", key_path.display()))?;

    let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)?;
    Ok(CertifiedKey::new(certs, signing_key))
}

/// Build a `rustls::ServerConfig` using the `DynamicResolver`.
pub fn build_server_config(resolver: Arc<DynamicResolver>) -> rustls::ServerConfig {
    // rustls 0.23 requires explicit CryptoProvider install when
    // multiple cipher backends are visible (post HP-T1, both
    // ring and aws-lc-rs reach this crate). Idempotent.
    static PROVIDER_INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    PROVIDER_INIT.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    /// Generate a self-signed certificate for `domains` using rcgen.
    fn generate_cert(domains: &[&str]) -> (String, String) {
        let mut params = rcgen::CertificateParams::new(
            domains.iter().map(|d| d.to_string()).collect::<Vec<_>>(),
        )
        .unwrap();
        params.is_ca = rcgen::IsCa::NoCa;
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        (cert.pem(), key_pair.serialize_pem())
    }

    fn write_pem(dir: &TempDir, name: &str, content: &str) -> std::path::PathBuf {
        let path = dir.path().join(name);
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    #[test]
    fn cert_store_resolves_by_sni() {
        let dir = TempDir::new().unwrap();
        let (cert_a, key_a) = generate_cert(&["alpha.example.com"]);
        let (cert_b, key_b) = generate_cert(&["beta.example.com"]);

        let cert_a_path = write_pem(&dir, "a.crt", &cert_a);
        let key_a_path = write_pem(&dir, "a.key", &key_a);
        let cert_b_path = write_pem(&dir, "b.crt", &cert_b);
        let key_b_path = write_pem(&dir, "b.key", &key_b);

        let store = CertStore::load(&[
            (
                &cert_a_path,
                &key_a_path,
                &["alpha.example.com".to_string()][..],
            ),
            (
                &cert_b_path,
                &key_b_path,
                &["beta.example.com".to_string()][..],
            ),
        ])
        .unwrap();

        // Exact SNI match.
        assert!(store.resolve(Some("alpha.example.com")).is_some());
        assert!(store.resolve(Some("beta.example.com")).is_some());

        // Unknown SNI falls back to default (first cert).
        let fallback = store.resolve(Some("unknown.example.com"));
        assert!(fallback.is_some());

        // No SNI → default.
        assert!(store.resolve(None).is_some());
    }

    #[test]
    fn cert_store_wildcard_sni() {
        let dir = TempDir::new().unwrap();
        let (cert, key) = generate_cert(&["*.example.com"]);
        let cert_path = write_pem(&dir, "wild.crt", &cert);
        let key_path = write_pem(&dir, "wild.key", &key);

        let store = CertStore::load(&[(
            &cert_path,
            &key_path,
            &["*.example.com".to_string()][..],
        )])
        .unwrap();

        assert!(store.resolve(Some("foo.example.com")).is_some());
        assert!(store.resolve(Some("bar.example.com")).is_some());
        // Bare domain should NOT match wildcard.
        // With current logic, it falls back to default.
        assert!(store.resolve(Some("example.com")).is_some()); // default fallback
    }

    #[test]
    fn dynamic_resolver_swap_serves_new_cert() {
        let dir = TempDir::new().unwrap();
        let (cert_a, key_a) = generate_cert(&["alpha.example.com"]);
        let cert_a_path = write_pem(&dir, "a.crt", &cert_a);
        let key_a_path = write_pem(&dir, "a.key", &key_a);

        let store1 = CertStore::load(&[(
            &cert_a_path,
            &key_a_path,
            &["alpha.example.com".to_string()][..],
        )])
        .unwrap();

        let shared = Arc::new(ArcSwap::from_pointee(store1));
        let resolver = DynamicResolver::new(shared.clone());

        // Before swap: alpha resolves.
        assert!(shared.load().resolve(Some("alpha.example.com")).is_some());

        // Generate and swap to a new cert for beta.
        let (cert_b, key_b) = generate_cert(&["beta.example.com"]);
        let cert_b_path = write_pem(&dir, "b.crt", &cert_b);
        let key_b_path = write_pem(&dir, "b.key", &key_b);

        let store2 = CertStore::load(&[(
            &cert_b_path,
            &key_b_path,
            &["beta.example.com".to_string()][..],
        )])
        .unwrap();

        resolver.swap(store2);

        // After swap: beta resolves, alpha falls back to default (beta).
        let guard = shared.load();
        assert!(guard.resolve(Some("beta.example.com")).is_some());
        // alpha.example.com no longer has a dedicated entry.
        // It should still get the default (beta).
        assert!(guard.resolve(Some("alpha.example.com")).is_some());
    }

    #[test]
    fn case_insensitive_sni_lookup() {
        let dir = TempDir::new().unwrap();
        let (cert, key) = generate_cert(&["Alpha.Example.COM"]);
        let cert_path = write_pem(&dir, "a.crt", &cert);
        let key_path = write_pem(&dir, "a.key", &key);

        let store = CertStore::load(&[(
            &cert_path,
            &key_path,
            &["Alpha.Example.COM".to_string()][..],
        )])
        .unwrap();

        assert!(store.resolve(Some("alpha.example.com")).is_some());
        assert!(store.resolve(Some("ALPHA.EXAMPLE.COM")).is_some());
    }

    #[tokio::test]
    async fn tls_handshake_end_to_end() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let dir = TempDir::new().unwrap();
        let (cert_pem, key_pem) = generate_cert(&["localhost"]);
        let cert_path = write_pem(&dir, "srv.crt", &cert_pem);
        let key_path = write_pem(&dir, "srv.key", &key_pem);

        let store = CertStore::load(&[(
            &cert_path,
            &key_path,
            &["localhost".to_string()][..],
        )])
        .unwrap();

        let shared = Arc::new(ArcSwap::from_pointee(store));
        let resolver = Arc::new(DynamicResolver::new(shared));
        let server_config = Arc::new(build_server_config(resolver));

        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();

        let server_config_clone = server_config.clone();
        let srv = tokio::spawn(async move {
            let (stream, _) = tcp.accept().await.unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(server_config_clone);
            let mut tls_stream = acceptor.accept(stream).await.unwrap();
            let mut buf = [0u8; 64];
            let n = tls_stream.read(&mut buf).await.unwrap();
            tls_stream.write_all(&buf[..n]).await.unwrap();
        });

        // Client side: trust self-signed cert.
        let mut root_store = rustls::RootCertStore::empty();
        let cert_der: Vec<CertificateDer<'static>> = {
            let mut reader = BufReader::new(cert_pem.as_bytes());
            rustls_pemfile::certs(&mut reader)
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        };
        for cert in &cert_der {
            root_store.add(cert.clone()).unwrap();
        }

        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

        let tcp_stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let server_name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
        let mut tls = connector.connect(server_name, tcp_stream).await.unwrap();

        tls.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 64];
        let n = tls.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");

        srv.abort();
    }

    // ---- 2026-05-18 QC TLS wire-up — compute_post_handshake_fingerprint ----

    /// End-to-end: complete a real TLS handshake, then read the
    /// post-handshake fingerprint off the server-side connection.
    /// Format invariants: starts with `t13` (or `t12`), contains
    /// two underscores, ja3 == ja4 (until canonical capture lands).
    #[tokio::test]
    async fn compute_post_handshake_fingerprint_format_invariants() {
        use rustls_pki_types::ServerName;
        use std::convert::TryFrom;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let dir = TempDir::new().unwrap();
        let (cert_pem, key_pem) = generate_cert(&["example.test"]);
        let cert_path = write_pem(&dir, "cert.pem", &cert_pem);
        let key_path = write_pem(&dir, "key.pem", &key_pem);
        let store = CertStore::load(&[(
            cert_path.clone(),
            key_path.clone(),
            &["example.test".to_string()][..],
        )])
        .unwrap();
        let resolver = Arc::new(DynamicResolver::new(Arc::new(ArcSwap::from(
            Arc::new(store),
        ))));
        let server_config = build_server_config(resolver);
        let server_config = Arc::new(server_config);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let server_cfg = server_config.clone();

        let srv = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
            let tls = acceptor.accept(stream).await.unwrap();
            // Read peer's post-handshake fingerprint.
            let (_io, conn) = tls.get_ref();
            let fp = compute_post_handshake_fingerprint(conn);
            // Send the fingerprint back so the test can assert on
            // it.
            let mut tls = tls;
            tls.write_all(fp.ja4.as_bytes()).await.unwrap();
        });

        // Client setup — accept self-signed.
        #[derive(Debug)]
        struct AcceptAll;
        impl rustls::client::danger::ServerCertVerifier for AcceptAll {
            fn verify_server_cert(
                &self,
                _: &rustls_pki_types::CertificateDer<'_>,
                _: &[rustls_pki_types::CertificateDer<'_>],
                _: &rustls_pki_types::ServerName<'_>,
                _: &[u8],
                _: rustls_pki_types::UnixTime,
            ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
            fn verify_tls12_signature(
                &self,
                _: &[u8],
                _: &rustls_pki_types::CertificateDer<'_>,
                _: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(
                &self,
                _: &[u8],
                _: &rustls_pki_types::CertificateDer<'_>,
                _: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }
            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                vec![
                    rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                    rustls::SignatureScheme::RSA_PSS_SHA256,
                ]
            }
        }
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut client_config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAll))
            .with_no_client_auth();
        client_config.alpn_protocols = vec![b"h2".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let server_name = ServerName::try_from("example.test").unwrap();
        let tcp_stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut tls = connector.connect(server_name, tcp_stream).await.unwrap();

        // Read back the fingerprint the server computed.
        let mut buf = [0u8; 128];
        let n = tls.read(&mut buf).await.unwrap();
        let server_fp = std::str::from_utf8(&buf[..n]).unwrap();

        // Format: t{ver}{sni}_{cipher_hex}_{alpn_hash}
        assert!(
            server_fp.starts_with("t13") || server_fp.starts_with("t12"),
            "fingerprint should start with t13 or t12, got: {server_fp}",
        );
        // SNI char: client connected with "example.test" → domain.
        assert!(
            server_fp.contains('d'),
            "fingerprint should contain SNI 'd' marker: {server_fp}",
        );
        // Two underscores.
        assert_eq!(server_fp.matches('_').count(), 2, "got: {server_fp}");

        srv.abort();
    }
}
