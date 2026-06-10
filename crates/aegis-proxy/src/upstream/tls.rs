use std::fs;
use std::io::BufReader;
use std::path::Path;

use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// Per-pool upstream TLS configuration — optionally with client certificates
/// for mutual TLS.
#[derive(Debug, Clone)]
pub struct UpstreamTlsConfig {
    pub ca_bundle: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
    pub server_name: String,
}

/// Build a `rustls::ClientConfig` for connecting to an upstream that may
/// require mTLS.
///
/// - If `ca_bundle` is provided, only those CAs are trusted.
/// - If `client_cert` + `client_key` are provided, the client presents them.
/// - Otherwise, falls back to system roots (via `webpki-roots`-compatible
///   empty store for now; production would use `rustls-native-certs`).
pub fn build_upstream_client_config(
    cfg: &UpstreamTlsConfig,
) -> Result<rustls::ClientConfig, Box<dyn std::error::Error + Send + Sync>> {
    let mut root_store = rustls::RootCertStore::empty();

    if let Some(ca_path) = &cfg.ca_bundle {
        let ca_file = fs::File::open(ca_path)?;
        let mut reader = BufReader::new(ca_file);
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()?;
        for cert in certs {
            root_store.add(cert)?;
        }
    }

    let client_config = if let (Some(cert_path), Some(key_path)) =
        (&cfg.client_cert, &cfg.client_key)
    {
        let certs = load_certs(Path::new(cert_path))?;
        let key = load_key(Path::new(key_path))?;

        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(certs, key)?
    } else {
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    Ok(client_config)
}

/// P2 — build the upstream `rustls::ClientConfig` from a pool's
/// resolved mTLS material ([`aegis_core::config::UpstreamMtlsResolved`]).
///
/// - Trust anchors: the custom `trust` CA bundle when set,
///   otherwise the public webpki roots (so a public-internet backend
///   still verifies).
/// - Client identity: always presented (P2 only resolves material for
///   enabled pools), loaded from the shared fleet identity's cert/key
///   **paths** — the private key is read here and never stored in
///   config or returned by any API.
///
/// `verify: false` and `allowed_sans` are rejected at config
/// validation in P2, so this always builds the verified path.
/// Fallible — a load/parse failure propagates so the caller fails the
/// pool's dials closed rather than silently downgrading.
pub fn client_config_from_resolved(
    m: &aegis_core::config::UpstreamMtlsResolved,
) -> Result<rustls::ClientConfig, Box<dyn std::error::Error + Send + Sync>> {
    use aegis_core::config::CertSource;

    let mut root_store = rustls::RootCertStore::empty();
    match &m.trust {
        Some(src) => {
            let certs = certs_from_source(src, "upstream_mtls.trust")?;
            if certs.is_empty() {
                return Err("upstream_mtls.trust: no certificates found".into());
            }
            for cert in certs {
                root_store.add(cert)?;
            }
        }
        None => {
            // Public webpki roots — same anchors hyper-rustls'
            // `.with_webpki_roots()` installs for the non-mTLS path.
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
    }

    let certs = certs_from_source(&m.client_cert, "upstream_mtls client cert")?;
    if certs.is_empty() {
        return Err("upstream_mtls: empty client cert chain".into());
    }
    // The private key is ALWAYS a reference resolved here — never
    // carried in config or the resolved struct. (P4 reference-only:
    // even state-source identities keep the key as a `key_ref`.)
    let key = load_key(Path::new(&m.client_key_ref))?;
    let mut client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)?;
    // P5 — TLS session resumption (mTLS.md §3.7): a reconnect to a
    // backend skips the full handshake (TLS 1.3 tickets + TLS 1.2
    // session IDs amortise the mTLS handshake cost off the hot path).
    // rustls enables resumption by default; we set it explicitly so it
    // can't silently regress, sized for our per-pool client model — one
    // `ClientConfig` is built per pool / cert signature and a pool has a
    // handful of backend members, so a modest cache is ample. 0-RTT
    // early data stays OFF (replay risk) — `in_memory_sessions` does not
    // enable it.
    client_config.resumption =
        rustls::client::Resumption::in_memory_sessions(UPSTREAM_SESSION_CACHE_SIZE);
    Ok(client_config)
}

/// Per-`ClientConfig` upstream TLS session cache size (resumption
/// tickets / session IDs). One config exists per pool / cert signature,
/// so this is per-pool headroom, not a global ceiling.
const UPSTREAM_SESSION_CACHE_SIZE: usize = 256;

/// Load a PUBLIC cert chain from a [`CertSource`] — a file on disk or
/// in-memory PEM (materialized from the config plane).
fn certs_from_source(
    src: &aegis_core::config::CertSource,
    what: &str,
) -> Result<Vec<CertificateDer<'static>>, Box<dyn std::error::Error + Send + Sync>> {
    use aegis_core::config::CertSource;
    match src {
        CertSource::File(path) => {
            let file = fs::File::open(path)
                .map_err(|e| format!("{what}: failed to read {}: {e}", path.display()))?;
            let mut reader = BufReader::new(file);
            Ok(rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?)
        }
        CertSource::Pem(pem) => {
            let mut reader = BufReader::new(pem.as_bytes());
            Ok(rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?)
        }
    }
}

fn load_certs(
    path: &Path,
) -> Result<Vec<CertificateDer<'static>>, Box<dyn std::error::Error + Send + Sync>> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(format!("no certificates found in {}", path.display()).into());
    }
    Ok(certs)
}

fn load_key(
    path: &Path,
) -> Result<PrivateKeyDer<'static>, Box<dyn std::error::Error + Send + Sync>> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| format!("no private key found in {}", path.display()).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::Arc;
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Generate a self-signed CA + leaf cert signed by that CA.
    fn generate_ca_and_leaf(
        leaf_domains: &[&str],
    ) -> (String, String, String, String) {
        // CA
        let mut ca_params =
            rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        // Leaf
        let leaf_params = rcgen::CertificateParams::new(
            leaf_domains.iter().map(|d| d.to_string()).collect::<Vec<_>>(),
        )
        .unwrap();
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &ca_cert, &ca_key)
            .unwrap();

        (
            ca_cert.pem(),
            leaf_cert.pem(),
            leaf_key.serialize_pem(),
            ca_key.serialize_pem(),
        )
    }

    fn write_pem(dir: &TempDir, name: &str, content: &str) -> String {
        let path = dir.path().join(name);
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path.to_str().unwrap().to_string()
    }

    #[test]
    fn builds_client_config_without_client_cert() {
        let dir = TempDir::new().unwrap();
        let (ca_pem, _leaf_pem, _leaf_key, _ca_key) = generate_ca_and_leaf(&["localhost"]);
        let ca_path = write_pem(&dir, "ca.crt", &ca_pem);

        let cfg = UpstreamTlsConfig {
            ca_bundle: Some(ca_path),
            client_cert: None,
            client_key: None,
            server_name: "localhost".into(),
        };

        let config = build_upstream_client_config(&cfg).unwrap();
        // No client cert → resolver should report no certs.
        assert!(!config.client_auth_cert_resolver.has_certs());
    }

    #[test]
    fn builds_client_config_with_mtls() {
        let dir = TempDir::new().unwrap();
        let (ca_pem, leaf_pem, leaf_key_pem, _ca_key) = generate_ca_and_leaf(&["localhost"]);
        let ca_path = write_pem(&dir, "ca.crt", &ca_pem);
        let cert_path = write_pem(&dir, "client.crt", &leaf_pem);
        let key_path = write_pem(&dir, "client.key", &leaf_key_pem);

        let cfg = UpstreamTlsConfig {
            ca_bundle: Some(ca_path),
            client_cert: Some(cert_path),
            client_key: Some(key_path),
            server_name: "localhost".into(),
        };

        let config = build_upstream_client_config(&cfg).unwrap();
        assert!(config.client_auth_cert_resolver.has_certs());
    }

    #[tokio::test]
    async fn mtls_connection_succeeds_with_client_cert() {
        let dir = TempDir::new().unwrap();

        // Generate CA + server cert + client cert.
        let (ca_pem, server_cert_pem, server_key_pem, _) =
            generate_ca_and_leaf(&["localhost"]);
        let (_, client_cert_pem, client_key_pem, _) =
            generate_ca_and_leaf(&["client"]);
        // For mTLS, the server needs to trust the client's CA.
        // In this test, we use the same CA for simplicity — regenerate client from same CA.
        let mut ca_params =
            rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let srv_params =
            rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        let srv_key = rcgen::KeyPair::generate().unwrap();
        let srv_cert = srv_params.signed_by(&srv_key, &ca_cert, &ca_key).unwrap();

        let cli_params =
            rcgen::CertificateParams::new(vec!["client".into()]).unwrap();
        let cli_key = rcgen::KeyPair::generate().unwrap();
        let cli_cert = cli_params.signed_by(&cli_key, &ca_cert, &ca_key).unwrap();

        let ca_pem = ca_cert.pem();
        let ca_path = write_pem(&dir, "ca.crt", &ca_pem);
        let srv_cert_path = write_pem(&dir, "srv.crt", &srv_cert.pem());
        let srv_key_path = write_pem(&dir, "srv.key", &srv_key.serialize_pem());
        let cli_cert_path = write_pem(&dir, "cli.crt", &cli_cert.pem());
        let cli_key_path = write_pem(&dir, "cli.key", &cli_key.serialize_pem());

        // Server: require client cert.
        let srv_certs = load_certs(Path::new(&srv_cert_path)).unwrap();
        let srv_priv = load_key(Path::new(&srv_key_path)).unwrap();

        let mut ca_store = rustls::RootCertStore::empty();
        let ca_der: Vec<CertificateDer<'static>> = {
            let mut r = BufReader::new(ca_pem.as_bytes());
            rustls_pemfile::certs(&mut r)
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        };
        for c in &ca_der {
            ca_store.add(c.clone()).unwrap();
        }

        let client_verifier =
            rustls::server::WebPkiClientVerifier::builder(Arc::new(ca_store))
                .build()
                .unwrap();

        let server_config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(srv_certs, srv_priv)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();

        let srv = tokio::spawn(async move {
            let (stream, _) = tcp.accept().await.unwrap();
            let mut tls = acceptor.accept(stream).await.unwrap();
            let mut buf = [0u8; 32];
            let n = tls.read(&mut buf).await.unwrap();
            tls.write_all(&buf[..n]).await.unwrap();
        });

        // Client: use mTLS config built by our function.
        let cfg = UpstreamTlsConfig {
            ca_bundle: Some(ca_path),
            client_cert: Some(cli_cert_path),
            client_key: Some(cli_key_path),
            server_name: "localhost".into(),
        };
        let client_config = build_upstream_client_config(&cfg).unwrap();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

        let tcp_stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let server_name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
        let mut tls = connector.connect(server_name, tcp_stream).await.unwrap();

        tls.write_all(b"mtls-ok").await.unwrap();
        let mut buf = [0u8; 32];
        let n = tls.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"mtls-ok");

        srv.abort();
    }

    #[tokio::test]
    async fn mtls_connection_rejected_without_client_cert() {
        let dir = TempDir::new().unwrap();

        // Same CA for server and client verification.
        let mut ca_params =
            rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let srv_params =
            rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        let srv_key = rcgen::KeyPair::generate().unwrap();
        let srv_cert = srv_params.signed_by(&srv_key, &ca_cert, &ca_key).unwrap();

        let ca_pem = ca_cert.pem();
        let ca_path = write_pem(&dir, "ca.crt", &ca_pem);
        let srv_cert_path = write_pem(&dir, "srv.crt", &srv_cert.pem());
        let srv_key_path = write_pem(&dir, "srv.key", &srv_key.serialize_pem());

        let srv_certs = load_certs(Path::new(&srv_cert_path)).unwrap();
        let srv_priv = load_key(Path::new(&srv_key_path)).unwrap();

        let mut ca_store = rustls::RootCertStore::empty();
        let ca_der: Vec<CertificateDer<'static>> = {
            let mut r = BufReader::new(ca_pem.as_bytes());
            rustls_pemfile::certs(&mut r)
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        };
        for c in &ca_der {
            ca_store.add(c.clone()).unwrap();
        }

        let client_verifier =
            rustls::server::WebPkiClientVerifier::builder(Arc::new(ca_store))
                .build()
                .unwrap();

        let server_config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(srv_certs, srv_priv)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();

        let srv = tokio::spawn(async move {
            let (stream, _) = tcp.accept().await.unwrap();
            // This should fail because client doesn't present a cert.
            let result = acceptor.accept(stream).await;
            assert!(result.is_err());
        });

        // Client: NO client cert.
        let cfg = UpstreamTlsConfig {
            ca_bundle: Some(ca_path),
            client_cert: None,
            client_key: None,
            server_name: "localhost".into(),
        };
        let client_config = build_upstream_client_config(&cfg).unwrap();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

        let tcp_stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let server_name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
        // The TLS handshake itself may succeed (client just sends no cert),
        // but the server will reject it.  Depending on the rustls version the
        // error surfaces either at connect() or at the first read/write.
        match connector.connect(server_name, tcp_stream).await {
            Err(_) => { /* expected */ }
            Ok(mut tls) => {
                // Server should tear down the connection.
                tls.write_all(b"test").await.ok();
                let mut buf = [0u8; 32];
                let n = tls.read(&mut buf).await.unwrap_or(0);
                assert_eq!(n, 0, "expected server to close connection");
            }
        }

        srv.await.ok();
    }

    /// P2 fail-closed (handshake) — the gold §6 gate. A pool with
    /// upstream mTLS whose `trust` CA does NOT sign the backend's
    /// server cert must FAIL the dial (untrusted backend), never
    /// silently connect. Exercises `client_config_from_resolved`
    /// end-to-end against a live rustls server.
    #[tokio::test]
    async fn upstream_mtls_fails_closed_on_untrusted_backend_cert() {
        use aegis_core::config::UpstreamMtlsResolved;
        // rustls needs a process-level CryptoProvider (build_client
        // installs it in production). Idempotent.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = TempDir::new().unwrap();

        // CA_A signs the backend's server cert.
        let mut ca_a_params =
            rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_a_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_a_key = rcgen::KeyPair::generate().unwrap();
        let ca_a = ca_a_params.self_signed(&ca_a_key).unwrap();
        let srv_params =
            rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        let srv_key = rcgen::KeyPair::generate().unwrap();
        let srv_cert = srv_params.signed_by(&srv_key, &ca_a, &ca_a_key).unwrap();

        // CA_B is what the WAF trusts — it does NOT sign the server.
        let mut ca_b_params =
            rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_b_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_b_key = rcgen::KeyPair::generate().unwrap();
        let ca_b = ca_b_params.self_signed(&ca_b_key).unwrap();
        let ca_b_path = write_pem(&dir, "ca_b.crt", &ca_b.pem());

        // The WAF's client identity (any leaf; the server below does
        // not request client auth, so its trust is irrelevant here).
        let cli_params = rcgen::CertificateParams::new(vec!["waf".into()]).unwrap();
        let cli_key = rcgen::KeyPair::generate().unwrap();
        let cli_cert = cli_params.self_signed(&cli_key).unwrap();
        let cli_cert_path = write_pem(&dir, "waf.crt", &cli_cert.pem());
        let cli_key_path = write_pem(&dir, "waf.key", &cli_key.serialize_pem());

        // Server presents the CA_A-signed cert; no client-cert check.
        let srv_cert_path = write_pem(&dir, "srv.crt", &srv_cert.pem());
        let srv_key_path = write_pem(&dir, "srv.key", &srv_key.serialize_pem());
        let srv_certs = load_certs(Path::new(&srv_cert_path)).unwrap();
        let srv_priv = load_key(Path::new(&srv_key_path)).unwrap();
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(srv_certs, srv_priv)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            if let Ok((stream, _)) = tcp.accept().await {
                // Handshake is expected to fail on the client side;
                // the server just attempts accept and ignores the err.
                let _ = acceptor.accept(stream).await;
            }
        });

        // WAF client config: present our cert, but TRUST only CA_B.
        let resolved = UpstreamMtlsResolved {
            client_cert: aegis_core::config::CertSource::File(cli_cert_path.into()),
            client_key_ref: cli_key_path,
            trust: Some(aegis_core::config::CertSource::File(ca_b_path.into())),
            verify: true,
            allowed_sans: Vec::new(),
            fingerprint: "v1|wrong-ca".into(),
        };
        let client_config = client_config_from_resolved(&resolved).unwrap();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let tcp_stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let server_name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
        let result = connector.connect(server_name, tcp_stream).await;
        assert!(
            result.is_err(),
            "WAF must reject a backend cert not signed by the pinned trust CA (fail closed)"
        );

        srv.abort();
    }

    /// P4 foundation — `client_config_from_resolved` accepts in-memory
    /// PEM material (`CertSource::Pem`) for both the client cert and
    /// the trust anchor, not just files. This is what a state-backed
    /// identity (cert materialized from the config plane) will use; the
    /// private key still comes from a `key_ref` on disk (reference-only).
    #[test]
    fn client_config_from_resolved_accepts_pem_source() {
        use aegis_core::config::{CertSource, UpstreamMtlsResolved};
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = TempDir::new().unwrap();
        // (ca_pem, leaf_cert_pem, leaf_key_pem, _ca_key_pem)
        let (ca_pem, cert_pem, key_pem, _) = generate_ca_and_leaf(&["waf"]);
        // Key stays a file ref (reference-only); cert + trust are PEM.
        let key_path = write_pem(&dir, "waf.key", &key_pem);
        let resolved = UpstreamMtlsResolved {
            client_cert: CertSource::Pem(cert_pem),
            client_key_ref: key_path,
            trust: Some(CertSource::Pem(ca_pem)),
            verify: true,
            allowed_sans: Vec::new(),
            fingerprint: "v1|pem-source".into(),
        };
        let cfg = client_config_from_resolved(&resolved)
            .expect("in-memory PEM material must build a valid client config");
        // Sanity: a client cert was installed (mTLS, not server-auth-only).
        assert!(cfg.client_auth_cert_resolver.has_certs());
    }
}
