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
}
