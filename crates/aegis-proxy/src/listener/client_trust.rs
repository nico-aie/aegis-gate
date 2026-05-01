//! MTLS-T2 — client-cert trust anchors for the inbound rustls
//! verifier.
//!
//! Owns the parsed `RootCertStore` built from
//! `cfg.tls.client_auth.ca_bundle`. Hot-swappable via `ArcSwap` so
//! a future MTLS-T5 reload can rotate the bundle without bouncing
//! listeners — the rustls `WebPkiClientVerifier` we hand out
//! reads through the swap on every handshake.
//!
//! Errors during PEM parsing surface as `WafError::Config` so the
//! boot path can fail loudly rather than silently downgrading to
//! "no client auth".

use std::fs;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use rustls::RootCertStore;
use rustls_pki_types::CertificateDer;

use aegis_core::{Result, WafError};

/// Hot-swappable trust anchor store for the inbound mTLS path.
///
/// Cheap to clone (`Arc` over an `ArcSwap`); every clone observes
/// the same swap target.
///
/// Usage:
///
///   1. boot path calls [`ClientTrustStore::load_from_pem_file`]
///      and stashes the result in `aegis-proxy::run`,
///   2. [`Self::current`] returns a fresh `Arc<RootCertStore>` to
///      hand to `WebPkiClientVerifier::builder`,
///   3. (MTLS-T5) the cfg-reload watcher calls
///      [`Self::swap`] to rotate the roots.
#[derive(Clone, Debug)]
pub struct ClientTrustStore {
    inner: Arc<ArcSwap<RootCertStore>>,
}

impl ClientTrustStore {
    /// Wrap an existing `RootCertStore` in a hot-swappable handle.
    /// Tests + the cfg-reload watcher use this; the boot path
    /// goes through [`Self::load_from_pem_file`].
    pub fn from_store(store: RootCertStore) -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(store)),
        }
    }

    /// Parse a PEM bundle and build a `ClientTrustStore`. Every
    /// `BEGIN CERTIFICATE` entry in the file becomes a trust
    /// anchor.
    ///
    /// Returns `Config` errors with the offending path so the boot
    /// log identifies the cause without dumping a stack trace.
    pub fn load_from_pem_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let bytes = fs::read(path).map_err(|e| {
            WafError::Config(format!(
                "client_auth.ca_bundle: failed to read {}: {e}",
                path.display(),
            ))
        })?;
        Self::load_from_pem_bytes(&bytes).map_err(|e| match e {
            WafError::Config(msg) => WafError::Config(format!(
                "client_auth.ca_bundle: {} ({})",
                msg,
                path.display(),
            )),
            other => other,
        })
    }

    /// Parse a PEM bundle from an in-memory slice. Pulled out so
    /// tests can drive the parser without touching the
    /// filesystem.
    pub fn load_from_pem_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = BufReader::new(bytes);
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| WafError::Config(format!("PEM parse failed: {e}")))?;
        if certs.is_empty() {
            return Err(WafError::Config(
                "PEM bundle contained no CERTIFICATE blocks".into(),
            ));
        }
        let mut store = RootCertStore::empty();
        for cert in certs {
            store
                .add(cert)
                .map_err(|e| WafError::Config(format!("rustls rejected CA: {e}")))?;
        }
        Ok(Self::from_store(store))
    }

    /// Snapshot the current root store. Cheap (`Arc` clone); the
    /// returned handle keeps the previous store alive even after
    /// a concurrent [`Self::swap`].
    pub fn current(&self) -> Arc<RootCertStore> {
        self.inner.load_full()
    }

    /// Replace the root store atomically. Subsequent
    /// `WebPkiClientVerifier` instances built from
    /// [`Self::current`] will see the new roots; verifiers that
    /// were already constructed continue to use the old store.
    /// MTLS-T5 wires this from the cfg-reload watcher.
    pub fn swap(&self, new_store: RootCertStore) {
        self.inner.store(Arc::new(new_store));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a one-shot self-signed CA in PEM form. Used to feed
    /// the loader without a real filesystem CA bundle.
    fn make_test_ca_pem() -> Vec<u8> {
        let mut params = rcgen::CertificateParams::new(vec!["test-ca".into()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        cert.pem().into_bytes()
    }

    #[test]
    fn load_from_pem_bytes_parses_a_real_certificate() {
        let pem = make_test_ca_pem();
        let store = ClientTrustStore::load_from_pem_bytes(&pem).expect("parses");
        // The current store should be reachable + non-empty.
        assert!(store.current().len() >= 1);
    }

    #[test]
    fn load_from_pem_bytes_rejects_empty_input() {
        let err = ClientTrustStore::load_from_pem_bytes(b"").unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("no CERTIFICATE"),
            "expected 'no CERTIFICATE' in error, got {msg}",
        );
    }

    #[test]
    fn load_from_pem_bytes_rejects_garbage_input() {
        let err = ClientTrustStore::load_from_pem_bytes(b"not a pem file at all")
            .unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("no CERTIFICATE"),
            "garbage input should be treated as empty bundle, got {msg}",
        );
    }

    #[test]
    fn load_from_pem_file_surfaces_path_in_error() {
        let err = ClientTrustStore::load_from_pem_file("/no/such/path.pem")
            .unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("/no/such/path.pem"),
            "error must include the offending path, got {msg}",
        );
    }

    #[test]
    fn swap_replaces_underlying_store() {
        let pem_a = make_test_ca_pem();
        let store = ClientTrustStore::load_from_pem_bytes(&pem_a).unwrap();
        let before = store.current();
        let len_before = before.len();

        // Swap to a fresh CA — the new store has its own count;
        // the old `Arc<RootCertStore>` we already held stays
        // valid (proves the swap doesn't mutate the old store).
        let pem_b = make_test_ca_pem();
        let new_inner = {
            let parsed = ClientTrustStore::load_from_pem_bytes(&pem_b).unwrap();
            // RootCertStore doesn't impl Clone — clone the
            // TrustAnchors into a fresh owned store.
            let cur = parsed.current();
            let mut owned = RootCertStore::empty();
            for ta in cur.roots.iter() {
                owned.roots.push(ta.clone());
            }
            owned
        };
        store.swap(new_inner);

        // Old snapshot still alive.
        assert_eq!(before.len(), len_before);
        // New current is reachable.
        let after = store.current();
        assert!(after.len() >= 1);
    }
}
