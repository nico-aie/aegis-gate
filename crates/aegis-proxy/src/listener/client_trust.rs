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
    /// MTLS-T10 Phase 2 — bytes of the most recently-loaded PEM.
    /// Empty before the first load; non-empty after every successful
    /// `load_from_pem_*` or `swap_pem`. The audit-mutated CA-bundle
    /// PUT handler reads this through `TrustAnchorWriter::current_pem`
    /// to compute the exact before/after diff that lands on the
    /// audit chain.
    last_pem: Arc<ArcSwap<Vec<u8>>>,
}

impl ClientTrustStore {
    /// Wrap an existing `RootCertStore` in a hot-swappable handle.
    /// Tests + the cfg-reload watcher use this; the boot path
    /// goes through [`Self::load_from_pem_file`].
    ///
    /// `last_pem` starts empty — callers that want preview/diff
    /// support after boot must round-trip through
    /// [`Self::load_from_pem_bytes`] or
    /// [`crate::listener::client_trust::ClientTrustStore::swap_pem`]
    /// instead.
    pub fn from_store(store: RootCertStore) -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(store)),
            last_pem: Arc::new(ArcSwap::from_pointee(Vec::new())),
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
        let store = parse_pem_to_root_store(bytes)?;
        let me = Self::from_store(store);
        me.last_pem.store(Arc::new(bytes.to_vec()));
        Ok(me)
    }

    /// MTLS-T10 Phase 2 — atomically replace the live root store
    /// from new PEM bytes. On parse / build failure the previous
    /// store stays in place and the error is bubbled up so the
    /// admin handler can surface it.
    ///
    /// Distinct from [`Self::swap`] (which takes an already-parsed
    /// `RootCertStore`); this is the path the dashboard's
    /// "Save & Apply" button drives.
    pub fn swap_pem(&self, pem: &[u8]) -> Result<usize> {
        let new_store = parse_pem_to_root_store(pem)?;
        let cert_count = new_store.len();
        self.inner.store(Arc::new(new_store));
        self.last_pem.store(Arc::new(pem.to_vec()));
        Ok(cert_count)
    }

    /// Snapshot the bytes of the last successfully-loaded PEM.
    /// Empty when the handle was constructed via
    /// [`Self::from_store`] without a subsequent load. Cheap (one
    /// `Arc` clone + one `Vec` copy on read).
    pub fn last_pem_bytes(&self) -> Vec<u8> {
        self.last_pem.load_full().as_ref().clone()
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

/// Shared PEM → `RootCertStore` parser. Pulled out so
/// `load_from_pem_bytes` and `swap_pem` share validation rules
/// (empty input → error, every CERTIFICATE must rustls-add cleanly).
fn parse_pem_to_root_store(pem: &[u8]) -> Result<RootCertStore> {
    let mut reader = BufReader::new(pem);
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
    Ok(store)
}

/// MTLS-T10 Phase 2 — bridge to the audit-mutated PUT handler in
/// `aegis-control`. The handler stays type-blind to the proxy
/// crate and drives swaps through this trait object.
impl aegis_control::api::mtls_ca_bundle::TrustAnchorWriter for ClientTrustStore {
    fn swap_pem(&self, pem: &[u8]) -> std::result::Result<usize, String> {
        ClientTrustStore::swap_pem(self, pem).map_err(|e| e.to_string())
    }

    fn current_pem(&self) -> Vec<u8> {
        self.last_pem_bytes()
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
    fn load_from_pem_bytes_seeds_last_pem_for_diff() {
        let pem = make_test_ca_pem();
        let store = ClientTrustStore::load_from_pem_bytes(&pem).unwrap();
        assert_eq!(
            store.last_pem_bytes(),
            pem,
            "load_from_pem_bytes must stash the bytes for Phase-2 diff",
        );
    }

    #[test]
    fn from_store_starts_with_empty_last_pem() {
        let store = ClientTrustStore::from_store(RootCertStore::empty());
        assert!(
            store.last_pem_bytes().is_empty(),
            "from_store must not synthesise PEM bytes",
        );
    }

    #[test]
    fn swap_pem_replaces_store_and_updates_last_pem() {
        let pem_a = make_test_ca_pem();
        let store = ClientTrustStore::load_from_pem_bytes(&pem_a).unwrap();
        let len_before = store.current().len();

        // Build a different CA and swap to it via the PEM path.
        let pem_b = {
            let mut params = rcgen::CertificateParams::new(vec!["swap-pem-ca".into()]).unwrap();
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let key = rcgen::KeyPair::generate().unwrap();
            params.self_signed(&key).unwrap().pem().into_bytes()
        };
        let count = store.swap_pem(&pem_b).unwrap();
        assert!(count >= 1);
        assert_eq!(
            store.last_pem_bytes(),
            pem_b,
            "swap_pem must update last_pem_bytes",
        );
        assert!(store.current().len() >= len_before);
    }

    #[test]
    fn swap_pem_with_garbage_keeps_old_store() {
        let pem_a = make_test_ca_pem();
        let store = ClientTrustStore::load_from_pem_bytes(&pem_a).unwrap();
        let last_before = store.last_pem_bytes();

        let err = store.swap_pem(b"not a pem").unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("no CERTIFICATE"));

        // last_pem_bytes is unchanged on failure — no half-applied state.
        assert_eq!(store.last_pem_bytes(), last_before);
    }

    #[test]
    fn trust_anchor_writer_trait_swaps_via_pem() {
        use aegis_control::api::mtls_ca_bundle::TrustAnchorWriter;

        let pem_a = make_test_ca_pem();
        let store = ClientTrustStore::load_from_pem_bytes(&pem_a).unwrap();
        let writer: &dyn TrustAnchorWriter = &store;
        assert_eq!(writer.current_pem(), pem_a);

        let pem_b = {
            let mut params = rcgen::CertificateParams::new(vec!["trait-swap-ca".into()]).unwrap();
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let key = rcgen::KeyPair::generate().unwrap();
            params.self_signed(&key).unwrap().pem().into_bytes()
        };
        let n = writer.swap_pem(&pem_b).unwrap();
        assert!(n >= 1);
        assert_eq!(writer.current_pem(), pem_b);
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
