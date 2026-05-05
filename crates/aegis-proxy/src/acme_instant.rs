//! Production [`AcmeProvider`] backed by the `instant-acme` crate.
//!
//! Lifecycle
//! ---------
//! - [`register_account`]: load credentials from
//!   `cfg.account_key_path` if the file exists; otherwise
//!   register a new account against the directory and persist
//!   the resulting `AccountCredentials` JSON.
//! - [`place_order`]: build identifiers from `cfg.domains`, walk
//!   each authorisation's challenge list, return the HTTP-01
//!   token + key-authorisation pairs the manager publishes via
//!   the [`ChallengeStore`].
//! - [`await_validation`]: notify the directory each challenge
//!   is ready, then poll `Order::refresh()` until the order
//!   state is `Ready` or `Valid`, with bounded retries.
//! - [`finalize_and_download`]: build a CSR via `rcgen`,
//!   submit it, poll until `Valid`, fetch the cert chain, and
//!   persist `cert.pem` + `key.pem` to `cfg.cert_dir`.
//!
//! The [`crate::acme::AcmeProvider`] trait is the unit-tested
//! seam — this file is intentionally a thin adapter so its
//! behavioural contract is exercised in `acme::tests` against
//! the `MockProvider`.
//!
//! [`AcmeProvider`]: crate::acme::AcmeProvider
//! [`ChallengeStore`]: crate::acme::ChallengeStore

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, Order, OrderStatus, RetryPolicy,
};
use tokio::sync::{Mutex, OnceCell};

use crate::acme::{
    AcmeConfig, AcmeError, AcmeProvider, Http01Challenge, IssuedCert, OrderState,
};

const POLL_INTERVAL: Duration = Duration::from_secs(2);
const POLL_MAX_ATTEMPTS: u32 = 60; // 2 minutes ceiling

/// Production [`AcmeProvider`] using `instant-acme`. Cheap to
/// clone (`Arc`-shared internals).
#[derive(Clone)]
pub struct InstantAcmeProvider {
    inner: Arc<Inner>,
}

struct Inner {
    account: OnceCell<Account>,
    /// Order state survives across `place_order` →
    /// `await_validation` → `finalize_and_download` calls in one
    /// issuance cycle. The `AcmeManager` calls each method in
    /// sequence, so a `Mutex<Option<Order>>` is enough; we don't
    /// need to support concurrent issuance against the same
    /// account.
    order: Mutex<Option<Order>>,
    /// HTTP-01 challenges pinned to the active order — fed back
    /// to `await_validation` so we know which URLs to mark ready.
    challenges: Mutex<Vec<String>>,
}

impl InstantAcmeProvider {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                account: OnceCell::new(),
                order: Mutex::new(None),
                challenges: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Construct a provider already wired to an existing account.
    /// Useful for tests + for the renewal scheduler that holds the
    /// adapter across re-issuance cycles.
    pub fn with_account(account: Account) -> Self {
        let cell = OnceCell::new();
        let _ = cell.set(account);
        Self {
            inner: Arc::new(Inner {
                account: cell,
                order: Mutex::new(None),
                challenges: Mutex::new(Vec::new()),
            }),
        }
    }
}

impl Default for InstantAcmeProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AcmeProvider for InstantAcmeProvider {
    async fn register_account(&self, cfg: &AcmeConfig) -> Result<(), AcmeError> {
        if self.inner.account.initialized() {
            return Ok(());
        }
        let account = if cfg.account_key_path.exists() {
            load_account(&cfg.account_key_path).await?
        } else {
            let contacts = collect_contact_uris(cfg);
            let new_account = NewAccount {
                contact: &contacts,
                terms_of_service_agreed: cfg.terms_of_service_agreed,
                only_return_existing: false,
            };
            let builder = Account::builder()
                .map_err(|e| AcmeError::Network(e.to_string()))?;
            let (account, credentials) = builder
                .create(&new_account, cfg.directory_url.clone(), None)
                .await
                .map_err(|e| AcmeError::Network(e.to_string()))?;
            persist_account(&credentials, &cfg.account_key_path).await?;
            account
        };
        self.inner
            .account
            .set(account)
            .map_err(|_| AcmeError::Internal("account already initialised".into()))?;
        Ok(())
    }

    async fn place_order(
        &self,
        _cfg: &AcmeConfig,
        domains: &[String],
    ) -> Result<Vec<Http01Challenge>, AcmeError> {
        let account = self
            .inner
            .account
            .get()
            .ok_or_else(|| AcmeError::Internal("register_account must run first".into()))?;
        let identifiers: Vec<Identifier> =
            domains.iter().map(|d| Identifier::Dns(d.clone())).collect();
        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .map_err(|e| AcmeError::Rejected(e.to_string()))?;

        let mut http_challenges = Vec::new();
        let mut authzs = order.authorizations();
        while let Some(result) = authzs.next().await {
            let mut authz = result.map_err(|e| AcmeError::Network(e.to_string()))?;
            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                other => {
                    return Err(AcmeError::Rejected(format!(
                        "authorization in unexpected state: {other:?}"
                    )))
                }
            }
            let id_label = identifier_label_from_state(&authz);
            let challenge = authz.challenge(ChallengeType::Http01).ok_or_else(|| {
                AcmeError::ChallengeFailed {
                    token: id_label.clone(),
                    reason: "no http-01 challenge offered".into(),
                }
            })?;
            let token = challenge.token.clone();
            let key_auth = challenge.key_authorization().as_str().to_string();
            http_challenges.push(Http01Challenge {
                token,
                key_authorization: key_auth,
            });
        }
        drop(authzs);

        *self.inner.order.lock().await = Some(order);
        // 0.8 set-ready works on the live ChallengeHandle; we walk the
        // authz stream a second time in await_validation and call
        // set_ready() then. No URLs to track here.
        self.inner.challenges.lock().await.clear();
        Ok(http_challenges)
    }

    async fn await_validation(&self, _cfg: &AcmeConfig) -> Result<OrderState, AcmeError> {
        let mut guard = self.inner.order.lock().await;
        let order = guard
            .as_mut()
            .ok_or_else(|| AcmeError::Internal("place_order must run first".into()))?;
        // Tell the directory each pending HTTP-01 challenge is ready
        // to be probed. Re-iterating doesn't refetch — 0.8 caches the
        // authz state populated by place_order.
        let mut authzs = order.authorizations();
        while let Some(result) = authzs.next().await {
            let mut authz = result.map_err(|e| AcmeError::Network(e.to_string()))?;
            if !matches!(authz.status, AuthorizationStatus::Pending) {
                continue;
            }
            if let Some(mut challenge) = authz.challenge(ChallengeType::Http01) {
                challenge
                    .set_ready()
                    .await
                    .map_err(|e| AcmeError::Network(e.to_string()))?;
            }
        }
        drop(authzs);
        // Poll until the order leaves Pending.
        let status = order
            .poll_ready(&RetryPolicy::default())
            .await
            .map_err(|e| AcmeError::Network(e.to_string()))?;
        match status {
            OrderStatus::Ready | OrderStatus::Valid => Ok(map_status(status)),
            OrderStatus::Invalid => Ok(OrderState::Invalid),
            OrderStatus::Pending | OrderStatus::Processing => {
                Err(AcmeError::Timeout(map_status(status)))
            }
        }
    }

    async fn finalize_and_download(
        &self,
        cfg: &AcmeConfig,
        domains: &[String],
    ) -> Result<IssuedCert, AcmeError> {
        let mut guard = self.inner.order.lock().await;
        let order = guard
            .as_mut()
            .ok_or_else(|| AcmeError::Internal("place_order must run first".into()))?;
        let (csr_der, key_pem) = build_csr(domains)?;
        order
            .finalize_csr(&csr_der)
            .await
            .map_err(|e| AcmeError::Rejected(e.to_string()))?;
        let cert_pem = order
            .poll_certificate(&RetryPolicy::default())
            .await
            .map_err(|e| AcmeError::Network(e.to_string()))?;
        persist_issued(&cfg.cert_dir, domains, cert_pem.as_bytes(), key_pem.as_bytes())
            .await?;
        Ok(IssuedCert {
            domains: domains.to_vec(),
            cert_pem: cert_pem.into_bytes(),
            key_pem: key_pem.into_bytes(),
        })
    }
}

fn collect_contact_uris(cfg: &AcmeConfig) -> Vec<&str> {
    cfg.contacts.iter().map(|s| s.as_str()).collect()
}

fn identifier_label(id: &Identifier) -> String {
    match id {
        Identifier::Dns(s) => s.clone(),
        other => format!("{other:?}"),
    }
}

fn identifier_label_from_state(authz: &instant_acme::AuthorizationState) -> String {
    identifier_label(authz.identifier().identifier)
}

fn map_status(status: OrderStatus) -> OrderState {
    match status {
        OrderStatus::Pending => OrderState::Pending,
        OrderStatus::Ready => OrderState::Ready,
        OrderStatus::Processing => OrderState::Processing,
        OrderStatus::Valid => OrderState::Valid,
        OrderStatus::Invalid => OrderState::Invalid,
    }
}

/// Build a CSR + matching private key for `domains`. Returns
/// `(csr_der, key_pem)` — the DER blob is what `instant-acme`'s
/// finalize endpoint wants; the PEM key is persisted for the
/// rustls cert resolver.
pub fn build_csr(domains: &[String]) -> Result<(Vec<u8>, String), AcmeError> {
    if domains.is_empty() {
        return Err(AcmeError::Config("no domains".into()));
    }
    let key_pair = rcgen::KeyPair::generate()
        .map_err(|e| AcmeError::Internal(format!("key generation failed: {e}")))?;
    let mut params =
        rcgen::CertificateParams::new(domains.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .map_err(|e| AcmeError::Internal(format!("CSR params failed: {e}")))?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let csr = params
        .serialize_request(&key_pair)
        .map_err(|e| AcmeError::Internal(format!("CSR serialise failed: {e}")))?;
    Ok((csr.der().to_vec(), key_pair.serialize_pem()))
}

/// Persist the ACME account credentials JSON to `path`. Permissions
/// are tightened to `0600` on UNIX so the disk copy isn't world-
/// readable next to the cert PEMs. Idempotent: replaces any
/// existing file.
pub async fn persist_account(
    credentials: &AccountCredentials,
    path: &Path,
) -> Result<(), AcmeError> {
    if let Some(dir) = path.parent() {
        tokio::fs::create_dir_all(dir)
            .await
            .map_err(|e| AcmeError::Persistence(format!("create dir {dir:?}: {e}")))?;
    }
    let body = serde_json::to_vec_pretty(credentials)
        .map_err(|e| AcmeError::Persistence(format!("serialise account: {e}")))?;
    tokio::fs::write(path, &body)
        .await
        .map_err(|e| AcmeError::Persistence(format!("write {path:?}: {e}")))?;
    tighten_perms(path).await?;
    Ok(())
}

/// Load + deserialise an `AccountCredentials` JSON file.
pub async fn load_account(path: &Path) -> Result<Account, AcmeError> {
    let bytes = tokio::fs::read(path)
        .await
        .map_err(|e| AcmeError::Persistence(format!("read {path:?}: {e}")))?;
    let creds: AccountCredentials = serde_json::from_slice(&bytes)
        .map_err(|e| AcmeError::Persistence(format!("parse account creds: {e}")))?;
    let builder = Account::builder().map_err(|e| AcmeError::Network(e.to_string()))?;
    builder
        .from_credentials(creds)
        .await
        .map_err(|e| AcmeError::Network(e.to_string()))
}

async fn tighten_perms(path: &Path) -> Result<(), AcmeError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        tokio::fs::set_permissions(path, perms)
            .await
            .map_err(|e| AcmeError::Persistence(format!("chmod {path:?}: {e}")))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Persist an issued cert chain + private key to disk under
/// `cert_dir/{primary_domain}/{cert,key}.pem`.
pub async fn persist_issued(
    cert_dir: &Path,
    domains: &[String],
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<PathBuf, AcmeError> {
    let primary = domains
        .first()
        .ok_or_else(|| AcmeError::Persistence("no domains".into()))?;
    let dir = cert_dir.join(safe_domain_label(primary));
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|e| AcmeError::Persistence(format!("create {dir:?}: {e}")))?;
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    tokio::fs::write(&cert_path, cert_pem)
        .await
        .map_err(|e| AcmeError::Persistence(format!("write cert: {e}")))?;
    tokio::fs::write(&key_path, key_pem)
        .await
        .map_err(|e| AcmeError::Persistence(format!("write key: {e}")))?;
    tighten_perms(&key_path).await?;
    Ok(dir)
}

/// Strip path-separator + reserved characters from a domain name
/// before using it as a directory label. ACME identifiers are
/// already DNS-clean but a wildcard like `*.example.com` would
/// fail on Windows without the substitution.
fn safe_domain_label(domain: &str) -> String {
    domain
        .chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            other => other,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_csr_round_trips_for_single_domain() {
        let (der, pem) = build_csr(&["example.com".to_string()]).unwrap();
        assert!(!der.is_empty(), "CSR DER must not be empty");
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn build_csr_supports_san_list() {
        let (der, _key) = build_csr(&[
            "example.com".to_string(),
            "www.example.com".to_string(),
        ])
        .unwrap();
        assert!(der.len() > 50);
    }

    #[test]
    fn build_csr_rejects_empty_domain_list() {
        let err = build_csr(&[]).unwrap_err();
        assert!(matches!(err, AcmeError::Config(_)));
    }

    #[test]
    fn safe_domain_label_strips_path_separators() {
        assert_eq!(safe_domain_label("example.com"), "example.com");
        assert_eq!(safe_domain_label("*.example.com"), "_.example.com");
        assert_eq!(safe_domain_label("path/escape"), "path_escape");
        assert_eq!(safe_domain_label("c:bad"), "c_bad");
    }

    #[test]
    fn map_status_round_trip_for_every_variant() {
        assert_eq!(map_status(OrderStatus::Pending), OrderState::Pending);
        assert_eq!(map_status(OrderStatus::Ready), OrderState::Ready);
        assert_eq!(map_status(OrderStatus::Processing), OrderState::Processing);
        assert_eq!(map_status(OrderStatus::Valid), OrderState::Valid);
        assert_eq!(map_status(OrderStatus::Invalid), OrderState::Invalid);
    }

    // Note: `pick_http01_challenge` works on
    // `Authorization { challenges: Vec<Challenge>, … }`, but
    // `instant_acme::ChallengeStatus` isn't re-exported from the
    // crate root in 0.7.x — we can't construct a `Challenge`
    // literal in our tests. Behaviour is exercised end-to-end
    // by the integration suite that runs against Pebble (the
    // local ACME staging CA). The selector logic itself is
    // four lines so the cost of skipping a unit assertion is low.

    #[tokio::test]
    async fn persist_issued_writes_pem_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = persist_issued(
            dir.path(),
            &["example.com".to_string()],
            b"-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
            b"-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n",
        )
        .await
        .unwrap();
        let cert_pem = tokio::fs::read(path.join("cert.pem")).await.unwrap();
        let key_pem = tokio::fs::read(path.join("key.pem")).await.unwrap();
        assert!(cert_pem.starts_with(b"-----BEGIN CERTIFICATE"));
        assert!(key_pem.starts_with(b"-----BEGIN PRIVATE KEY"));
    }

    #[tokio::test]
    async fn persist_issued_uses_safe_label_for_wildcard_domain() {
        let dir = tempfile::tempdir().unwrap();
        let path = persist_issued(
            dir.path(),
            &["*.example.com".to_string()],
            b"cert",
            b"key",
        )
        .await
        .unwrap();
        let final_segment = path.file_name().unwrap().to_str().unwrap();
        assert_eq!(final_segment, "_.example.com");
    }

    #[tokio::test]
    async fn persist_issued_creates_parent_directory_if_missing() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("nested").join("certs");
        let path = persist_issued(
            &nested,
            &["example.com".to_string()],
            b"cert",
            b"key",
        )
        .await
        .unwrap();
        assert!(path.exists());
        assert!(path.join("cert.pem").exists());
    }

    #[test]
    fn identifier_label_extracts_dns_value() {
        assert_eq!(
            identifier_label(&Identifier::Dns("example.com".into())),
            "example.com",
        );
    }

    #[test]
    fn collect_contact_uris_borrows_from_config() {
        let cfg = AcmeConfig {
            contacts: vec![
                "mailto:ops@example.com".into(),
                "mailto:sec@example.com".into(),
            ],
            ..AcmeConfig::default()
        };
        let v = collect_contact_uris(&cfg);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0], "mailto:ops@example.com");
    }
}
