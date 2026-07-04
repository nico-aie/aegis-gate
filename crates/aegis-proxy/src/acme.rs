//! ACME / Let's Encrypt automation (P5 of the security-toggle plan).
//!
//! # Architecture
//!
//! Three pieces, designed so the network-talking provider is the
//! only async / impure component:
//!
//! 1. [`AcmeProvider`] — async trait abstracting the directory
//!    interactions (account registration, order placement,
//!    challenge response, certificate download). Exists so the
//!    state machine can be exhaustively tested against a mock
//!    provider and the real `instant-acme` impl can land as one
//!    drop-in struct.
//! 2. [`AcmeManager`] — pure state machine that walks an
//!    [`OrderState`] from `Pending` to `Valid` (or `Invalid`),
//!    drives the [`AcmeProvider`], and persists the issued
//!    certificate via the [`CertWriter`] callback.
//! 3. [`ChallengeStore`] — `Arc<ArcSwap<HashMap<token, key_auth>>>`
//!    consulted by the proxy's force-https listener so it can
//!    serve `/.well-known/acme-challenge/{token}` while continuing
//!    to redirect every other request.
//!
//! # Where the network impl lives
//!
//! This module ships the state machine + a mock provider that is
//! exercised end-to-end in tests. The concrete `instant-acme`-backed
//! [`AcmeProvider`] lives in `acme_instant.rs` and is wired at boot
//! (`run.rs`) — the "P5-network follow-up" this doc once promised
//! has shipped.
//!
//! Why split that way: the state machine is the high-leverage
//! correctness surface (renewal scheduling, challenge cleanup,
//! audit-chain interaction). The network impl is a thin adapter
//! over `instant-acme`'s API, and adding it here would couple the
//! tests to network availability.


use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Static configuration mirror of `aegis_core::config::AcmeConfig`.
/// Re-exported here so tests don't need a full `WafConfig`.
#[derive(Debug, Clone)]
pub struct AcmeConfig {
    pub directory_url: String,
    pub contacts: Vec<String>,
    pub domains: Vec<String>,
    pub account_key_path: PathBuf,
    pub cert_dir: PathBuf,
    pub renew_before: Duration,
    pub terms_of_service_agreed: bool,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            directory_url: "https://acme-v02.api.letsencrypt.org/directory".into(),
            contacts: Vec::new(),
            domains: Vec::new(),
            account_key_path: PathBuf::from("/var/lib/aegis/acme.key"),
            cert_dir: PathBuf::from("/var/lib/aegis/certs"),
            renew_before: Duration::from_secs(30 * 24 * 3600),
            terms_of_service_agreed: false,
        }
    }
}

impl AcmeConfig {
    /// Build from the cross-crate `aegis_core::config::AcmeConfig`.
    pub fn from_core(cfg: &aegis_core::config::AcmeConfig) -> Self {
        Self {
            directory_url: cfg.directory_url.clone(),
            contacts: cfg.contacts.clone(),
            domains: cfg.domains.clone(),
            account_key_path: cfg.account_key_path.clone(),
            cert_dir: cfg.cert_dir.clone(),
            renew_before: cfg.renew_before,
            terms_of_service_agreed: cfg.terms_of_service_agreed,
        }
    }
}

/// State of an ACME order — mirrors RFC 8555 §7.1.6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderState {
    /// Order accepted; challenges issued and pending.
    Pending,
    /// All authorisations satisfied; ready to finalise (CSR upload).
    Ready,
    /// Finalisation in progress.
    Processing,
    /// Certificate issued and downloadable.
    Valid,
    /// Order or any authorisation failed permanently.
    Invalid,
}

impl OrderState {
    /// Order is in a terminal state.
    pub fn is_terminal(self) -> bool {
        matches!(self, OrderState::Valid | OrderState::Invalid)
    }
}

/// Token + key-authorization for an HTTP-01 challenge. Per RFC
/// 8555 §8.3, the key authorization is `token + "." + thumbprint`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http01Challenge {
    pub token: String,
    pub key_authorization: String,
}

impl Http01Challenge {
    /// Well-known path the ACME server will probe.
    pub fn path(&self) -> String {
        format!("/.well-known/acme-challenge/{}", self.token)
    }
}

/// One issued cert ready for the [`CertStore`] hot-reload path.
#[derive(Debug, Clone)]
pub struct IssuedCert {
    pub domains: Vec<String>,
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
}

/// Errors produced by [`AcmeProvider`] and [`AcmeManager`].
#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    #[error("acme network error: {0}")]
    Network(String),
    #[error("acme directory rejected: {0}")]
    Rejected(String),
    #[error("challenge {token} failed validation: {reason}")]
    ChallengeFailed { token: String, reason: String },
    #[error("order timed out in state {0:?}")]
    Timeout(OrderState),
    #[error("cert persistence failed: {0}")]
    Persistence(String),
    #[error("invalid configuration: {0}")]
    Config(String),
    /// Programmer error — invariant violation that shouldn't be
    /// reachable in production. Use sparingly; prefer the more
    /// specific variants when they fit.
    #[error("acme internal: {0}")]
    Internal(String),
}

/// Async provider trait. The real implementation wraps
/// `instant-acme`; tests use [`MockProvider`].
#[async_trait]
pub trait AcmeProvider: Send + Sync {
    /// Register or load the ACME account corresponding to
    /// `cfg.account_key_path`. Idempotent.
    async fn register_account(&self, cfg: &AcmeConfig) -> Result<(), AcmeError>;

    /// Place a new order for the given domains. Returns the
    /// HTTP-01 challenges for each authorisation.
    async fn place_order(
        &self,
        cfg: &AcmeConfig,
        domains: &[String],
    ) -> Result<Vec<Http01Challenge>, AcmeError>;

    /// Tell the directory to validate the published challenges
    /// and wait for the order to leave the `Pending` state.
    async fn await_validation(&self, cfg: &AcmeConfig) -> Result<OrderState, AcmeError>;

    /// Finalise the order with a CSR built from the existing
    /// account key and download the issued certificate.
    async fn finalize_and_download(
        &self,
        cfg: &AcmeConfig,
        domains: &[String],
    ) -> Result<IssuedCert, AcmeError>;
}

/// In-memory store of currently active HTTP-01 challenges.
/// Cheap to clone (Arc-shared). The force-https listener holds a
/// clone and consults it on every request.
#[derive(Clone, Default)]
pub struct ChallengeStore {
    inner: Arc<ArcSwap<HashMap<String, String>>>,
}

impl ChallengeStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up `key_authorization` for a given token. `None` means
    /// the proxy should redirect (or 404) instead of serving a
    /// challenge response.
    pub fn lookup(&self, token: &str) -> Option<String> {
        self.inner.load().get(token).cloned()
    }

    /// Insert one challenge. Atomic — the rebuilt map is published
    /// via `ArcSwap::store`.
    pub fn insert(&self, token: String, key_authorization: String) {
        let mut next = (**self.inner.load()).clone();
        next.insert(token, key_authorization);
        self.inner.store(Arc::new(next));
    }

    /// Bulk insert.
    pub fn insert_many(&self, challenges: &[Http01Challenge]) {
        let mut next = (**self.inner.load()).clone();
        for c in challenges {
            next.insert(c.token.clone(), c.key_authorization.clone());
        }
        self.inner.store(Arc::new(next));
    }

    /// Remove tokens matching the provided slice. Used after the
    /// directory finishes validating the order so we don't leak
    /// challenge entries to unrelated probes.
    pub fn remove_many(&self, tokens: &[String]) {
        let mut next = (**self.inner.load()).clone();
        for t in tokens {
            next.remove(t);
        }
        self.inner.store(Arc::new(next));
    }

    /// Number of active challenges — exposed for metrics.
    pub fn len(&self) -> usize {
        self.inner.load().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.load().is_empty()
    }
}

/// Receives an [`IssuedCert`] from the manager. Production wires
/// this to the existing `Arc<ArcSwap<CertStore>>` swap; tests
/// capture the value into a `Vec`.
pub type CertWriter = Arc<dyn Fn(IssuedCert) -> Result<(), AcmeError> + Send + Sync>;

/// Producer of "what certs do we currently have on disk" — used
/// by the renewal scheduler to decide whether to re-issue. Each
/// entry is the PEM bytes of one certificate file.
pub type CertInventory = Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>;

/// Pure state machine. Delegates network calls to [`AcmeProvider`]
/// and challenge publication to [`ChallengeStore`].
pub struct AcmeManager {
    config: AcmeConfig,
    provider: Arc<dyn AcmeProvider>,
    challenges: ChallengeStore,
    cert_writer: CertWriter,
}

impl AcmeManager {
    pub fn new(
        config: AcmeConfig,
        provider: Arc<dyn AcmeProvider>,
        challenges: ChallengeStore,
        cert_writer: CertWriter,
    ) -> Self {
        Self {
            config,
            provider,
            challenges,
            cert_writer,
        }
    }

    /// Run one full issuance cycle: register → order → publish
    /// challenges → wait → finalise → persist. Idempotent for
    /// `register_account`. Cleans up published challenges in both
    /// success and failure paths so the store doesn't leak.
    pub async fn issue(&self) -> Result<IssuedCert, AcmeError> {
        if self.config.domains.is_empty() {
            return Err(AcmeError::Config("no domains configured".into()));
        }
        self.provider.register_account(&self.config).await?;
        let challenges = self
            .provider
            .place_order(&self.config, &self.config.domains)
            .await?;
        self.challenges.insert_many(&challenges);
        let tokens: Vec<String> = challenges.iter().map(|c| c.token.clone()).collect();

        // Validation + finalisation. If any step errors, still
        // strip the challenges from the store before propagating.
        let outcome = async {
            let state = self.provider.await_validation(&self.config).await?;
            if state != OrderState::Ready && state != OrderState::Valid {
                return Err(AcmeError::Timeout(state));
            }
            let issued = self
                .provider
                .finalize_and_download(&self.config, &self.config.domains)
                .await?;
            (self.cert_writer)(issued.clone())?;
            Ok(issued)
        }
        .await;
        self.challenges.remove_many(&tokens);
        outcome
    }

    /// Decide whether the cert at `cert_pem` should be renewed
    /// against the configured `renew_before`. Returns `true` for
    /// missing / unparseable certs (fail-open: better to over-renew
    /// than to silently expire).
    pub fn needs_renewal(&self, cert_pem: &[u8], now: chrono::DateTime<chrono::Utc>) -> bool {
        match cert_not_after(cert_pem) {
            Some(not_after) => {
                let renew_at = not_after - chrono::Duration::from_std(self.config.renew_before)
                    .unwrap_or(chrono::Duration::zero());
                now >= renew_at
            }
            None => true,
        }
    }

    pub fn challenges(&self) -> ChallengeStore {
        self.challenges.clone()
    }

    pub fn config(&self) -> &AcmeConfig {
        &self.config
    }
}

/// Spawn a background task that periodically inspects every cert
/// returned by `inventory` and re-issues whenever any of them is
/// within `cfg.renew_before` of expiry. Returns the join handle
/// so the caller can detach (typical) or hold for shutdown.
///
/// The scheduler runs at half the renew window, capped at one
/// hour — checking once a day on a 30-day window is plenty, and
/// checking every minute is wasteful. Errors from `manager.issue`
/// are logged but don't stop the loop; transient ACME outages
/// shouldn't disable the scheduler.
pub fn spawn_renewal_scheduler(
    manager: Arc<AcmeManager>,
    inventory: CertInventory,
) -> tokio::task::JoinHandle<()> {
    let interval = renewal_check_interval(manager.config().renew_before);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await; // absorb the immediate first tick
        loop {
            ticker.tick().await;
            let now = chrono::Utc::now();
            let certs = inventory();
            let any_due = certs.iter().any(|pem| manager.needs_renewal(pem, now));
            if any_due {
                if let Err(e) = manager.issue().await {
                    tracing::warn!(error = %e, "acme renewal failed; will retry next cycle");
                } else {
                    tracing::info!("acme renewal succeeded");
                }
            }
        }
    })
}

/// Half the renew window, clamped to `[60s, 3600s]`. Pulled out
/// for unit tests — callers don't need it directly.
pub fn renewal_check_interval(renew_before: Duration) -> Duration {
    let half = renew_before / 2;
    half.clamp(Duration::from_secs(60), Duration::from_secs(3600))
}

/// Parse the first certificate from PEM and return its `notAfter`
/// timestamp. `None` means the PEM is empty or unparseable.
///
/// Uses webpki's der parser via `x509-parser` would pull in another
/// crate; instead we lean on `rustls_pemfile` to extract the DER
/// and walk the SEQUENCE manually for `Validity.notAfter`. The
/// alternative — `webpki::EndEntityCert` — doesn't expose validity.
pub fn cert_not_after(pem_bytes: &[u8]) -> Option<chrono::DateTime<chrono::Utc>> {
    let mut reader = std::io::BufReader::new(pem_bytes);
    let der = rustls_pemfile::certs(&mut reader)
        .next()?
        .ok()?;
    parse_not_after_der(der.as_ref())
}

/// Extract the `notAfter` GeneralizedTime / UTCTime from an X.509
/// DER blob. Hand-rolled tag walker — ~30 lines and avoids
/// pulling in `x509-parser` for one field.
fn parse_not_after_der(der: &[u8]) -> Option<chrono::DateTime<chrono::Utc>> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    // tbsCertificate ::= SEQUENCE { version[0] EXPLICIT INTEGER DEFAULT v1,
    //                               serialNumber, signature, issuer,
    //                               validity, ... }
    // validity ::= SEQUENCE { notBefore Time, notAfter Time }
    let (cert_seq, _) = parse_der_sequence(der)?;
    let (tbs_seq, _) = parse_der_sequence(cert_seq)?;
    let mut cursor = tbs_seq;

    // Optional version tag [0].
    if cursor.first() == Some(&0xA0) {
        let (_, rest) = parse_der_tlv(cursor)?;
        cursor = rest;
    }
    // serialNumber INTEGER
    let (_, rest) = parse_der_tlv(cursor)?;
    cursor = rest;
    // signature SEQUENCE
    let (_, rest) = parse_der_tlv(cursor)?;
    cursor = rest;
    // issuer SEQUENCE
    let (_, rest) = parse_der_tlv(cursor)?;
    cursor = rest;
    // validity SEQUENCE
    let (validity, _) = parse_der_sequence(cursor)?;
    parse_validity_time(validity)
}

/// Walk validity := SEQUENCE { notBefore, notAfter } and return
/// the parsed `notAfter`.
fn parse_validity_time(validity: &[u8]) -> Option<chrono::DateTime<chrono::Utc>> {
    // first TLV = notBefore — skip
    let (_, rest) = parse_der_tlv(validity)?;
    // second TLV = notAfter
    parse_der_time(rest)
}

fn parse_der_time(input: &[u8]) -> Option<chrono::DateTime<chrono::Utc>> {
    let tag = *input.first()?;
    let (body, _) = parse_der_tlv(input)?;
    let s = std::str::from_utf8(body).ok()?;
    match tag {
        0x17 => {
            // UTCTime: YYMMDDHHMMSSZ
            if s.len() != 13 || !s.ends_with('Z') {
                return None;
            }
            let yy: i32 = s[..2].parse().ok()?;
            let year = if yy < 50 { 2000 + yy } else { 1900 + yy };
            parse_compact_time(year, &s[2..12])
        }
        0x18 => {
            // GeneralizedTime: YYYYMMDDHHMMSSZ
            if s.len() != 15 || !s.ends_with('Z') {
                return None;
            }
            let year: i32 = s[..4].parse().ok()?;
            parse_compact_time(year, &s[4..14])
        }
        _ => None,
    }
}

fn parse_compact_time(year: i32, mmddhhmmss: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    let mm: u32 = mmddhhmmss.get(0..2)?.parse().ok()?;
    let dd: u32 = mmddhhmmss.get(2..4)?.parse().ok()?;
    let hh: u32 = mmddhhmmss.get(4..6)?.parse().ok()?;
    let mi: u32 = mmddhhmmss.get(6..8)?.parse().ok()?;
    let ss: u32 = mmddhhmmss.get(8..10)?.parse().ok()?;
    let date = chrono::NaiveDate::from_ymd_opt(year, mm, dd)?;
    let time = chrono::NaiveTime::from_hms_opt(hh, mi, ss)?;
    Some(date.and_time(time).and_utc())
}

/// Parse a single DER TLV (tag-length-value). Returns `(value,
/// rest)` where `rest` is the bytes after the value.
fn parse_der_tlv(input: &[u8]) -> Option<(&[u8], &[u8])> {
    if input.len() < 2 {
        return None;
    }
    let len_byte = input[1];
    let (value_start, value_len) = if len_byte & 0x80 == 0 {
        (2, len_byte as usize)
    } else {
        let n = (len_byte & 0x7F) as usize;
        if n == 0 || input.len() < 2 + n {
            return None;
        }
        let mut len = 0usize;
        for &b in &input[2..2 + n] {
            len = (len << 8) | (b as usize);
        }
        (2 + n, len)
    };
    if input.len() < value_start + value_len {
        return None;
    }
    let value = &input[value_start..value_start + value_len];
    let rest = &input[value_start + value_len..];
    Some((value, rest))
}

/// Same as [`parse_der_tlv`] but assert the tag is SEQUENCE
/// (0x30). Returns `None` otherwise.
fn parse_der_sequence(input: &[u8]) -> Option<(&[u8], &[u8])> {
    if input.first() != Some(&0x30) {
        return None;
    }
    parse_der_tlv(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Mock provider — deterministic, in-memory. Records every
    /// call so tests can assert on the order and arguments.
    struct MockProvider {
        calls: Mutex<Vec<String>>,
        challenges: Mutex<Vec<Http01Challenge>>,
        await_state: Mutex<OrderState>,
        finalise_result: Mutex<Option<IssuedCert>>,
        register_err: Mutex<Option<AcmeError>>,
        place_err: Mutex<Option<AcmeError>>,
    }

    impl MockProvider {
        fn new() -> Arc<Self> {
            let m = Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                challenges: Mutex::new(Vec::new()),
                await_state: Mutex::new(OrderState::Ready),
                finalise_result: Mutex::new(None),
                register_err: Mutex::new(None),
                place_err: Mutex::new(None),
            });
            *m.finalise_result.lock().unwrap() = Some(IssuedCert {
                domains: vec!["example.com".into()],
                cert_pem: b"-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n".to_vec(),
                key_pem: b"-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n"
                    .to_vec(),
            });
            *m.challenges.lock().unwrap() = vec![Http01Challenge {
                token: "tok-1".into(),
                key_authorization: "tok-1.thumb".into(),
            }];
            m
        }
    }

    #[async_trait]
    impl AcmeProvider for MockProvider {
        async fn register_account(&self, _cfg: &AcmeConfig) -> Result<(), AcmeError> {
            self.calls.lock().unwrap().push("register".into());
            if let Some(e) = self.register_err.lock().unwrap().take() {
                return Err(e);
            }
            Ok(())
        }

        async fn place_order(
            &self,
            _cfg: &AcmeConfig,
            _domains: &[String],
        ) -> Result<Vec<Http01Challenge>, AcmeError> {
            self.calls.lock().unwrap().push("place_order".into());
            if let Some(e) = self.place_err.lock().unwrap().take() {
                return Err(e);
            }
            Ok(self.challenges.lock().unwrap().clone())
        }

        async fn await_validation(&self, _cfg: &AcmeConfig) -> Result<OrderState, AcmeError> {
            self.calls.lock().unwrap().push("await".into());
            Ok(*self.await_state.lock().unwrap())
        }

        async fn finalize_and_download(
            &self,
            _cfg: &AcmeConfig,
            _domains: &[String],
        ) -> Result<IssuedCert, AcmeError> {
            self.calls.lock().unwrap().push("finalize".into());
            self.finalise_result
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(|| AcmeError::Network("no fake cert".into()))
        }
    }

    fn cfg(domains: &[&str]) -> AcmeConfig {
        AcmeConfig {
            directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory".into(),
            contacts: vec!["ops@example.com".into()],
            domains: domains.iter().map(|s| s.to_string()).collect(),
            account_key_path: PathBuf::from("/tmp/aegis-test/acme.key"),
            cert_dir: PathBuf::from("/tmp/aegis-test/certs"),
            renew_before: Duration::from_secs(30 * 24 * 3600),
            terms_of_service_agreed: true,
        }
    }

    fn captured_writer() -> (CertWriter, Arc<Mutex<Vec<IssuedCert>>>) {
        let buf: Arc<Mutex<Vec<IssuedCert>>> = Arc::new(Mutex::new(Vec::new()));
        let buf_clone = Arc::clone(&buf);
        let writer: CertWriter = Arc::new(move |c| {
            buf_clone.lock().unwrap().push(c);
            Ok(())
        });
        (writer, buf)
    }

    // ---------- ChallengeStore --------------------------------------

    #[test]
    fn challenge_store_insert_and_lookup() {
        let s = ChallengeStore::new();
        s.insert("tok-1".into(), "tok-1.thumb".into());
        assert_eq!(s.lookup("tok-1"), Some("tok-1.thumb".into()));
        assert_eq!(s.lookup("nope"), None);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn challenge_store_remove_many() {
        let s = ChallengeStore::new();
        s.insert("a".into(), "av".into());
        s.insert("b".into(), "bv".into());
        s.remove_many(&["a".into()]);
        assert!(s.lookup("a").is_none());
        assert!(s.lookup("b").is_some());
    }

    #[test]
    fn challenge_store_insert_many() {
        let s = ChallengeStore::new();
        s.insert_many(&[
            Http01Challenge {
                token: "x".into(),
                key_authorization: "x.k".into(),
            },
            Http01Challenge {
                token: "y".into(),
                key_authorization: "y.k".into(),
            },
        ]);
        assert_eq!(s.len(), 2);
    }

    // ---------- OrderState ------------------------------------------

    #[test]
    fn order_state_terminal_set() {
        assert!(OrderState::Valid.is_terminal());
        assert!(OrderState::Invalid.is_terminal());
        assert!(!OrderState::Pending.is_terminal());
        assert!(!OrderState::Ready.is_terminal());
        assert!(!OrderState::Processing.is_terminal());
    }

    // ---------- AcmeManager.issue happy path ------------------------

    #[tokio::test]
    async fn issue_walks_full_order_and_persists_cert() {
        let provider = MockProvider::new();
        let (writer, captured) = captured_writer();
        let manager = AcmeManager::new(
            cfg(&["example.com"]),
            provider.clone(),
            ChallengeStore::new(),
            writer,
        );
        let issued = manager.issue().await.unwrap();
        assert_eq!(issued.domains, vec!["example.com".to_string()]);
        assert_eq!(captured.lock().unwrap().len(), 1);
        let calls = provider.calls.lock().unwrap().clone();
        assert_eq!(calls, vec!["register", "place_order", "await", "finalize"]);
    }

    #[tokio::test]
    async fn issue_publishes_challenges_during_validation_and_cleans_up() {
        let provider = MockProvider::new();
        let store = ChallengeStore::new();
        let (writer, _) = captured_writer();
        let manager = AcmeManager::new(
            cfg(&["example.com"]),
            provider,
            store.clone(),
            writer,
        );
        manager.issue().await.unwrap();
        // After a successful order the challenge map is empty
        // again — the proxy stops serving challenges once the
        // directory has finished probing.
        assert!(store.is_empty(), "challenge store leaked tokens");
    }

    // ---------- AcmeManager.issue error paths -----------------------

    #[tokio::test]
    async fn issue_rejects_when_no_domains_configured() {
        let provider = MockProvider::new();
        let (writer, _) = captured_writer();
        let manager =
            AcmeManager::new(cfg(&[]), provider, ChallengeStore::new(), writer);
        let err = manager.issue().await.unwrap_err();
        assert!(matches!(err, AcmeError::Config(_)));
    }

    #[tokio::test]
    async fn issue_propagates_register_error_without_placing_order() {
        let provider = MockProvider::new();
        *provider.register_err.lock().unwrap() =
            Some(AcmeError::Rejected("locked".into()));
        let (writer, captured) = captured_writer();
        let store = ChallengeStore::new();
        let manager = AcmeManager::new(
            cfg(&["example.com"]),
            provider.clone(),
            store.clone(),
            writer,
        );
        let err = manager.issue().await.unwrap_err();
        assert!(matches!(err, AcmeError::Rejected(_)));
        let calls = provider.calls.lock().unwrap().clone();
        assert_eq!(calls, vec!["register"]);
        assert!(captured.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn issue_cleans_challenges_on_validation_timeout() {
        let provider = MockProvider::new();
        *provider.await_state.lock().unwrap() = OrderState::Pending;
        let (writer, _) = captured_writer();
        let store = ChallengeStore::new();
        let manager = AcmeManager::new(
            cfg(&["example.com"]),
            provider,
            store.clone(),
            writer,
        );
        let err = manager.issue().await.unwrap_err();
        assert!(matches!(err, AcmeError::Timeout(OrderState::Pending)));
        // Even though the order failed, the published challenge
        // tokens were stripped from the store.
        assert!(store.is_empty(), "challenge store leaked on timeout");
    }

    // ---------- Renewal scheduling ----------------------------------

    fn self_signed_cert(days_valid: i64) -> Vec<u8> {
        // `rcgen` uses `time::OffsetDateTime` for validity. Compute
        // the "now" / "now + days" pair via the time crate to avoid
        // chrono ↔ time interop dependencies.
        use std::time::{SystemTime, UNIX_EPOCH};
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let mut params = rcgen::CertificateParams::new(vec!["example.com".into()]).unwrap();
        params.not_before = time::OffsetDateTime::from_unix_timestamp(now_secs).unwrap();
        params.not_after =
            time::OffsetDateTime::from_unix_timestamp(now_secs + days_valid * 86_400).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        cert.pem().into_bytes()
    }

    #[test]
    fn cert_not_after_round_trips_for_self_signed_cert() {
        let pem = self_signed_cert(365);
        let not_after = cert_not_after(&pem).expect("notAfter parses");
        let now = chrono::Utc::now();
        let days = (not_after - now).num_days();
        assert!((360..=370).contains(&days), "got {days} days");
    }

    #[test]
    fn cert_not_after_returns_none_for_garbage() {
        assert!(cert_not_after(b"").is_none());
        assert!(cert_not_after(b"not a pem").is_none());
    }

    #[test]
    fn needs_renewal_true_when_within_renew_before_window() {
        let provider = MockProvider::new();
        let (writer, _) = captured_writer();
        let mut config = cfg(&["example.com"]);
        config.renew_before = Duration::from_secs(60 * 24 * 3600); // 60d
        let manager =
            AcmeManager::new(config, provider, ChallengeStore::new(), writer);

        let pem = self_signed_cert(30); // expires in 30d
        let now = chrono::Utc::now();
        assert!(
            manager.needs_renewal(&pem, now),
            "30-day cert with 60-day window should be due"
        );
    }

    #[test]
    fn needs_renewal_false_when_outside_window() {
        let provider = MockProvider::new();
        let (writer, _) = captured_writer();
        let mut config = cfg(&["example.com"]);
        config.renew_before = Duration::from_secs(15 * 24 * 3600); // 15d
        let manager =
            AcmeManager::new(config, provider, ChallengeStore::new(), writer);

        let pem = self_signed_cert(60); // expires in 60d
        let now = chrono::Utc::now();
        assert!(
            !manager.needs_renewal(&pem, now),
            "60-day cert with 15-day window should not renew yet"
        );
    }

    #[test]
    fn needs_renewal_true_for_unparseable_cert() {
        let provider = MockProvider::new();
        let (writer, _) = captured_writer();
        let manager = AcmeManager::new(
            cfg(&["example.com"]),
            provider,
            ChallengeStore::new(),
            writer,
        );
        assert!(manager.needs_renewal(b"", chrono::Utc::now()));
    }

    // ---------- Http01Challenge -------------------------------------

    // ---------- Renewal scheduler interval ---------------------------

    #[test]
    fn renewal_check_interval_clamps_short_window_to_one_minute() {
        // 30s renew_before → half is 15s, clamped up to 60s.
        let i = renewal_check_interval(Duration::from_secs(30));
        assert_eq!(i, Duration::from_secs(60));
    }

    #[test]
    fn renewal_check_interval_clamps_long_window_to_one_hour() {
        // 30-day renew_before → half is 15 days, clamped down to 1h.
        let i = renewal_check_interval(Duration::from_secs(30 * 86_400));
        assert_eq!(i, Duration::from_secs(3600));
    }

    #[test]
    fn renewal_check_interval_returns_half_for_mid_range() {
        // 1h renew_before → half is 30 min — falls inside the band.
        let i = renewal_check_interval(Duration::from_secs(3600));
        assert_eq!(i, Duration::from_secs(1800));
    }

    #[test]
    fn http01_challenge_well_known_path() {
        let c = Http01Challenge {
            token: "xyz".into(),
            key_authorization: "xyz.thumb".into(),
        };
        assert_eq!(c.path(), "/.well-known/acme-challenge/xyz");
    }
}
