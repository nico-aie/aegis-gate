//! MTLS-T6 — sliding-window per-identity tracker for the
//! `/api/mtls/connections` and `/api/mtls/failures` endpoints.
//!
//! Sibling to [`aegis_security::risk::RiskTracker`] in shape:
//! a `DashMap<key, entry>` keyed by the identity principal
//! (SAN for `mtls`, URI for `spiffe`, `"anonymous"` for the
//! catch-all). Each entry holds a sliding count + per-decision
//! breakdown + last-seen timestamp. Idle entries are reaped on
//! a bounded interval to keep the map size in check.
//!
//! This module is **wired but not populated** in the MTLS-T6
//! slice — `record_request` exists but no caller invokes it
//! until MTLS-T3 lands the identity-extraction stage. Same
//! applies to `record_failure` (wired by MTLS-T2). The endpoint
//! handlers serve empty `[]` until then; the dashboard page
//! gracefully renders an empty state.
//!
//! ## CA bundle parsing
//!
//! `CaSummary` parses the operator-supplied PEM bundle once at
//! boot (and on hot-reload via MTLS-T5) to surface
//! subject + fingerprint + expiry without ever exposing the raw
//! PEM bytes to the dashboard. Operators can validate the bundle
//! BEFORE flipping `mode: required` — useful for catching typos
//! in `cfg.tls.client_auth.ca_bundle` paths.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use rustls_pemfile;
use serde::Serialize;

/// Default sliding window — last hour of activity.
const DEFAULT_WINDOW: Duration = Duration::from_secs(3600);

/// Idle-entry sweep interval. Bounded so the hot path pays at
/// most one mutex try-lock per request when the sweep gate
/// fires; otherwise zero overhead.
const IDLE_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Size cap for the failures `DashMap`. Reasons are
/// `&'static str` keys so the cap is really a uniqueness check;
/// in practice we expect ≤ 8 distinct reasons.
const MAX_FAILURE_REASONS: usize = 32;

// ---------------------------------------------------------------------------
// IdentityTracker
// ---------------------------------------------------------------------------

/// Live tracker for client-identity activity surfaced by the
/// `/api/mtls/*` endpoints.
///
/// Cheap to clone — internals are `Arc`. Hot-path
/// `record_request` is wait-free per-key (DashMap shard) +
/// atomic counters on the entry; no global mutex.
#[derive(Clone)]
pub struct IdentityTracker {
    inner: Arc<Inner>,
}

struct Inner {
    /// Principal key → activity entry. Key is the
    /// `ClientIdentity::principal()` string; for `Anonymous`
    /// the key is the literal `"anonymous"` so the row is
    /// visible to operators (often the most-asked question is
    /// "how much traffic still has no cert?").
    by_principal: DashMap<String, IdentityEntry>,
    /// Per-reason handshake-failure counters. `&'static str`
    /// keys come from a small enum-derived set —
    /// `unknown_ca`, `expired`, `revoked`, `san_not_allowed`,
    /// `bad_signature`, `chain_invalid`, `other`.
    failures: DashMap<&'static str, FailureEntry>,
    /// Parsed CA bundle metadata. `None` until the boot path
    /// (or MTLS-T5 hot-reload) feeds in
    /// `cfg.tls.client_auth.ca_bundle`. Wrapped in ArcSwap so
    /// the `/api/mtls/ca-summary` endpoint reads atomically.
    ca_summary: ArcSwap<Option<CaSummary>>,
    /// Sliding-window length. Snapshots return only entries
    /// touched within this duration. Default
    /// [`DEFAULT_WINDOW`] = 1 h.
    window: Duration,
    /// Last sweep tick. Bounded by [`IDLE_SWEEP_INTERVAL`].
    last_sweep: parking_lot::Mutex<Instant>,
}

#[derive(Debug)]
struct IdentityEntry {
    last_seen: parking_lot::Mutex<Instant>,
    request_count: AtomicU64,
    /// Per-decision counters. Keys come from `Action::as_str`
    /// (`allow`, `block`, `challenge`, `rate_limit`, `timeout`,
    /// `circuit_breaker`).
    decisions: DashMap<&'static str, AtomicU64>,
    /// Identity kind (`mtls` / `spiffe` / `anonymous`) — the
    /// stable label from `ClientIdentity::kind()`. Captured on
    /// first record so the snapshot can report it without the
    /// caller re-supplying it.
    kind: &'static str,
}

#[derive(Debug)]
struct FailureEntry {
    last_seen: parking_lot::Mutex<Instant>,
    count: AtomicU64,
}

impl IdentityTracker {
    /// Empty tracker with default 1-hour window.
    pub fn new() -> Self {
        Self::with_window(DEFAULT_WINDOW)
    }

    /// Tracker with a custom sliding-window duration. Useful
    /// for tests that want deterministic eviction.
    pub fn with_window(window: Duration) -> Self {
        Self {
            inner: Arc::new(Inner {
                by_principal: DashMap::new(),
                failures: DashMap::new(),
                ca_summary: ArcSwap::from_pointee(None),
                window,
                last_sweep: parking_lot::Mutex::new(Instant::now()),
            }),
        }
    }

    /// Record a request keyed by the identity principal +
    /// kind, with the contract decision label. **Hot path** —
    /// O(1) wait-free per shard.
    pub fn record_request(
        &self,
        principal: &str,
        kind: &'static str,
        decision_label: &'static str,
    ) {
        self.record_request_at(
            principal,
            kind,
            decision_label,
            Instant::now(),
        )
    }

    /// Test seam — drives the clock from the caller.
    pub fn record_request_at(
        &self,
        principal: &str,
        kind: &'static str,
        decision_label: &'static str,
        now: Instant,
    ) {
        {
            let entry = self
                .inner
                .by_principal
                .entry(principal.to_string())
                .or_insert_with(|| IdentityEntry {
                    last_seen: parking_lot::Mutex::new(now),
                    request_count: AtomicU64::new(0),
                    decisions: DashMap::new(),
                    kind,
                });
            entry.request_count.fetch_add(1, Ordering::Relaxed);
            *entry.last_seen.lock() = now;
            // Drop the entry's per-decision dashmap ref before
            // the outer entry guard drops to avoid the
            // borrow-overlap clippy/borrowck flagged.
            let dec = entry
                .decisions
                .entry(decision_label)
                .or_insert_with(|| AtomicU64::new(0));
            dec.fetch_add(1, Ordering::Relaxed);
        }
        self.maybe_sweep(now);
    }

    /// Record a TLS handshake failure. **Hot path** when the
    /// rustls layer rejects a client cert. `reason` is one of
    /// the small set of `&'static str` constants exported by
    /// `aegis_proxy::listener::tls_policy::failure_reason` (or
    /// the equivalent — the contract is "stable label").
    pub fn record_failure(&self, reason: &'static str) {
        self.record_failure_at(reason, Instant::now())
    }

    /// Test seam.
    pub fn record_failure_at(&self, reason: &'static str, now: Instant) {
        if self.inner.failures.len() >= MAX_FAILURE_REASONS
            && !self.inner.failures.contains_key(reason)
        {
            // Cap reached — drop the new reason. Prevents an
            // operator-supplied error string (if ever wired)
            // from blowing up memory.
            return;
        }
        let entry = self.inner.failures.entry(reason).or_insert_with(|| {
            FailureEntry {
                last_seen: parking_lot::Mutex::new(now),
                count: AtomicU64::new(0),
            }
        });
        entry.count.fetch_add(1, Ordering::Relaxed);
        *entry.last_seen.lock() = now;
    }

    /// Set / replace the CA bundle summary. Called by the boot
    /// path with the parsed cert metadata so the
    /// `/api/mtls/ca-summary` endpoint can serve operators
    /// even before MTLS-T2's rustls wiring lands. Hot-reload
    /// (MTLS-T5) will re-parse + call this.
    pub fn set_ca_summary(&self, summary: Option<CaSummary>) {
        self.inner.ca_summary.store(Arc::new(summary));
    }

    /// Snapshot every identity that's seen activity within the
    /// sliding window. Sorted by `request_count` descending so
    /// the busiest callers float to the top of the dashboard
    /// table.
    pub fn snapshot_connections(&self) -> Vec<IdentitySnapshot> {
        self.snapshot_connections_at(Instant::now())
    }

    /// Test seam.
    pub fn snapshot_connections_at(&self, now: Instant) -> Vec<IdentitySnapshot> {
        let cutoff = now.checked_sub(self.inner.window).unwrap_or(now);
        let mut out: Vec<IdentitySnapshot> = self
            .inner
            .by_principal
            .iter()
            .filter_map(|kv| {
                let last_seen = *kv.value().last_seen.lock();
                if last_seen < cutoff {
                    return None;
                }
                let decisions: std::collections::BTreeMap<String, u64> = kv
                    .value()
                    .decisions
                    .iter()
                    .map(|d| (d.key().to_string(), d.value().load(Ordering::Relaxed)))
                    .collect();
                Some(IdentitySnapshot {
                    principal: kv.key().clone(),
                    kind: kv.value().kind.to_string(),
                    request_count: kv
                        .value()
                        .request_count
                        .load(Ordering::Relaxed),
                    last_seen_ms: last_seen_to_unix_ms(last_seen, now),
                    decisions,
                })
            })
            .collect();
        out.sort_by(|a, b| b.request_count.cmp(&a.request_count));
        out
    }

    /// Snapshot the per-reason handshake-failure counts.
    pub fn snapshot_failures(&self) -> Vec<FailureSnapshot> {
        self.snapshot_failures_at(Instant::now())
    }

    pub fn snapshot_failures_at(&self, now: Instant) -> Vec<FailureSnapshot> {
        let cutoff = now.checked_sub(self.inner.window).unwrap_or(now);
        let mut out: Vec<FailureSnapshot> = self
            .inner
            .failures
            .iter()
            .filter_map(|kv| {
                let last_seen = *kv.value().last_seen.lock();
                if last_seen < cutoff {
                    return None;
                }
                Some(FailureSnapshot {
                    reason: kv.key().to_string(),
                    count: kv.value().count.load(Ordering::Relaxed),
                    last_seen_ms: last_seen_to_unix_ms(last_seen, now),
                })
            })
            .collect();
        out.sort_by(|a, b| b.count.cmp(&a.count));
        out
    }

    /// Returns the latest CA summary set via [`Self::set_ca_summary`].
    pub fn ca_summary(&self) -> Option<CaSummary> {
        (**self.inner.ca_summary.load()).clone()
    }

    /// Sliding-window length the snapshots filter against.
    pub fn window_seconds(&self) -> u64 {
        self.inner.window.as_secs()
    }

    /// Drop entries idle for more than `2 × window`. Bounded
    /// to one sweep per [`IDLE_SWEEP_INTERVAL`] — the hot
    /// path pays one try-lock when the gate fires, zero when
    /// it doesn't.
    fn maybe_sweep(&self, now: Instant) {
        let mut guard = match self.inner.last_sweep.try_lock() {
            Some(g) => g,
            None => return,
        };
        if now.saturating_duration_since(*guard) < IDLE_SWEEP_INTERVAL {
            return;
        }
        *guard = now;
        drop(guard);

        let stale_after = self.inner.window * 2;
        self.inner.by_principal.retain(|_, entry| {
            now.saturating_duration_since(*entry.last_seen.lock()) < stale_after
        });
        self.inner.failures.retain(|_, entry| {
            now.saturating_duration_since(*entry.last_seen.lock()) < stale_after
        });
    }
}

impl Default for IdentityTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Snapshot DTOs (serde)
// ---------------------------------------------------------------------------

/// Per-identity snapshot row. Serialised into the
/// `/api/mtls/connections` response.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct IdentitySnapshot {
    pub principal: String,
    pub kind: String,
    pub request_count: u64,
    pub last_seen_ms: i64,
    pub decisions: std::collections::BTreeMap<String, u64>,
}

/// Per-reason handshake-failure snapshot.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FailureSnapshot {
    pub reason: String,
    pub count: u64,
    pub last_seen_ms: i64,
}

// ---------------------------------------------------------------------------
// CA bundle summary
// ---------------------------------------------------------------------------

/// Summary of the operator-supplied CA bundle, served by the
/// `/api/mtls/ca-summary` endpoint. Carries only metadata —
/// **never the raw PEM bytes**. Operators can validate paths,
/// expiry, and subject names without compromising the
/// trust-anchor secret.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CaSummary {
    pub bundle_path: String,
    pub last_loaded_ms: i64,
    pub certificates: Vec<CaCertSummary>,
}

/// Per-cert metadata entry within a `CaSummary`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CaCertSummary {
    pub subject: String,
    pub fingerprint_sha256: String,
    pub not_before_ms: i64,
    pub not_after_ms: i64,
    pub days_until_expiry: i64,
}

/// Errors from [`parse_ca_bundle`].
#[derive(Debug)]
pub enum CaParseError {
    Io(std::io::Error),
    NoCerts,
    Parse(String),
}

impl std::fmt::Display for CaParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "ca bundle io: {e}"),
            Self::NoCerts => write!(f, "ca bundle contained no certificates"),
            Self::Parse(m) => write!(f, "ca bundle parse: {m}"),
        }
    }
}

impl std::error::Error for CaParseError {}

/// Parse the CA bundle PEM file at `path` into a [`CaSummary`].
/// Pure function — usable from tests with a temp PEM file.
pub fn parse_ca_bundle(path: &Path) -> Result<CaSummary, CaParseError> {
    let pem = std::fs::read(path).map_err(CaParseError::Io)?;
    let certificates = parse_ca_bundle_bytes(&pem)?;
    Ok(CaSummary {
        bundle_path: path.display().to_string(),
        last_loaded_ms: Utc::now().timestamp_millis(),
        certificates,
    })
}

/// Parse PEM cert bytes (a file's contents, or in-memory PEM
/// materialized from the config plane) into per-cert metadata
/// summaries. Public material only — never touches private keys.
/// Shared by [`parse_ca_bundle`] (file path) and the Zero Trust
/// upstream-identity view (state-source in-memory PEM, P4).
pub fn parse_ca_bundle_bytes(pem: &[u8]) -> Result<Vec<CaCertSummary>, CaParseError> {
    use std::io::BufReader;
    use x509_parser::prelude::FromDer;

    let mut reader = BufReader::new(pem);
    let der_certs: Vec<rustls_pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(CaParseError::Io)?;
    if der_certs.is_empty() {
        return Err(CaParseError::NoCerts);
    }

    let now = Utc::now();
    let mut out = Vec::with_capacity(der_certs.len());
    for der in &der_certs {
        let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(der)
            .map_err(|e| CaParseError::Parse(format!("{e}")))?;
        let subject = parsed.subject().to_string();
        let not_before_ms = parsed.validity().not_before.timestamp() * 1000;
        let not_after_ms = parsed.validity().not_after.timestamp() * 1000;
        let not_after_dt =
            DateTime::<Utc>::from_timestamp(parsed.validity().not_after.timestamp(), 0)
                .unwrap_or(now);
        let days_until_expiry = (not_after_dt - now).num_days();

        // SHA-256 fingerprint of the cert DER, hex-encoded
        // colon-separated to match the openssl convention.
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(der.as_ref());
        let digest = hasher.finalize();
        let fingerprint_sha256 = digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":");

        out.push(CaCertSummary {
            subject,
            fingerprint_sha256,
            not_before_ms,
            not_after_ms,
            days_until_expiry,
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/// Convert a monotonic `Instant` to a unix-ms timestamp by
/// subtracting from the wall-clock now. Snapshots are read at
/// dashboard refresh rate so the small drift is fine.
fn last_seen_to_unix_ms(last_seen: Instant, now: Instant) -> i64 {
    let elapsed = now.saturating_duration_since(last_seen);
    let now_ms = Utc::now().timestamp_millis();
    now_ms - elapsed.as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tracker_returns_empty_snapshots() {
        let t = IdentityTracker::new();
        assert!(t.snapshot_connections().is_empty());
        assert!(t.snapshot_failures().is_empty());
        assert!(t.ca_summary().is_none());
    }

    #[test]
    fn record_request_increments_count_and_decision() {
        let t = IdentityTracker::new();
        t.record_request("admin@aegis.local", "mtls", "allow");
        t.record_request("admin@aegis.local", "mtls", "allow");
        t.record_request("admin@aegis.local", "mtls", "block");

        let snap = t.snapshot_connections();
        assert_eq!(snap.len(), 1);
        let row = &snap[0];
        assert_eq!(row.principal, "admin@aegis.local");
        assert_eq!(row.kind, "mtls");
        assert_eq!(row.request_count, 3);
        assert_eq!(row.decisions.get("allow"), Some(&2));
        assert_eq!(row.decisions.get("block"), Some(&1));
    }

    #[test]
    fn snapshot_sorted_by_request_count_desc() {
        let t = IdentityTracker::new();
        for _ in 0..3 {
            t.record_request("alice", "mtls", "allow");
        }
        for _ in 0..7 {
            t.record_request("bob", "mtls", "allow");
        }
        for _ in 0..1 {
            t.record_request("anonymous", "anonymous", "allow");
        }
        let snap = t.snapshot_connections();
        assert_eq!(snap.len(), 3);
        assert_eq!(snap[0].principal, "bob");
        assert_eq!(snap[1].principal, "alice");
        assert_eq!(snap[2].principal, "anonymous");
    }

    #[test]
    fn entries_outside_window_filtered_out() {
        // 1-second window — old entries fall off.
        let t = IdentityTracker::with_window(Duration::from_secs(1));
        let now = Instant::now();
        let stale = now - Duration::from_secs(10);
        t.record_request_at("old", "mtls", "allow", stale);
        t.record_request_at("new", "mtls", "allow", now);

        let snap = t.snapshot_connections_at(now);
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].principal, "new");
    }

    #[test]
    fn record_failure_aggregates_per_reason() {
        let t = IdentityTracker::new();
        t.record_failure("unknown_ca");
        t.record_failure("unknown_ca");
        t.record_failure("expired");

        let snap = t.snapshot_failures();
        assert_eq!(snap.len(), 2);
        // Sorted by count desc.
        assert_eq!(snap[0].reason, "unknown_ca");
        assert_eq!(snap[0].count, 2);
        assert_eq!(snap[1].reason, "expired");
        assert_eq!(snap[1].count, 1);
    }

    #[test]
    fn record_failure_caps_reason_count() {
        let t = IdentityTracker::new();
        // First, fill to cap.
        let reasons: Vec<&'static str> = (0..MAX_FAILURE_REASONS)
            .map(|i| Box::leak(format!("reason-{i}").into_boxed_str()) as &'static str)
            .collect();
        for r in &reasons {
            t.record_failure(r);
        }
        // One more reason — should be dropped.
        t.record_failure("overflow_reason");
        let snap = t.snapshot_failures();
        assert!(
            !snap.iter().any(|s| s.reason == "overflow_reason"),
            "overflow reason should not be tracked when cap reached",
        );
    }

    #[test]
    fn set_ca_summary_round_trip() {
        let t = IdentityTracker::new();
        let summary = CaSummary {
            bundle_path: "/etc/aegis/ca.pem".into(),
            last_loaded_ms: 1234,
            certificates: vec![CaCertSummary {
                subject: "CN=Test".into(),
                fingerprint_sha256: "ab:cd".into(),
                not_before_ms: 0,
                not_after_ms: 1_000_000,
                days_until_expiry: 365,
            }],
        };
        t.set_ca_summary(Some(summary.clone()));
        assert_eq!(t.ca_summary(), Some(summary));
    }

    #[test]
    fn set_ca_summary_clears_with_none() {
        let t = IdentityTracker::new();
        t.set_ca_summary(Some(CaSummary {
            bundle_path: "p".into(),
            last_loaded_ms: 0,
            certificates: vec![],
        }));
        assert!(t.ca_summary().is_some());
        t.set_ca_summary(None);
        assert!(t.ca_summary().is_none());
    }

    #[test]
    fn parse_ca_bundle_extracts_subject_and_fingerprint() {
        use std::io::Write;
        // Self-signed cert via rcgen — same pattern as the
        // existing TLS tests.
        let mut params = rcgen::CertificateParams::new(vec!["test.example.com".to_string()])
            .unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let pem = cert.pem();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(pem.as_bytes()).unwrap();
        f.sync_all().unwrap();

        let summary = parse_ca_bundle(&path).unwrap();
        assert_eq!(summary.bundle_path, path.display().to_string());
        assert_eq!(summary.certificates.len(), 1);
        let c = &summary.certificates[0];
        assert!(!c.subject.is_empty());
        // SHA-256 fingerprint is 32 bytes → 64 hex chars + 31
        // colons = 95 characters.
        assert_eq!(c.fingerprint_sha256.len(), 95);
    }

    #[test]
    fn parse_ca_bundle_rejects_empty_pem() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.pem");
        std::fs::File::create(&path)
            .unwrap()
            .write_all(b"")
            .unwrap();
        let err = parse_ca_bundle(&path).unwrap_err();
        assert!(matches!(err, CaParseError::NoCerts));
    }

    #[test]
    fn parse_ca_bundle_io_error_for_missing_file() {
        let err = parse_ca_bundle(Path::new("/nonexistent/path/ca.pem")).unwrap_err();
        assert!(matches!(err, CaParseError::Io(_)));
    }

    #[test]
    fn cheap_clone_shares_state() {
        let t = IdentityTracker::new();
        let t2 = t.clone();
        t.record_request("alice", "mtls", "allow");
        // Clone observes the same state.
        let snap = t2.snapshot_connections();
        assert_eq!(snap.len(), 1);
    }
}
