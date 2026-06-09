//! Upstream mTLS handshake / dial failure surface (P4).
//!
//! A process-global, bounded in-memory histogram of upstream
//! (WAF-as-client) handshake failures, grouped by `(pool, reason)`.
//! The data plane records here when `forward()` returns
//! `ForwardError::Handshake`; the Zero Trust console reads a snapshot
//! via `GET /api/zero-trust/upstream/failures`.
//!
//! Mirrors the downstream `identity_tracker` failure histogram but for
//! the opposite direction. A global singleton (like
//! `aegis_control::copilot::service::set_global`) is used so the data
//! plane can record without threading a new `Arc` through
//! `ProxyContext` → `DashboardServices` → the request handler.
//!
//! Reasons are a best-effort classification of the rustls/hyper error
//! string — an observability hint, not a contract.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Cap on distinct `(pool, reason)` keys so a misbehaving backend (or
/// a flood of distinct error strings) can't grow this unbounded.
const MAX_KEYS: usize = 256;

static TRACKER: OnceLock<UpstreamMtlsFailureTracker> = OnceLock::new();

/// Process-global tracker handle.
pub fn global() -> &'static UpstreamMtlsFailureTracker {
    TRACKER.get_or_init(UpstreamMtlsFailureTracker::new)
}

/// One `(pool, reason)` bucket.
#[derive(Clone, Debug)]
struct Bucket {
    count: u64,
    last_seen_ms: u64,
}

/// Bounded histogram of upstream mTLS handshake failures.
pub struct UpstreamMtlsFailureTracker {
    buckets: Mutex<HashMap<(String, String), Bucket>>,
}

impl Default for UpstreamMtlsFailureTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl UpstreamMtlsFailureTracker {
    pub fn new() -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Record one handshake failure for `pool`, classifying `err_msg`
    /// into a coarse reason. No-op (drops the sample) once `MAX_KEYS`
    /// distinct buckets exist and this is a new key — existing
    /// buckets keep counting.
    pub fn record(&self, pool: &str, err_msg: &str) {
        let reason = classify(err_msg);
        let now = now_ms();
        let mut g = match self.buckets.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let key = (pool.to_string(), reason.to_string());
        if let Some(b) = g.get_mut(&key) {
            b.count += 1;
            b.last_seen_ms = now;
        } else if g.len() < MAX_KEYS {
            g.insert(
                key,
                Bucket {
                    count: 1,
                    last_seen_ms: now,
                },
            );
        }
    }

    /// Snapshot every bucket as JSON-ready rows, sorted by descending
    /// count then pool name. Stable for the dashboard.
    pub fn snapshot(&self) -> Vec<FailureRow> {
        let g = match self.buckets.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let mut rows: Vec<FailureRow> = g
            .iter()
            .map(|((pool, reason), b)| FailureRow {
                pool: pool.clone(),
                reason: reason.clone(),
                count: b.count,
                last_seen_ms: b.last_seen_ms,
            })
            .collect();
        rows.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.pool.cmp(&b.pool)));
        rows
    }

    /// Total failures across all buckets — for a headline count.
    pub fn total(&self) -> u64 {
        let g = match self.buckets.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        g.values().map(|b| b.count).sum()
    }

    #[cfg(test)]
    fn clear(&self) {
        self.buckets.lock().unwrap().clear();
    }
}

/// JSON-ready failure row for the read endpoint.
#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub struct FailureRow {
    pub pool: String,
    pub reason: String,
    pub count: u64,
    pub last_seen_ms: u64,
}

/// Render the snapshot as the `/api/zero-trust/upstream/failures` body.
pub fn render() -> String {
    let rows = global().snapshot();
    let body = serde_json::json!({
        "total": global().total(),
        "failures": rows,
    });
    body.to_string()
}

/// Coarse classification of a rustls/hyper handshake error string into
/// a stable reason code for the dashboard. Best-effort.
pub fn classify(err_msg: &str) -> &'static str {
    let m = err_msg.to_ascii_lowercase();
    if m.contains("expired") || m.contains("certexpired") {
        "cert_expired"
    } else if m.contains("notvalidforname") || m.contains("not valid for name") {
        "san_mismatch"
    } else if m.contains("unknownissuer")
        || m.contains("unknown issuer")
        || m.contains("invalid peer certificate")
        || m.contains("unable to get local issuer")
    {
        "untrusted_backend_cert"
    } else if m.contains("client cert")
        || m.contains("client_cert")
        || m.contains("client key")
        || m.contains("client_key")
        || m.contains("private key")
    {
        "client_identity_error"
    } else {
        "handshake_failed"
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_maps_known_reasons() {
        assert_eq!(classify("invalid peer certificate: UnknownIssuer"), "untrusted_backend_cert");
        assert_eq!(classify("invalid peer certificate: Expired"), "cert_expired");
        assert_eq!(classify("invalid peer certificate: NotValidForName"), "san_mismatch");
        assert_eq!(
            classify("upstream_mtls client cert: file not found"),
            "client_identity_error"
        );
        assert_eq!(classify("connection reset by peer"), "handshake_failed");
    }

    #[test]
    fn record_aggregates_per_pool_reason_and_snapshots_sorted() {
        let t = UpstreamMtlsFailureTracker::new();
        t.record("payments", "invalid peer certificate: UnknownIssuer");
        t.record("payments", "invalid peer certificate: UnknownIssuer");
        t.record("search", "invalid peer certificate: Expired");
        let rows = t.snapshot();
        assert_eq!(rows.len(), 2);
        // Highest count first.
        assert_eq!(rows[0].pool, "payments");
        assert_eq!(rows[0].reason, "untrusted_backend_cert");
        assert_eq!(rows[0].count, 2);
        assert_eq!(t.total(), 3);
    }

    #[test]
    fn bucket_cap_bounds_distinct_keys() {
        let t = UpstreamMtlsFailureTracker::new();
        for i in 0..(MAX_KEYS + 50) {
            t.record(&format!("pool-{i}"), "handshake_failed boom");
        }
        assert_eq!(t.snapshot().len(), MAX_KEYS);
    }

    #[test]
    fn global_singleton_is_stable() {
        global().clear();
        global().record("api", "invalid peer certificate: UnknownIssuer");
        assert_eq!(global().total(), 1);
        global().clear();
    }
}
