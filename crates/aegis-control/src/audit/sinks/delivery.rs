//! PE-2 (committee round-2 🔴3) — per-sink audit delivery accounting.
//!
//! Each running sink task (jsonl persist, syslog forwarder) registers
//! a [`SinkDeliveryHandle`] under its [`sink_key`] and records batch
//! outcomes. `/api/cold-tier` joins the configured sink list against
//! [`DeliveryRegistry::snapshot`] so operators see real
//! delivered/error counters and last-success timestamps instead of
//! the old hardcoded `delivery: "unknown"`.
//!
//! The registry is deliberately tiny: sinks are operator-configured
//! (a handful per node), so a `Mutex<HashMap>` keyed by destination
//! is plenty. Counters are relaxed atomics — this is an ops signal,
//! not an ordering-sensitive ledger.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use aegis_core::config::AuditSinkConfig;

/// Live counters for one running sink task.
#[derive(Default)]
pub struct SinkDeliveryHandle {
    delivered: AtomicU64,
    errors: AtomicU64,
    /// Unix millis of the last successful write; 0 = never.
    last_success_ms: AtomicU64,
    /// Unix millis of the last failed write; 0 = never.
    last_error_ms: AtomicU64,
}

impl SinkDeliveryHandle {
    /// Record a successful flush of `events` events.
    pub fn record_success(&self, events: u64) {
        self.delivered.fetch_add(events, Ordering::Relaxed);
        self.last_success_ms.store(now_ms(), Ordering::Relaxed);
    }

    /// Record a failed flush (the batch was dropped for this sink).
    pub fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
        self.last_error_ms.store(now_ms(), Ordering::Relaxed);
    }
}

/// Point-in-time view of one sink's counters.
#[derive(Clone, Debug)]
pub struct DeliverySnapshot {
    pub delivered: u64,
    pub errors: u64,
    pub last_success: Option<chrono::DateTime<chrono::Utc>>,
    pub last_error: Option<chrono::DateTime<chrono::Utc>>,
}

impl DeliverySnapshot {
    fn from_handle(h: &SinkDeliveryHandle) -> Self {
        Self {
            delivered: h.delivered.load(Ordering::Relaxed),
            errors: h.errors.load(Ordering::Relaxed),
            last_success: ms_to_ts(h.last_success_ms.load(Ordering::Relaxed)),
            last_error: ms_to_ts(h.last_error_ms.load(Ordering::Relaxed)),
        }
    }

    /// Raw millis view, used by the renderer to order the last
    /// success vs the last error without re-parsing timestamps.
    pub fn last_success_ms(&self) -> u64 {
        self.last_success
            .map(|t| t.timestamp_millis().max(0) as u64)
            .unwrap_or(0)
    }

    pub fn last_error_ms(&self) -> u64 {
        self.last_error
            .map(|t| t.timestamp_millis().max(0) as u64)
            .unwrap_or(0)
    }
}

/// Registry of running sink tasks, keyed by [`sink_key`].
#[derive(Default)]
pub struct DeliveryRegistry {
    inner: Mutex<HashMap<String, Arc<SinkDeliveryHandle>>>,
}

impl DeliveryRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Process-wide registry the production sink tasks record into.
    pub fn global() -> &'static DeliveryRegistry {
        static GLOBAL: OnceLock<DeliveryRegistry> = OnceLock::new();
        GLOBAL.get_or_init(DeliveryRegistry::new)
    }

    /// Get-or-create the handle for `key`. Called once per sink at
    /// task spawn; cheap enough to call per-flush too.
    pub fn handle(&self, key: impl Into<String>) -> Arc<SinkDeliveryHandle> {
        let mut map = self.inner.lock().expect("delivery registry poisoned");
        Arc::clone(map.entry(key.into()).or_default())
    }

    pub fn snapshot(&self) -> HashMap<String, DeliverySnapshot> {
        let map = self.inner.lock().expect("delivery registry poisoned");
        map.iter()
            .map(|(k, h)| (k.clone(), DeliverySnapshot::from_handle(h)))
            .collect()
    }
}

/// Canonical registry key for a configured sink. Sink tasks and the
/// `/api/cold-tier` renderer must agree on this string — that's why
/// the per-kind helpers below exist for tasks that only know their
/// own destination, not the full `AuditSinkConfig`.
pub fn sink_key(cfg: &AuditSinkConfig) -> String {
    match cfg {
        AuditSinkConfig::Jsonl { path, .. } => jsonl_key(path),
        AuditSinkConfig::Syslog { address, .. } => syslog_key(address),
        AuditSinkConfig::Splunk { endpoint, .. } => format!("splunk:{endpoint}"),
        AuditSinkConfig::Kafka { brokers, topic } => {
            format!("kafka:{}/{topic}", brokers.join(","))
        }
    }
}

pub fn jsonl_key(path: &std::path::Path) -> String {
    format!("jsonl:{}", path.display())
}

pub fn syslog_key(address: &str) -> String {
    format!("syslog:{address}")
}

fn now_ms() -> u64 {
    chrono::Utc::now().timestamp_millis().max(0) as u64
}

fn ms_to_ts(ms: u64) -> Option<chrono::DateTime<chrono::Utc>> {
    if ms == 0 {
        return None;
    }
    chrono::DateTime::from_timestamp_millis(ms as i64)
}
