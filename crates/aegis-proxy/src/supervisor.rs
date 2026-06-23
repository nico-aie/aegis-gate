use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;

use aegis_core::audit::{AuditBus, AuditClass, AuditEvent};
use aegis_core::config::load_config;

use crate::config_source::config_store::{Activate, ConfigStore};

// ─────────────────── In-Flight Tracker ─────────────────────────

/// Tracks the number of in-flight requests for graceful drain.
#[derive(Debug)]
pub struct InFlightTracker {
    count: AtomicUsize,
    draining: AtomicBool,
}

impl InFlightTracker {
    pub fn new() -> Self {
        Self {
            count: AtomicUsize::new(0),
            draining: AtomicBool::new(false),
        }
    }

    /// Increment the in-flight count. Returns `false` if draining (reject new work).
    pub fn acquire(&self) -> bool {
        if self.draining.load(Ordering::Acquire) {
            return false;
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Decrement the in-flight count.
    pub fn release(&self) {
        self.count.fetch_sub(1, Ordering::Relaxed);
    }

    /// Current in-flight count.
    pub fn in_flight(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }

    /// Enter drain mode — stop accepting new requests.
    pub fn start_drain(&self) {
        self.draining.store(true, Ordering::Release);
    }

    /// Whether we are draining.
    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }
}

impl Default for InFlightTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Handle for coordinating graceful drain.
pub struct DrainHandle {
    tracker: Arc<InFlightTracker>,
    drain_timeout: Duration,
}

impl DrainHandle {
    pub fn new(tracker: Arc<InFlightTracker>, drain_timeout: Duration) -> Self {
        Self {
            tracker,
            drain_timeout,
        }
    }

    /// Initiate graceful drain: stop accepting, wait for in-flight to reach 0,
    /// or timeout. Returns the number of requests that were still in-flight
    /// when the timeout expired (0 = clean drain).
    pub async fn drain(&self) -> usize {
        self.tracker.start_drain();
        tracing::info!("drain started, waiting up to {:?}", self.drain_timeout);

        let deadline = tokio::time::Instant::now() + self.drain_timeout;
        let mut interval = tokio::time::interval(Duration::from_millis(50));

        loop {
            interval.tick().await;
            let remaining = self.tracker.in_flight();
            if remaining == 0 {
                tracing::info!("drain complete, 0 in-flight");
                return 0;
            }
            if tokio::time::Instant::now() >= deadline {
                tracing::warn!("drain timeout, {remaining} requests still in-flight");
                return remaining;
            }
        }
    }
}

// ─────────────────── Config file watcher (publisher) ─────────────────────────

/// Spawn the config-file watcher as a **publisher** into the versioned config
/// plane. On a file change it validates the new config and activates it as a
/// new `config:waf:doc` version; the shared-store watcher
/// ([`crate::config_source::redis_source`]) is the single applier that swaps it
/// into the live data plane. The file no longer writes the live config
/// directly — that removes the old file-vs-doc dual authority (a stray file
/// save could clobber API-applied state, and file-only sections went stale).
///
/// Only spawned when `config_plane.file_watch = publish` (the default); under
/// `off` the file is bootstrap-only and the caller skips this entirely.
pub fn spawn_config_watcher(
    path: PathBuf,
    store: ConfigStore,
    bus: AuditBus,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = watch_loop(path, store, bus).await {
            tracing::error!("config watcher exited with error: {e}");
        }
    })
}

/// Outcome of publishing a file change into the config plane. Returned so the
/// decision is unit-testable; the watcher only logs/audits it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PublishOutcome {
    /// Validated and activated a new config version.
    Published { version: u64 },
    /// File content is byte-identical to the active doc — nothing to publish.
    Unchanged,
    /// CAS lost: a peer (or an API edit) activated between our read and write.
    /// Log-and-converge — the shared-store watcher applies the winning version.
    Conflict { current: u64 },
    /// The new file failed validation; the active config is kept (NACK).
    Invalid,
    /// Reading the file or the store failed; the active config is kept.
    Error,
}

/// Validate the changed file and publish it into `config:waf:doc`. Kept free of
/// the notify/debounce plumbing so it can be unit-tested directly.
pub(crate) async fn publish_file_change(
    store: &ConfigStore,
    path: &Path,
    bus: &AuditBus,
) -> PublishOutcome {
    // Validate before publishing — a broken edit must never reach the doc.
    if let Err(e) = load_config(path) {
        tracing::error!("config file changed but failed validation, not publishing: {e}");
        emit_file_audit(bus, path, "config_reload_failed", format!("{e}"));
        return PublishOutcome::Invalid;
    }
    // Store the verbatim file text — the single validation surface the applier
    // re-parses, and it preserves `${secret:...}` refs for load-time resolution.
    let blob = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "config file unreadable after change");
            return PublishOutcome::Error;
        }
    };
    let current = match store.load().await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "config store read failed; keeping live config");
            return PublishOutcome::Error;
        }
    };
    if current.as_ref().map(|d| d.blob.as_str()) == Some(blob.as_str()) {
        tracing::debug!("config file unchanged vs active doc; skipping publish");
        return PublishOutcome::Unchanged;
    }
    let expected = current.as_ref().map(|d| d.version).unwrap_or(0);
    match store
        .activate(expected, blob, "file-watch", "file change")
        .await
    {
        Ok(Activate::Applied { version }) => {
            tracing::info!(version, "config file change published to the config plane");
            emit_file_audit(bus, path, "config_published", format!("published v{version}"));
            PublishOutcome::Published { version }
        }
        Ok(Activate::Conflict { current }) => {
            // Log-and-converge: a peer/API edit won the race; the shared-store
            // watcher will apply the winning version. We do not retry.
            tracing::info!(
                current,
                "config plane advanced concurrently; file publish stood down (will converge)",
            );
            PublishOutcome::Conflict { current }
        }
        Err(e) => {
            tracing::error!("config file publish failed, keeping live config: {e}");
            emit_file_audit(bus, path, "config_reload_failed", format!("{e}"));
            PublishOutcome::Error
        }
    }
}

fn emit_file_audit(bus: &AuditBus, path: &Path, action: &str, reason: String) {
    bus.emit(AuditEvent {
        schema_version: 1,
        ts: chrono::Utc::now(),
        request_id: String::new(),
        class: AuditClass::Admin,
        tenant_id: None,
        tier: None,
        action: action.into(),
        reason,
        client_ip: String::new(),
        route_id: None,
        rule_id: None,
        risk_score: None,
        method: None,
        path: None,
        mode: None,
        fields: serde_json::json!({"path": path.display().to_string(), "source": "file"}),
    });
}

async fn watch_loop(path: PathBuf, store: ConfigStore, bus: AuditBus) -> aegis_core::Result<()> {
    let (tx, mut rx) = mpsc::channel::<notify::Result<Event>>(64);

    let mut watcher = RecommendedWatcher::new(
        move |res| {
            let _ = tx.blocking_send(res);
        },
        notify::Config::default(),
    )
    .map_err(|e| aegis_core::WafError::Config(format!("watcher init: {e}")))?;

    watcher
        .watch(&path, RecursiveMode::NonRecursive)
        .map_err(|e| aegis_core::WafError::Config(format!("watcher start: {e}")))?;

    tracing::info!("config watcher (publisher) started on {}", path.display());

    // Keep watcher alive for the duration of this task.
    let _watcher = watcher;

    while let Some(event_result) = rx.recv().await {
        let event = match event_result {
            Ok(ev) => ev,
            Err(e) => {
                tracing::warn!("file watch error: {e}");
                continue;
            }
        };

        // Only react to content modifications.
        if !matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
            continue;
        }

        // Small debounce — editors may trigger multiple events.
        tokio::time::sleep(Duration::from_millis(100)).await;

        tracing::info!("config file changed, publishing to the config plane…");
        let _ = publish_file_change(&store, &path, &bus).await;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::in_memory::InMemoryBackend;
    use std::io::Write;

    fn minimal_yaml() -> String {
        r#"
listeners:
  data:
    - bind: "127.0.0.1:8080"
  admin:
    bind: "127.0.0.1:9090"
routes:
  - id: catch-all
    path: "/"
    upstream: default
upstreams:
  default:
    members:
      - addr: "127.0.0.1:3000"
state:
  backend: in_memory
"#
        .into()
    }

    fn test_store() -> ConfigStore {
        ConfigStore::new(Arc::new(InMemoryBackend::new()))
    }

    // ─── Config file watcher → publisher contract ───
    //
    // The file watcher now *publishes* into `config:waf:doc`; the shared-store
    // watcher is the sole applier. So these tests assert the publish decision,
    // not a live-handle swap — the apply behaviour (route table / TLS / rate
    // limit / risk / compliance) is covered at the applier layer in
    // `config_source::reload` + `config_source::redis_source`.

    #[tokio::test]
    async fn publish_activates_new_version_on_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("waf.yaml");
        std::fs::write(&path, minimal_yaml()).unwrap();
        let store = test_store();
        // Boot-seed: the file is already doc v1.
        store
            .activate(0, minimal_yaml(), "boot-seed", "seed")
            .await
            .unwrap();
        let bus = AuditBus::new(8);

        std::fs::write(&path, minimal_yaml().replace("127.0.0.1:8080", "127.0.0.1:8888")).unwrap();
        let outcome = publish_file_change(&store, &path, &bus).await;

        assert_eq!(outcome, PublishOutcome::Published { version: 2 });
        let doc = store.load().await.unwrap().unwrap();
        assert!(doc.blob.contains("127.0.0.1:8888"));
    }

    #[tokio::test]
    async fn publish_skips_when_file_matches_active_doc() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("waf.yaml");
        std::fs::write(&path, minimal_yaml()).unwrap();
        let store = test_store();
        store
            .activate(0, minimal_yaml(), "boot-seed", "seed")
            .await
            .unwrap();
        let bus = AuditBus::new(8);

        let outcome = publish_file_change(&store, &path, &bus).await;

        assert_eq!(outcome, PublishOutcome::Unchanged);
        assert_eq!(
            store.load().await.unwrap().unwrap().version,
            1,
            "byte-identical content must not bump the version",
        );
    }

    #[tokio::test]
    async fn publish_rejects_invalid_config_and_keeps_active() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("waf.yaml");
        std::fs::write(&path, minimal_yaml()).unwrap();
        let store = test_store();
        store
            .activate(0, minimal_yaml(), "boot-seed", "seed")
            .await
            .unwrap();
        let bus = AuditBus::new(8);
        let mut rx = bus.subscribe();

        // Valid YAML, but an unknown top-level key → `deny_unknown_fields` fails.
        std::fs::write(&path, "not_a_real_waf_field: 123\n").unwrap();
        let outcome = publish_file_change(&store, &path, &bus).await;

        assert_eq!(outcome, PublishOutcome::Invalid);
        assert_eq!(
            store.load().await.unwrap().unwrap().version,
            1,
            "an invalid file must not publish a new version",
        );
        let mut saw_failed = false;
        while let Ok(ev) = rx.try_recv() {
            if ev.action == "config_reload_failed" {
                saw_failed = true;
            }
        }
        assert!(saw_failed, "expected a config_reload_failed audit event");
    }

    #[tokio::test]
    async fn reload_on_file_change_publishes_new_version() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("waf.yaml");
        std::fs::write(&config_path, minimal_yaml()).unwrap();

        let store = test_store();
        store
            .activate(0, minimal_yaml(), "boot-seed", "seed")
            .await
            .unwrap();
        let bus = AuditBus::new(16);
        let mut rx = bus.subscribe();

        let handle = spawn_config_watcher(config_path.clone(), store.clone(), bus);

        // Give the watcher time to register.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Mutate the file (change the bind address).
        let updated = minimal_yaml().replace("127.0.0.1:8080", "127.0.0.1:8888");
        {
            let mut f = std::fs::File::create(&config_path).unwrap();
            f.write_all(updated.as_bytes()).unwrap();
            f.sync_all().unwrap();
        }

        // Wait for the debounced publish.
        tokio::time::sleep(Duration::from_secs(2)).await;

        let doc = store.load().await.unwrap().expect("doc present");
        assert_eq!(doc.version, 2, "a file change should publish a new version");
        assert!(doc.blob.contains("127.0.0.1:8888"));

        let mut saw_publish = false;
        while let Ok(ev) = rx.try_recv() {
            if ev.action == "config_published" {
                assert!(matches!(ev.class, AuditClass::Admin));
                saw_publish = true;
            }
        }
        assert!(saw_publish, "expected a config_published audit event");

        handle.abort();
    }

    // Note: the `Conflict` (CAS-loss) arm is a genuine race — a peer/API edit
    // activating between our read and CAS — with no deterministic single-thread
    // seam to drive it. The CAS itself is covered by
    // `config_store::tests::stale_expected_version_conflicts`; here it maps to a
    // log-and-converge no-op.

    // ─── In-flight tracker tests ───

    #[test]
    fn tracker_acquire_release() {
        let t = InFlightTracker::new();
        assert!(t.acquire());
        assert!(t.acquire());
        assert_eq!(t.in_flight(), 2);
        t.release();
        assert_eq!(t.in_flight(), 1);
        t.release();
        assert_eq!(t.in_flight(), 0);
    }

    #[test]
    fn tracker_rejects_during_drain() {
        let t = InFlightTracker::new();
        assert!(t.acquire());
        t.start_drain();
        assert!(t.is_draining());
        assert!(!t.acquire()); // rejected
        assert_eq!(t.in_flight(), 1); // existing request still counted
    }

    #[tokio::test]
    async fn drain_completes_when_empty() {
        let tracker = Arc::new(InFlightTracker::new());
        let handle = DrainHandle::new(tracker.clone(), Duration::from_secs(5));
        let remaining = handle.drain().await;
        assert_eq!(remaining, 0);
    }

    #[tokio::test]
    async fn drain_waits_for_inflight() {
        let tracker = Arc::new(InFlightTracker::new());
        tracker.acquire();
        tracker.acquire();

        let t2 = tracker.clone();
        // Simulate requests finishing after 100ms.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            t2.release();
            t2.release();
        });

        let handle = DrainHandle::new(tracker, Duration::from_secs(5));
        let remaining = handle.drain().await;
        assert_eq!(remaining, 0);
    }

    #[tokio::test]
    async fn drain_times_out() {
        let tracker = Arc::new(InFlightTracker::new());
        tracker.acquire(); // Never released.

        let handle = DrainHandle::new(tracker, Duration::from_millis(200));
        let remaining = handle.drain().await;
        assert_eq!(remaining, 1);
    }
}
