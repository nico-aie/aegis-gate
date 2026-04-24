use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;

use aegis_core::audit::{AuditBus, AuditClass, AuditEvent};
use aegis_core::config::{load_config, WafConfig};

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

/// Spawn a background task that watches `path` for changes and hot-reloads the
/// configuration into `cfg` via atomic swap.
///
/// On successful reload an `AuditClass::Admin` event is emitted on the bus.
/// On failure the old config is kept and the error is logged + emitted.
pub fn spawn_config_watcher(
    path: PathBuf,
    cfg: Arc<ArcSwap<WafConfig>>,
    bus: AuditBus,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = watch_loop(path, cfg, bus).await {
            tracing::error!("config watcher exited with error: {e}");
        }
    })
}

async fn watch_loop(
    path: PathBuf,
    cfg: Arc<ArcSwap<WafConfig>>,
    bus: AuditBus,
) -> aegis_core::Result<()> {
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

    tracing::info!("config watcher started on {}", path.display());

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
        if !matches!(
            event.kind,
            EventKind::Modify(_) | EventKind::Create(_)
        ) {
            continue;
        }

        // Small debounce — editors may trigger multiple events.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        tracing::info!("config file changed, reloading…");

        match load_config(&path) {
            Ok(new_cfg) => {
                cfg.store(Arc::new(new_cfg));
                tracing::info!("config reloaded successfully");
                bus.emit(AuditEvent {
                    schema_version: 1,
                    ts: chrono::Utc::now(),
                    request_id: String::new(),
                    class: AuditClass::Admin,
                    tenant_id: None,
                    tier: None,
                    action: "config_reload".into(),
                    reason: "file changed".into(),
                    client_ip: String::new(),
                    route_id: None,
                    rule_id: None,
                    risk_score: None,
                    fields: serde_json::json!({"path": path.display().to_string()}),
                });
            }
            Err(e) => {
                tracing::error!("config reload failed, keeping previous config: {e}");
                bus.emit(AuditEvent {
                    schema_version: 1,
                    ts: chrono::Utc::now(),
                    request_id: String::new(),
                    class: AuditClass::Admin,
                    tenant_id: None,
                    tier: None,
                    action: "config_reload_failed".into(),
                    reason: format!("{e}"),
                    client_ip: String::new(),
                    route_id: None,
                    rule_id: None,
                    risk_score: None,
                    fields: serde_json::json!({"path": path.display().to_string()}),
                });
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[tokio::test]
    async fn reload_on_file_change() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("waf.yaml");
        std::fs::write(&config_path, minimal_yaml()).unwrap();

        let initial = load_config(&config_path).unwrap();
        let cfg = Arc::new(ArcSwap::from_pointee(initial));
        let bus = AuditBus::new(16);
        let mut rx = bus.subscribe();

        let handle = spawn_config_watcher(config_path.clone(), cfg.clone(), bus);

        // Give watcher time to register.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Mutate the file (change the bind address).
        let updated = minimal_yaml().replace("127.0.0.1:8080", "127.0.0.1:8888");
        {
            let mut f = std::fs::File::create(&config_path).unwrap();
            f.write_all(updated.as_bytes()).unwrap();
            f.sync_all().unwrap();
        }

        // Wait for reload.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let loaded = cfg.load();
        assert_eq!(
            loaded.listeners.data[0].bind,
            "127.0.0.1:8888".parse().unwrap(),
        );

        // Should have received an audit event.
        let ev = rx.try_recv().unwrap();
        assert!(matches!(ev.class, AuditClass::Admin));
        assert_eq!(ev.action, "config_reload");

        handle.abort();
    }

    #[tokio::test]
    async fn bad_config_keeps_old() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("waf.yaml");
        std::fs::write(&config_path, minimal_yaml()).unwrap();

        let initial = load_config(&config_path).unwrap();
        let original_bind = initial.listeners.data[0].bind;
        let cfg = Arc::new(ArcSwap::from_pointee(initial));
        let bus = AuditBus::new(16);
        let mut rx = bus.subscribe();

        let handle = spawn_config_watcher(config_path.clone(), cfg.clone(), bus);
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Drain any spurious events from watcher startup.
        while rx.try_recv().is_ok() {}

        // Write invalid YAML.
        {
            let mut f = std::fs::File::create(&config_path).unwrap();
            f.write_all(b"not: [valid: yaml: config").unwrap();
            f.sync_all().unwrap();
        }

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        // Config should be unchanged.
        let loaded = cfg.load();
        assert_eq!(loaded.listeners.data[0].bind, original_bind);

        // Should have a failure event (find it among any events).
        let mut found_failure = false;
        while let Ok(ev) = rx.try_recv() {
            if ev.action == "config_reload_failed" {
                assert!(matches!(ev.class, AuditClass::Admin));
                found_failure = true;
                break;
            }
        }
        assert!(found_failure, "expected config_reload_failed audit event");

        handle.abort();
    }

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
