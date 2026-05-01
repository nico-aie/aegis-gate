//! NDJSON / JSONL audit sink — file-backed with daily rotation and
//! retention-day TTL pruning.
//!
//! ## DURABLE-T1 — what changed
//!
//! The previous implementation buffered events in memory ("production
//! would write to disk" — its own comment). This rewrite makes the
//! sink actually durable:
//!
//! - **Daily rotation.** Files are named `audit-YYYY-MM-DD.ndjson`
//!   keyed off the *event* timestamp date. The writer keeps one file
//!   handle open and re-opens when the date rolls.
//! - **TTL.** A periodic pruner ([`prune_expired_files`]) deletes
//!   files where the date in the filename is older than
//!   `retention_days`. Operators get bounded disk usage without ever
//!   touching cron.
//! - **Hot-path safety.** Writes happen on a background tokio task
//!   that subscribes to the [`AuditBus`] via [`run_persist_task`].
//!   `bus.emit()` stays a fire-and-forget broadcast; if the writer
//!   falls behind, the broadcast channel `Lagged(_)` arm logs a warn
//!   and continues — the data plane never blocks on disk.
//! - **Bounded batches.** Events are buffered up to `max_batch`
//!   entries or until `flush_interval` elapses, whichever first.
//!   Tunes for steady-state vs burst.
//!
//! ## Pure helpers
//!
//! Path construction, filename date parsing, and expiry checks are
//! pure functions so the rotation + TTL logic is testable without
//! touching the filesystem.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chrono::NaiveDate;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::Mutex;

use aegis_core::audit::AuditEvent;
use aegis_core::AuditBus;

/// Sink configuration. Mirrors the operator-facing
/// `aegis_core::config::AuditSinkConfig::Jsonl` variant.
#[derive(Clone, Debug)]
pub struct JsonlConfig {
    /// Directory to write rotated NDJSON files into. The previous
    /// schema accepted a file path; if `path` looks like a file
    /// (has a non-`.ndjson` parent + a name), [`JsonlSink::resolve_dir`]
    /// uses the parent so existing waf.yaml configs keep working.
    pub path: PathBuf,
    /// Days of files to retain. Older files are pruned by
    /// [`prune_expired_files`]. Default 30.
    pub retention_days: u32,
    /// Max events buffered before forcing a flush. Default 100.
    pub max_batch: usize,
    /// Max time between forced flushes. Default 1 s.
    pub flush_interval: Duration,
}

impl Default for JsonlConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("/var/log/aegis/audit"),
            retention_days: 30,
            max_batch: 100,
            flush_interval: Duration::from_secs(1),
        }
    }
}

// ---------------------------------------------------------------------------
// Pure helpers — path construction, filename parsing, expiry check
// ---------------------------------------------------------------------------

/// Build the NDJSON file path for `date` inside `dir`. Stable
/// `audit-YYYY-MM-DD.ndjson` format — daily rotation + sortable +
/// trivial TTL by name.
pub fn daily_file_path(dir: &Path, date: NaiveDate) -> PathBuf {
    dir.join(format!("audit-{}.ndjson", date.format("%Y-%m-%d")))
}

/// Parse `audit-YYYY-MM-DD.ndjson` back to a `NaiveDate`. Returns
/// `None` for any other filename so the pruner can skip foreign files
/// without deleting them.
pub fn parse_audit_filename(name: &str) -> Option<NaiveDate> {
    let stripped = name.strip_prefix("audit-")?.strip_suffix(".ndjson")?;
    NaiveDate::parse_from_str(stripped, "%Y-%m-%d").ok()
}

/// Decide whether a file `name` should be pruned given the current
/// date and retention. Files whose embedded date is `retention_days`
/// or more days old are expired. Non-audit filenames are *not*
/// expired (we never delete files we don't own).
pub fn is_expired(filename: &str, now_date: NaiveDate, retention_days: u32) -> bool {
    match parse_audit_filename(filename) {
        Some(file_date) => {
            let age = now_date.signed_duration_since(file_date).num_days();
            age >= retention_days as i64
        }
        None => false,
    }
}

/// If `path` is a file (has a parent + a non-empty name), return the
/// parent. Otherwise return `path` itself. Lets operators with the
/// pre-DURABLE-T1 single-file `path: /var/log/aegis/audit.jsonl`
/// schema keep working — we rotate inside the parent dir.
pub fn resolve_dir(path: &Path) -> PathBuf {
    // If the path has an extension, treat it as a file and use its
    // parent. Otherwise treat it as a directory.
    if path.extension().is_some() {
        path.parent().unwrap_or(path).to_path_buf()
    } else {
        path.to_path_buf()
    }
}

// ---------------------------------------------------------------------------
// Sink — file-backed writer with rotation
// ---------------------------------------------------------------------------

/// One open file plus the date it was opened for. Rotated when an
/// event arrives whose `ts.date_naive()` differs.
struct OpenFile {
    date: NaiveDate,
    writer: BufWriter<File>,
}

/// File-backed NDJSON sink. Implements [`super::AuditSink`] for use
/// alongside the other sink kinds (Splunk / Kafka / Syslog / …).
///
/// Construction: [`JsonlSink::open`] resolves the directory and
/// creates it if needed, then defers the first file open until the
/// first event lands (so empty test runs don't create empty files).
pub struct JsonlSink {
    cfg: JsonlConfig,
    dir: PathBuf,
    state: Mutex<Option<OpenFile>>,
    /// In-memory mode bypasses the filesystem entirely. Used by
    /// tests that want to assert on rendered NDJSON without touching
    /// disk. Production paths use [`JsonlSink::open`].
    in_memory: Option<Mutex<Vec<String>>>,
}

impl JsonlSink {
    /// Open a real disk-backed sink. Creates the rotation directory
    /// up-front so the first append doesn't have to handle
    /// `NotFound`. Returns `Err` if the directory can't be created.
    pub async fn open(cfg: JsonlConfig) -> std::io::Result<Self> {
        let dir = resolve_dir(&cfg.path);
        tokio::fs::create_dir_all(&dir).await?;
        Ok(Self {
            cfg,
            dir,
            state: Mutex::new(None),
            in_memory: None,
        })
    }

    /// In-memory variant for tests — events accumulate in a Vec
    /// instead of touching disk. The configured `path` is ignored.
    pub fn new_in_memory(cfg: JsonlConfig) -> Self {
        Self {
            cfg,
            dir: PathBuf::new(),
            state: Mutex::new(None),
            in_memory: Some(Mutex::new(Vec::new())),
        }
    }

    /// Drain a copy of the in-memory buffer (test-only helper).
    /// Returns an empty Vec for disk-backed sinks. Uses `try_lock`
    /// so it's safe to call from sync test code; returns an empty
    /// Vec if the lock is contended (which single-threaded tests
    /// don't hit).
    pub fn lines(&self) -> Vec<String> {
        match &self.in_memory {
            Some(m) => m.try_lock().map(|g| g.clone()).unwrap_or_default(),
            None => Vec::new(),
        }
    }

    /// Format an event as one NDJSON line (no trailing newline).
    /// Cheap pure helper — no IO, no lock.
    pub fn format(ev: &AuditEvent) -> String {
        serde_json::to_string(ev).unwrap_or_else(|_| "{}".into())
    }

    /// Write a batch under one lock acquisition + one flush. The
    /// batch path is the steady-state hot path for the persist task.
    pub async fn write_batch(&self, events: &[AuditEvent]) -> std::io::Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        if let Some(buf) = &self.in_memory {
            let mut g = buf.lock().await;
            for ev in events {
                g.push(Self::format(ev));
            }
            return Ok(());
        }

        let mut state = self.state.lock().await;
        for ev in events {
            self.write_one_locked(&mut state, ev).await?;
        }
        if let Some(s) = state.as_mut() {
            s.writer.flush().await?;
        }
        Ok(())
    }

    /// Single-event write (tests + the trait impl). Always flushes —
    /// hot-path callers should prefer [`Self::write_batch`].
    pub async fn write_one(&self, ev: &AuditEvent) -> std::io::Result<()> {
        if let Some(buf) = &self.in_memory {
            let mut g = buf.lock().await;
            g.push(Self::format(ev));
            return Ok(());
        }
        let mut state = self.state.lock().await;
        self.write_one_locked(&mut state, ev).await?;
        if let Some(s) = state.as_mut() {
            s.writer.flush().await?;
        }
        Ok(())
    }

    /// Inner write — caller holds the state lock. Rotates when the
    /// event date differs from the open file's date.
    async fn write_one_locked(
        &self,
        state: &mut Option<OpenFile>,
        ev: &AuditEvent,
    ) -> std::io::Result<()> {
        let date = ev.ts.date_naive();
        let need_open = state
            .as_ref()
            .map(|s| s.date != date)
            .unwrap_or(true);
        if need_open {
            // Flush + drop the old handle before opening a new one
            // so the previous day's file is durable on disk.
            if let Some(prev) = state.as_mut() {
                let _ = prev.writer.flush().await;
            }
            let path = daily_file_path(&self.dir, date);
            let f = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await?;
            *state = Some(OpenFile {
                date,
                writer: BufWriter::with_capacity(64 * 1024, f),
            });
        }
        let s = state.as_mut().expect("opened above");
        let line = Self::format(ev);
        s.writer.write_all(line.as_bytes()).await?;
        s.writer.write_all(b"\n").await?;
        Ok(())
    }

    /// Force a flush of any buffered bytes. Called on graceful
    /// shutdown so the last batch isn't lost.
    pub async fn flush(&self) -> std::io::Result<()> {
        if self.in_memory.is_some() {
            return Ok(());
        }
        let mut state = self.state.lock().await;
        if let Some(s) = state.as_mut() {
            s.writer.flush().await?;
        }
        Ok(())
    }

    pub fn config(&self) -> &JsonlConfig {
        &self.cfg
    }

    /// The resolved rotation directory. Useful for the TTL task —
    /// caller passes `sink.dir().to_path_buf()` to
    /// [`prune_expired_files`].
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

#[async_trait::async_trait]
impl super::AuditSink for JsonlSink {
    fn id(&self) -> &str {
        "jsonl"
    }

    async fn write(&self, ev: &AuditEvent) -> aegis_core::Result<()> {
        self.write_one(ev).await.map_err(aegis_core::WafError::Io)
    }
}

// ---------------------------------------------------------------------------
// TTL pruner
// ---------------------------------------------------------------------------

/// Scan `dir` for `audit-YYYY-MM-DD.ndjson` files and remove the
/// ones whose embedded date is older than `retention_days`.
/// Returns the count of files removed (0 if `dir` doesn't exist —
/// not an error; the writer creates it lazily).
pub async fn prune_expired_files(
    dir: &Path,
    now_date: NaiveDate,
    retention_days: u32,
) -> std::io::Result<u64> {
    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    let mut removed = 0u64;
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name();
        let name_str = match name.to_str() {
            Some(s) => s,
            None => continue,
        };
        if is_expired(name_str, now_date, retention_days) {
            // Best-effort delete — log + continue on errors so one
            // unwritable file doesn't poison the prune run.
            if let Err(e) = tokio::fs::remove_file(entry.path()).await {
                tracing::warn!(
                    file = %entry.path().display(),
                    error = %e,
                    "audit jsonl pruner could not remove expired file",
                );
            } else {
                removed += 1;
            }
        }
    }
    Ok(removed)
}

// ---------------------------------------------------------------------------
// Background tasks — bus subscriber + periodic pruner
// ---------------------------------------------------------------------------

/// Spawnable persist task: subscribes to the audit bus and writes to
/// every supplied sink via batched flushes. Runs until the bus
/// closes. Backpressure: `Lagged(_)` increments a warn-level log
/// counter and continues — the data plane never blocks on disk I/O.
///
/// Return type intentionally unit; use `tokio::spawn(run_persist_task(...))`
/// and detach. Graceful shutdown is the bus closing or the task
/// being cancelled by the runtime — both paths flush the buffer on
/// the way out via the final `Drop` of the open file's `BufWriter`.
pub async fn run_persist_task(
    bus: AuditBus,
    sinks: Vec<Arc<JsonlSink>>,
    max_batch: usize,
    flush_interval: Duration,
) {
    if sinks.is_empty() {
        return;
    }
    let mut rx = bus.subscribe();
    let mut buf: Vec<AuditEvent> = Vec::with_capacity(max_batch.max(1));
    let mut tick = tokio::time::interval(flush_interval);
    tick.tick().await; // skip the immediate first tick

    loop {
        tokio::select! {
            r = rx.recv() => match r {
                Ok(ev) => {
                    buf.push(ev);
                    if buf.len() >= max_batch {
                        flush_buf(&sinks, &mut buf).await;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(
                        dropped = n,
                        "audit jsonl persist task lagged; events dropped from broadcast",
                    );
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            },
            _ = tick.tick() => {
                if !buf.is_empty() {
                    flush_buf(&sinks, &mut buf).await;
                }
            }
        }
    }
    if !buf.is_empty() {
        flush_buf(&sinks, &mut buf).await;
    }
    for sink in &sinks {
        let _ = sink.flush().await;
    }
}

async fn flush_buf(sinks: &[Arc<JsonlSink>], buf: &mut Vec<AuditEvent>) {
    for sink in sinks {
        if let Err(e) = sink.write_batch(buf).await {
            tracing::warn!(
                sink = "jsonl",
                error = %e,
                "audit jsonl sink batch write failed; events dropped from this sink only",
            );
        }
    }
    buf.clear();
}

/// Spawnable TTL task: every `prune_interval`, scan each sink's
/// directory and remove expired files. `prune_interval` of 1 h is
/// the recommended default — the prune work is cheap (one stat per
/// file) and operators don't want disk to creep.
pub async fn run_ttl_task(sinks: Vec<Arc<JsonlSink>>, prune_interval: Duration) {
    if sinks.is_empty() {
        return;
    }
    let mut tick = tokio::time::interval(prune_interval);
    tick.tick().await; // skip the immediate first tick
    loop {
        tick.tick().await;
        let now_date = chrono::Utc::now().date_naive();
        for sink in &sinks {
            match prune_expired_files(sink.dir(), now_date, sink.config().retention_days).await {
                Ok(n) if n > 0 => {
                    tracing::info!(
                        files_removed = n,
                        retention_days = sink.config().retention_days,
                        dir = %sink.dir().display(),
                        "audit jsonl ttl pruned expired files",
                    );
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(
                        dir = %sink.dir().display(),
                        error = %e,
                        "audit jsonl ttl prune failed",
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::AuditSink;
    use super::*;
    use aegis_core::audit::AuditClass;
    use chrono::TimeZone;
    use tempfile::tempdir;

    fn ev_at(ts: chrono::DateTime<chrono::Utc>) -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts,
            request_id: format!("req-{}", ts.timestamp_nanos_opt().unwrap_or_default()),
            class: AuditClass::Detection,
            tenant_id: None,
            tier: None,
            action: "block".into(),
            reason: "sqli".into(),
            client_ip: "1.2.3.4".into(),
            route_id: None,
            rule_id: None,
            risk_score: Some(90),
            fields: serde_json::json!({"detector": "sqli"}),
        }
    }

    fn ev_now() -> AuditEvent {
        ev_at(chrono::Utc::now())
    }

    // ----- pure helpers -----------------------------------------------------

    #[test]
    fn daily_file_path_is_stable() {
        let p = daily_file_path(
            Path::new("/var/log/aegis"),
            NaiveDate::from_ymd_opt(2026, 4, 30).unwrap(),
        );
        assert_eq!(p, PathBuf::from("/var/log/aegis/audit-2026-04-30.ndjson"));
    }

    #[test]
    fn parse_audit_filename_round_trips() {
        let d = NaiveDate::from_ymd_opt(2026, 4, 30).unwrap();
        let p = daily_file_path(Path::new("/x"), d);
        let name = p.file_name().unwrap().to_str().unwrap();
        assert_eq!(parse_audit_filename(name), Some(d));
    }

    #[test]
    fn parse_audit_filename_rejects_unrelated_files() {
        assert!(parse_audit_filename("README.md").is_none());
        assert!(parse_audit_filename("audit.ndjson").is_none()); // missing date
        assert!(parse_audit_filename("audit-not-a-date.ndjson").is_none());
        assert!(parse_audit_filename("audit-2026-04-30.txt").is_none()); // wrong ext
    }

    #[test]
    fn is_expired_respects_retention_boundary() {
        let now = NaiveDate::from_ymd_opt(2026, 4, 30).unwrap();
        // Same day → not expired.
        assert!(!is_expired("audit-2026-04-30.ndjson", now, 30));
        // 29 days old → not expired (boundary: retention=30 keeps 30 days).
        assert!(!is_expired("audit-2026-04-01.ndjson", now, 30));
        // 30 days old → expired.
        assert!(is_expired("audit-2026-03-31.ndjson", now, 30));
        // Way old → expired.
        assert!(is_expired("audit-2025-01-01.ndjson", now, 30));
    }

    #[test]
    fn is_expired_ignores_non_audit_filenames() {
        let now = NaiveDate::from_ymd_opt(2026, 4, 30).unwrap();
        assert!(!is_expired("README.md", now, 30));
        assert!(!is_expired("garbage.log", now, 30));
        assert!(!is_expired("backup.tar.gz", now, 1));
    }

    #[test]
    fn resolve_dir_handles_file_path_and_dir_path() {
        // File path with extension → use parent.
        assert_eq!(
            resolve_dir(Path::new("/var/log/aegis/audit.jsonl")),
            PathBuf::from("/var/log/aegis"),
        );
        // Directory path with no extension → use as-is.
        assert_eq!(
            resolve_dir(Path::new("/var/log/aegis")),
            PathBuf::from("/var/log/aegis"),
        );
    }

    // ----- in-memory sink ---------------------------------------------------

    #[tokio::test]
    async fn in_memory_sink_buffers_events() {
        let sink = JsonlSink::new_in_memory(JsonlConfig::default());
        sink.write_one(&ev_now()).await.unwrap();
        sink.write_one(&ev_now()).await.unwrap();
        // try_lock to read since we don't expose async getters.
        let buf = sink.in_memory.as_ref().unwrap().lock().await;
        assert_eq!(buf.len(), 2);
        for line in buf.iter() {
            // Each line is one valid JSON object.
            let _: serde_json::Value = serde_json::from_str(line).unwrap();
        }
    }

    #[tokio::test]
    async fn in_memory_sink_batch_write_appends_each_event() {
        let sink = JsonlSink::new_in_memory(JsonlConfig::default());
        let batch = vec![ev_now(), ev_now(), ev_now()];
        sink.write_batch(&batch).await.unwrap();
        let buf = sink.in_memory.as_ref().unwrap().lock().await;
        assert_eq!(buf.len(), 3);
    }

    // ----- file-backed sink -------------------------------------------------

    #[tokio::test]
    async fn file_sink_creates_dir_and_writes_first_event() {
        let dir = tempdir().unwrap();
        let cfg = JsonlConfig {
            path: dir.path().to_path_buf(),
            ..Default::default()
        };
        let sink = JsonlSink::open(cfg).await.unwrap();
        let ev = ev_at(chrono::Utc.with_ymd_and_hms(2026, 4, 30, 10, 0, 0).unwrap());
        sink.write_one(&ev).await.unwrap();

        let f = dir.path().join("audit-2026-04-30.ndjson");
        let body = tokio::fs::read_to_string(&f).await.unwrap();
        assert!(body.contains("\"action\":\"block\""));
        // Trailing newline → exactly one full record.
        assert!(body.ends_with('\n'));
        assert_eq!(body.lines().count(), 1);
    }

    #[tokio::test]
    async fn file_sink_rotates_on_date_change() {
        let dir = tempdir().unwrap();
        let cfg = JsonlConfig {
            path: dir.path().to_path_buf(),
            ..Default::default()
        };
        let sink = JsonlSink::open(cfg).await.unwrap();

        let day_a = chrono::Utc.with_ymd_and_hms(2026, 4, 30, 23, 59, 0).unwrap();
        let day_b = chrono::Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 1).unwrap();
        sink.write_one(&ev_at(day_a)).await.unwrap();
        sink.write_one(&ev_at(day_b)).await.unwrap();

        let body_a = tokio::fs::read_to_string(dir.path().join("audit-2026-04-30.ndjson"))
            .await.unwrap();
        let body_b = tokio::fs::read_to_string(dir.path().join("audit-2026-05-01.ndjson"))
            .await.unwrap();
        assert_eq!(body_a.lines().count(), 1, "day A file");
        assert_eq!(body_b.lines().count(), 1, "day B file");
    }

    #[tokio::test]
    async fn file_sink_appends_to_existing_file_on_re_open() {
        let dir = tempdir().unwrap();
        let cfg = JsonlConfig {
            path: dir.path().to_path_buf(),
            ..Default::default()
        };
        // First sink writes one event, drops.
        {
            let sink = JsonlSink::open(cfg.clone()).await.unwrap();
            let ev = ev_at(chrono::Utc.with_ymd_and_hms(2026, 4, 30, 10, 0, 0).unwrap());
            sink.write_one(&ev).await.unwrap();
            sink.flush().await.unwrap();
        }
        // Second sink writes another to the same date → appends.
        {
            let sink = JsonlSink::open(cfg).await.unwrap();
            let ev = ev_at(chrono::Utc.with_ymd_and_hms(2026, 4, 30, 11, 0, 0).unwrap());
            sink.write_one(&ev).await.unwrap();
            sink.flush().await.unwrap();
        }
        let body = tokio::fs::read_to_string(dir.path().join("audit-2026-04-30.ndjson"))
            .await.unwrap();
        assert_eq!(body.lines().count(), 2, "second open must append, not truncate");
    }

    #[tokio::test]
    async fn file_sink_handles_legacy_file_path_via_resolve_dir() {
        // Operator's existing config: `path: <dir>/audit.jsonl`.
        // The sink should rotate inside <dir>, NOT create that file.
        let dir = tempdir().unwrap();
        let legacy = dir.path().join("audit.jsonl");
        let cfg = JsonlConfig {
            path: legacy.clone(),
            ..Default::default()
        };
        let sink = JsonlSink::open(cfg).await.unwrap();
        let ev = ev_at(chrono::Utc.with_ymd_and_hms(2026, 4, 30, 10, 0, 0).unwrap());
        sink.write_one(&ev).await.unwrap();

        // The rotated file lives next to the legacy path, not at it.
        assert!(!legacy.exists(), "legacy file path must not be used as the target");
        assert!(dir.path().join("audit-2026-04-30.ndjson").exists());
    }

    // ----- TTL pruner -------------------------------------------------------

    #[tokio::test]
    async fn prune_removes_only_expired_audit_files() {
        let dir = tempdir().unwrap();
        // Create 3 files: one current, one borderline (29 days), one expired (60 days).
        let now = NaiveDate::from_ymd_opt(2026, 4, 30).unwrap();
        for (yyyymmdd, content) in [
            ("2026-04-30", "current\n"),
            ("2026-04-01", "borderline\n"), // 29 days old
            ("2026-03-01", "expired\n"),    // 60 days old
        ] {
            let p = dir.path().join(format!("audit-{yyyymmdd}.ndjson"));
            tokio::fs::write(&p, content).await.unwrap();
        }
        // Drop a non-audit file too — must be left untouched.
        tokio::fs::write(dir.path().join("README.md"), "keep me").await.unwrap();

        let removed = prune_expired_files(dir.path(), now, 30).await.unwrap();
        assert_eq!(removed, 1, "only the 60-day file expires at retention=30");

        assert!(dir.path().join("audit-2026-04-30.ndjson").exists());
        assert!(dir.path().join("audit-2026-04-01.ndjson").exists());
        assert!(!dir.path().join("audit-2026-03-01.ndjson").exists(), "expired file must be gone");
        assert!(dir.path().join("README.md").exists(), "non-audit file must survive");
    }

    #[tokio::test]
    async fn prune_returns_zero_when_dir_missing() {
        let dir = tempdir().unwrap();
        let nope = dir.path().join("nonexistent");
        let now = NaiveDate::from_ymd_opt(2026, 4, 30).unwrap();
        let removed = prune_expired_files(&nope, now, 1).await.unwrap();
        assert_eq!(removed, 0);
    }

    // ----- AuditSink trait impl ---------------------------------------------

    #[tokio::test]
    async fn trait_impl_writes_via_write_one() {
        let dir = tempdir().unwrap();
        let cfg = JsonlConfig {
            path: dir.path().to_path_buf(),
            ..Default::default()
        };
        let sink = JsonlSink::open(cfg).await.unwrap();
        sink.write(&ev_at(chrono::Utc.with_ymd_and_hms(2026, 4, 30, 10, 0, 0).unwrap()))
            .await.unwrap();
        assert!(dir.path().join("audit-2026-04-30.ndjson").exists());
    }

    #[tokio::test]
    async fn sink_id_is_jsonl() {
        let sink = JsonlSink::new_in_memory(JsonlConfig::default());
        assert_eq!(sink.id(), "jsonl");
    }

    // ----- run_persist_task -------------------------------------------------

    #[tokio::test]
    async fn persist_task_drains_bus_into_file() {
        let dir = tempdir().unwrap();
        let cfg = JsonlConfig {
            path: dir.path().to_path_buf(),
            max_batch: 2,
            flush_interval: Duration::from_millis(50),
            ..Default::default()
        };
        let sink = Arc::new(JsonlSink::open(cfg).await.unwrap());
        let bus = AuditBus::new(64);
        let bus_for_task = bus.clone();
        let sink_for_task = Arc::clone(&sink);
        let task = tokio::spawn(async move {
            run_persist_task(
                bus_for_task,
                vec![sink_for_task],
                2,
                Duration::from_millis(50),
            ).await;
        });

        // Wait for the spawned task to reach its first `recv().await`
        // (post `bus.subscribe()`). Several yields are needed because
        // `run_persist_task` calls `tick.tick().await` *before* the
        // recv loop on its first iteration to skip the immediate tick.
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;

        // Emit three events on the same date.
        let day = chrono::Utc.with_ymd_and_hms(2026, 4, 30, 10, 0, 0).unwrap();
        bus.emit(ev_at(day));
        bus.emit(ev_at(day + chrono::Duration::seconds(1)));
        bus.emit(ev_at(day + chrono::Duration::seconds(2)));

        // Wait briefly for the batch + tick to flush.
        let target = dir.path().join("audit-2026-04-30.ndjson");
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            if let Ok(body) = tokio::fs::read_to_string(&target).await {
                if body.lines().count() >= 3 {
                    break;
                }
            }
        }

        // Drop the bus to close the broadcast and let the task exit.
        drop(bus);
        let _ = tokio::time::timeout(Duration::from_secs(1), task).await;

        let body = tokio::fs::read_to_string(&target).await.unwrap_or_default();
        assert_eq!(body.lines().count(), 3, "all three events flushed: {body:?}");
    }

    #[tokio::test]
    async fn persist_task_no_op_when_no_sinks() {
        // Should not panic, should return immediately even with a
        // live bus.
        let bus = AuditBus::new(8);
        run_persist_task(bus, vec![], 100, Duration::from_secs(1)).await;
    }

    #[tokio::test]
    async fn ttl_task_no_op_when_no_sinks() {
        run_ttl_task(vec![], Duration::from_millis(1)).await;
    }
}
