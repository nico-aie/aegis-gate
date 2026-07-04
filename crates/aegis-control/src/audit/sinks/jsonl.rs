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

/// 2026-05-17 F-CRITICAL-013 (control audit): figure out the
/// `prev_hash` seed for a new daily file. Three cases, in order:
///
/// 1. `new_path` already exists (we're rotating to a file we
///    wrote earlier today — e.g. after a process restart). Tail
///    its last line and return that `ChainEntry.hash`.
/// 2. Some other `audit-YYYY-MM-DD.ndjson` sits in `dir`. Pick
///    the most recent prior date by filename, tail it, and
///    return its last line's hash. This is what closes the
///    cross-day chain: deleting an entire daily file then breaks
///    the verifier on the FIRST entry of the file that follows it.
/// 3. Empty / missing directory → `genesis_hash()`.
///
/// All errors (unreadable file, malformed last line, etc.) fall
/// through to `genesis_hash()`. The verifier will surface the
/// drift if an attacker tampers with the seed source — we don't
/// need to panic here.
pub async fn resolve_seed_prev_hash(dir: &Path, new_path: &Path) -> String {
    use crate::audit::chain::{genesis_hash, ChainEntry};

    async fn tail_last_hash(path: &Path) -> Option<String> {
        let body = tokio::fs::read_to_string(path).await.ok()?;
        // Iterate non-empty lines from the end.
        for line in body.lines().rev() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(entry) = serde_json::from_str::<ChainEntry>(line) {
                return Some(entry.hash);
            }
        }
        None
    }

    // Case 1: the new file already has content.
    if let Ok(meta) = tokio::fs::metadata(new_path).await {
        if meta.is_file() && meta.len() > 0 {
            if let Some(h) = tail_last_hash(new_path).await {
                return h;
            }
        }
    }

    // Case 2: pick the most-recent prior audit file in the dir.
    let new_name = new_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let new_date = parse_audit_filename(new_name);

    if let Ok(mut rd) = tokio::fs::read_dir(dir).await {
        let mut best: Option<(NaiveDate, PathBuf)> = None;
        while let Ok(Some(ent)) = rd.next_entry().await {
            let name = ent.file_name();
            let name_s = match name.to_str() {
                Some(s) => s.to_string(),
                None => continue,
            };
            let Some(d) = parse_audit_filename(&name_s) else {
                continue;
            };
            // Skip ourselves; only consider files dated strictly
            // earlier than the new file's date.
            if let Some(target) = new_date {
                if d >= target {
                    continue;
                }
            }
            match &best {
                Some((bd, _)) if *bd >= d => {}
                _ => best = Some((d, ent.path())),
            }
        }
        if let Some((_, prev_path)) = best {
            if let Some(h) = tail_last_hash(&prev_path).await {
                return h;
            }
        }
    }

    // Case 3: nothing to link to.
    genesis_hash()
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
///
/// 2026-05-17 F-CRITICAL-013 (control audit): tracks the running
/// chain `prev_hash` so each written line is a
/// `crate::audit::chain::ChainEntry` linked to its predecessor.
/// On rotation, the new file's `prev_hash` is seeded from the
/// previous file's last entry hash (tailed from disk) — that
/// closes the cross-day chain so deleting an entire daily file
/// breaks verification on the next file's first entry.
struct OpenFile {
    date: NaiveDate,
    writer: BufWriter<File>,
    /// SHA-256 hex of the previous chain entry. Seeded from
    /// `genesis_hash()` for a brand-new audit directory, or from
    /// the tail of the previous file at rotation.
    prev_hash: String,
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

    /// The operator-configured sink path — the identity half of this
    /// sink's [`super::delivery::jsonl_key`] registry key.
    pub fn source_path(&self) -> &Path {
        &self.cfg.path
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
    ///
    /// 2026-05-17 F-CRITICAL-013: `flush` drains the user-space
    /// `BufWriter` into the kernel; `sync_data` then asks the
    /// kernel to flush its page cache to disk. README's
    /// "tamper-evident" claim required both — previously only
    /// `flush` was called and a power-loss / OOM-kill could lose
    /// up to `max_batch` events that the kernel hadn't pushed to
    /// the platter yet. Per-batch `sync_data` adds ~5 ms on
    /// rotational disks, sub-ms on SSDs; operators can tune
    /// `max_batch` (default 100) to amortise.
    pub async fn write_batch(&self, events: &[AuditEvent]) -> std::io::Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        if let Some(buf) = &self.in_memory {
            let mut g = buf.lock().await;
            for ev in events {
                let line = Self::format_chained_in_memory(&mut g, ev);
                g.push(line);
            }
            return Ok(());
        }

        let mut state = self.state.lock().await;
        for ev in events {
            self.write_one_locked(&mut state, ev).await?;
        }
        if let Some(s) = state.as_mut() {
            s.writer.flush().await?;
            s.writer.get_ref().sync_data().await?;
        }
        Ok(())
    }

    /// Single-event write (tests + the trait impl). Always flushes —
    /// hot-path callers should prefer [`Self::write_batch`].
    ///
    /// 2026-05-17 F-CRITICAL-013: also `sync_data` after flush —
    /// see `write_batch` for rationale.
    pub async fn write_one(&self, ev: &AuditEvent) -> std::io::Result<()> {
        if let Some(buf) = &self.in_memory {
            let mut g = buf.lock().await;
            let line = Self::format_chained_in_memory(&mut g, ev);
            g.push(line);
            return Ok(());
        }
        let mut state = self.state.lock().await;
        self.write_one_locked(&mut state, ev).await?;
        if let Some(s) = state.as_mut() {
            s.writer.flush().await?;
            s.writer.get_ref().sync_data().await?;
        }
        Ok(())
    }

    /// 2026-05-17 F-CRITICAL-013: in-memory sink format helper —
    /// produces the same `ChainEntry` wire shape the disk-backed
    /// path emits so tests asserting on the in-memory lines see
    /// real chain semantics. Reads the last line of `buf` to
    /// determine `prev_hash`; falls back to `genesis_hash()` for
    /// the first entry.
    fn format_chained_in_memory(buf: &mut Vec<String>, ev: &AuditEvent) -> String {
        let prev_hash = buf
            .last()
            .and_then(|s| serde_json::from_str::<crate::audit::chain::ChainEntry>(s).ok())
            .map(|e| e.hash)
            .unwrap_or_else(crate::audit::chain::genesis_hash);
        let entry = crate::audit::chain::ChainEntry {
            hash: crate::audit::chain::chain_hash(&prev_hash, ev),
            event: ev.clone(),
        };
        serde_json::to_string(&entry).unwrap_or_else(|_| "{}".into())
    }

    /// Inner write — caller holds the state lock. Rotates when the
    /// event date differs from the open file's date.
    ///
    /// 2026-05-17 F-CRITICAL-013 (control audit): each event is
    /// wrapped in a `ChainEntry` and serialised as one atomic
    /// `write_all` (line + newline in one buffer) so a torn write
    /// can't leave half a line on disk. The running `prev_hash`
    /// lives on the `OpenFile` state; on rotation the new file's
    /// seed is read from the previous day's tail line.
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
            // Flush + sync + drop the old handle before opening a
            // new one so the previous day's file is durable on disk
            // and the tail we re-read carries the actual last line.
            if let Some(prev) = state.as_mut() {
                let _ = prev.writer.flush().await;
                let _ = prev.writer.get_ref().sync_data().await;
            }
            let path = daily_file_path(&self.dir, date);
            // Seed `prev_hash` for the new file. Three cases:
            //   1. File at `path` already exists (we rotated to it
            //      earlier today, e.g. after a process restart) →
            //      read its last line, take that ChainEntry.hash.
            //   2. Some other audit-YYYY-MM-DD.ndjson sits in the
            //      directory (most-recent prior day) → take its
            //      last line's hash. Closes the cross-day chain.
            //   3. Empty directory → start at genesis.
            let prev_hash = resolve_seed_prev_hash(&self.dir, &path).await;
            let f = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await?;
            *state = Some(OpenFile {
                date,
                writer: BufWriter::with_capacity(64 * 1024, f),
                prev_hash,
            });
        }
        let s = state.as_mut().expect("opened above");
        let chain_entry = crate::audit::chain::ChainEntry {
            hash: crate::audit::chain::chain_hash(&s.prev_hash, ev),
            event: ev.clone(),
        };
        // One atomic write — line + `\n` in a single syscall'd
        // `write_all`. A torn write (write returns short) is still
        // possible on rotational filesystems but the buffer is
        // single-shot from this layer's perspective so we don't
        // leave a half-line crossing two operations.
        let mut buf = serde_json::to_vec(&chain_entry)
            .unwrap_or_else(|_| b"{}".to_vec());
        buf.push(b'\n');
        s.writer.write_all(&buf).await?;
        s.prev_hash = chain_entry.hash;
        Ok(())
    }

    /// Force a flush of any buffered bytes. Called on graceful
    /// shutdown so the last batch isn't lost.
    ///
    /// 2026-05-17 F-CRITICAL-013: `sync_data` after flush — the
    /// shutdown path is exactly the case where the README's
    /// "tamper-evident" claim has to be true. Process exit
    /// without sync would lose anything the kernel hadn't paged
    /// out yet.
    pub async fn flush(&self) -> std::io::Result<()> {
        if self.in_memory.is_some() {
            return Ok(());
        }
        let mut state = self.state.lock().await;
        if let Some(s) = state.as_mut() {
            s.writer.flush().await?;
            s.writer.get_ref().sync_data().await?;
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
    // PE-2 — register a delivery handle per sink so `/api/cold-tier`
    // reports real counters (delivered / errors / last success).
    let delivery: Vec<_> = sinks
        .iter()
        .map(|s| {
            super::delivery::DeliveryRegistry::global()
                .handle(super::delivery::jsonl_key(s.source_path()))
        })
        .collect();
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
                        flush_buf(&sinks, &delivery, &mut buf).await;
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
                    flush_buf(&sinks, &delivery, &mut buf).await;
                }
            }
        }
    }
    if !buf.is_empty() {
        flush_buf(&sinks, &delivery, &mut buf).await;
    }
    for sink in &sinks {
        let _ = sink.flush().await;
    }
}

async fn flush_buf(
    sinks: &[Arc<JsonlSink>],
    delivery: &[Arc<super::delivery::SinkDeliveryHandle>],
    buf: &mut Vec<AuditEvent>,
) {
    for (sink, handle) in sinks.iter().zip(delivery) {
        match sink.write_batch(buf).await {
            Ok(()) => handle.record_success(buf.len() as u64),
            Err(e) => {
                handle.record_error();
                tracing::warn!(
                    sink = "jsonl",
                    error = %e,
                    "audit jsonl sink batch write failed; events dropped from this sink only",
                );
            }
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
            method: None,
            path: None,
            mode: None,
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

    /// 2026-05-17 F-CRITICAL-013 (control audit): every line the
    /// sink writes is a `ChainEntry` (with `prev_hash` field via
    /// the inner `event` + outer `hash` shape), not a bare
    /// `AuditEvent`. Verifier expects `ChainEntry`; pre-fix the
    /// sink wrote `AuditEvent` and `verify_ndjson` errored on
    /// line 1 of every file the sink produced.
    #[tokio::test]
    async fn file_sink_emits_chain_entries_not_bare_events() {
        use crate::audit::chain::ChainEntry;
        use crate::audit::verify::{verify_ndjson, VerifyResult};

        let dir = tempdir().unwrap();
        let cfg = JsonlConfig {
            path: dir.path().to_path_buf(),
            ..Default::default()
        };
        let sink = JsonlSink::open(cfg).await.unwrap();
        for h in 0..3 {
            let ev = ev_at(
                chrono::Utc
                    .with_ymd_and_hms(2026, 4, 30, h, 0, 0)
                    .unwrap(),
            );
            sink.write_one(&ev).await.unwrap();
        }
        sink.flush().await.unwrap();

        let body =
            tokio::fs::read_to_string(dir.path().join("audit-2026-04-30.ndjson"))
                .await
                .unwrap();

        // Every line parses as ChainEntry, NOT as bare AuditEvent.
        for line in body.lines().filter(|l| !l.is_empty()) {
            let entry: ChainEntry = serde_json::from_str(line)
                .expect("sink must emit ChainEntry, not AuditEvent");
            assert!(!entry.hash.is_empty(), "hash field must be populated");
            assert_eq!(entry.event.action, "block");
        }

        // And the verifier accepts the whole file.
        assert!(matches!(
            verify_ndjson(&body),
            VerifyResult::Clean { entries: 3 }
        ));
    }

    /// 2026-05-17 F-CRITICAL-013: cross-day chain linkage. When
    /// rotation opens a new daily file, the first entry's
    /// `prev_hash` MUST equal the previous day's last entry hash.
    /// Pre-fix every daily file restarted at `genesis_hash()`, so
    /// deleting an entire day's file left remaining files
    /// individually verify-clean — multi-day attack masking gap.
    #[tokio::test]
    async fn file_sink_chains_across_daily_rotation() {
        use crate::audit::chain::ChainEntry;
        use crate::audit::verify::{verify_ndjson, VerifyResult};

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
        sink.flush().await.unwrap();

        let body_a =
            tokio::fs::read_to_string(dir.path().join("audit-2026-04-30.ndjson"))
                .await
                .unwrap();
        let body_b =
            tokio::fs::read_to_string(dir.path().join("audit-2026-05-01.ndjson"))
                .await
                .unwrap();

        let last_a: ChainEntry =
            serde_json::from_str(body_a.lines().last().unwrap()).unwrap();
        let first_b: ChainEntry =
            serde_json::from_str(body_b.lines().next().unwrap()).unwrap();

        // The KEY chain semantic: day B's first entry was hashed
        // with day A's last entry's hash as prev_hash. We can
        // verify that by recomputing.
        let expected = crate::audit::chain::chain_hash(&last_a.hash, &first_b.event);
        assert_eq!(
            expected, first_b.hash,
            "cross-day rotation must seed prev_hash from previous file's tail",
        );

        // Concatenated verification (single stream) also passes.
        let concatenated = format!("{body_a}{body_b}");
        assert!(matches!(
            verify_ndjson(&concatenated),
            VerifyResult::Clean { entries: 2 }
        ));
    }

    /// 2026-05-17 F-CRITICAL-013: re-opening the sink against an
    /// existing same-day file picks up the running prev_hash from
    /// the file's tail, so the next entry stays in chain. This is
    /// the "process restart mid-day" path.
    #[tokio::test]
    async fn file_sink_resumes_chain_on_same_day_reopen() {
        use crate::audit::verify::{verify_ndjson, VerifyResult};
        let dir = tempdir().unwrap();
        let cfg = JsonlConfig {
            path: dir.path().to_path_buf(),
            ..Default::default()
        };
        {
            let sink = JsonlSink::open(cfg.clone()).await.unwrap();
            let ev = ev_at(chrono::Utc.with_ymd_and_hms(2026, 4, 30, 10, 0, 0).unwrap());
            sink.write_one(&ev).await.unwrap();
            sink.flush().await.unwrap();
        }
        {
            let sink = JsonlSink::open(cfg).await.unwrap();
            let ev = ev_at(chrono::Utc.with_ymd_and_hms(2026, 4, 30, 11, 0, 0).unwrap());
            sink.write_one(&ev).await.unwrap();
            sink.flush().await.unwrap();
        }
        let body =
            tokio::fs::read_to_string(dir.path().join("audit-2026-04-30.ndjson"))
                .await
                .unwrap();
        // After reopen the second line was hashed with the FIRST
        // line's hash as prev_hash. verify_ndjson walks the full
        // chain and must pass.
        assert!(matches!(
            verify_ndjson(&body),
            VerifyResult::Clean { entries: 2 }
        ));
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
