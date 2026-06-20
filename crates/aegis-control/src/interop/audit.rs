//! Minimal-schema JSONL audit sink.
//!
//! Writes one JSON line per request with a small fixed schema
//! (8 fields by default; one optional `rule_id`) to a
//! configurable file path (default `./waf_audit.log`). Append-
//! only; the control plane's `reset_state` MUST NOT truncate it.
//!
//! Distinct from the tamper-evident SHA-256 audit chain in
//! `aegis-control::audit`. Both run in parallel — the chain is
//! the long-term forensic record; this sink is the SIEM-friendly
//! request log.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, RecvTimeoutError, SyncSender};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use serde::Serialize;

/// Bound on the writer's backlog. Bounded so a stalled disk can't grow
/// the queue without limit; large enough that the batching writer never
/// fills it under normal data-plane load (each slot is one serialized
/// line). On a full channel `append` blocks briefly — back-pressure, not
/// loss: the OC contract requires every line to land.
const CHANNEL_CAPACITY: usize = 65_536;

/// Flush after this many buffered lines regardless of time — caps the
/// window of un-fsynced entries under sustained load.
const FLUSH_EVERY: usize = 256;

/// Flush at least this often when lines are trickling in, so the OC sees
/// an entry well within its correlation window even at low rates.
const FLUSH_INTERVAL: Duration = Duration::from_millis(25);

/// One audit entry, in the exact contract schema. Field names
/// MUST match the spec — renaming is a benchmark-breaking change.
#[derive(Clone, Debug, Serialize)]
pub struct MinimalAuditEntry {
    /// UUID v4 — same value as the `X-WAF-Request-Id` header.
    pub request_id: String,
    /// Unix epoch milliseconds.
    pub ts_ms: i64,
    /// TCP peer address (NOT XFF). IPv4 dotted decimal expected.
    pub ip: String,
    /// Uppercase HTTP method.
    pub method: String,
    /// Request path including query string.
    pub path: String,
    /// One of: allow | block | challenge | rate_limit | timeout | circuit_breaker.
    pub action: String,
    /// 0–100.
    pub risk_score: u32,
    /// `enforce` or `log_only`. Must match `X-WAF-Mode`.
    pub mode: String,
    /// Optional rule/policy/detector ID — bonus field, kept
    /// in the schema because the OC's documentation calls it
    /// out as a recommended addition. Skipped when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// 2026-05-05 — bonus field. Resolved tier (route override
    /// or path heuristic): `critical | high | medium | low`.
    /// Skipped when `None` (e.g. early rate-limit blocks before
    /// tier classification ran). The dashboard's Live Feed reads
    /// this so the `TIER` column shows the real classification
    /// instead of falling back to a risk-score bucket.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
}

/// Message to the dedicated writer thread.
enum WriterMsg {
    /// One serialized, newline-terminated JSONL line.
    Line(Vec<u8>),
    /// Flush barrier — the writer flushes pending lines then acks, so a
    /// caller can guarantee durability without dropping the sink.
    Sync(SyncSender<()>),
}

/// Append-only file sink for [`MinimalAuditEntry`].
/// `reset_state` in the control plane MUST NOT truncate it.
///
/// 2026-06-20 (Fix A, plans/issues/PLAN-perf-throughput-cliff-2026-06-20.md):
/// writes are handed off to a single dedicated writer thread over a bounded
/// channel; the thread owns the `BufWriter<File>` and batches flushes (every
/// [`FLUSH_EVERY`] lines or [`FLUSH_INTERVAL`], whichever first). This takes
/// the per-request disk `flush()` and the global writer mutex off the data
/// plane's hot path — `append` now only serializes the entry and enqueues it.
/// The OC still sees each entry within its correlation window (≤ 25 ms).
pub struct MinimalJsonlSink {
    path: PathBuf,
    tx: SyncSender<WriterMsg>,
    handle: Option<JoinHandle<()>>,
    flushes: Arc<AtomicU64>,
}

impl MinimalJsonlSink {
    /// Open the file in append mode, creating it if missing, and spawn
    /// the writer thread. Returns an error only when the path is
    /// unwritable — the caller should fail-fast at boot in that case so
    /// the OC's startup probe doesn't silently miss audit evidence.
    pub fn open(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        let writer = BufWriter::new(file);

        let (tx, rx) = sync_channel::<WriterMsg>(CHANNEL_CAPACITY);
        let flushes = Arc::new(AtomicU64::new(0));
        let flushes_w = Arc::clone(&flushes);
        let handle = std::thread::Builder::new()
            .name("aegis-interop-audit".into())
            .spawn(move || writer_loop(rx, writer, &flushes_w))
            .map_err(std::io::Error::other)?;

        Ok(Self {
            path,
            tx,
            handle: Some(handle),
            flushes,
        })
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Append one entry. Serializes the line and enqueues it for the
    /// writer thread — no disk I/O and no global writer mutex on the
    /// caller's (data-plane) thread. Blocks only if the bounded backlog
    /// is full (back-pressure under a stalled disk; never silently drops,
    /// per the OC contract).
    pub fn append(&self, entry: &MinimalAuditEntry) -> std::io::Result<()> {
        let mut line = serde_json::to_vec(entry).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e)
        })?;
        line.push(b'\n');
        self.tx.send(WriterMsg::Line(line)).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "interop audit writer thread is gone",
            )
        })
    }

    /// Block until every entry enqueued before this call is flushed to
    /// disk. Used by graceful shutdown and by callers that must read the
    /// file back. A no-op-fast path if the writer is already idle.
    pub fn sync(&self) {
        let (ack_tx, ack_rx) = sync_channel::<()>(0);
        if self.tx.send(WriterMsg::Sync(ack_tx)).is_ok() {
            let _ = ack_rx.recv();
        }
    }

    /// Number of disk flushes the writer has performed. Observability +
    /// regression guard that flushes stay decoupled from append count.
    pub fn flushes(&self) -> u64 {
        self.flushes.load(Ordering::Relaxed)
    }
}

impl Drop for MinimalJsonlSink {
    fn drop(&mut self) {
        // Dropping `tx` disconnects the channel; the writer drains the
        // remaining backlog, performs a final flush, and exits. Join so
        // the file is durable before the sink goes away (the contract
        // tests read the file right after dropping the sink).
        if let Some(handle) = self.handle.take() {
            // Replace tx with a fresh disconnected sender so the original
            // is dropped now, signalling shutdown before we join.
            let (dead_tx, _) = sync_channel::<WriterMsg>(1);
            let live_tx = std::mem::replace(&mut self.tx, dead_tx);
            drop(live_tx);
            let _ = handle.join();
        }
    }
}

/// Drain the channel, batching flushes. Owns the `BufWriter` for its
/// whole lifetime so no other thread ever touches the file.
fn writer_loop(
    rx: std::sync::mpsc::Receiver<WriterMsg>,
    mut writer: BufWriter<File>,
    flushes: &AtomicU64,
) {
    let mut pending: usize = 0;
    let do_flush = |w: &mut BufWriter<File>, pending: &mut usize| {
        if *pending > 0 {
            let _ = w.flush();
            flushes.fetch_add(1, Ordering::Relaxed);
            *pending = 0;
        }
    };

    loop {
        match rx.recv_timeout(FLUSH_INTERVAL) {
            Ok(WriterMsg::Line(bytes)) => {
                if writer.write_all(&bytes).is_ok() {
                    pending += 1;
                }
                if pending >= FLUSH_EVERY {
                    do_flush(&mut writer, &mut pending);
                }
            }
            Ok(WriterMsg::Sync(ack)) => {
                // All lines enqueued before this barrier are already
                // dequeued (FIFO, single consumer); flush them then ack.
                do_flush(&mut writer, &mut pending);
                let _ = ack.send(());
            }
            Err(RecvTimeoutError::Timeout) => {
                do_flush(&mut writer, &mut pending);
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    // Final durability on shutdown.
    do_flush(&mut writer, &mut pending);
}

/// Format a single entry as the JSONL line that would be written.
/// Useful for unit tests + benchmark dry-runs without touching disk.
pub fn format_line(entry: &MinimalAuditEntry) -> String {
    serde_json::to_string(entry).unwrap_or_else(|_| "{}".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};

    fn entry_template() -> MinimalAuditEntry {
        MinimalAuditEntry {
            request_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            ts_ms: 1_777_363_200_123,
            ip: "127.0.0.1".into(),
            method: "POST".into(),
            path: "/login".into(),
            action: "block".into(),
            risk_score: 75,
            mode: "enforce".into(),
            rule_id: Some("rule-001".into()),
            tier: Some("critical".into()),
        }
    }

    #[test]
    fn line_contains_all_required_fields() {
        let line = format_line(&entry_template());
        for required in [
            "request_id",
            "ts_ms",
            "ip",
            "method",
            "path",
            "action",
            "risk_score",
            "mode",
        ] {
            assert!(
                line.contains(required),
                "missing required field {required} in {line}",
            );
        }
    }

    #[test]
    fn line_omits_rule_id_when_none() {
        let mut e = entry_template();
        e.rule_id = None;
        let line = format_line(&e);
        assert!(!line.contains("rule_id"), "rule_id leaked: {line}");
    }

    #[test]
    fn entry_is_one_line_no_internal_newlines() {
        // JSONL contract — one valid JSON object per line.
        let line = format_line(&entry_template());
        assert!(!line.contains('\n'));
        // Sanity: it parses back as a single object.
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert!(v.is_object());
    }

    #[test]
    fn sink_appends_two_entries_with_newline() {
        let dir = tempdir();
        let path = dir.join("waf_audit.log");
        let sink = MinimalJsonlSink::open(&path).unwrap();
        sink.append(&entry_template()).unwrap();
        sink.append(&entry_template()).unwrap();
        drop(sink);

        let f = File::open(&path).unwrap();
        let lines: Vec<String> = BufReader::new(f)
            .lines()
            .filter_map(|l| l.ok())
            .collect();
        assert_eq!(lines.len(), 2);
        for l in &lines {
            // Every line must parse as one JSON object.
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            assert!(v.is_object());
        }
    }

    #[test]
    fn sink_is_append_only_across_reopens() {
        // Simulates `reset_state` re-opening the file: the
        // contract REQUIRES prior entries to remain.
        let dir = tempdir();
        let path = dir.join("waf_audit.log");
        {
            let s = MinimalJsonlSink::open(&path).unwrap();
            s.append(&entry_template()).unwrap();
        }
        {
            let s = MinimalJsonlSink::open(&path).unwrap();
            s.append(&entry_template()).unwrap();
        }
        let content = std::fs::read_to_string(&path).unwrap();
        let line_count = content.lines().count();
        assert_eq!(
            line_count, 2,
            "audit log MUST NOT be truncated on reopen — got {line_count} lines",
        );
    }

    #[test]
    fn risk_score_renders_as_integer_not_string() {
        let line = format_line(&entry_template());
        assert!(line.contains("\"risk_score\":75"), "got {line}");
    }

    // ---- Fix A (perf/audit-sink-async-writer) -------------------------
    // The interop sink must NOT flush to disk on every append under a
    // global mutex (that serialized all data-plane workers across a
    // blocking syscall — the throughput cliff root cause, see
    // plans/issues/PLAN-perf-throughput-cliff-2026-06-20.md §P0). Writes
    // are handed to a dedicated writer thread that batches flushes. These
    // tests pin the new behavior; the durability/append-only/schema tests
    // above remain the unchanged external contract.

    #[test]
    fn append_batches_flushes_not_one_per_entry() {
        // A burst of appends well under the size-flush threshold, then a
        // single explicit sync, must produce only a handful of flushes —
        // NOT one per entry (which is what the old flush-per-write sink
        // did). This is the core Fix A guarantee: disk flush is decoupled
        // from the per-request append.
        let dir = tempdir();
        let path = dir.join("waf_audit.log");
        let sink = MinimalJsonlSink::open(&path).unwrap();

        const N: usize = 50; // < FLUSH_EVERY so size-flush never triggers
        for _ in 0..N {
            sink.append(&entry_template()).unwrap();
        }
        sink.sync();

        let flushes = sink.flushes();
        assert!(
            flushes <= 10,
            "expected flushes decoupled from {N} appends (batched), got {flushes}",
        );
        // And every entry is durably on disk after sync.
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content.lines().count(), N, "all entries must persist");
    }

    #[test]
    fn concurrent_appends_all_persist_after_sync() {
        // Many worker threads appending concurrently must lose nothing and
        // never tear a line (each line stays a valid JSON object). Drives
        // the single-writer channel design.
        use std::sync::Arc;
        use std::thread;

        let dir = tempdir();
        let path = dir.join("waf_audit.log");
        let sink = Arc::new(MinimalJsonlSink::open(&path).unwrap());

        const THREADS: usize = 8;
        const PER_THREAD: usize = 250;
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let s = Arc::clone(&sink);
                thread::spawn(move || {
                    for _ in 0..PER_THREAD {
                        s.append(&entry_template()).unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        sink.sync();

        let f = File::open(&path).unwrap();
        let lines: Vec<String> =
            BufReader::new(f).lines().filter_map(|l| l.ok()).collect();
        assert_eq!(
            lines.len(),
            THREADS * PER_THREAD,
            "no audit lines may be lost under concurrency",
        );
        for l in &lines {
            let v: serde_json::Value = serde_json::from_str(l)
                .unwrap_or_else(|e| panic!("torn line {l:?}: {e}"));
            assert!(v.is_object());
        }
    }

    #[test]
    fn ip_field_is_serialised_as_string() {
        let line = format_line(&entry_template());
        assert!(line.contains("\"ip\":\"127.0.0.1\""), "got {line}");
    }

    fn tempdir() -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir()
            .join(format!("aegis-hk-audit-{nanos}-{}", rand_u32()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn rand_u32() -> u32 {
        use std::sync::atomic::{AtomicU32, Ordering};
        static CTR: AtomicU32 = AtomicU32::new(0);
        CTR.fetch_add(1, Ordering::Relaxed)
    }
}
