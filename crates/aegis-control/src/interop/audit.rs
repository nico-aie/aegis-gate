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
use std::sync::Mutex;

use serde::Serialize;

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
}

/// Append-only file sink for [`MinimalAuditEntry`].
/// `reset_state` in the control plane MUST NOT truncate it.
pub struct MinimalJsonlSink {
    path: PathBuf,
    writer: Mutex<BufWriter<File>>,
}

impl MinimalJsonlSink {
    /// Open the file in append mode, creating it if missing.
    /// Returns an error only when the path is unwritable — the
    /// caller should fail-fast at boot in that case so the OC's
    /// startup probe doesn't silently miss audit evidence.
    pub fn open(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        Ok(Self {
            path,
            writer: Mutex::new(BufWriter::new(file)),
        })
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Append one entry. Each call writes a single newline-
    /// terminated JSON object and flushes the buffer so the OC
    /// sees the entry within the contract's correlation window.
    pub fn append(&self, entry: &MinimalAuditEntry) -> std::io::Result<()> {
        let mut line = serde_json::to_vec(entry).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e)
        })?;
        line.push(b'\n');
        let mut w = self.writer.lock().expect("audit writer poisoned");
        w.write_all(&line)?;
        w.flush()?;
        Ok(())
    }
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
