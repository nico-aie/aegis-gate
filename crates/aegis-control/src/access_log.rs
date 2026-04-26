/// Access log writer with multiple format support.
///
/// Formats: `combined` (Apache), `json` (ECS-compatible), `template` (custom).
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};

/// Access log format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogFormat {
    Combined,
    Json,
    Template(String),
}

/// Access log entry.
#[derive(Clone, Debug, Serialize)]
pub struct AccessLogEntry {
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub protocol: String,
    pub status: u16,
    pub body_bytes: u64,
    pub duration_ms: f64,
    pub user_agent: String,
    pub referer: String,
    pub request_id: String,
    pub ts: DateTime<Utc>,
}

/// Format an access log entry.
pub fn format_entry(entry: &AccessLogEntry, fmt: &LogFormat) -> String {
    match fmt {
        LogFormat::Combined => format_combined(entry),
        LogFormat::Json => format_json(entry),
        LogFormat::Template(tpl) => format_template(entry, tpl),
    }
}

/// Apache combined log format.
fn format_combined(e: &AccessLogEntry) -> String {
    let ts = e.ts.format("%d/%b/%Y:%H:%M:%S %z");
    format!(
        "{} - - [{}] \"{} {} {}\" {} {} \"{}\" \"{}\"",
        e.client_ip, ts, e.method, e.path, e.protocol,
        e.status, e.body_bytes, e.referer, e.user_agent,
    )
}

/// JSON (ECS-compatible) format.
fn format_json(e: &AccessLogEntry) -> String {
    serde_json::to_string(e).unwrap_or_else(|_| "{}".into())
}

/// Custom template format.
///
/// Supported variables: `$remote_addr`, `$request_method`, `$request_uri`,
/// `$status`, `$body_bytes_sent`, `$request_time`, `$http_user_agent`,
/// `$http_referer`, `$request_id`.
fn format_template(e: &AccessLogEntry, tpl: &str) -> String {
    tpl.replace("$remote_addr", &e.client_ip)
        .replace("$request_method", &e.method)
        .replace("$request_uri", &e.path)
        .replace("$status", &e.status.to_string())
        .replace("$body_bytes_sent", &e.body_bytes.to_string())
        .replace("$request_time", &format!("{:.3}", e.duration_ms / 1000.0))
        .replace("$http_user_agent", &e.user_agent)
        .replace("$http_referer", &e.referer)
        .replace("$request_id", &e.request_id)
}

/// Access log writer with bounded channel and drop counter.
pub struct AccessLogWriter {
    format: LogFormat,
    buffer: std::sync::Mutex<Vec<String>>,
    dropped: AtomicU64,
    max_buffer: usize,
}

impl AccessLogWriter {
    pub fn new(format: LogFormat, max_buffer: usize) -> Self {
        Self {
            format,
            buffer: std::sync::Mutex::new(Vec::new()),
            dropped: AtomicU64::new(0),
            max_buffer,
        }
    }

    /// Write an entry. Returns false if dropped due to backpressure.
    pub fn write(&self, entry: &AccessLogEntry) -> bool {
        let line = format_entry(entry, &self.format);
        let mut buf = self.buffer.lock().unwrap();
        if buf.len() >= self.max_buffer {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        buf.push(line);
        true
    }

    /// Drain all buffered lines.
    pub fn drain(&self) -> Vec<String> {
        let mut buf = self.buffer.lock().unwrap();
        std::mem::take(&mut *buf)
    }

    /// Number of dropped entries.
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Current buffer size.
    pub fn buffer_size(&self) -> usize {
        self.buffer.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_entry() -> AccessLogEntry {
        AccessLogEntry {
            client_ip: "1.2.3.4".into(),
            method: "GET".into(),
            path: "/api/users".into(),
            protocol: "HTTP/1.1".into(),
            status: 200,
            body_bytes: 1234,
            duration_ms: 42.5,
            user_agent: "Mozilla/5.0".into(),
            referer: "https://example.com".into(),
            request_id: "req-001".into(),
            ts: Utc::now(),
        }
    }

    // Combined format tests.
    #[test]
    fn combined_format_contains_ip() {
        let line = format_entry(&test_entry(), &LogFormat::Combined);
        assert!(line.starts_with("1.2.3.4"));
    }

    #[test]
    fn combined_format_contains_method() {
        let line = format_entry(&test_entry(), &LogFormat::Combined);
        assert!(line.contains("GET /api/users HTTP/1.1"));
    }

    #[test]
    fn combined_format_contains_status() {
        let line = format_entry(&test_entry(), &LogFormat::Combined);
        assert!(line.contains("200"));
    }

    #[test]
    fn combined_format_contains_ua() {
        let line = format_entry(&test_entry(), &LogFormat::Combined);
        assert!(line.contains("Mozilla/5.0"));
    }

    #[test]
    fn combined_format_contains_referer() {
        let line = format_entry(&test_entry(), &LogFormat::Combined);
        assert!(line.contains("https://example.com"));
    }

    #[test]
    fn combined_format_contains_bytes() {
        let line = format_entry(&test_entry(), &LogFormat::Combined);
        assert!(line.contains("1234"));
    }

    // JSON format tests.
    #[test]
    fn json_format_valid() {
        let line = format_entry(&test_entry(), &LogFormat::Json);
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["client_ip"], "1.2.3.4");
        assert_eq!(parsed["method"], "GET");
        assert_eq!(parsed["status"], 200);
    }

    #[test]
    fn json_format_contains_all_fields() {
        let line = format_entry(&test_entry(), &LogFormat::Json);
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert!(parsed.get("client_ip").is_some());
        assert!(parsed.get("method").is_some());
        assert!(parsed.get("path").is_some());
        assert!(parsed.get("status").is_some());
        assert!(parsed.get("body_bytes").is_some());
        assert!(parsed.get("duration_ms").is_some());
        assert!(parsed.get("user_agent").is_some());
        assert!(parsed.get("request_id").is_some());
    }

    #[test]
    fn json_format_duration() {
        let line = format_entry(&test_entry(), &LogFormat::Json);
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert!((parsed["duration_ms"].as_f64().unwrap() - 42.5).abs() < 0.01);
    }

    // Template format tests.
    #[test]
    fn template_substitution() {
        let tpl = "$remote_addr $request_method $request_uri $status".to_string();
        let line = format_entry(&test_entry(), &LogFormat::Template(tpl));
        assert_eq!(line, "1.2.3.4 GET /api/users 200");
    }

    #[test]
    fn template_request_time() {
        let tpl = "$request_time".to_string();
        let line = format_entry(&test_entry(), &LogFormat::Template(tpl));
        assert_eq!(line, "0.043"); // 42.5ms → 0.043s
    }

    #[test]
    fn template_request_id() {
        let tpl = "[$request_id]".to_string();
        let line = format_entry(&test_entry(), &LogFormat::Template(tpl));
        assert_eq!(line, "[req-001]");
    }

    #[test]
    fn template_all_vars() {
        let tpl = "$remote_addr $request_method $request_uri $status $body_bytes_sent $request_time $http_user_agent $http_referer $request_id".to_string();
        let line = format_entry(&test_entry(), &LogFormat::Template(tpl));
        assert!(line.contains("1.2.3.4"));
        assert!(line.contains("GET"));
        assert!(line.contains("/api/users"));
        assert!(line.contains("200"));
        assert!(line.contains("1234"));
        assert!(line.contains("Mozilla"));
        assert!(line.contains("req-001"));
    }

    // Writer tests.
    #[test]
    fn writer_buffers_entries() {
        let w = AccessLogWriter::new(LogFormat::Json, 100);
        assert!(w.write(&test_entry()));
        assert!(w.write(&test_entry()));
        assert_eq!(w.buffer_size(), 2);
    }

    #[test]
    fn writer_drain() {
        let w = AccessLogWriter::new(LogFormat::Json, 100);
        w.write(&test_entry());
        w.write(&test_entry());
        let lines = w.drain();
        assert_eq!(lines.len(), 2);
        assert_eq!(w.buffer_size(), 0);
    }

    #[test]
    fn writer_backpressure_drops() {
        let w = AccessLogWriter::new(LogFormat::Json, 2);
        assert!(w.write(&test_entry()));
        assert!(w.write(&test_entry()));
        assert!(!w.write(&test_entry())); // Dropped.
        assert_eq!(w.dropped_count(), 1);
        assert_eq!(w.buffer_size(), 2);
    }

    #[test]
    fn writer_dropped_counter() {
        let w = AccessLogWriter::new(LogFormat::Json, 1);
        w.write(&test_entry());
        w.write(&test_entry()); // Drop 1.
        w.write(&test_entry()); // Drop 2.
        assert_eq!(w.dropped_count(), 2);
    }

    #[test]
    fn writer_drain_resets_buffer() {
        let w = AccessLogWriter::new(LogFormat::Combined, 10);
        w.write(&test_entry());
        w.drain();
        assert!(w.write(&test_entry()));
        assert_eq!(w.buffer_size(), 1);
    }

    // Golden file comparisons.
    #[test]
    fn combined_golden() {
        let mut entry = test_entry();
        entry.ts = chrono::DateTime::parse_from_rfc3339("2024-01-15T12:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let line = format_entry(&entry, &LogFormat::Combined);
        assert!(line.contains("15/Jan/2024:12:30:00"));
        assert!(line.contains("GET /api/users HTTP/1.1"));
        assert!(line.contains("200 1234"));
    }

    #[test]
    fn json_golden() {
        let entry = test_entry();
        let line = format_entry(&entry, &LogFormat::Json);
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["path"], "/api/users");
        assert_eq!(v["status"], 200);
        assert_eq!(v["body_bytes"], 1234);
    }

    #[test]
    fn template_golden() {
        let tpl = "$remote_addr - [$request_method] $request_uri -> $status ($body_bytes_sent bytes, $request_time s)".to_string();
        let line = format_entry(&test_entry(), &LogFormat::Template(tpl));
        assert!(line.starts_with("1.2.3.4 - [GET] /api/users -> 200"));
    }

    // Status code variants.
    #[test]
    fn format_404() {
        let mut entry = test_entry();
        entry.status = 404;
        let line = format_entry(&entry, &LogFormat::Combined);
        assert!(line.contains("404"));
    }

    #[test]
    fn format_500() {
        let mut entry = test_entry();
        entry.status = 500;
        let line = format_entry(&entry, &LogFormat::Json);
        assert!(line.contains("500"));
    }

    #[test]
    fn format_post() {
        let mut entry = test_entry();
        entry.method = "POST".into();
        entry.path = "/api/data".into();
        let line = format_entry(&entry, &LogFormat::Combined);
        assert!(line.contains("POST /api/data"));
    }
}
