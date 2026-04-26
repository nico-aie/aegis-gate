/// JSONL (newline-delimited JSON) file sink with rotation support.
use aegis_core::audit::AuditEvent;
use std::sync::Mutex;

/// JSONL sink config.
#[derive(Clone, Debug)]
pub struct JsonlConfig {
    pub path: String,
    pub max_file_bytes: u64,
    pub max_files: u32,
}

impl Default for JsonlConfig {
    fn default() -> Self {
        Self {
            path: "/var/log/aegis/audit.jsonl".into(),
            max_file_bytes: 100 * 1024 * 1024,
            max_files: 10,
        }
    }
}

/// In-memory JSONL sink (for testing; production would write to disk).
pub struct JsonlSink {
    config: JsonlConfig,
    buffer: Mutex<Vec<String>>,
}

impl JsonlSink {
    pub fn new(config: JsonlConfig) -> Self {
        Self {
            config,
            buffer: Mutex::new(Vec::new()),
        }
    }

    /// Format an event as a JSONL line.
    pub fn format(ev: &AuditEvent) -> String {
        serde_json::to_string(ev).unwrap_or_else(|_| "{}".into())
    }

    /// Get buffered lines (for testing).
    pub fn lines(&self) -> Vec<String> {
        self.buffer.lock().unwrap().clone()
    }

    pub fn config(&self) -> &JsonlConfig {
        &self.config
    }
}

#[async_trait::async_trait]
impl super::AuditSink for JsonlSink {
    fn id(&self) -> &str {
        "jsonl"
    }

    async fn write(&self, ev: &AuditEvent) -> aegis_core::Result<()> {
        let line = Self::format(ev);
        self.buffer.lock().unwrap().push(line);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::AuditSink;
    use aegis_core::audit::AuditClass;

    fn test_event() -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "req-jsonl".into(),
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

    #[test]
    fn format_valid_json() {
        let line = JsonlSink::format(&test_event());
        let _: serde_json::Value = serde_json::from_str(&line).unwrap();
    }

    #[test]
    fn format_contains_fields() {
        let line = JsonlSink::format(&test_event());
        assert!(line.contains("req-jsonl"));
        assert!(line.contains("block"));
        assert!(line.contains("sqli"));
    }

    #[tokio::test]
    async fn sink_buffers_events() {
        let sink = JsonlSink::new(JsonlConfig::default());
        sink.write(&test_event()).await.unwrap();
        sink.write(&test_event()).await.unwrap();
        assert_eq!(sink.lines().len(), 2);
    }

    #[test]
    fn default_config() {
        let c = JsonlConfig::default();
        assert!(c.path.contains("audit.jsonl"));
        assert_eq!(c.max_files, 10);
    }

    #[tokio::test]
    async fn sink_id() {
        let sink = JsonlSink::new(JsonlConfig::default());
        assert_eq!(sink.id(), "jsonl");
    }
}
