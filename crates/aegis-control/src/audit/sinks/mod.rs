pub mod cef;
pub mod ecs;
pub mod jsonl;
pub mod kafka;
pub mod leef;
pub mod ocsf;
pub mod splunk_hec;
pub mod syslog;

use aegis_core::audit::AuditEvent;

/// Audit sink trait.
#[async_trait::async_trait]
pub trait AuditSink: Send + Sync {
    /// Sink identifier.
    fn id(&self) -> &str;

    /// Write a single audit event.
    async fn write(&self, ev: &AuditEvent) -> aegis_core::Result<()>;
}

/// Sink delivery outcome for metrics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SinkOutcome {
    Delivered,
    Spooled,
    Dropped,
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummySink;

    #[async_trait::async_trait]
    impl AuditSink for DummySink {
        fn id(&self) -> &str {
            "dummy"
        }
        async fn write(&self, _ev: &AuditEvent) -> aegis_core::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn dummy_sink_works() {
        let sink = DummySink;
        assert_eq!(sink.id(), "dummy");
        let ev = AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "test".into(),
            class: aegis_core::audit::AuditClass::System,
            tenant_id: None,
            tier: None,
            action: "test".into(),
            reason: "test".into(),
            client_ip: "".into(),
            route_id: None,
            rule_id: None,
            risk_score: None,
            fields: serde_json::Value::Null,
        };
        sink.write(&ev).await.unwrap();
    }
}
