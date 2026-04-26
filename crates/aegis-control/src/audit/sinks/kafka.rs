/// Kafka sink stub.
use aegis_core::audit::AuditEvent;
use std::sync::Mutex;

/// Kafka config.
#[derive(Clone, Debug)]
pub struct KafkaConfig {
    pub brokers: Vec<String>,
    pub topic: String,
    pub key_field: String,
}

impl Default for KafkaConfig {
    fn default() -> Self {
        Self {
            brokers: vec!["localhost:9092".into()],
            topic: "aegis-audit".into(),
            key_field: "request_id".into(),
        }
    }
}

/// Kafka message for testing.
#[derive(Clone, Debug)]
pub struct KafkaMessage {
    pub key: String,
    pub value: String,
    pub topic: String,
}

/// In-memory Kafka sink (for testing).
pub struct KafkaSink {
    config: KafkaConfig,
    messages: Mutex<Vec<KafkaMessage>>,
}

impl KafkaSink {
    pub fn new(config: KafkaConfig) -> Self {
        Self {
            config,
            messages: Mutex::new(Vec::new()),
        }
    }

    pub fn messages(&self) -> Vec<KafkaMessage> {
        self.messages.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl super::AuditSink for KafkaSink {
    fn id(&self) -> &str {
        "kafka"
    }

    async fn write(&self, ev: &AuditEvent) -> aegis_core::Result<()> {
        let value = serde_json::to_string(ev).unwrap_or_default();
        let key = ev.request_id.clone();
        let msg = KafkaMessage {
            key,
            value,
            topic: self.config.topic.clone(),
        };
        self.messages.lock().unwrap().push(msg);
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
            request_id: "req-kafka".into(),
            class: AuditClass::Detection,
            tenant_id: None,
            tier: None,
            action: "block".into(),
            reason: "sqli".into(),
            client_ip: "1.2.3.4".into(),
            route_id: None,
            rule_id: None,
            risk_score: None,
            fields: serde_json::Value::Null,
        }
    }

    #[tokio::test]
    async fn kafka_sink_buffers() {
        let sink = KafkaSink::new(KafkaConfig::default());
        sink.write(&test_event()).await.unwrap();
        let msgs = sink.messages();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].key, "req-kafka");
        assert_eq!(msgs[0].topic, "aegis-audit");
    }

    #[tokio::test]
    async fn kafka_sink_id() {
        let sink = KafkaSink::new(KafkaConfig::default());
        assert_eq!(sink.id(), "kafka");
    }

    #[tokio::test]
    async fn kafka_message_is_json() {
        let sink = KafkaSink::new(KafkaConfig::default());
        sink.write(&test_event()).await.unwrap();
        let msg = &sink.messages()[0];
        let _: serde_json::Value = serde_json::from_str(&msg.value).unwrap();
    }

    #[test]
    fn default_config() {
        let c = KafkaConfig::default();
        assert_eq!(c.topic, "aegis-audit");
        assert_eq!(c.brokers.len(), 1);
    }
}
