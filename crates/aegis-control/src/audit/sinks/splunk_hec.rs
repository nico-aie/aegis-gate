/// Splunk HTTP Event Collector (HEC) sink stub.
use aegis_core::audit::AuditEvent;
use serde::Serialize;
use std::sync::Mutex;

/// HEC config.
#[derive(Clone, Debug)]
pub struct HecConfig {
    pub url: String,
    pub token: String,
    pub index: String,
    pub source_type: String,
}

/// HEC event payload.
#[derive(Serialize)]
pub struct HecPayload {
    pub time: f64,
    pub host: String,
    pub source: String,
    pub sourcetype: String,
    pub index: String,
    pub event: serde_json::Value,
}

/// Format an AuditEvent as a HEC payload.
pub fn format_hec(ev: &AuditEvent, config: &HecConfig) -> String {
    let payload = HecPayload {
        time: ev.ts.timestamp() as f64 + (ev.ts.timestamp_subsec_millis() as f64 / 1000.0),
        host: "aegis-waf".into(),
        source: "aegis:audit".into(),
        sourcetype: config.source_type.clone(),
        index: config.index.clone(),
        event: serde_json::to_value(ev).unwrap_or(serde_json::Value::Null),
    };
    serde_json::to_string(&payload).unwrap_or_default()
}

/// In-memory HEC sink (for testing).
pub struct HecSink {
    config: HecConfig,
    payloads: Mutex<Vec<String>>,
}

impl HecSink {
    pub fn new(config: HecConfig) -> Self {
        Self {
            config,
            payloads: Mutex::new(Vec::new()),
        }
    }

    pub fn payloads(&self) -> Vec<String> {
        self.payloads.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl super::AuditSink for HecSink {
    fn id(&self) -> &str {
        "splunk_hec"
    }

    async fn write(&self, ev: &AuditEvent) -> aegis_core::Result<()> {
        let payload = format_hec(ev, &self.config);
        self.payloads.lock().unwrap().push(payload);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::AuditSink;
    use aegis_core::audit::AuditClass;

    fn test_config() -> HecConfig {
        HecConfig {
            url: "https://splunk.local:8088".into(),
            token: "test-token".into(),
            index: "waf".into(),
            source_type: "aegis:audit".into(),
        }
    }

    fn test_event() -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "req-hec".into(),
            class: AuditClass::Detection,
            tenant_id: None,
            tier: None,
            action: "block".into(),
            reason: "xss".into(),
            client_ip: "5.6.7.8".into(),
            route_id: None,
            rule_id: None,
            risk_score: None,
            fields: serde_json::Value::Null,
        }
    }

    #[test]
    fn hec_format_valid_json() {
        let json = format_hec(&test_event(), &test_config());
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["host"], "aegis-waf");
        assert_eq!(v["index"], "waf");
    }

    #[test]
    fn hec_format_contains_event() {
        let json = format_hec(&test_event(), &test_config());
        assert!(json.contains("req-hec"));
        assert!(json.contains("block"));
    }

    #[tokio::test]
    async fn sink_buffers() {
        let sink = HecSink::new(test_config());
        sink.write(&test_event()).await.unwrap();
        assert_eq!(sink.payloads().len(), 1);
    }

    #[tokio::test]
    async fn sink_id() {
        let sink = HecSink::new(test_config());
        assert_eq!(sink.id(), "splunk_hec");
    }

    #[test]
    fn hec_time_is_epoch() {
        let json = format_hec(&test_event(), &test_config());
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["time"].as_f64().unwrap() > 1_000_000_000.0);
    }
}
