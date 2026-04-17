use crate::tier::Tier;

#[derive(Clone, Debug, serde::Serialize)]
pub struct AuditEvent {
    pub schema_version: u32,
    pub ts: chrono::DateTime<chrono::Utc>,
    pub request_id: String,
    pub class: AuditClass,
    pub tenant_id: Option<String>,
    pub tier: Option<Tier>,
    pub action: String,
    pub reason: String,
    pub client_ip: String,
    pub route_id: Option<String>,
    pub rule_id: Option<String>,
    pub risk_score: Option<u32>,
    pub fields: serde_json::Value,
}

#[derive(Copy, Clone, Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditClass {
    Detection,
    Admin,
    Access,
    System,
}

#[derive(Clone)]
pub struct AuditBus(tokio::sync::broadcast::Sender<AuditEvent>);

impl AuditBus {
    pub fn new(cap: usize) -> Self {
        let (tx, _) = tokio::sync::broadcast::channel(cap);
        Self(tx)
    }

    pub fn emit(&self, ev: AuditEvent) {
        let _ = self.0.send(ev);
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<AuditEvent> {
        self.0.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_event_serializes_to_json() {
        let ev = AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "req-001".into(),
            class: AuditClass::Detection,
            tenant_id: None,
            tier: Some(Tier::High),
            action: "block".into(),
            reason: "sqli detected".into(),
            client_ip: "1.2.3.4".into(),
            route_id: Some("api-users".into()),
            rule_id: Some("sqli-1".into()),
            risk_score: Some(85),
            fields: serde_json::json!({"detector": "sqli"}),
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"schema_version\":1"));
        assert!(json.contains("\"class\":\"detection\""));
    }

    #[test]
    fn audit_class_variants_serialize_snake_case() {
        let det = serde_json::to_string(&AuditClass::Detection).unwrap();
        let admin = serde_json::to_string(&AuditClass::Admin).unwrap();
        let access = serde_json::to_string(&AuditClass::Access).unwrap();
        let system = serde_json::to_string(&AuditClass::System).unwrap();

        assert_eq!(det, "\"detection\"");
        assert_eq!(admin, "\"admin\"");
        assert_eq!(access, "\"access\"");
        assert_eq!(system, "\"system\"");
    }

    #[test]
    fn audit_event_schema_version_starts_at_one() {
        let ev = AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "req-002".into(),
            class: AuditClass::System,
            tenant_id: None,
            tier: None,
            action: "startup".into(),
            reason: "waf started".into(),
            client_ip: "".into(),
            route_id: None,
            rule_id: None,
            risk_score: None,
            fields: serde_json::Value::Null,
        };
        assert_eq!(ev.schema_version, 1);
    }

    #[tokio::test]
    async fn audit_bus_emit_and_subscribe() {
        let bus = AuditBus::new(16);
        let mut rx = bus.subscribe();

        let ev = AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "req-bus".into(),
            class: AuditClass::Detection,
            tenant_id: None,
            tier: None,
            action: "block".into(),
            reason: "test".into(),
            client_ip: "1.2.3.4".into(),
            route_id: None,
            rule_id: None,
            risk_score: None,
            fields: serde_json::Value::Null,
        };
        bus.emit(ev);

        let received = rx.recv().await.unwrap();
        assert_eq!(received.request_id, "req-bus");
    }

    #[test]
    fn audit_bus_emit_without_subscribers_does_not_panic() {
        let bus = AuditBus::new(4);
        let ev = AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "req-no-sub".into(),
            class: AuditClass::System,
            tenant_id: None,
            tier: None,
            action: "test".into(),
            reason: "no subscriber".into(),
            client_ip: "".into(),
            route_id: None,
            rule_id: None,
            risk_score: None,
            fields: serde_json::Value::Null,
        };
        bus.emit(ev); // should not panic
    }
}
