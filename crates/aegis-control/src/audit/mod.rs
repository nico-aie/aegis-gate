pub mod chain;
pub mod sinks;
pub mod state_snapshot;
pub mod verify;
pub mod witness;

use aegis_core::audit::{AuditClass, AuditEvent};
use serde::{Deserialize, Serialize};

/// Admin change entry for the admin audit trail.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminChangeEntry {
    pub ts: chrono::DateTime<chrono::Utc>,
    pub actor: String,
    pub resource: String,
    pub action: String,
    pub reason: String,
    pub diff: serde_json::Value,
}

impl AdminChangeEntry {
    /// Convert to an AuditEvent for chain insertion.
    pub fn to_audit_event(&self, request_id: &str) -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts: self.ts,
            request_id: request_id.into(),
            class: AuditClass::Admin,
            tenant_id: None,
            tier: None,
            action: self.action.clone(),
            reason: self.reason.clone(),
            client_ip: String::new(),
            route_id: None,
            rule_id: None,
            risk_score: None,
            fields: serde_json::json!({
                "actor": self.actor,
                "resource": self.resource,
                "diff": self.diff,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_change_to_audit_event() {
        let entry = AdminChangeEntry {
            ts: chrono::Utc::now(),
            actor: "admin".into(),
            resource: "/api/config".into(),
            action: "update".into(),
            reason: "change TLS settings".into(),
            diff: serde_json::json!({"tls.min_version": {"old": "1.2", "new": "1.3"}}),
        };
        let ev = entry.to_audit_event("req-admin-1");
        assert_eq!(ev.request_id, "req-admin-1");
        assert!(matches!(ev.class, AuditClass::Admin));
        assert_eq!(ev.action, "update");
        let fields = ev.fields.as_object().unwrap();
        assert_eq!(fields["actor"], "admin");
        assert_eq!(fields["resource"], "/api/config");
    }

    #[test]
    fn admin_change_serializes() {
        let entry = AdminChangeEntry {
            ts: chrono::Utc::now(),
            actor: "ops".into(),
            resource: "/api/rules".into(),
            action: "create".into(),
            reason: "add sqli rule".into(),
            diff: serde_json::json!({"added": "rule-42"}),
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("ops"));
        assert!(json.contains("rule-42"));
    }

    #[test]
    fn admin_change_deserializes() {
        let json = r#"{"ts":"2024-01-15T12:00:00Z","actor":"admin","resource":"/api/config","action":"update","reason":"test","diff":{}}"#;
        let entry: AdminChangeEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.actor, "admin");
    }
}
