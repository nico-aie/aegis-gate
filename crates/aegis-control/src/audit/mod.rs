pub mod chain;
pub mod sinks;
pub mod state_snapshot;
pub mod verify;

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
    /// The actor's client IP as observed at the admin edge (RC-5a / V9).
    /// Empty string when unknown (e.g. a code path that bypasses the
    /// admin listener); `to_audit_event` maps it straight onto the
    /// top-level `AuditEvent.client_ip` so the durable chain records
    /// *where* an admin change came from, not just who.
    #[serde(default)]
    pub client_ip: String,
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
            action: self.action.as_str().into(),
            reason: self.reason.clone(),
            client_ip: self.client_ip.clone(),
            route_id: None,
            rule_id: None,
            risk_score: None,
            method: None,
            path: None,
            mode: None,
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
            client_ip: String::new(),
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
    fn to_audit_event_populates_client_ip() {
        // RC-5a / V9: the actor's real client IP must land on the
        // top-level AuditEvent.client_ip, not be dropped to "".
        let entry = AdminChangeEntry {
            ts: chrono::Utc::now(),
            actor: "ops".into(),
            resource: "/api/mode".into(),
            action: "mode_set".into(),
            reason: "pin enforce".into(),
            diff: serde_json::json!({}),
            client_ip: "203.0.113.7".into(),
        };
        let ev = entry.to_audit_event("req-mode-1");
        assert_eq!(ev.client_ip, "203.0.113.7");
    }

    #[test]
    fn to_audit_event_client_ip_empty_when_unknown() {
        // No recorded IP → empty fallback, never a panic.
        let entry = AdminChangeEntry {
            ts: chrono::Utc::now(),
            actor: "ops".into(),
            resource: "/api/mode".into(),
            action: "mode_set".into(),
            reason: "pin enforce".into(),
            diff: serde_json::json!({}),
            client_ip: String::new(),
        };
        let ev = entry.to_audit_event("req-mode-2");
        assert_eq!(ev.client_ip, "");
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
            client_ip: "198.51.100.4".into(),
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
