/// Elastic Common Schema (ECS) sink formatter.
use aegis_core::audit::AuditEvent;
use serde::Serialize;

/// ECS-formatted event.
#[derive(Serialize)]
pub struct EcsEvent {
    #[serde(rename = "@timestamp")]
    pub timestamp: String,
    pub event: EcsEventMeta,
    pub source: EcsSource,
    pub observer: EcsObserver,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<EcsRule>,
}

#[derive(Serialize)]
pub struct EcsEventMeta {
    pub kind: String,
    pub category: Vec<String>,
    pub action: String,
    pub outcome: String,
}

#[derive(Serialize)]
pub struct EcsSource {
    pub ip: String,
}

#[derive(Serialize)]
pub struct EcsObserver {
    pub product: String,
    pub vendor: String,
    #[serde(rename = "type")]
    pub obs_type: String,
}

#[derive(Serialize)]
pub struct EcsRule {
    pub id: String,
}

/// Format an AuditEvent as ECS JSON.
pub fn format_ecs(ev: &AuditEvent) -> String {
    let ecs = EcsEvent {
        timestamp: ev.ts.to_rfc3339(),
        event: EcsEventMeta {
            kind: "alert".into(),
            category: vec!["web".into()],
            action: ev.action.clone(),
            outcome: if ev.action == "allow" {
                "success".into()
            } else {
                "failure".into()
            },
        },
        source: EcsSource {
            ip: ev.client_ip.clone(),
        },
        observer: EcsObserver {
            product: "Aegis WAF".into(),
            vendor: "Aegis".into(),
            obs_type: "waf".into(),
        },
        message: ev.reason.clone(),
        rule: ev.rule_id.as_ref().map(|id| EcsRule { id: id.clone() }),
    };
    serde_json::to_string(&ecs).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::audit::AuditClass;

    fn test_event() -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "req-ecs".into(),
            class: AuditClass::Detection,
            tenant_id: None,
            tier: None,
            action: "block".into(),
            reason: "path traversal".into(),
            client_ip: "10.0.0.1".into(),
            route_id: None,
            rule_id: Some("pt-001".into()),
            risk_score: None,
            fields: serde_json::Value::Null,
        }
    }

    #[test]
    fn ecs_valid_json() {
        let json = format_ecs(&test_event());
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["observer"]["product"], "Aegis WAF");
    }

    #[test]
    fn ecs_contains_source_ip() {
        let json = format_ecs(&test_event());
        assert!(json.contains("10.0.0.1"));
    }

    #[test]
    fn ecs_has_rule() {
        let json = format_ecs(&test_event());
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["rule"]["id"], "pt-001");
    }

    #[test]
    fn ecs_no_rule_when_absent() {
        let mut ev = test_event();
        ev.rule_id = None;
        let json = format_ecs(&ev);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v.get("rule").is_none());
    }

    #[test]
    fn ecs_outcome_failure_for_block() {
        let json = format_ecs(&test_event());
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["event"]["outcome"], "failure");
    }

    #[test]
    fn ecs_outcome_success_for_allow() {
        let mut ev = test_event();
        ev.action = "allow".into();
        let json = format_ecs(&ev);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["event"]["outcome"], "success");
    }
}
