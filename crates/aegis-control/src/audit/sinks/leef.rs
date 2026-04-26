/// LEEF (Log Event Extended Format) sink for QRadar.
use aegis_core::audit::AuditEvent;

/// Format as LEEF 2.0.
pub fn format_leef(ev: &AuditEvent) -> String {
    let severity = match ev.class {
        aegis_core::audit::AuditClass::Detection => 8,
        aegis_core::audit::AuditClass::Admin => 3,
        aegis_core::audit::AuditClass::Access => 1,
        aegis_core::audit::AuditClass::System => 3,
    };
    let sep = '\t';
    let mut attrs = format!(
        "src={}{sep}action={}{sep}reason={}{sep}sev={severity}",
        ev.client_ip, ev.action, ev.reason,
    );
    if let Some(route) = &ev.route_id {
        attrs.push_str(&format!("{sep}routeId={route}"));
    }
    if let Some(rule) = &ev.rule_id {
        attrs.push_str(&format!("{sep}ruleId={rule}"));
    }
    format!("LEEF:2.0|Aegis|WAF|1.0|{action}|{attrs}", action = ev.action)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::audit::AuditClass;

    fn test_event() -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "req-leef".into(),
            class: AuditClass::Detection,
            tenant_id: None,
            tier: None,
            action: "block".into(),
            reason: "xss".into(),
            client_ip: "10.0.0.1".into(),
            route_id: Some("web".into()),
            rule_id: None,
            risk_score: None,
            fields: serde_json::Value::Null,
        }
    }

    #[test]
    fn leef_header() {
        let line = format_leef(&test_event());
        assert!(line.starts_with("LEEF:2.0|Aegis|WAF|1.0|"));
    }

    #[test]
    fn leef_contains_src() {
        let line = format_leef(&test_event());
        assert!(line.contains("src=10.0.0.1"));
    }

    #[test]
    fn leef_contains_action() {
        let line = format_leef(&test_event());
        assert!(line.contains("action=block"));
    }

    #[test]
    fn leef_severity() {
        let line = format_leef(&test_event());
        assert!(line.contains("sev=8"));
    }

    #[test]
    fn leef_route_id() {
        let line = format_leef(&test_event());
        assert!(line.contains("routeId=web"));
    }
}
