/// CEF (Common Event Format) sink for ArcSight and similar SIEM platforms.
use aegis_core::audit::AuditEvent;

/// Format an event as CEF.
///
/// `CEF:0|Aegis|WAF|1.0|{action}|{reason}|{severity}|src={ip} ...`
pub fn format_cef(ev: &AuditEvent) -> String {
    let severity = match ev.class {
        aegis_core::audit::AuditClass::Detection => 7,
        aegis_core::audit::AuditClass::Admin => 3,
        aegis_core::audit::AuditClass::Access => 1,
        aegis_core::audit::AuditClass::System => 3,
    };
    let action = cef_escape(&ev.action);
    let reason = cef_escape(&ev.reason);
    let mut ext = format!("src={} requestId={}", ev.client_ip, ev.request_id);
    if let Some(route) = &ev.route_id {
        ext.push_str(&format!(" cs1={route}"));
    }
    if let Some(rule) = &ev.rule_id {
        ext.push_str(&format!(" cs2={rule}"));
    }
    if let Some(score) = ev.risk_score {
        ext.push_str(&format!(" cn1={score}"));
    }
    format!("CEF:0|Aegis|WAF|1.0|{action}|{reason}|{severity}|{ext}")
}

fn cef_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('|', "\\|")
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::audit::AuditClass;

    fn test_event() -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "req-cef".into(),
            class: AuditClass::Detection,
            tenant_id: None,
            tier: None,
            action: "block".into(),
            reason: "sqli detected".into(),
            client_ip: "1.2.3.4".into(),
            route_id: Some("api-users".into()),
            rule_id: Some("sqli-1".into()),
            risk_score: Some(85),
            fields: serde_json::Value::Null,
        }
    }

    #[test]
    fn cef_starts_with_header() {
        let line = format_cef(&test_event());
        assert!(line.starts_with("CEF:0|Aegis|WAF|1.0|"));
    }

    #[test]
    fn cef_contains_action_and_reason() {
        let line = format_cef(&test_event());
        assert!(line.contains("block"));
        assert!(line.contains("sqli detected"));
    }

    #[test]
    fn cef_contains_extensions() {
        let line = format_cef(&test_event());
        assert!(line.contains("src=1.2.3.4"));
        assert!(line.contains("requestId=req-cef"));
        assert!(line.contains("cs1=api-users"));
        assert!(line.contains("cs2=sqli-1"));
        assert!(line.contains("cn1=85"));
    }

    #[test]
    fn cef_escapes_pipes() {
        let mut ev = test_event();
        ev.action = "block|drop".into();
        let line = format_cef(&ev);
        assert!(line.contains("block\\|drop"));
    }

    #[test]
    fn cef_severity_detection() {
        let line = format_cef(&test_event());
        assert!(line.contains("|7|")); // severity 7 for detection
    }
}
