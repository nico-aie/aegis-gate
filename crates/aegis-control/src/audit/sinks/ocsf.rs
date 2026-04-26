/// OCSF (Open Cybersecurity Schema Framework) sink.
use aegis_core::audit::AuditEvent;
use serde::Serialize;

/// OCSF security finding (class_uid 2001).
#[derive(Serialize)]
pub struct OcsfFinding {
    pub class_uid: u32,
    pub category_uid: u32,
    pub severity_id: u32,
    pub activity_id: u32,
    pub time: i64,
    pub message: String,
    pub src_endpoint: OcsfEndpoint,
    pub metadata: OcsfMetadata,
    pub finding: OcsfFindingInfo,
}

#[derive(Serialize)]
pub struct OcsfEndpoint {
    pub ip: String,
}

#[derive(Serialize)]
pub struct OcsfMetadata {
    pub product: OcsfProduct,
    pub version: String,
}

#[derive(Serialize)]
pub struct OcsfProduct {
    pub name: String,
    pub vendor_name: String,
}

#[derive(Serialize)]
pub struct OcsfFindingInfo {
    pub uid: String,
    pub title: String,
    pub desc: String,
}

/// Convert AuditEvent to OCSF JSON.
pub fn format_ocsf(ev: &AuditEvent) -> String {
    let severity_id = match ev.class {
        aegis_core::audit::AuditClass::Detection => 3, // High
        aegis_core::audit::AuditClass::Admin => 1,     // Informational
        aegis_core::audit::AuditClass::Access => 1,
        aegis_core::audit::AuditClass::System => 2,    // Low
    };
    let finding = OcsfFinding {
        class_uid: 2001,
        category_uid: 2,
        severity_id,
        activity_id: 1,
        time: ev.ts.timestamp_millis(),
        message: ev.reason.clone(),
        src_endpoint: OcsfEndpoint {
            ip: ev.client_ip.clone(),
        },
        metadata: OcsfMetadata {
            product: OcsfProduct {
                name: "Aegis WAF".into(),
                vendor_name: "Aegis".into(),
            },
            version: "1.0.0".into(),
        },
        finding: OcsfFindingInfo {
            uid: ev.request_id.clone(),
            title: ev.action.clone(),
            desc: ev.reason.clone(),
        },
    };
    serde_json::to_string(&finding).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::audit::AuditClass;

    fn test_event() -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "req-ocsf".into(),
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

    #[test]
    fn ocsf_valid_json() {
        let json = format_ocsf(&test_event());
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["class_uid"], 2001);
    }

    #[test]
    fn ocsf_contains_product() {
        let json = format_ocsf(&test_event());
        assert!(json.contains("Aegis WAF"));
    }

    #[test]
    fn ocsf_contains_finding() {
        let json = format_ocsf(&test_event());
        assert!(json.contains("req-ocsf"));
        assert!(json.contains("sqli"));
    }

    #[test]
    fn ocsf_severity() {
        let json = format_ocsf(&test_event());
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["severity_id"], 3); // Detection → High
    }
}
