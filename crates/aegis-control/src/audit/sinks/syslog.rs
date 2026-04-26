/// Syslog sink (RFC 5424) — UDP/TLS stub.
use aegis_core::audit::AuditEvent;
use std::sync::Mutex;

/// Syslog transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyslogTransport {
    Udp,
    Tcp,
    Tls,
}

/// Syslog config.
#[derive(Clone, Debug)]
pub struct SyslogConfig {
    pub host: String,
    pub port: u16,
    pub transport: SyslogTransport,
    pub facility: u8,
    pub app_name: String,
}

impl Default for SyslogConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 514,
            transport: SyslogTransport::Udp,
            facility: 10, // security/authorization
            app_name: "aegis-waf".into(),
        }
    }
}

/// Format as RFC 5424 syslog message.
pub fn format_rfc5424(ev: &AuditEvent, config: &SyslogConfig) -> String {
    let severity = match ev.class {
        aegis_core::audit::AuditClass::Detection => 4, // warning
        aegis_core::audit::AuditClass::Admin => 6,     // informational
        aegis_core::audit::AuditClass::Access => 6,
        aegis_core::audit::AuditClass::System => 5,    // notice
    };
    let priority = config.facility * 8 + severity;
    let ts = ev.ts.to_rfc3339();
    let msg = serde_json::to_string(ev).unwrap_or_default();
    format!(
        "<{priority}>1 {ts} - {app} - - - {msg}",
        app = config.app_name,
    )
}

/// In-memory syslog sink (for testing).
pub struct SyslogSink {
    config: SyslogConfig,
    messages: Mutex<Vec<String>>,
}

impl SyslogSink {
    pub fn new(config: SyslogConfig) -> Self {
        Self {
            config,
            messages: Mutex::new(Vec::new()),
        }
    }

    pub fn messages(&self) -> Vec<String> {
        self.messages.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl super::AuditSink for SyslogSink {
    fn id(&self) -> &str {
        "syslog"
    }

    async fn write(&self, ev: &AuditEvent) -> aegis_core::Result<()> {
        let msg = format_rfc5424(ev, &self.config);
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
            request_id: "req-sys".into(),
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
    fn rfc5424_format_has_priority() {
        let msg = format_rfc5424(&test_event(), &SyslogConfig::default());
        assert!(msg.starts_with("<84>")); // facility=10 * 8 + severity=4
    }

    #[test]
    fn rfc5424_format_has_app_name() {
        let msg = format_rfc5424(&test_event(), &SyslogConfig::default());
        assert!(msg.contains("aegis-waf"));
    }

    #[test]
    fn rfc5424_format_has_event_data() {
        let msg = format_rfc5424(&test_event(), &SyslogConfig::default());
        assert!(msg.contains("req-sys"));
        assert!(msg.contains("block"));
    }

    #[tokio::test]
    async fn sink_buffers() {
        let sink = SyslogSink::new(SyslogConfig::default());
        sink.write(&test_event()).await.unwrap();
        assert_eq!(sink.messages().len(), 1);
    }

    #[test]
    fn admin_severity() {
        let mut ev = test_event();
        ev.class = AuditClass::Admin;
        let msg = format_rfc5424(&ev, &SyslogConfig::default());
        assert!(msg.starts_with("<86>")); // 10*8 + 6
    }
}
