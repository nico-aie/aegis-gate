use aegis_core::audit::{AuditBus, AuditEvent};

/// Format an AuditEvent as an SSE `data:` line.
pub fn format_sse(ev: &AuditEvent) -> String {
    let json = serde_json::to_string(ev).unwrap_or_else(|_| "{}".into());
    format!("data: {json}\n\n")
}

/// SSE stream task: receives events from AuditBus and formats them.
///
/// Returns an async stream of SSE-formatted strings. Stops after `limit`
/// events or when the bus closes.
pub async fn stream_events(
    bus: &AuditBus,
    limit: usize,
) -> Vec<String> {
    let mut rx = bus.subscribe();
    let mut events = Vec::new();
    while events.len() < limit {
        match tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv()).await {
            Ok(Ok(ev)) => events.push(format_sse(&ev)),
            _ => break,
        }
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::audit::AuditClass;

    fn test_event(id: &str) -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: id.into(),
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
        }
    }

    #[test]
    fn format_sse_contains_data_prefix() {
        let ev = test_event("req-1");
        let sse = format_sse(&ev);
        assert!(sse.starts_with("data: "));
        assert!(sse.ends_with("\n\n"));
    }

    #[test]
    fn format_sse_contains_event_json() {
        let ev = test_event("req-sse");
        let sse = format_sse(&ev);
        assert!(sse.contains("req-sse"));
        assert!(sse.contains("detection"));
        assert!(sse.contains("block"));
    }

    #[test]
    fn format_sse_valid_json() {
        let ev = test_event("req-json");
        let sse = format_sse(&ev);
        let json_part = sse.strip_prefix("data: ").unwrap().trim();
        let parsed: serde_json::Value = serde_json::from_str(json_part).unwrap();
        assert_eq!(parsed["request_id"], "req-json");
    }

    #[tokio::test]
    async fn stream_receives_events() {
        let bus = AuditBus::new(16);
        let bus_clone = bus.clone();

        // Spawn stream receiver.
        let handle = tokio::spawn(async move {
            stream_events(&bus_clone, 2).await
        });

        // Give receiver time to subscribe.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        bus.emit(test_event("ev-1"));
        bus.emit(test_event("ev-2"));

        let events = handle.await.unwrap();
        assert_eq!(events.len(), 2);
        assert!(events[0].contains("ev-1"));
        assert!(events[1].contains("ev-2"));
    }

    #[tokio::test]
    async fn stream_stops_on_disconnect() {
        let bus = AuditBus::new(4);
        let bus_clone = bus.clone();

        let handle = tokio::spawn(async move {
            stream_events(&bus_clone, 100).await
        });

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        bus.emit(test_event("ev-x"));
        // Drop all senders by not emitting more — receiver will get lagged/closed.
        drop(bus);

        let events = handle.await.unwrap();
        // Should have received at least the one event before disconnect.
        assert!(!events.is_empty());
    }
}
