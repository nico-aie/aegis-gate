use aegis_core::audit::{AuditBus, AuditClass, AuditEvent};

/// Format an AuditEvent as an SSE `data:` line.
pub fn format_sse(ev: &AuditEvent) -> String {
    let json = serde_json::to_string(ev).unwrap_or_else(|_| "{}".into());
    format!("data: {json}\n\n")
}

/// Server-side filter applied to the SSE stream (D-M3-T3.1).
///
/// All fields are optional. An empty filter matches every event;
/// any populated field is an `AND` constraint that must match for the
/// event to be pushed to the client. Multiple values per field are
/// `OR`-combined (a query like `?class=detection&class=admin` lets
/// both classes through).
///
/// The Live Feed page consumes this on the client too — the filter
/// strip composes a query string when the user toggles a chip; the
/// SSE handler honours it without re-streaming filtered-out events.
#[derive(Clone, Debug, Default)]
pub struct EventFilter {
    pub classes: Vec<AuditClass>,
    pub actions: Vec<String>,
    pub routes: Vec<String>,
}

impl EventFilter {
    pub fn is_empty(&self) -> bool {
        self.classes.is_empty() && self.actions.is_empty() && self.routes.is_empty()
    }

    /// Parse filter from a raw query string. Recognises repeated
    /// `class=`, `action=`, `route=` parameters. Unknown classes are
    /// silently skipped (the URL is operator-supplied; we'd rather
    /// match nothing than 500).
    pub fn parse_query(query: &str) -> Self {
        let mut classes = Vec::new();
        let mut actions = Vec::new();
        let mut routes = Vec::new();
        for pair in query.split('&') {
            let Some((key, value)) = pair.split_once('=') else { continue };
            if value.is_empty() {
                continue;
            }
            match key {
                "class" => {
                    if let Some(c) = parse_class(value) {
                        classes.push(c);
                    }
                }
                "action" => actions.push(value.to_string()),
                "route" => routes.push(value.to_string()),
                _ => {}
            }
        }
        Self {
            classes,
            actions,
            routes,
        }
    }
}

fn parse_class(s: &str) -> Option<AuditClass> {
    match s.to_ascii_lowercase().as_str() {
        "detection" => Some(AuditClass::Detection),
        "admin" => Some(AuditClass::Admin),
        "access" => Some(AuditClass::Access),
        "system" => Some(AuditClass::System),
        _ => None,
    }
}

/// `true` if an audit event passes the filter.
pub fn event_matches(filter: &EventFilter, ev: &AuditEvent) -> bool {
    if !filter.classes.is_empty()
        && !filter.classes.iter().any(|c| audit_class_eq(c, &ev.class))
    {
        return false;
    }
    if !filter.actions.is_empty()
        && !filter.actions.iter().any(|a| a.as_str() == ev.action.as_str())
    {
        return false;
    }
    if !filter.routes.is_empty() {
        let route = ev.route_id.as_deref().unwrap_or("");
        if !filter.routes.iter().any(|r| r == route) {
            return false;
        }
    }
    true
}

fn audit_class_eq(a: &AuditClass, b: &AuditClass) -> bool {
    matches!(
        (a, b),
        (AuditClass::Detection, AuditClass::Detection)
            | (AuditClass::Admin, AuditClass::Admin)
            | (AuditClass::Access, AuditClass::Access)
            | (AuditClass::System, AuditClass::System)
    )
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
            method: None,
            path: None,
            mode: None,
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

    // ---------- D-M3-T3.1: SSE filter predicate ------------------------

    fn ev_full(
        class: AuditClass,
        action: &str,
        route: Option<&str>,
    ) -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "test".into(),
            class,
            tenant_id: None,
            tier: None,
            action: action.into(),
            reason: "test".into(),
            client_ip: "1.2.3.4".into(),
            route_id: route.map(|s| s.into()),
            rule_id: None,
            risk_score: None,
            method: None,
            path: None,
            mode: None,
            fields: serde_json::Value::Null,
        }
    }

    #[test]
    fn empty_filter_matches_everything() {
        let f = EventFilter::default();
        assert!(f.is_empty());
        assert!(event_matches(&f, &ev_full(AuditClass::Detection, "block", None)));
        assert!(event_matches(&f, &ev_full(AuditClass::Admin, "login", None)));
        assert!(event_matches(&f, &ev_full(AuditClass::Access, "allow", None)));
    }

    #[test]
    fn class_filter_keeps_only_matching_class() {
        let f = EventFilter {
            classes: vec![AuditClass::Detection],
            ..Default::default()
        };
        assert!(event_matches(&f, &ev_full(AuditClass::Detection, "block", None)));
        assert!(!event_matches(&f, &ev_full(AuditClass::Admin, "login", None)));
    }

    #[test]
    fn action_filter_is_or_combined() {
        let f = EventFilter {
            actions: vec!["block".into(), "challenge".into()],
            ..Default::default()
        };
        assert!(event_matches(&f, &ev_full(AuditClass::Detection, "block", None)));
        assert!(event_matches(&f, &ev_full(AuditClass::Detection, "challenge", None)));
        assert!(!event_matches(&f, &ev_full(AuditClass::Detection, "allow", None)));
    }

    #[test]
    fn route_filter_against_route_id() {
        let f = EventFilter {
            routes: vec!["api-users".into()],
            ..Default::default()
        };
        assert!(event_matches(
            &f,
            &ev_full(AuditClass::Detection, "block", Some("api-users"))
        ));
        assert!(!event_matches(
            &f,
            &ev_full(AuditClass::Detection, "block", Some("other"))
        ));
        assert!(!event_matches(&f, &ev_full(AuditClass::Detection, "block", None)));
    }

    #[test]
    fn fields_combine_with_and() {
        // class=Detection AND action=block: only events matching both
        let f = EventFilter {
            classes: vec![AuditClass::Detection],
            actions: vec!["block".into()],
            ..Default::default()
        };
        assert!(event_matches(&f, &ev_full(AuditClass::Detection, "block", None)));
        assert!(!event_matches(&f, &ev_full(AuditClass::Detection, "allow", None)));
        assert!(!event_matches(&f, &ev_full(AuditClass::Admin, "block", None)));
    }

    #[test]
    fn parse_query_recognises_documented_keys() {
        let f = EventFilter::parse_query("class=detection&action=block&route=api");
        assert_eq!(f.classes.len(), 1);
        assert!(matches!(f.classes[0], AuditClass::Detection));
        assert_eq!(f.actions, vec!["block"]);
        assert_eq!(f.routes, vec!["api"]);
    }

    #[test]
    fn parse_query_supports_repeated_keys() {
        let f = EventFilter::parse_query("class=detection&class=admin");
        assert_eq!(f.classes.len(), 2);
    }

    #[test]
    fn parse_query_skips_unknown_class_value() {
        let f = EventFilter::parse_query("class=bogus");
        assert!(f.classes.is_empty());
        assert!(f.is_empty());
    }

    #[test]
    fn parse_query_handles_empty_and_garbage() {
        // The parser must not panic on operator-supplied input.
        let _ = EventFilter::parse_query("");
        let _ = EventFilter::parse_query("=");
        let _ = EventFilter::parse_query("class");
        let _ = EventFilter::parse_query("&&");
        let _ = EventFilter::parse_query("class=&action=&route=");
    }

    #[test]
    fn filter_predicate_filters_thousand_events() {
        // Per the milestone: "feeds 1000 events, asserts predicate
        // filters them."
        let f = EventFilter {
            classes: vec![AuditClass::Detection],
            actions: vec!["block".into()],
            ..Default::default()
        };
        let mut matched = 0usize;
        for i in 0..1000 {
            let ev = if i % 5 == 0 {
                ev_full(AuditClass::Detection, "block", None)
            } else {
                ev_full(AuditClass::Access, "allow", None)
            };
            if event_matches(&f, &ev) {
                matched += 1;
            }
        }
        // Exactly the every-5th events match.
        assert_eq!(matched, 200);
    }

    // ---------- P1 (2026-07-02) — node scope filter -------------------
    //
    // Fleet-published events carry `fields.origin_node` (stamped by
    // `fleet_events::stamp_origin`); LOCAL events carry no origin — that
    // absence means "this node". A `?node=<id>` filter must therefore
    // match remote events by their stamp and local events by the
    // server-side self node id (never from the query string).

    fn ev_with_origin(origin: Option<&str>) -> AuditEvent {
        let mut ev = ev_full(AuditClass::Detection, "block", None);
        if let Some(o) = origin {
            ev.fields = serde_json::json!({ "origin_node": o });
        }
        ev
    }

    #[test]
    fn parse_query_recognises_node_key() {
        let f = EventFilter::parse_query("node=node-b");
        assert_eq!(f.node.as_deref(), Some("node-b"));
        assert!(!f.is_empty(), "a node filter is not an empty filter");
        // Absent → None (today's unscoped behavior).
        assert!(EventFilter::parse_query("class=detection").node.is_none());
    }

    #[test]
    fn parse_query_never_populates_self_node() {
        // self_node is server-supplied identity, not operator input — a
        // crafted query must not be able to set it.
        let f = EventFilter::parse_query("node=node-b&self_node=node-b");
        assert!(f.self_node.is_none());
    }

    #[test]
    fn node_filter_matches_remote_events_by_origin_stamp() {
        let f = EventFilter::parse_query("node=node-b").with_self_node(Some("node-a".into()));
        assert!(event_matches(&f, &ev_with_origin(Some("node-b"))));
        assert!(!event_matches(&f, &ev_with_origin(Some("node-c"))));
    }

    #[test]
    fn node_filter_matches_local_events_via_self_node() {
        // Local events have NO origin stamp — they belong to the self node.
        let scoped_to_self =
            EventFilter::parse_query("node=node-a").with_self_node(Some("node-a".into()));
        assert!(event_matches(&scoped_to_self, &ev_with_origin(None)));

        // Scoped to a peer → local (unstamped) events are filtered out.
        let scoped_to_peer =
            EventFilter::parse_query("node=node-b").with_self_node(Some("node-a".into()));
        assert!(!event_matches(&scoped_to_peer, &ev_with_origin(None)));

        // No self identity (single-node, roster off): a node filter can
        // only match stamped events — unstamped ones are excluded rather
        // than guessed.
        let no_identity = EventFilter::parse_query("node=node-a").with_self_node(None);
        assert!(!event_matches(&no_identity, &ev_with_origin(None)));
    }

    #[test]
    fn node_filter_and_combines_with_other_keys() {
        let f = EventFilter::parse_query("node=node-b&action=block")
            .with_self_node(Some("node-a".into()));
        // Right node + right action.
        assert!(event_matches(&f, &ev_with_origin(Some("node-b"))));
        // Right node, wrong action.
        let mut allow = ev_with_origin(Some("node-b"));
        allow.action = "allow".into();
        assert!(!event_matches(&f, &allow));
    }

    #[test]
    fn no_node_filter_keeps_merged_behavior() {
        // Unscoped ('all'): local + every peer's events pass, unchanged.
        let f = EventFilter::default().with_self_node(Some("node-a".into()));
        assert!(event_matches(&f, &ev_with_origin(None)));
        assert!(event_matches(&f, &ev_with_origin(Some("node-b"))));
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
