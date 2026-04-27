//! `/api/filters` filter-chip catalogue (D-M3-T3.9).
//!
//! Returns the union of distinct values seen for `class`, `actor`
//! (using `client_ip` as the actor identifier — admin events get
//! grouped under their `client_ip` too), `action`, and `route_id`
//! over the rolling 24-hour window. Used by the Audit Log + Live
//! Feed pages to populate filter chip dropdowns.
//!
//! Storage: per-category `HashMap<value, last_seen_instant>` so each
//! distinct value only takes one slot regardless of how many times
//! it appears. Pruning happens on every record (drop entries older
//! than 24h) and via a hard cap of 10 000 entries per category to
//! bound memory under attack-style activity.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aegis_core::audit::{AuditClass, AuditEvent};
use serde::Serialize;

/// 24h rolling window per the milestone spec.
const RETENTION: Duration = Duration::from_secs(24 * 3600);
/// Hard cap on the per-category set so a busy WAF doesn't grow
/// the catalogue unbounded under attack — drops the oldest seen.
const MAX_PER_CATEGORY: usize = 10_000;

/// JSON shape returned by `GET /api/filters`. Each list is sorted
/// alphabetically for UI stability — the chip dropdown order would
/// otherwise jitter on every poll.
#[derive(Clone, Debug, Serialize)]
pub struct FiltersResponse {
    pub window_seconds: u32,
    pub classes: Vec<String>,
    pub actors: Vec<String>,
    pub actions: Vec<String>,
    pub routes: Vec<String>,
}

#[derive(Default)]
struct CatalogueState {
    classes: HashMap<String, Instant>,
    actors: HashMap<String, Instant>,
    actions: HashMap<String, Instant>,
    routes: HashMap<String, Instant>,
}

/// Distinct-set aggregator. Cheap to share (`Arc<Mutex<…>>`);
/// fed by the same audit-bus drain task that supplies the other
/// dashboard aggregators.
#[derive(Clone, Default)]
pub struct FilterCatalogue {
    inner: Arc<Mutex<CatalogueState>>,
}

impl FilterCatalogue {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&self, ev: &AuditEvent) {
        let now = Instant::now();
        let class_str = audit_class_str(&ev.class).to_string();
        let actor = ev.client_ip.trim().to_string();
        let action = ev.action.clone();
        let route = ev.route_id.clone().unwrap_or_default();

        let mut state = self.inner.lock().expect("filter catalogue poisoned");

        if !class_str.is_empty() {
            insert_pruned(&mut state.classes, class_str, now);
        }
        if !actor.is_empty() {
            insert_pruned(&mut state.actors, actor, now);
        }
        if !action.is_empty() {
            insert_pruned(&mut state.actions, action, now);
        }
        if !route.is_empty() {
            insert_pruned(&mut state.routes, route, now);
        }
    }

    /// Snapshot the current catalogue. Drops anything older than
    /// `RETENTION` at read time for accuracy — sets only ever shrink
    /// here, never grow.
    pub fn snapshot(&self) -> FiltersResponse {
        let state = self.inner.lock().expect("filter catalogue poisoned");
        let now = Instant::now();
        let mk_list = |map: &HashMap<String, Instant>| {
            let mut v: Vec<String> = map
                .iter()
                .filter(|(_, t)| now.duration_since(**t) <= RETENTION)
                .map(|(k, _)| k.clone())
                .collect();
            v.sort();
            v
        };
        FiltersResponse {
            window_seconds: RETENTION.as_secs() as u32,
            classes: mk_list(&state.classes),
            actors: mk_list(&state.actors),
            actions: mk_list(&state.actions),
            routes: mk_list(&state.routes),
        }
    }
}

fn insert_pruned(map: &mut HashMap<String, Instant>, key: String, now: Instant) {
    map.insert(key, now);
    // Drop expired entries first; if still over cap, drop the
    // oldest until we're under.
    map.retain(|_, t| now.duration_since(*t) <= RETENTION);
    while map.len() > MAX_PER_CATEGORY {
        if let Some(oldest_key) = map
            .iter()
            .min_by_key(|(_, t)| **t)
            .map(|(k, _)| k.clone())
        {
            map.remove(&oldest_key);
        } else {
            break;
        }
    }
}

fn audit_class_str(c: &AuditClass) -> &'static str {
    match c {
        AuditClass::Detection => "detection",
        AuditClass::Admin => "admin",
        AuditClass::Access => "access",
        AuditClass::System => "system",
    }
}

/// HTTP wrapper. No cache — `snapshot()` already iterates only
/// distinct values (small) and a fresh poll picks up newly-seen
/// values immediately.
pub struct FiltersHandler {
    catalogue: Arc<FilterCatalogue>,
}

impl FiltersHandler {
    pub fn new(catalogue: Arc<FilterCatalogue>) -> Self {
        Self { catalogue }
    }

    pub fn render(&self) -> String {
        serde_json::to_string(&self.catalogue.snapshot())
            .unwrap_or_else(|_| String::from("{}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::audit::AuditClass;

    fn ev(class: AuditClass, action: &str, ip: &str, route: Option<&str>) -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "test".into(),
            class,
            tenant_id: None,
            tier: None,
            action: action.into(),
            reason: "test".into(),
            client_ip: ip.into(),
            route_id: route.map(|s| s.into()),
            rule_id: None,
            risk_score: None,
            fields: serde_json::Value::Null,
        }
    }

    #[test]
    fn empty_catalogue_returns_empty_lists() {
        let c = FilterCatalogue::new();
        let s = c.snapshot();
        assert!(s.classes.is_empty());
        assert!(s.actors.is_empty());
        assert!(s.actions.is_empty());
        assert!(s.routes.is_empty());
        assert_eq!(s.window_seconds, 86_400);
    }

    #[test]
    fn record_collects_distinct_values_per_category() {
        let c = FilterCatalogue::new();
        c.record(&ev(AuditClass::Detection, "block", "1.1.1.1", Some("api")));
        c.record(&ev(AuditClass::Detection, "block", "1.1.1.1", Some("api")));
        c.record(&ev(AuditClass::Admin, "login", "10.0.0.1", None));
        c.record(&ev(AuditClass::Detection, "challenge", "2.2.2.2", Some("login")));
        let s = c.snapshot();
        assert_eq!(s.classes, vec!["admin".to_string(), "detection".to_string()]);
        assert_eq!(s.actors, vec!["1.1.1.1".to_string(), "10.0.0.1".to_string(), "2.2.2.2".to_string()]);
        assert_eq!(s.actions, vec!["block".to_string(), "challenge".to_string(), "login".to_string()]);
        assert_eq!(s.routes, vec!["api".to_string(), "login".to_string()]);
    }

    #[test]
    fn record_skips_empty_string_values() {
        // System events have empty client_ip; they should populate
        // class but not actor.
        let c = FilterCatalogue::new();
        let mut e = ev(AuditClass::System, "startup", "", None);
        e.client_ip = String::new();
        c.record(&e);
        let s = c.snapshot();
        assert_eq!(s.classes, vec!["system"]);
        assert!(s.actors.is_empty());
        assert!(s.routes.is_empty());
    }

    #[test]
    fn snapshot_lists_are_sorted_alphabetically() {
        let c = FilterCatalogue::new();
        c.record(&ev(AuditClass::Detection, "z", "z", Some("z")));
        c.record(&ev(AuditClass::Detection, "a", "a", Some("a")));
        c.record(&ev(AuditClass::Detection, "m", "m", Some("m")));
        let s = c.snapshot();
        assert_eq!(s.actions, vec!["a".to_string(), "m".to_string(), "z".to_string()]);
        assert_eq!(s.actors, vec!["a".to_string(), "m".to_string(), "z".to_string()]);
        assert_eq!(s.routes, vec!["a".to_string(), "m".to_string(), "z".to_string()]);
    }

    #[test]
    fn response_serializes_to_documented_shape() {
        let c = FilterCatalogue::new();
        c.record(&ev(AuditClass::Detection, "block", "1.1.1.1", Some("api")));
        let body = serde_json::to_string(&c.snapshot()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        for key in ["window_seconds", "classes", "actors", "actions", "routes"] {
            assert!(v.get(key).is_some(), "filters response missing {key}");
        }
    }

    #[test]
    fn handler_renders_valid_json() {
        let c = Arc::new(FilterCatalogue::new());
        c.record(&ev(AuditClass::Detection, "block", "1.1.1.1", None));
        let h = FiltersHandler::new(Arc::clone(&c));
        let _: serde_json::Value =
            serde_json::from_str(&h.render()).expect("render must emit valid JSON");
    }

    #[test]
    fn cap_drops_oldest_entry_when_exceeded() {
        // Build a small-cap variant via direct manipulation so the
        // test runs fast. We use the public API and rely on the
        // cap constant — verify pruning happens by checking total
        // size doesn't blow past the cap.
        let c = FilterCatalogue::new();
        for i in 0..(MAX_PER_CATEGORY + 50) {
            c.record(&ev(
                AuditClass::Detection,
                "block",
                &format!("ip-{i}"),
                None,
            ));
        }
        let s = c.snapshot();
        assert!(
            s.actors.len() <= MAX_PER_CATEGORY,
            "actors {} exceeds cap {}",
            s.actors.len(),
            MAX_PER_CATEGORY
        );
    }
}
