//! Deterministic per-event clustering for smart-catch triage
//! (Copilot — per-event follow-up to P3/P4).
//!
//! Groups recent audit events by the detector that fired (`rule_id`),
//! surfacing how a detector connects to specific source IPs + paths —
//! the cross-correlation the aggregate snapshot flattens away. The LLM
//! then names + explains + suggests rules over these **cluster
//! summaries** (never the raw events), which bounds token cost and PII
//! egress. Pure + deterministic so it's fully unit-testable.

use std::collections::{BTreeMap, HashSet};

use aegis_core::audit::{AuditAction, AuditEvent};

/// One deterministically-formed cluster, keyed by detector.
#[derive(Clone, Debug, serde::Serialize)]
pub struct EventCluster {
    /// Detector / rule that fired (`rule_id`).
    pub detector: String,
    pub events: usize,
    pub blocked: usize,
    pub distinct_ips: usize,
    /// Up to [`SAMPLE`] distinct source IPs (first-seen order).
    pub sample_ips: Vec<String>,
    /// Up to [`SAMPLE`] distinct request paths.
    pub sample_paths: Vec<String>,
}

const MAX_CLUSTERS: usize = 8;
const SAMPLE: usize = 5;

#[derive(Default)]
struct Acc {
    events: usize,
    blocked: usize,
    sample_ips: Vec<String>,
    sample_paths: Vec<String>,
    ip_set: HashSet<String>,
    path_set: HashSet<String>,
}

/// Cluster recent audit events by detector (`rule_id`). Only events that
/// name a detector are clustered — plain allows aren't campaign signal.
/// Sorted by event count (desc), capped at [`MAX_CLUSTERS`].
pub fn cluster_events(events: &[AuditEvent]) -> Vec<EventCluster> {
    let mut groups: BTreeMap<String, Acc> = BTreeMap::new();
    for ev in events {
        let detector = match ev.rule_id.as_deref() {
            Some(d) if !d.is_empty() => d,
            _ => continue,
        };
        let acc = groups.entry(detector.to_string()).or_default();
        acc.events += 1;
        if matches!(ev.action, AuditAction::Block) {
            acc.blocked += 1;
        }
        if acc.ip_set.insert(ev.client_ip.clone()) && acc.sample_ips.len() < SAMPLE {
            acc.sample_ips.push(ev.client_ip.clone());
        }
        if let Some(p) = ev.path.as_deref() {
            if acc.path_set.insert(p.to_string()) && acc.sample_paths.len() < SAMPLE {
                acc.sample_paths.push(p.to_string());
            }
        }
    }
    let mut out: Vec<EventCluster> = groups
        .into_iter()
        .map(|(detector, a)| EventCluster {
            detector,
            events: a.events,
            blocked: a.blocked,
            distinct_ips: a.ip_set.len(),
            sample_ips: a.sample_ips,
            sample_paths: a.sample_paths,
        })
        .collect();
    out.sort_by(|a, b| b.events.cmp(&a.events).then_with(|| a.detector.cmp(&b.detector)));
    out.truncate(MAX_CLUSTERS);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::audit::{AuditClass, AuditEvent};

    fn ev(detector: Option<&str>, ip: &str, path: &str, action: AuditAction) -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "r".into(),
            class: AuditClass::Detection,
            tenant_id: None,
            tier: None,
            action,
            reason: String::new(),
            client_ip: ip.into(),
            route_id: None,
            rule_id: detector.map(|d| d.into()),
            risk_score: None,
            method: Some("GET".into()),
            path: Some(path.into()),
            mode: None,
            fields: serde_json::Value::Null,
        }
    }

    #[test]
    fn clusters_by_detector_with_distinct_ips_and_blocked() {
        let events = vec![
            ev(Some("sqli"), "1.1.1.1", "/login", AuditAction::Block),
            ev(Some("sqli"), "1.1.1.2", "/search", AuditAction::Block),
            ev(Some("sqli"), "1.1.1.1", "/login", AuditAction::Challenge),
            ev(Some("xss"), "2.2.2.2", "/comment", AuditAction::Block),
        ];
        let clusters = cluster_events(&events);
        assert_eq!(clusters.len(), 2);
        // Sorted by event count — sqli (3) first.
        let sqli = &clusters[0];
        assert_eq!(sqli.detector, "sqli");
        assert_eq!(sqli.events, 3);
        assert_eq!(sqli.blocked, 2); // two Block, one Challenge
        assert_eq!(sqli.distinct_ips, 2);
        assert!(sqli.sample_paths.contains(&"/login".to_string()));
        assert!(sqli.sample_paths.contains(&"/search".to_string()));
    }

    #[test]
    fn skips_events_without_a_detector() {
        let events = vec![
            ev(None, "1.1.1.1", "/", AuditAction::Allow),
            ev(Some(""), "1.1.1.2", "/", AuditAction::Allow),
            ev(Some("sqli"), "1.1.1.3", "/x", AuditAction::Block),
        ];
        let clusters = cluster_events(&events);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].detector, "sqli");
    }

    #[test]
    fn samples_capped_but_distinct_count_exact() {
        let events: Vec<AuditEvent> = (0..10)
            .map(|i| ev(Some("sqli"), &format!("10.0.0.{i}"), "/x", AuditAction::Block))
            .collect();
        let c = &cluster_events(&events)[0];
        assert_eq!(c.distinct_ips, 10, "all distinct IPs counted");
        assert_eq!(c.sample_ips.len(), SAMPLE, "sample capped at 5");
    }

    #[test]
    fn empty_input_yields_no_clusters() {
        assert!(cluster_events(&[]).is_empty());
    }
}
