//! HACK-T4 — `GET /api/config/versions` (Tier-B bonus).
//!
//! A timeline view of every audit-mutated configuration change
//! the WAF has accepted. Operators browse the list to answer
//! "who changed what when?" without grepping JSONL files.
//!
//! ## How "version" is defined
//!
//! Each entry in the [`crate::api::audit::AuditRing`] gets a
//! monotonic sequence number on insert. We expose that `seq` as
//! the version identifier for this surface. Version numbers
//! reset on process restart (the ring is in-process); the
//! audit chain's hash linking is the cross-restart identity
//! (verified offline via `waf audit verify`).
//!
//! ## What counts as a "config change"
//!
//! Any audit event with `class = Admin` is included. That
//! covers every audit-mutated PUT/POST/DELETE handler
//! (mode toggle, detector mask, rule CRUD, blacklist /
//! whitelist edits, alert receivers, upstream pool config,
//! risk thresholds, mTLS hot-reloads, etc.).
//! The dashboard renders one row per event with the action,
//! reason, actor (extracted from the `fields.user` field when
//! present), and an expandable JSON view of the full payload.
//!
//! ## What's NOT in this surface (deferred)
//!
//! - **Rollback**: re-applying an old configuration is per-
//!   handler logic (the audit event records WHAT changed but
//!   not the full pre-state for every mutation type). A
//!   rollback button on this surface would need either
//!   per-event before-state snapshots (more storage) or
//!   per-handler inverse-apply logic (more code). The plan
//!   in `plans/hackathon-readiness.md` HACK-T4 description
//!   explicitly defers rollback as a follow-up; this slice
//!   delivers the timeline browser, which is the visible
//!   Tier-B operator value per v2.3 §2.4.

use std::sync::Arc;

use serde::Serialize;

use crate::api::audit::AuditRing;
use aegis_core::audit::AuditClass;

/// One row of the timeline view.
#[derive(Clone, Debug, Serialize)]
pub struct ConfigVersionEntry {
    /// Monotonic version (audit-ring seq).
    pub seq: u64,
    /// ISO-8601 timestamp.
    pub ts: chrono::DateTime<chrono::Utc>,
    /// Audit action label (e.g. `mode_changed`,
    /// `detectors_updated`, `rule_upserted`, `tls_reloaded`).
    pub action: String,
    /// Free-form reason emitted by the mutation handler.
    pub reason: String,
    /// Actor — extracted from `fields.user` when the
    /// mutation handler stamped it; falls back to `"system"`
    /// for cfg-watcher-driven changes (file/etcd reload).
    pub actor: String,
    /// Source — `dashboard` for audit-mutated UI handlers,
    /// `file` / `etcd` for cfg-watcher reloads, `system`
    /// otherwise. Derived from `fields.source` when present.
    pub source: String,
    /// Request id from the original audit event — operators
    /// can paste this into the Audit Log filter to see the
    /// full event chain.
    pub request_id: String,
    /// Full audit-event `fields` payload — JSON object the
    /// dashboard renders inside the expandable per-row pane.
    pub fields: serde_json::Value,
}

/// JSON shape returned by `GET /api/config/versions`.
#[derive(Clone, Debug, Serialize)]
pub struct ConfigVersionsResponse {
    /// Total Admin-class events visible in the audit ring
    /// (after the requested `limit` is applied).
    pub count: usize,
    /// Whether the audit ring evicted older Admin-class
    /// events that didn't fit in the bounded buffer. Mirrors
    /// the gap field on `/api/audit/since` so operators know
    /// to consult the JSONL sink for full history.
    pub bounded: bool,
    /// Newest-first ordered timeline entries.
    pub versions: Vec<ConfigVersionEntry>,
}

/// Walk the audit ring and pick out every `class = Admin`
/// event, newest-first, capped at `limit`. Pure read — no
/// side effects on the ring.
pub fn render(ring: &Arc<AuditRing>, limit: u32) -> String {
    let resp = build(ring, limit);
    serde_json::to_string(&resp).unwrap_or_else(|_| "{}".into())
}

/// Test seam — returns the typed response so unit tests can
/// inspect fields without re-parsing JSON.
pub fn build(ring: &Arc<AuditRing>, limit: u32) -> ConfigVersionsResponse {
    let limit = limit.max(1);
    // Pull every event from the ring (it's bounded, so this
    // is at most the configured capacity — typically 1024).
    let snapshot = ring.since(0, u32::MAX);

    let mut admin_events: Vec<ConfigVersionEntry> = snapshot
        .events
        .into_iter()
        .filter(|e| matches!(e.event.class, AuditClass::Admin))
        .map(|e| ConfigVersionEntry {
            seq: e.seq,
            ts: e.event.ts,
            action: e.event.action.as_str().to_string(),
            reason: e.event.reason.clone(),
            actor: extract_actor(&e.event.fields),
            source: extract_source(&e.event.fields),
            request_id: e.event.request_id.clone(),
            fields: e.event.fields.clone(),
        })
        .collect();

    // Newest-first.
    admin_events.sort_by(|a, b| b.seq.cmp(&a.seq));

    // Cap at limit.
    let limit_usize = limit as usize;
    if admin_events.len() > limit_usize {
        admin_events.truncate(limit_usize);
    }

    ConfigVersionsResponse {
        count: admin_events.len(),
        bounded: snapshot.gap,
        versions: admin_events,
    }
}

fn extract_actor(fields: &serde_json::Value) -> String {
    fields
        .get("user")
        .and_then(|v| v.as_str())
        .or_else(|| fields.get("actor").and_then(|v| v.as_str()))
        .unwrap_or("system")
        .to_string()
}

fn extract_source(fields: &serde_json::Value) -> String {
    fields
        .get("source")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| {
            // Default heuristic: events with a `path` look
            // like cfg-watcher reloads (file source); the
            // rest are dashboard mutations.
            if fields.get("path").is_some() {
                "file"
            } else {
                "dashboard"
            }
        })
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::audit::{AuditClass, AuditEvent};

    fn admin_event(action: &str, reason: &str, fields: serde_json::Value) -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: format!("req-{action}"),
            class: AuditClass::Admin,
            tenant_id: None,
            tier: None,
            action: action.into(),
            reason: reason.into(),
            client_ip: String::new(),
            route_id: None,
            rule_id: None,
            risk_score: None,
            method: None,
            path: None,
            mode: None,
            fields,
        }
    }

    fn detection_event() -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "req-detection".into(),
            class: AuditClass::Detection,
            tenant_id: None,
            tier: None,
            action: "block".into(),
            reason: "sqli".into(),
            client_ip: "1.2.3.4".into(),
            route_id: None,
            rule_id: Some("sqli".into()),
            risk_score: Some(40),
            method: None,
            path: None,
            mode: None,
            fields: serde_json::json!({}),
        }
    }

    #[test]
    fn empty_ring_returns_zero_versions() {
        let ring = Arc::new(AuditRing::new());
        let resp = build(&ring, 50);
        assert_eq!(resp.count, 0);
        assert!(resp.versions.is_empty());
    }

    #[test]
    fn detection_events_are_excluded() {
        let ring = Arc::new(AuditRing::new());
        ring.record(detection_event());
        ring.record(detection_event());
        let resp = build(&ring, 50);
        assert_eq!(resp.count, 0, "Detection-class events must not appear");
    }

    #[test]
    fn admin_events_are_returned_newest_first() {
        let ring = Arc::new(AuditRing::new());
        ring.record(admin_event("mode_changed", "log_only → enforce", serde_json::json!({"user": "admin"})));
        ring.record(admin_event("detectors_updated", "sqli disabled", serde_json::json!({"user": "alice"})));
        ring.record(admin_event("rule_upserted", "id=block-bots", serde_json::json!({"user": "bob"})));

        let resp = build(&ring, 50);
        assert_eq!(resp.count, 3);
        // Newest first.
        assert_eq!(resp.versions[0].action, "rule_upserted");
        assert_eq!(resp.versions[0].actor, "bob");
        assert_eq!(resp.versions[1].action, "detectors_updated");
        assert_eq!(resp.versions[2].action, "mode_changed");
    }

    #[test]
    fn limit_caps_returned_rows() {
        let ring = Arc::new(AuditRing::new());
        for i in 0..10 {
            ring.record(admin_event(
                &format!("action_{i}"),
                &format!("reason_{i}"),
                serde_json::json!({"user": "u"}),
            ));
        }
        let resp = build(&ring, 5);
        assert_eq!(resp.count, 5);
        assert_eq!(resp.versions.len(), 5);
        // Newest first means action_9, action_8, action_7, action_6, action_5.
        assert_eq!(resp.versions[0].action, "action_9");
        assert_eq!(resp.versions[4].action, "action_5");
    }

    #[test]
    fn actor_falls_back_to_system_when_no_user_field() {
        let ring = Arc::new(AuditRing::new());
        ring.record(admin_event(
            "tls_reloaded",
            "cfg-watcher rotated certs",
            serde_json::json!({"path": "/etc/aegis/waf.yaml", "source": "file"}),
        ));
        let resp = build(&ring, 5);
        assert_eq!(resp.versions[0].actor, "system");
        assert_eq!(resp.versions[0].source, "file");
    }

    #[test]
    fn source_heuristic_when_field_absent() {
        let ring = Arc::new(AuditRing::new());
        // No `source` field; `path` present → file.
        ring.record(admin_event(
            "tls_reloaded",
            "cert rotation",
            serde_json::json!({"path": "/etc/aegis/waf.yaml"}),
        ));
        // No `source` and no `path` → dashboard.
        ring.record(admin_event(
            "mode_changed",
            "operator toggle",
            serde_json::json!({"user": "admin"}),
        ));
        let resp = build(&ring, 5);
        // Newest-first: mode_changed first.
        assert_eq!(resp.versions[0].source, "dashboard");
        assert_eq!(resp.versions[1].source, "file");
    }

    #[test]
    fn explicit_source_field_wins() {
        let ring = Arc::new(AuditRing::new());
        ring.record(admin_event(
            "config_reload",
            "etcd watcher",
            serde_json::json!({"source": "etcd"}),
        ));
        let resp = build(&ring, 5);
        assert_eq!(resp.versions[0].source, "etcd");
    }

    #[test]
    fn limit_zero_is_treated_as_one() {
        let ring = Arc::new(AuditRing::new());
        ring.record(admin_event("a", "r", serde_json::json!({})));
        ring.record(admin_event("b", "r", serde_json::json!({})));
        let resp = build(&ring, 0);
        assert_eq!(resp.count, 1);
    }

    #[test]
    fn render_produces_valid_json() {
        let ring = Arc::new(AuditRing::new());
        ring.record(admin_event(
            "mode_changed",
            "operator toggle",
            serde_json::json!({"user": "admin"}),
        ));
        let body = render(&ring, 50);
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["count"], 1);
        assert_eq!(parsed["versions"][0]["action"], "mode_changed");
        assert_eq!(parsed["versions"][0]["actor"], "admin");
    }

    #[test]
    fn fields_payload_is_preserved_for_diff_view() {
        let ring = Arc::new(AuditRing::new());
        let payload = serde_json::json!({
            "user": "admin",
            "before": {"mode": "enforce"},
            "after": {"mode": "log_only"},
        });
        ring.record(admin_event("mode_changed", "shadow rollout", payload.clone()));
        let resp = build(&ring, 5);
        assert_eq!(resp.versions[0].fields, payload);
    }

    #[test]
    fn admin_events_interleaved_with_detection_only_admin_returned() {
        let ring = Arc::new(AuditRing::new());
        ring.record(admin_event("rule_upserted", "id=r1", serde_json::json!({})));
        ring.record(detection_event());
        ring.record(admin_event("rule_deleted", "id=r1", serde_json::json!({})));
        ring.record(detection_event());
        ring.record(admin_event("mode_changed", "enforce", serde_json::json!({})));

        let resp = build(&ring, 50);
        assert_eq!(resp.count, 3);
        assert!(resp.versions.iter().all(|v| v.action.starts_with("rule_") || v.action == "mode_changed"));
    }
}
