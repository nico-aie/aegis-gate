//! `/api/incidents` — operator overlay on top of `SloEngine` alerts.
//!
//! The SLO engine surfaces what's currently *firing*. SOC analysts
//! need a layer above that: who's working it, when it was
//! acknowledged, whether it's snoozed, when it was resolved.
//!
//! This module owns that overlay. It does not replace `/api/alerts`
//! (which still returns the raw firing list) — it composes on top.
//!
//! ## State model
//!
//! Each incident is keyed by `alert_id`, derived from the
//! `SloAlert` shape as `<sli>:<fired_at_unix>`. The tracker holds:
//!
//! - `status`: `firing | acknowledged | snoozed | resolved`
//! - `acked_at` + `acked_by` (operator user)
//! - `snoozed_until` (incident hidden from the firing list until)
//! - `resolved_at`
//! - `note` (operator-supplied context)
//!
//! Snoozed incidents auto-resurrect: every render filters out
//! states whose `snoozed_until` has already passed.

use std::collections::HashMap;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::slo::SloAlert;

/// Lifecycle for an operator-tracked incident.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    Firing,
    Acknowledged,
    Snoozed,
    Resolved,
}

/// Operator overlay for one alert.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IncidentState {
    pub alert_id: String,
    pub status: IncidentStatus,
    pub acked_at: Option<DateTime<Utc>>,
    pub acked_by: Option<String>,
    pub snoozed_until: Option<DateTime<Utc>>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub note: Option<String>,
}

impl IncidentState {
    fn new(alert_id: String) -> Self {
        Self {
            alert_id,
            status: IncidentStatus::Firing,
            acked_at: None,
            acked_by: None,
            snoozed_until: None,
            resolved_at: None,
            note: None,
        }
    }
}

/// Stable ID for an alert.
///
/// MED-OBS-01 (2026-05-12) — the format includes `window_hours`
/// so multi-window alerts (1h / 6h / 72h on the same SLI) track
/// as distinct incidents.  Critically, this format also matches
/// the id the dashboard synthesizes when it POSTs to
/// `/api/incidents/<id>/ack`: the alerts API renders
/// `name = "{sli}-{window}h"` (see `tracking.rs::from_engine`),
/// and the dashboard does `id = format!("{name}:{ts}")`.  Before
/// this fix the overlay was written under the dashboard's key
/// but `enrich()` looked it up by the bare `{sli}:{ts}` key —
/// so ack POST returned 200 but the GET shape still reported
/// `firing` with `acked_at: null`.
pub fn alert_id(a: &SloAlert) -> String {
    format!("{:?}-{}h:{}", a.sli, a.window_hours, a.fired_at.timestamp())
}

/// In-process incident state.
pub struct IncidentTracker {
    state: Mutex<HashMap<String, IncidentState>>,
}

impl Default for IncidentTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl IncidentTracker {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Acknowledge an alert. Records `acked_at = now`, optional
    /// `acked_by`, and flips status from `Firing` to `Acknowledged`.
    /// Idempotent — re-acking just refreshes the timestamp.
    pub fn ack(&self, id: &str, by: Option<String>, note: Option<String>) -> IncidentState {
        let mut s = self.state.lock().expect("incident state poisoned");
        let entry = s
            .entry(id.to_string())
            .or_insert_with(|| IncidentState::new(id.to_string()));
        entry.status = IncidentStatus::Acknowledged;
        entry.acked_at = Some(Utc::now());
        entry.acked_by = by.or(entry.acked_by.take());
        if let Some(n) = note {
            entry.note = Some(n);
        }
        entry.clone()
    }

    /// Snooze an alert until `until`. The renderer hides snoozed
    /// incidents until the deadline passes.
    pub fn snooze(&self, id: &str, until: DateTime<Utc>, note: Option<String>) -> IncidentState {
        let mut s = self.state.lock().expect("incident state poisoned");
        let entry = s
            .entry(id.to_string())
            .or_insert_with(|| IncidentState::new(id.to_string()));
        entry.status = IncidentStatus::Snoozed;
        entry.snoozed_until = Some(until);
        if let Some(n) = note {
            entry.note = Some(n);
        }
        entry.clone()
    }

    /// Mark resolved. The SloEngine may still re-fire the alert if
    /// the underlying SLI breach returns; this overlay records the
    /// operator's "I'm done with this one" intent.
    pub fn resolve(&self, id: &str, by: Option<String>, note: Option<String>) -> IncidentState {
        let mut s = self.state.lock().expect("incident state poisoned");
        let entry = s
            .entry(id.to_string())
            .or_insert_with(|| IncidentState::new(id.to_string()));
        entry.status = IncidentStatus::Resolved;
        entry.resolved_at = Some(Utc::now());
        if entry.acked_by.is_none() {
            entry.acked_by = by;
        }
        if let Some(n) = note {
            entry.note = Some(n);
        }
        entry.clone()
    }

    /// Look up the overlay for one alert ID. `None` when the
    /// alert was never touched (still `Firing` from the engine's
    /// view).
    pub fn get(&self, id: &str) -> Option<IncidentState> {
        let mut s = self.state.lock().expect("incident state poisoned");
        // Auto-clear expired snoozes.
        if let Some(entry) = s.get_mut(id) {
            if entry.status == IncidentStatus::Snoozed {
                if let Some(until) = entry.snoozed_until {
                    if until < Utc::now() {
                        entry.status = IncidentStatus::Firing;
                        entry.snoozed_until = None;
                    }
                }
            }
            return Some(entry.clone());
        }
        None
    }

    /// Compose `SloEngine::active_alerts()` with our overlay.
    pub fn enrich(&self, active: Vec<SloAlert>) -> Vec<EnrichedAlert> {
        active
            .into_iter()
            .map(|a| {
                let id = alert_id(&a);
                let overlay = self.get(&id);
                let status = overlay
                    .as_ref()
                    .map(|s| s.status)
                    .unwrap_or(IncidentStatus::Firing);
                EnrichedAlert {
                    id,
                    sli: format!("{:?}", a.sli),
                    severity: format!("{:?}", a.severity).to_lowercase(),
                    fired_at: a.fired_at,
                    resolved_at: a.resolved_at,
                    burn_rate: a.burn_rate,
                    budget_consumed_pct: a.budget_consumed_pct,
                    window_hours: a.window_hours,
                    runbook_url: a.runbook_url,
                    status,
                    acked_at: overlay.as_ref().and_then(|s| s.acked_at),
                    acked_by: overlay.as_ref().and_then(|s| s.acked_by.clone()),
                    snoozed_until: overlay.as_ref().and_then(|s| s.snoozed_until),
                    incident_resolved_at: overlay.as_ref().and_then(|s| s.resolved_at),
                    note: overlay.and_then(|s| s.note),
                }
            })
            .collect()
    }
}

/// Wire shape for `GET /api/incidents`.
#[derive(Clone, Debug, Serialize)]
pub struct EnrichedAlert {
    pub id: String,
    pub sli: String,
    pub severity: String,
    pub fired_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub burn_rate: f64,
    pub budget_consumed_pct: f64,
    pub window_hours: u64,
    pub runbook_url: String,
    pub status: IncidentStatus,
    pub acked_at: Option<DateTime<Utc>>,
    pub acked_by: Option<String>,
    pub snoozed_until: Option<DateTime<Utc>>,
    pub incident_resolved_at: Option<DateTime<Utc>>,
    pub note: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slo::{AlertSeverity, SliKind};

    fn alert(sli: SliKind, ts: i64) -> SloAlert {
        SloAlert {
            sli,
            severity: AlertSeverity::Ticket,
            fired_at: DateTime::from_timestamp(ts, 0).unwrap(),
            resolved_at: None,
            burn_rate: 2.0,
            budget_consumed_pct: 25.0,
            window_hours: 1,
            runbook_url: "".into(),
            measured: 0.9985,
            target: 0.999,
        }
    }

    #[test]
    fn ack_marks_acknowledged_with_timestamp() {
        let t = IncidentTracker::new();
        let a = alert(SliKind::DataPlaneAvailability, 1700000000);
        let id = alert_id(&a);
        let s = t.ack(&id, Some("alice".into()), Some("looking at it".into()));
        assert_eq!(s.status, IncidentStatus::Acknowledged);
        assert!(s.acked_at.is_some());
        assert_eq!(s.acked_by.as_deref(), Some("alice"));
        assert_eq!(s.note.as_deref(), Some("looking at it"));
    }

    #[test]
    fn snooze_with_future_deadline_hides_in_active_view() {
        let t = IncidentTracker::new();
        let a = alert(SliKind::DataPlaneAvailability, 1700000000);
        let id = alert_id(&a);
        let until = Utc::now() + chrono::Duration::minutes(15);
        t.snooze(&id, until, None);
        let got = t.get(&id).unwrap();
        assert_eq!(got.status, IncidentStatus::Snoozed);
        assert_eq!(got.snoozed_until, Some(until));
    }

    #[test]
    fn snooze_with_past_deadline_auto_clears_to_firing() {
        let t = IncidentTracker::new();
        let a = alert(SliKind::DataPlaneAvailability, 1700000000);
        let id = alert_id(&a);
        let past = Utc::now() - chrono::Duration::minutes(1);
        t.snooze(&id, past, None);
        let got = t.get(&id).unwrap();
        // Reading the state auto-clears expired snooze.
        assert_eq!(got.status, IncidentStatus::Firing);
        assert!(got.snoozed_until.is_none());
    }

    #[test]
    fn resolve_marks_resolved_with_timestamp() {
        let t = IncidentTracker::new();
        let a = alert(SliKind::DataPlaneAvailability, 1700000000);
        let id = alert_id(&a);
        t.resolve(&id, Some("bob".into()), None);
        let got = t.get(&id).unwrap();
        assert_eq!(got.status, IncidentStatus::Resolved);
        assert!(got.resolved_at.is_some());
    }

    #[test]
    fn enrich_composes_engine_view_with_overlay() {
        let t = IncidentTracker::new();
        let a1 = alert(SliKind::DataPlaneAvailability, 1700000000);
        let a2 = alert(SliKind::WafOverheadP99, 1700000050);
        let id1 = alert_id(&a1);
        t.ack(&id1, Some("alice".into()), None);
        let enriched = t.enrich(vec![a1, a2]);
        assert_eq!(enriched.len(), 2);
        assert_eq!(enriched[0].status, IncidentStatus::Acknowledged);
        assert_eq!(enriched[0].acked_by.as_deref(), Some("alice"));
        assert_eq!(enriched[1].status, IncidentStatus::Firing);
        assert!(enriched[1].acked_at.is_none());
    }

    #[test]
    fn alert_id_is_stable_for_same_alert() {
        let a1 = alert(SliKind::DataPlaneAvailability, 1700000000);
        let a2 = alert(SliKind::DataPlaneAvailability, 1700000000);
        assert_eq!(alert_id(&a1), alert_id(&a2));
    }

    #[test]
    fn alert_id_differs_for_different_fired_at() {
        let a1 = alert(SliKind::DataPlaneAvailability, 1700000000);
        let a2 = alert(SliKind::DataPlaneAvailability, 1700000001);
        assert_ne!(alert_id(&a1), alert_id(&a2));
    }

    // MED-OBS-01 (2026-05-12) regression coverage.

    fn alert_with_window(sli: SliKind, ts: i64, window_hours: u64) -> SloAlert {
        SloAlert {
            sli,
            severity: AlertSeverity::Page,
            fired_at: DateTime::from_timestamp(ts, 0).unwrap(),
            resolved_at: None,
            burn_rate: 999.99,
            budget_consumed_pct: 99999.99,
            window_hours,
            runbook_url: "".into(),
            measured: 0.0,
            target: 0.999,
        }
    }

    #[test]
    fn alert_id_format_includes_window_hours_and_timestamp() {
        // Must match the dashboard-synthesized id:
        //   alerts API name = "<SliKind>-<N>h"
        //   dashboard id    = "<name>:<ts>"
        // → "<SliKind>-<N>h:<ts>"
        let a = alert_with_window(SliKind::DataPlaneAvailability, 1778570234, 1);
        assert_eq!(
            alert_id(&a),
            "DataPlaneAvailability-1h:1778570234",
            "format must match the dashboard ack URL synthesis"
        );
    }

    #[test]
    fn alert_id_differs_for_different_window_hours_on_same_sli() {
        let a1 = alert_with_window(SliKind::DataPlaneAvailability, 1700000000, 1);
        let a72 = alert_with_window(SliKind::DataPlaneAvailability, 1700000000, 72);
        assert_ne!(
            alert_id(&a1),
            alert_id(&a72),
            "multi-window alerts must track as distinct incidents"
        );
    }

    #[test]
    fn ack_then_enrich_returns_acknowledged_status() {
        // The MED-OBS-01 regression: the ack handler writes the
        // overlay under whatever id the path param carries, then
        // enrich() looks it up by `alert_id(&a)`.  Before the fix
        // these two strings disagreed; after the fix they match.
        let tracker = IncidentTracker::new();
        let a = alert_with_window(SliKind::DataPlaneAvailability, 1778570234, 1);
        let stored_id = alert_id(&a);
        tracker.ack(&stored_id, Some("admin".into()), None);

        let enriched = tracker.enrich(vec![a]);
        assert_eq!(enriched.len(), 1);
        assert_eq!(
            enriched[0].status,
            IncidentStatus::Acknowledged,
            "ack write must round-trip through enrich"
        );
        assert!(
            enriched[0].acked_at.is_some(),
            "acked_at must populate after the ack write"
        );
        assert_eq!(enriched[0].acked_by.as_deref(), Some("admin"));
    }
}
