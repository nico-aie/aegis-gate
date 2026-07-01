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
//! Each incident is keyed by `incident_uid` (`<SLI>-<window>h`),
//! node-independent so overlay converges across the fleet. The tracker holds:
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
use std::sync::{Arc, Mutex};

use aegis_core::state::{StateBackend, CONTROL_INCIDENTS_KEY};
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
/// IF-P1a (incidents fleet federation) — node-independent incident
/// identity: `<SLI>-<window>h` (e.g. `DataPlaneAvailability-1h`).
///
/// The per-node fire timestamp is deliberately NOT part of the identity.
/// The same SLI+window is ONE logical incident across the fleet (and
/// across re-fires), so ack/snooze/resolve overlay converges by uid —
/// the prerequisite for federating incidents cross-node. `fired_at` is
/// still surfaced as a display field on `EnrichedAlert`, just not in the
/// key. This now matches `tracking.rs::from_engine`, which already keys
/// its ack-store on the bare `{:?}-{}h` (incidents.rs was the outlier
/// that appended `:{ts}`).
///
/// `window_hours` stays in the key so multi-window alerts (1h / 6h / 72h
/// on the same SLI) remain distinct incidents.
pub fn incident_uid(a: &SloAlert) -> String {
    format!("{:?}-{}h", a.sli, a.window_hours)
}

/// Durable write of one incident overlay (field = `alert_id`, value =
/// JSON) to `control:waf:incidents`. Best-effort: an encode or backend
/// error is logged and swallowed — the operator action already succeeded
/// in memory, and persistence is strictly subordinate to the live overlay
/// (durability plan §6).
async fn persist_to(backend: &Arc<dyn StateBackend>, state: &IncidentState) {
    let json = match serde_json::to_vec(state) {
        Ok(j) => j,
        Err(e) => {
            tracing::warn!(error = %e, id = %state.alert_id, "incident persist: encode failed");
            return;
        }
    };
    if let Err(e) = backend
        .hset_multi(CONTROL_INCIDENTS_KEY, &[(state.alert_id.clone(), json)])
        .await
    {
        tracing::warn!(error = %e, id = %state.alert_id, "incident persist: write failed");
    }
}

/// In-process incident state.
pub struct IncidentTracker {
    state: Mutex<HashMap<String, IncidentState>>,
    /// 2026-06-24 — durable-store handle for the interim Redis durability
    /// bridge (`redis-interim-durability` P1). `None` on the no-Redis /
    /// single-node path, which behaves exactly as before. A0 only stores
    /// the handle (inert); the write-through on ack/snooze/resolve and the
    /// boot hydrate that read it land in A1. Constructor-injected (unlike
    /// `RiskTracker`'s setter) because the tracker is built late enough
    /// (`dashboard_services::spawn_*`) that the backend already exists.
    backend: Option<Arc<dyn StateBackend>>,
}

impl Default for IncidentTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl IncidentTracker {
    pub fn new() -> Self {
        Self::with_backend(None)
    }

    /// Build a tracker with an optional durable backend. Pass `Some(..)`
    /// (under `#[cfg(feature = "redis")]`) to enable P1 durability; `None`
    /// is the in-memory-only path.
    pub fn with_backend(backend: Option<Arc<dyn StateBackend>>) -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
            backend,
        }
    }

    // --- 2026-06-24 (redis-interim-durability P1) — durable overlay. ---

    /// Fire-and-forget the durable write for `state` off the operator's
    /// request path. Spawns only when a backend is attached AND a Tokio
    /// runtime is live (unit tests without a reactor simply skip — they
    /// exercise the free `persist_to` helper directly). The operator's HTTP
    /// response never blocks on Redis.
    fn spawn_persist(&self, state: IncidentState) {
        let Some(backend) = self.backend.clone() else {
            return;
        };
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        tokio::spawn(async move {
            persist_to(&backend, &state).await;
        });
    }

    /// Boot hydration (P1): load the durable overlay from
    /// `control:waf:incidents` into the in-memory read cache. Runs once at
    /// startup before serving. No-op without a backend. A decode failure on
    /// one field is logged and skipped — one corrupt entry must not block
    /// the rest of the overlay from loading.
    pub async fn hydrate(&self) {
        let Some(backend) = self.backend.as_ref() else {
            return;
        };
        let fields = match backend.hscan(CONTROL_INCIDENTS_KEY).await {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(error = %e, "incident hydrate: hscan failed");
                return;
            }
        };
        let mut loaded = 0usize;
        let mut s = self.state.lock().expect("incident state poisoned");
        for (id, bytes) in fields {
            match serde_json::from_slice::<IncidentState>(&bytes) {
                Ok(state) => {
                    s.insert(id, state);
                    loaded += 1;
                }
                Err(e) => {
                    tracing::warn!(error = %e, field = %id, "incident hydrate: decode skipped")
                }
            }
        }
        if loaded > 0 {
            tracing::info!(loaded, "incident overlay hydrated from durable store");
        }
    }

    /// Reset hook (sync half) — drop the in-memory overlay. Paired with
    /// [`unlink_durable`] on `/__waf_control/reset_state` so a reset gives a
    /// clean incident slate that does not resurrect on the next boot
    /// (durability plan §4).
    ///
    /// [`unlink_durable`]: Self::unlink_durable
    pub fn clear_local(&self) {
        self.state.lock().expect("incident state poisoned").clear();
    }

    /// Reset hook (async half) — `UNLINK` the durable hash. No-op without a
    /// backend. Swallows-with-log like the other reset cleaners: a backend
    /// hiccup must not turn a reset into an error.
    pub async fn unlink_durable(&self) {
        let Some(backend) = self.backend.as_ref() else {
            return;
        };
        if let Err(e) = backend.unlink(CONTROL_INCIDENTS_KEY).await {
            tracing::warn!(error = %e, "incident reset: durable unlink failed");
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
        let snapshot = entry.clone();
        drop(s);
        self.spawn_persist(snapshot.clone());
        snapshot
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
        let snapshot = entry.clone();
        drop(s);
        self.spawn_persist(snapshot.clone());
        snapshot
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
        let snapshot = entry.clone();
        drop(s);
        self.spawn_persist(snapshot.clone());
        snapshot
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
                let id = incident_uid(&a);
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
    fn incident_uid_is_node_independent_across_fire_times() {
        // The same SLI+window firing at different wall-clock times (i.e.
        // on different fleet nodes) must share ONE identity, so an ack on
        // any node's fire converges with every other node's view.
        let a1 = alert(SliKind::DataPlaneAvailability, 1700000000);
        let a2 = alert(SliKind::DataPlaneAvailability, 1700009999); // later fire
        assert_eq!(incident_uid(&a1), incident_uid(&a2));
        assert!(
            !incident_uid(&a1).contains(':'),
            "uid must not carry a per-node fire timestamp"
        );

        // Ack keyed by the uid is visible when enriching a *different*
        // node's fire of the same incident.
        let t = IncidentTracker::new();
        t.ack(&incident_uid(&a1), Some("alice".into()), None);
        let enriched = t.enrich(vec![a2]);
        assert_eq!(enriched.len(), 1);
        assert_eq!(enriched[0].id, incident_uid(&a1));
        assert_eq!(enriched[0].status, IncidentStatus::Acknowledged);
        assert_eq!(enriched[0].acked_by.as_deref(), Some("alice"));
    }

    #[test]
    fn ack_marks_acknowledged_with_timestamp() {
        let t = IncidentTracker::new();
        let a = alert(SliKind::DataPlaneAvailability, 1700000000);
        let id = incident_uid(&a);
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
        let id = incident_uid(&a);
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
        let id = incident_uid(&a);
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
        let id = incident_uid(&a);
        t.resolve(&id, Some("bob".into()), None);
        let got = t.get(&id).unwrap();
        assert_eq!(got.status, IncidentStatus::Resolved);
        assert!(got.resolved_at.is_some());
    }

    // ---- 2026-06-24 P1 incident durability (A1) -----------------------

    /// Minimal stateful backend that actually stores hashes, so the durable
    /// round-trip (persist → hydrate) is deterministic without a live Redis.
    /// Every non-hash method is an inert default-or-trivial impl.
    #[derive(Clone, Default)]
    struct MapHashBackend {
        hashes: Arc<std::sync::Mutex<HashMap<String, HashMap<String, Vec<u8>>>>>,
    }
    #[async_trait::async_trait]
    impl StateBackend for MapHashBackend {
        async fn get(&self, _k: &str) -> aegis_core::Result<Option<Vec<u8>>> { Ok(None) }
        async fn set(&self, _k: &str, _v: &[u8], _t: std::time::Duration) -> aegis_core::Result<()> { Ok(()) }
        async fn del(&self, _k: &str) -> aegis_core::Result<()> { Ok(()) }
        async fn incr_window(&self, _k: &str, _w: std::time::Duration, _l: u64) -> aegis_core::Result<aegis_core::SlidingWindowResult> {
            Ok(aegis_core::SlidingWindowResult { count: 0, allowed: true, retry_after: None })
        }
        async fn token_bucket(&self, _k: &str, _r: u32, _b: u32) -> aegis_core::Result<bool> { Ok(true) }
        async fn get_risk(&self, _k: &aegis_core::risk::RiskKey) -> aegis_core::Result<u32> { Ok(0) }
        async fn add_risk(&self, _k: &aegis_core::risk::RiskKey, _d: i32, _m: u32) -> aegis_core::Result<u32> { Ok(0) }
        async fn auto_block(&self, _ip: std::net::IpAddr, _t: std::time::Duration) -> aegis_core::Result<()> { Ok(()) }
        async fn is_auto_blocked(&self, _ip: std::net::IpAddr) -> aegis_core::Result<bool> { Ok(false) }
        async fn put_nonce(&self, _n: &str, _t: std::time::Duration) -> aegis_core::Result<bool> { Ok(true) }
        async fn consume_nonce(&self, _n: &str) -> aegis_core::Result<bool> { Ok(true) }
        async fn hset_multi(&self, key: &str, fields: &[(String, Vec<u8>)]) -> aegis_core::Result<()> {
            let mut g = self.hashes.lock().unwrap();
            let h = g.entry(key.to_string()).or_default();
            for (f, v) in fields { h.insert(f.clone(), v.clone()); }
            Ok(())
        }
        async fn hdel(&self, key: &str, fields: &[String]) -> aegis_core::Result<()> {
            if let Some(h) = self.hashes.lock().unwrap().get_mut(key) {
                for f in fields { h.remove(f); }
            }
            Ok(())
        }
        async fn hscan(&self, key: &str) -> aegis_core::Result<Vec<(String, Vec<u8>)>> {
            Ok(self.hashes.lock().unwrap().get(key)
                .map(|h| h.iter().map(|(f, v)| (f.clone(), v.clone())).collect())
                .unwrap_or_default())
        }
        async fn unlink(&self, key: &str) -> aegis_core::Result<()> {
            self.hashes.lock().unwrap().remove(key);
            Ok(())
        }
    }

    fn backend() -> Arc<MapHashBackend> {
        Arc::new(MapHashBackend::default())
    }

    /// Pump the runtime until `f` is true or the bound is hit. Used to await
    /// the fire-and-forget `spawn_persist` task deterministically (it runs
    /// on the same runtime as the test).
    async fn wait_until<F: Fn() -> bool>(f: F) {
        for _ in 0..1000 {
            if f() { return; }
            tokio::task::yield_now().await;
        }
        panic!("condition not met within bound");
    }

    #[tokio::test]
    async fn ack_writes_through_to_durable_store() {
        let be = backend();
        let t = IncidentTracker::with_backend(Some(be.clone() as Arc<dyn StateBackend>));
        let a = alert(SliKind::DataPlaneAvailability, 1700000000);
        let id = incident_uid(&a);
        t.ack(&id, Some("alice".into()), Some("triaging".into()));
        // The write is fire-and-forget; await it.
        let beq = be.clone();
        let idq = id.clone();
        wait_until(|| {
            beq.hashes.lock().unwrap()
                .get(CONTROL_INCIDENTS_KEY)
                .map(|h| h.contains_key(&idq))
                .unwrap_or(false)
        })
        .await;
    }

    #[tokio::test]
    async fn ack_overlay_survives_a_simulated_restart() {
        // Write through tracker1, then hydrate a fresh tracker2 from the
        // SAME backend — the ack must reappear (the durability contract).
        let be = backend();
        let a = alert(SliKind::DataPlaneAvailability, 1700000001);
        let id = incident_uid(&a);
        let acked = IncidentState {
            alert_id: id.clone(),
            status: IncidentStatus::Acknowledged,
            acked_at: Some(Utc::now()),
            acked_by: Some("carol".into()),
            snoozed_until: None,
            resolved_at: None,
            note: Some("owned".into()),
        };
        persist_to(&(be.clone() as Arc<dyn StateBackend>), &acked).await;

        let restarted = IncidentTracker::with_backend(Some(be as Arc<dyn StateBackend>));
        assert!(restarted.get(&id).is_none(), "empty before hydrate");
        restarted.hydrate().await;
        let got = restarted.get(&id).expect("overlay rehydrated");
        assert_eq!(got.status, IncidentStatus::Acknowledged);
        assert_eq!(got.acked_by.as_deref(), Some("carol"));
        assert_eq!(got.note.as_deref(), Some("owned"));
    }

    #[tokio::test]
    async fn reset_clears_both_in_memory_and_durable() {
        let be = backend();
        let t = IncidentTracker::with_backend(Some(be.clone() as Arc<dyn StateBackend>));
        let a = alert(SliKind::DataPlaneAvailability, 1700000002);
        let id = incident_uid(&a);
        t.ack(&id, Some("dave".into()), None);
        let beq = be.clone();
        let idq = id.clone();
        wait_until(|| {
            beq.hashes.lock().unwrap().get(CONTROL_INCIDENTS_KEY)
                .map(|h| h.contains_key(&idq)).unwrap_or(false)
        })
        .await;

        t.clear_local();
        t.unlink_durable().await;
        assert!(t.get(&id).is_none(), "in-memory overlay cleared");
        assert!(
            be.hashes.lock().unwrap().get(CONTROL_INCIDENTS_KEY).is_none(),
            "durable hash unlinked"
        );
    }

    #[tokio::test]
    async fn hydrate_skips_corrupt_fields_but_loads_the_rest() {
        let be = backend();
        let good = IncidentState {
            alert_id: "good:1".into(),
            status: IncidentStatus::Resolved,
            acked_at: None, acked_by: None, snoozed_until: None,
            resolved_at: Some(Utc::now()), note: None,
        };
        persist_to(&(be.clone() as Arc<dyn StateBackend>), &good).await;
        // Inject a corrupt field directly.
        be.hashes.lock().unwrap()
            .get_mut(CONTROL_INCIDENTS_KEY).unwrap()
            .insert("bad:2".into(), b"{not json".to_vec());

        let t = IncidentTracker::with_backend(Some(be as Arc<dyn StateBackend>));
        t.hydrate().await;
        assert_eq!(t.get("good:1").unwrap().status, IncidentStatus::Resolved);
        assert!(t.get("bad:2").is_none(), "corrupt field skipped, not fatal");
    }

    #[tokio::test]
    async fn no_backend_path_is_unchanged_and_inert() {
        // Without a backend: mutators still work in memory, and the durable
        // hooks are harmless no-ops (no panic, nothing to load/clear).
        let t = IncidentTracker::new();
        let a = alert(SliKind::DataPlaneAvailability, 1700000003);
        let id = incident_uid(&a);
        let s = t.ack(&id, Some("erin".into()), None);
        assert_eq!(s.status, IncidentStatus::Acknowledged);
        t.hydrate().await; // no-op
        t.unlink_durable().await; // no-op
        assert_eq!(t.get(&id).unwrap().acked_by.as_deref(), Some("erin"));
        t.clear_local();
        assert!(t.get(&id).is_none());
    }

    #[test]
    fn enrich_composes_engine_view_with_overlay() {
        let t = IncidentTracker::new();
        let a1 = alert(SliKind::DataPlaneAvailability, 1700000000);
        let a2 = alert(SliKind::WafOverheadP99, 1700000050);
        let id1 = incident_uid(&a1);
        t.ack(&id1, Some("alice".into()), None);
        let enriched = t.enrich(vec![a1, a2]);
        assert_eq!(enriched.len(), 2);
        assert_eq!(enriched[0].status, IncidentStatus::Acknowledged);
        assert_eq!(enriched[0].acked_by.as_deref(), Some("alice"));
        assert_eq!(enriched[1].status, IncidentStatus::Firing);
        assert!(enriched[1].acked_at.is_none());
    }

    #[test]
    fn incident_uid_is_stable_for_same_alert() {
        let a1 = alert(SliKind::DataPlaneAvailability, 1700000000);
        let a2 = alert(SliKind::DataPlaneAvailability, 1700000000);
        assert_eq!(incident_uid(&a1), incident_uid(&a2));
    }

    // IF-P1a — the inverse of the old `differs_for_different_fired_at`:
    // node-independence is asserted by
    // `incident_uid_is_node_independent_across_fire_times` above.

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
    fn incident_uid_format_is_sli_and_window_without_timestamp() {
        // IF-P1a — the uid is node-independent: "<SliKind>-<N>h", no
        // trailing ":<ts>". Matches `tracking.rs::from_engine`'s name/id
        // and the dashboard's `id = a.id || name` synthesis.
        let a = alert_with_window(SliKind::DataPlaneAvailability, 1778570234, 1);
        assert_eq!(
            incident_uid(&a),
            "DataPlaneAvailability-1h",
            "uid must be node-independent (no fire timestamp)"
        );
    }

    #[test]
    fn incident_uid_differs_for_different_window_hours_on_same_sli() {
        let a1 = alert_with_window(SliKind::DataPlaneAvailability, 1700000000, 1);
        let a72 = alert_with_window(SliKind::DataPlaneAvailability, 1700000000, 72);
        assert_ne!(
            incident_uid(&a1),
            incident_uid(&a72),
            "multi-window alerts must track as distinct incidents"
        );
    }

    #[test]
    fn ack_then_enrich_returns_acknowledged_status() {
        // The MED-OBS-01 regression: the ack handler writes the
        // overlay under whatever id the path param carries, then
        // enrich() looks it up by `incident_uid(&a)`.  Before the fix
        // these two strings disagreed; after the fix they match.
        let tracker = IncidentTracker::new();
        let a = alert_with_window(SliKind::DataPlaneAvailability, 1778570234, 1);
        let stored_id = incident_uid(&a);
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
