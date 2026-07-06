//! AU-1 (committee round-2 🟡3) — audit events for the admin auth
//! surface: `login_success`, `login_failure`, `logout`.
//!
//! Pre-fix, `authenticate()`/`logout()` left **no** audit trail — an
//! investigator could not answer "who logged in when, and from
//! where?". This module owns the event taxonomy (Member-2's TF track
//! re-uses it for TOTP/credential-change events) and the
//! anti-flood aggregation so a credential-stuffing run can't melt
//! the audit bus one-event-per-attempt.
//!
//! ## Taxonomy (class `Access`)
//!
//! | action | reason | notes |
//! |---|---|---|
//! | `login_success` | `ok` | `fields.user` = authenticated user |
//! | `login_failure` | outcome bucket | `invalid_credentials` / `locked_out` / `rate_limited` / `bad_request` / `store_unavailable` — **never** submitted values |
//! | `login_failure` | bucket, aggregated | `fields.count` > 1 — flood window roll-up |
//! | `logout` | `ok` | only on real session revocation |
//!
//! The failure buckets deliberately mirror [`super::login::LoginOutcome`]
//! (the wire's anti-enumeration posture): the trail records *that*
//! and *how often* auth failed, not which factor was wrong.
//!
//! ## Aggregation
//!
//! First failure from an IP emits immediately. Further failures
//! inside `window` are counted, not emitted; the roll-up event
//! (`fields.count` = suppressed total) flushes on the next
//! event from that IP after the window closes. A burst that simply
//! stops leaves its tail count un-flushed until the IP is seen
//! again — documented trade-off, no timer task on the auth path.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use aegis_core::audit::{AuditClass, AuditEvent};
use aegis_core::AuditBus;

/// Default aggregation window for repeated failures per IP.
pub const DEFAULT_FAILURE_WINDOW: Duration = Duration::from_secs(30);

/// Cap on tracked failure windows — the login surface is pre-auth,
/// so a botnet rotating source IPs must not grow this map without
/// bound. At the cap, closed windows are swept (their roll-ups
/// emitted); if every slot is still live, new IPs get their
/// immediate event but no suppression tracking (rotation defeats
/// per-IP aggregation anyway — each new IP's first event is
/// emitted regardless).
pub const MAX_TRACKED_FAILURE_IPS: usize = 10_000;

struct FailureWindow {
    started: Instant,
    /// Failures suppressed since the immediate first event.
    suppressed: u64,
    reason: &'static str,
}

/// Emits auth audit events onto the bus with per-IP failure
/// aggregation. One instance per process (lives on
/// `DashboardServices`).
pub struct LoginAuditor {
    bus: AuditBus,
    window: Duration,
    failures: Mutex<HashMap<String, FailureWindow>>,
}

impl LoginAuditor {
    pub fn new(bus: AuditBus) -> Self {
        Self::with_window(bus, DEFAULT_FAILURE_WINDOW)
    }

    pub fn with_window(bus: AuditBus, window: Duration) -> Self {
        Self {
            bus,
            window,
            failures: Mutex::new(HashMap::new()),
        }
    }

    /// Successful login. Flushes any pending failure roll-up for the
    /// IP first (order: the flood is on the record before the
    /// success that ended it).
    pub fn record_success(&self, ip: &str, user: &str) {
        self.flush_if_closed(ip, true);
        self.bus.emit(event(
            "login_success",
            "ok",
            ip,
            Some(user),
            None,
        ));
    }

    /// Failed login with a bucketed reason — callers must pass one
    /// of the [`LoginOutcome`]-derived buckets, never request
    /// content. First failure per IP emits immediately; repeats
    /// inside the window aggregate.
    pub fn record_failure(&self, ip: &str, user: Option<&str>, reason: &'static str) {
        let mut map = self.failures.lock().expect("login audit state poisoned");
        match map.get_mut(ip) {
            Some(w) if w.started.elapsed() < self.window => {
                w.suppressed += 1;
                return;
            }
            Some(w) => {
                // Window closed — flush the roll-up, start fresh.
                let suppressed = w.suppressed;
                let prev_reason = w.reason;
                *w = FailureWindow { started: Instant::now(), suppressed: 0, reason };
                if suppressed > 0 {
                    self.bus.emit(event(
                        "login_failure",
                        prev_reason,
                        ip,
                        None,
                        Some(suppressed),
                    ));
                }
            }
            None => {
                if map.len() >= MAX_TRACKED_FAILURE_IPS {
                    // Sweep closed windows first (emitting their
                    // roll-ups — counts are never silently lost).
                    let closed: Vec<String> = map
                        .iter()
                        .filter(|(_, w)| w.started.elapsed() >= self.window)
                        .map(|(k, _)| k.clone())
                        .collect();
                    for key in closed {
                        if let Some(w) = map.remove(&key) {
                            if w.suppressed > 0 {
                                self.bus.emit(event(
                                    "login_failure",
                                    w.reason,
                                    &key,
                                    None,
                                    Some(w.suppressed),
                                ));
                            }
                        }
                    }
                }
                if map.len() < MAX_TRACKED_FAILURE_IPS {
                    map.insert(
                        ip.to_string(),
                        FailureWindow { started: Instant::now(), suppressed: 0, reason },
                    );
                }
                // At a still-full cap the IP goes untracked: its
                // immediate event below still fires.
            }
        }
        self.bus.emit(event("login_failure", reason, ip, user, None));
    }

    /// TOTP-2 (TF-1) — password verified but the account has no enrolled
    /// second factor under `require_totp`: an enrollment-only session was
    /// issued. Distinct action from `login_success` so the committee
    /// evidence ("password alone never granted admin access") is
    /// readable straight off the audit chain.
    pub fn record_enrollment_required(&self, ip: &str, user: &str) {
        self.flush_if_closed(ip, true);
        self.bus.emit(event(
            "login_enrollment_required",
            "totp_enrollment_required",
            ip,
            Some(user),
            None,
        ));
    }

    /// Real logout (session revoked). Idempotent no-cookie logouts
    /// are *not* audited — nothing happened.
    pub fn record_logout(&self, ip: &str) {
        self.flush_if_closed(ip, false);
        self.bus.emit(event("logout", "ok", ip, None, None));
    }

    /// Flush a closed failure window for `ip`, if any. `force`
    /// flushes even when the window is still open (used on success:
    /// the flood ended — put its count on the record now).
    fn flush_if_closed(&self, ip: &str, force: bool) {
        let mut map = self.failures.lock().expect("login audit state poisoned");
        let flush = match map.get(ip) {
            Some(w) => (force || w.started.elapsed() >= self.window) && w.suppressed > 0,
            None => false,
        };
        let closed = map
            .get(ip)
            .map(|w| w.started.elapsed() >= self.window)
            .unwrap_or(false);
        if flush {
            let w = map.remove(ip).expect("checked above");
            self.bus.emit(event(
                "login_failure",
                w.reason,
                ip,
                None,
                Some(w.suppressed),
            ));
        } else if closed || force {
            map.remove(ip);
        }
    }
}

/// AU-1 — the control-plane `reset_state` wipe leaves a trail. The
/// event is emitted **before** the wipe executes so the wipe can't
/// erase evidence of itself (chain order proves it). Actor is the
/// control-plane secret principal — the surface is loopback-only,
/// gated by `X-Benchmark-Secret`.
pub fn reset_state_event(source_ip: &str) -> AuditEvent {
    let mut ev = event("reset_state", "control_plane_state_wipe", source_ip, None, None);
    ev.class = AuditClass::Admin;
    if let serde_json::Value::Object(map) = &mut ev.fields {
        map.insert(
            "actor".into(),
            serde_json::Value::String("control-plane-secret".into()),
        );
    }
    ev
}

fn event(
    action: &str,
    reason: &'static str,
    ip: &str,
    user: Option<&str>,
    aggregated_count: Option<u64>,
) -> AuditEvent {
    let mut fields = serde_json::Map::new();
    if let Some(u) = user {
        fields.insert("user".into(), serde_json::Value::String(u.into()));
    }
    if let Some(n) = aggregated_count {
        fields.insert("count".into(), serde_json::Value::Number(n.into()));
    }
    let fields = serde_json::Value::Object(fields);
    AuditEvent {
        schema_version: 1,
        ts: chrono::Utc::now(),
        request_id: uuid::Uuid::new_v4().to_string(),
        class: AuditClass::Access,
        tenant_id: None,
        tier: None,
        action: action.into(),
        reason: reason.into(),
        client_ip: ip.into(),
        route_id: None,
        rule_id: None,
        risk_score: None,
        method: None,
        path: None,
        mode: None,
        fields,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bus_and_rx() -> (AuditBus, tokio::sync::broadcast::Receiver<AuditEvent>) {
        let bus = AuditBus::new(64);
        let rx = bus.subscribe();
        (bus, rx)
    }

    fn drain(rx: &mut tokio::sync::broadcast::Receiver<AuditEvent>) -> Vec<AuditEvent> {
        let mut out = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            out.push(ev);
        }
        out
    }

    #[tokio::test]
    async fn success_emits_exactly_one_access_event() {
        let (bus, mut rx) = bus_and_rx();
        let a = LoginAuditor::new(bus);
        a.record_success("10.0.0.1", "admin");
        let evs = drain(&mut rx);
        assert_eq!(evs.len(), 1);
        assert!(matches!(evs[0].class, AuditClass::Access));
        assert_eq!(evs[0].action.as_str(), "login_success");
        assert_eq!(evs[0].client_ip, "10.0.0.1");
        assert_eq!(evs[0].fields["user"].as_str(), Some("admin"));
    }

    #[tokio::test]
    async fn logout_emits_exactly_one_event() {
        let (bus, mut rx) = bus_and_rx();
        let a = LoginAuditor::new(bus);
        a.record_logout("10.0.0.2");
        let evs = drain(&mut rx);
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].action.as_str(), "logout");
    }

    #[tokio::test]
    async fn failure_flood_aggregates_inside_window() {
        let (bus, mut rx) = bus_and_rx();
        let a = LoginAuditor::with_window(bus, Duration::from_secs(30));
        for _ in 0..20 {
            a.record_failure("10.9.9.9", Some("admin"), "invalid_credentials");
        }
        let evs = drain(&mut rx);
        assert_eq!(
            evs.len(),
            1,
            "flood must emit one immediate event, not one per attempt",
        );
        assert_eq!(evs[0].action.as_str(), "login_failure");
        assert_eq!(evs[0].reason, "invalid_credentials");
    }

    #[tokio::test]
    async fn suppressed_failures_flush_as_rollup_after_window() {
        let (bus, mut rx) = bus_and_rx();
        let a = LoginAuditor::with_window(bus, Duration::from_millis(30));
        for _ in 0..5 {
            a.record_failure("10.8.8.8", None, "invalid_credentials");
        }
        assert_eq!(drain(&mut rx).len(), 1, "one immediate event");
        tokio::time::sleep(Duration::from_millis(40)).await;
        // Next failure after the window: roll-up (count=4) + the new
        // immediate event.
        a.record_failure("10.8.8.8", None, "invalid_credentials");
        let evs = drain(&mut rx);
        assert_eq!(evs.len(), 2, "roll-up + fresh immediate event");
        let rollup = evs
            .iter()
            .find(|e| e.fields.get("count").is_some())
            .expect("roll-up event carries fields.count");
        assert_eq!(rollup.fields["count"].as_u64(), Some(4));
    }

    #[tokio::test]
    async fn success_flushes_pending_rollup_first() {
        let (bus, mut rx) = bus_and_rx();
        let a = LoginAuditor::with_window(bus, Duration::from_secs(30));
        for _ in 0..3 {
            a.record_failure("10.7.7.7", None, "invalid_credentials");
        }
        drain(&mut rx);
        a.record_success("10.7.7.7", "admin");
        let evs = drain(&mut rx);
        assert_eq!(evs.len(), 2, "roll-up then success");
        assert_eq!(evs[0].action.as_str(), "login_failure");
        assert_eq!(evs[0].fields["count"].as_u64(), Some(2));
        assert_eq!(evs[1].action.as_str(), "login_success");
    }

    #[tokio::test]
    async fn tracked_ip_cap_bounds_memory_and_flushes_swept_rollups() {
        // Botnet rotation: the map must never exceed the cap, and a
        // swept closed window with suppressed failures must emit its
        // roll-up rather than losing the count. Big bus so the
        // 10k-event flood doesn't lap the subscriber.
        let bus = AuditBus::new(32_768);
        let mut rx = bus.subscribe();
        let a = LoginAuditor::with_window(bus, Duration::from_millis(10));
        // Build 3 suppressed failures on one IP, let its window close.
        for _ in 0..4 {
            a.record_failure("10.0.0.1", None, "invalid_credentials");
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
        drain(&mut rx);
        // Flood distinct IPs well past the cap. (Cap is 10k — drive
        // enough to prove boundedness without a slow test.)
        for i in 0..(MAX_TRACKED_FAILURE_IPS + 50) {
            a.record_failure(&format!("10.1.{}.{}", i / 256, i % 256), None, "invalid_credentials");
        }
        let tracked = a.failures.lock().unwrap().len();
        assert!(
            tracked <= MAX_TRACKED_FAILURE_IPS,
            "tracked windows must stay capped, got {tracked}",
        );
        // The swept 10.0.0.1 roll-up (count=3) is somewhere in the
        // drained stream — the count was not silently lost.
        let mut evs = Vec::new();
        loop {
            use tokio::sync::broadcast::error::TryRecvError;
            match rx.try_recv() {
                Ok(ev) => evs.push(ev),
                Err(TryRecvError::Lagged(_)) => continue,
                Err(_) => break,
            }
        }
        assert!(
            evs.iter().any(|e| e.client_ip == "10.0.0.1"
                && e.fields["count"].as_u64() == Some(3)),
            "sweep must flush the suppressed roll-up",
        );
    }

    #[tokio::test]
    async fn independent_ips_do_not_share_windows() {
        let (bus, mut rx) = bus_and_rx();
        let a = LoginAuditor::new(bus);
        a.record_failure("10.1.1.1", None, "invalid_credentials");
        a.record_failure("10.2.2.2", None, "invalid_credentials");
        assert_eq!(drain(&mut rx).len(), 2, "first failure per IP is immediate");
    }

    #[test]
    fn reset_state_event_is_admin_class_with_actor() {
        let ev = reset_state_event("127.0.0.1");
        assert!(matches!(ev.class, AuditClass::Admin));
        assert_eq!(ev.action.as_str(), "reset_state");
        assert_eq!(ev.client_ip, "127.0.0.1");
        assert_eq!(ev.fields["actor"].as_str(), Some("control-plane-secret"));
    }

    #[test]
    fn events_serialize_without_free_text_slots_for_secrets() {
        // The API cannot receive credential material at all — the
        // only strings an event carries are ip / user / static
        // buckets. Serialize and pin the field set so a future
        // "helpful" field addition trips this.
        let ev = event("login_failure", "invalid_credentials", "1.2.3.4", Some("admin"), None);
        let v: serde_json::Value = serde_json::from_str(&serde_json::to_string(&ev).unwrap()).unwrap();
        let fields = v["fields"].as_object().unwrap();
        for key in fields.keys() {
            assert!(
                ["user", "count"].contains(&key.as_str()),
                "unexpected free-form field {key} on auth audit event",
            );
        }
    }
}
