//! HACK-T4 rollback dispatcher (deferred follow-up).
//!
//! Re-applies the captured `before` state of an audit-mutated
//! configuration change. The Console "Rollback to #N" button
//! POSTs to `/api/config/versions/{seq}/rollback`; this module
//! is the pure dispatcher that finds the audit event, validates
//! it's rollback-able, and re-applies the inverse.
//!
//! ## v1 scope
//!
//! Only `mode_set` is wired in v1 — its audit event carries a
//! single flat `before.mode` / `after.mode` field that fully
//! captures the pre-state. Other mutations (rule CRUD,
//! detector mask, blacklist) carry richer payloads that need
//! per-handler inverse-apply logic; they're added in follow-ups
//! one at a time. The dispatcher returns
//! [`RollbackError::NotRollbackable`] for any action not in the
//! allow-list so the Console can render a disabled button +
//! tooltip explaining why.
//!
//! ## Audit chain semantics
//!
//! A successful rollback emits a NEW Admin event with
//! `action: "{orig}_rollback"` so the chain captures the fact
//! that a rollback happened. The new event is itself
//! rollback-able (a "rollback the rollback" path), but only
//! when the new event's action is in the allow-list — i.e.
//! `mode_rollback` itself isn't rollback-able in v1, only the
//! original `mode_set`. Future iterations could lift this by
//! treating any `*_rollback` action as redirecting to the
//! captured `before` field of its own payload.

use std::sync::Arc;

use aegis_core::audit::{AuditClass, AuditEvent};
use serde::Serialize;

use crate::api::audit::AuditRing;
use crate::api::mtls::AllowedSansStore;
use crate::interop::headers::Mode;
use crate::interop::mode::ModeStore;

/// Action labels the dispatcher knows how to roll back. Grow
/// this list one entry at a time per follow-up; the matching
/// arm in [`rollback_for_seq`] runs the inverse-apply for that
/// action.
///
/// **v1** — `mode_set` only.
/// **v2** — adds `risk_thresholds_set`, `mtls_sans_set`,
///          `mtls_sans_removed`.
pub const ROLLBACKABLE_ACTIONS: &[&str] = &[
    "mode_set",
    "risk_thresholds_set",
    "mtls_sans_set",
    "mtls_sans_removed",
];

/// Live state stores the rollback dispatcher needs to apply the
/// inverse of a captured mutation. Each store is borrowed; the
/// caller is responsible for plumbing live references from the
/// admin runtime.
///
/// Every field except `mode_store` is optional so unit tests
/// (and v1-only deployments) can construct a partial target set.
/// A `None` field paired with an action that needs that store
/// returns [`RollbackError::ApplyFailed`] with a clear message.
pub struct RollbackTargets<'a> {
    pub mode_store: &'a ModeStore,
    pub risk: Option<&'a aegis_security::risk::RiskTracker>,
    pub allowed_sans: Option<&'a AllowedSansStore>,
}

impl<'a> RollbackTargets<'a> {
    /// Convenience constructor — only mode-store wired (v1 shape).
    pub fn mode_only(mode_store: &'a ModeStore) -> Self {
        Self { mode_store, risk: None, allowed_sans: None }
    }
}

/// Outcome returned to the dispatcher on success. Carries the
/// before+after mode so the Console + audit emitter can show
/// the diff that was applied.
#[derive(Debug, Clone, Serialize)]
pub struct RollbackOutcome {
    /// Sequence the rollback targeted.
    pub rolled_back_to_seq: u64,
    /// Original action being rolled back (e.g. `mode_set`).
    pub action: String,
    /// Compact diff payload — `before` is what we applied,
    /// `after` is what was live just before the rollback.
    /// Both are JSON values so future rollback targets can
    /// surface their own shapes without enum churn.
    pub before: serde_json::Value,
    pub after: serde_json::Value,
}

/// Errors from [`rollback_for_seq`]. Each maps cleanly to an
/// HTTP status in the dispatcher: `NotFound` → 404, the rest
/// → 422 (semantic refusal: the request is well-formed but
/// the target can't be rolled back).
#[derive(Debug, thiserror::Error)]
pub enum RollbackError {
    /// No audit-ring entry with the supplied seq. Either the
    /// seq is too low (evicted) or too high (not yet
    /// recorded).
    #[error("audit version {0} not found in the ring")]
    NotFound(u64),
    /// Audit event exists but its `class` is not `Admin`.
    /// Rollback only applies to operator-initiated mutations,
    /// not detection events.
    #[error("audit version {seq} is not an admin event ({class:?})")]
    NotAdminClass {
        seq: u64,
        class: AuditClass,
    },
    /// Action label not in [`ROLLBACKABLE_ACTIONS`].
    #[error("action `{0}` is not rollback-able in this build")]
    NotRollbackable(String),
    /// The audit event's `fields` payload didn't carry the
    /// expected `before.<subfield>` data. Either the handler
    /// stamped a partial payload or the schema drifted.
    #[error("audit event missing `before.{0}` field for rollback")]
    MissingBefore(String),
    /// Re-applying the inverse failed. Typically a state-
    /// store error.
    #[error("apply failed: {0}")]
    ApplyFailed(String),
}

/// Pure dispatcher — finds the audit event, validates it's
/// rollback-able, and re-applies the inverse. Returns the
/// before+after diff so the caller can emit the rollback audit
/// event with the same payload.
pub fn rollback_for_seq(
    ring: &Arc<AuditRing>,
    seq: u64,
    targets: &RollbackTargets<'_>,
) -> Result<RollbackOutcome, RollbackError> {
    let event = lookup_event(ring, seq)?;

    if !matches!(event.class, AuditClass::Admin) {
        return Err(RollbackError::NotAdminClass {
            seq,
            class: event.class,
        });
    }
    if !ROLLBACKABLE_ACTIONS.iter().any(|a| *a == event.action) {
        return Err(RollbackError::NotRollbackable(event.action.clone()));
    }

    match event.action.as_str() {
        "mode_set" => apply_mode_rollback(seq, &event, targets.mode_store),
        "risk_thresholds_set" => apply_risk_thresholds_rollback(seq, &event, targets.risk),
        "mtls_sans_set" | "mtls_sans_removed" => {
            apply_mtls_sans_rollback(seq, &event, targets.allowed_sans)
        }
        // Future cases land here. The const ROLLBACKABLE_ACTIONS
        // gate keeps this match aligned.
        other => Err(RollbackError::NotRollbackable(other.to_string())),
    }
}

/// `mode_set` rollback — pull `before.mode` out of the event,
/// snapshot the live mode (for the `after` in the rollback
/// audit event), and call `mode_store.set_all` to apply.
fn apply_mode_rollback(
    seq: u64,
    event: &AuditEvent,
    mode_store: &ModeStore,
) -> Result<RollbackOutcome, RollbackError> {
    let before_mode_str = event
        .fields
        .get("diff")
        .and_then(|d| d.get("before"))
        .and_then(|b| b.get("mode"))
        .and_then(|m| m.as_str())
        .ok_or_else(|| RollbackError::MissingBefore("diff.before.mode".into()))?;

    let target_mode = match before_mode_str {
        "enforce" => Mode::Enforce,
        "log_only" => Mode::LogOnly,
        other => {
            return Err(RollbackError::ApplyFailed(format!(
                "unknown mode literal `{other}` in audit event",
            )));
        }
    };

    let live_mode = mode_store.resolve("rules_engine", None);
    mode_store.set_all(target_mode);

    Ok(RollbackOutcome {
        rolled_back_to_seq: seq,
        action: event.action.clone(),
        before: serde_json::json!({ "mode": mode_str(target_mode) }),
        after: serde_json::json!({ "mode": mode_str(live_mode) }),
    })
}

fn mode_str(m: Mode) -> &'static str {
    match m {
        Mode::Enforce => "enforce",
        Mode::LogOnly => "log_only",
    }
}

/// `risk_thresholds_set` rollback — pull the full
/// `{challenge_at, block_at, max}` triple from `before` and
/// re-apply via `RiskTracker::set_thresholds`. The store does
/// validation (challenge_at <= block_at, both <= max) so a
/// drifted audit payload surfaces as `ApplyFailed` rather than
/// silently breaking invariants.
fn apply_risk_thresholds_rollback(
    seq: u64,
    event: &AuditEvent,
    risk: Option<&aegis_security::risk::RiskTracker>,
) -> Result<RollbackOutcome, RollbackError> {
    let risk = risk.ok_or_else(|| {
        RollbackError::ApplyFailed("risk store not wired into rollback targets".into())
    })?;

    let before = event
        .fields
        .get("diff")
        .and_then(|d| d.get("before"))
        .ok_or_else(|| RollbackError::MissingBefore("diff.before".into()))?;

    let challenge_at = before
        .get("challenge_at")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .ok_or_else(|| RollbackError::MissingBefore("diff.before.challenge_at".into()))?;
    let block_at = before
        .get("block_at")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .ok_or_else(|| RollbackError::MissingBefore("diff.before.block_at".into()))?;
    let max = before
        .get("max")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .unwrap_or(100); // legacy audits before max was stamped

    let target = aegis_core::config::RiskThresholds {
        challenge_at,
        block_at,
        max,
    };

    let live = risk.thresholds();
    let live_json = serde_json::json!({
        "challenge_at": live.challenge_at,
        "block_at":     live.block_at,
        "max":          live.max,
    });

    risk.set_thresholds(target.clone());

    Ok(RollbackOutcome {
        rolled_back_to_seq: seq,
        action: event.action.clone(),
        before: serde_json::json!({
            "challenge_at": target.challenge_at,
            "block_at":     target.block_at,
            "max":          target.max,
        }),
        after: live_json,
    })
}

/// `mtls_sans_set` / `mtls_sans_removed` rollback — both stamp
/// the full pre-mutation list under `before.allowed`, so the
/// inverse is a single whole-list `store.store(before.allowed)`
/// call. The two actions share this code path because the audit
/// payload shape is identical.
fn apply_mtls_sans_rollback(
    seq: u64,
    event: &AuditEvent,
    allowed_sans: Option<&AllowedSansStore>,
) -> Result<RollbackOutcome, RollbackError> {
    let store = allowed_sans.ok_or_else(|| {
        RollbackError::ApplyFailed("allowed-SANs store not wired into rollback targets".into())
    })?;

    let before_list_val = event
        .fields
        .get("diff")
        .and_then(|d| d.get("before"))
        .and_then(|b| b.get("allowed"))
        .ok_or_else(|| RollbackError::MissingBefore("diff.before.allowed".into()))?;

    let before_list: Vec<String> = before_list_val
        .as_array()
        .ok_or_else(|| {
            RollbackError::ApplyFailed("diff.before.allowed is not an array".into())
        })?
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();

    let live = store.current();
    store.store(before_list.clone());

    Ok(RollbackOutcome {
        rolled_back_to_seq: seq,
        action: event.action.clone(),
        before: serde_json::json!({ "allowed": before_list }),
        after: serde_json::json!({ "allowed": live }),
    })
}

fn lookup_event(
    ring: &Arc<AuditRing>,
    seq: u64,
) -> Result<AuditEvent, RollbackError> {
    // The ring exposes a since-cursor view; pull every entry
    // and find the matching seq. Ring is bounded (typically
    // 1024) so the linear scan is bounded too.
    let snap = ring.since(0, u32::MAX);
    snap.events
        .into_iter()
        .find(|e| e.seq == seq)
        .map(|e| e.event)
        .ok_or(RollbackError::NotFound(seq))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::audit::AuditClass;

    fn admin_mode_set_event(before: &str, after: &str) -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: format!("req-{before}-to-{after}"),
            class: AuditClass::Admin,
            tenant_id: None,
            tier: None,
            action: "mode_set".into(),
            reason: "operator pins global mode".into(),
            client_ip: String::new(),
            route_id: None,
            rule_id: None,
            risk_score: None,
            fields: serde_json::json!({
                "actor": "admin",
                "diff": {
                    "before": { "mode": before },
                    "after":  { "mode": after  },
                },
                "resource": "/api/mode",
            }),
        }
    }

    fn admin_event_with_action(action: &str) -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: format!("req-{action}"),
            class: AuditClass::Admin,
            tenant_id: None,
            tier: None,
            action: action.into(),
            reason: "operator change".into(),
            client_ip: String::new(),
            route_id: None,
            rule_id: None,
            risk_score: None,
            fields: serde_json::json!({}),
        }
    }

    fn detection_event() -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "req-det".into(),
            class: AuditClass::Detection,
            tenant_id: None,
            tier: None,
            action: "block".into(),
            reason: "sqli".into(),
            client_ip: "1.2.3.4".into(),
            route_id: None,
            rule_id: Some("sqli".into()),
            risk_score: Some(40),
            fields: serde_json::json!({}),
        }
    }

    #[test]
    fn not_found_when_seq_does_not_exist() {
        let ring = Arc::new(AuditRing::new());
        let mode = ModeStore::new(Mode::Enforce);
        let err = rollback_for_seq(&ring, 999, &RollbackTargets::mode_only(&mode)).unwrap_err();
        assert!(matches!(err, RollbackError::NotFound(999)));
    }

    #[test]
    fn rejects_detection_class_event() {
        let ring = Arc::new(AuditRing::new());
        let seq = ring.record(detection_event());
        let mode = ModeStore::new(Mode::Enforce);
        let err = rollback_for_seq(&ring, seq, &RollbackTargets::mode_only(&mode)).unwrap_err();
        assert!(matches!(err, RollbackError::NotAdminClass { .. }));
    }

    #[test]
    fn rejects_unsupported_action_with_explanation() {
        let ring = Arc::new(AuditRing::new());
        let seq = ring.record(admin_event_with_action("rule_upserted"));
        let mode = ModeStore::new(Mode::Enforce);
        let err = rollback_for_seq(&ring, seq, &RollbackTargets::mode_only(&mode)).unwrap_err();
        match err {
            RollbackError::NotRollbackable(a) => assert_eq!(a, "rule_upserted"),
            other => panic!("expected NotRollbackable, got {other:?}"),
        }
    }

    #[test]
    fn mode_set_rollback_re_applies_before_state() {
        let ring = Arc::new(AuditRing::new());
        // Operator went enforce → log_only.
        let seq = ring.record(admin_mode_set_event("enforce", "log_only"));
        // Live store is currently log_only (post-mutation).
        let mode_store = ModeStore::new(Mode::LogOnly);

        let outcome = rollback_for_seq(&ring, seq, &RollbackTargets::mode_only(&mode_store)).unwrap();
        assert_eq!(outcome.rolled_back_to_seq, seq);
        assert_eq!(outcome.action, "mode_set");
        assert_eq!(outcome.before["mode"], "enforce");
        assert_eq!(outcome.after["mode"], "log_only");

        // Live store should now be enforce again.
        assert_eq!(
            mode_store.resolve("rules_engine", None),
            Mode::Enforce,
        );
    }

    #[test]
    fn mode_set_rollback_handles_log_only_target() {
        let ring = Arc::new(AuditRing::new());
        // Operator went log_only → enforce; rolling back puts
        // us back to log_only.
        let seq = ring.record(admin_mode_set_event("log_only", "enforce"));
        let mode_store = ModeStore::new(Mode::Enforce);

        let outcome = rollback_for_seq(&ring, seq, &RollbackTargets::mode_only(&mode_store)).unwrap();
        assert_eq!(outcome.before["mode"], "log_only");
        assert_eq!(outcome.after["mode"], "enforce");
        assert_eq!(
            mode_store.resolve("rules_engine", None),
            Mode::LogOnly,
        );
    }

    #[test]
    fn missing_before_subfield_surfaces_error() {
        let ring = Arc::new(AuditRing::new());
        // Construct an event whose fields don't carry
        // `diff.before.mode`.
        let mut ev = admin_mode_set_event("enforce", "log_only");
        ev.fields = serde_json::json!({ "actor": "admin" });
        let seq = ring.record(ev);
        let mode_store = ModeStore::new(Mode::Enforce);

        let err = rollback_for_seq(&ring, seq, &RollbackTargets::mode_only(&mode_store)).unwrap_err();
        match err {
            RollbackError::MissingBefore(path) => {
                assert!(path.contains("before.mode"), "got {path}");
            }
            other => panic!("expected MissingBefore, got {other:?}"),
        }
    }

    #[test]
    fn unknown_mode_literal_surfaces_apply_failed() {
        let ring = Arc::new(AuditRing::new());
        let mut ev = admin_mode_set_event("typo_mode", "log_only");
        // Use the typo'd mode in the audit event.
        ev.fields = serde_json::json!({
            "diff": { "before": { "mode": "garbage_mode" }, "after": { "mode": "log_only" } },
        });
        let seq = ring.record(ev);
        let mode_store = ModeStore::new(Mode::Enforce);

        let err = rollback_for_seq(&ring, seq, &RollbackTargets::mode_only(&mode_store)).unwrap_err();
        match err {
            RollbackError::ApplyFailed(msg) => {
                assert!(msg.contains("garbage_mode"));
            }
            other => panic!("expected ApplyFailed, got {other:?}"),
        }
    }

    #[test]
    fn outcome_serialises_to_expected_json() {
        let ring = Arc::new(AuditRing::new());
        let seq = ring.record(admin_mode_set_event("enforce", "log_only"));
        let mode_store = ModeStore::new(Mode::LogOnly);
        let outcome = rollback_for_seq(&ring, seq, &RollbackTargets::mode_only(&mode_store)).unwrap();
        let json = serde_json::to_value(&outcome).unwrap();
        assert_eq!(json["rolled_back_to_seq"], seq);
        assert_eq!(json["action"], "mode_set");
        assert_eq!(json["before"]["mode"], "enforce");
        assert_eq!(json["after"]["mode"], "log_only");
    }

    // ---------------- v2 — risk_thresholds_set ----------------

    fn risk_thresholds_event(
        before_challenge: u32, before_block: u32, before_max: u32,
        after_challenge: u32, after_block: u32, after_max: u32,
    ) -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "req-rt".into(),
            class: AuditClass::Admin,
            tenant_id: None,
            tier: None,
            action: "risk_thresholds_set".into(),
            reason: "operator updated risk thresholds".into(),
            client_ip: String::new(),
            route_id: None,
            rule_id: None,
            risk_score: None,
            fields: serde_json::json!({
                "actor": "admin",
                "diff": {
                    "before": { "challenge_at": before_challenge,
                                "block_at":     before_block,
                                "max":          before_max },
                    "after":  { "challenge_at": after_challenge,
                                "block_at":     after_block,
                                "max":          after_max  },
                },
                "resource": "/api/risk/thresholds",
            }),
        }
    }

    #[test]
    fn risk_thresholds_rollback_re_applies_before() {
        let ring = Arc::new(AuditRing::new());
        // Operator went 40/80/100 → 30/60/100. Roll back to 40/80/100.
        let seq = ring.record(risk_thresholds_event(40, 80, 100, 30, 60, 100));
        let mode = ModeStore::new(Mode::Enforce);
        let risk_cfg = aegis_core::config::RiskConfig {
            weights: aegis_core::config::RiskWeights::default(),
            decay_half_life: std::time::Duration::from_secs(300),
            thresholds: aegis_core::config::RiskThresholds {
                challenge_at: 30, block_at: 60, max: 100,
            },
            trust_recovery: None,
            strikes: None,
        };
        let risk = aegis_security::risk::RiskTracker::new(&risk_cfg);

        let targets = RollbackTargets {
            mode_store: &mode, risk: Some(&risk), allowed_sans: None,
        };
        let outcome = rollback_for_seq(&ring, seq, &targets).unwrap();

        assert_eq!(outcome.action, "risk_thresholds_set");
        assert_eq!(outcome.before["challenge_at"], 40);
        assert_eq!(outcome.before["block_at"], 80);
        assert_eq!(outcome.after["challenge_at"], 30);
        assert_eq!(outcome.after["block_at"], 60);

        let live = risk.thresholds();
        assert_eq!(live.challenge_at, 40);
        assert_eq!(live.block_at, 80);
    }

    #[test]
    fn risk_thresholds_rollback_without_store_fails() {
        let ring = Arc::new(AuditRing::new());
        let seq = ring.record(risk_thresholds_event(40, 80, 100, 30, 60, 100));
        let mode = ModeStore::new(Mode::Enforce);
        let targets = RollbackTargets::mode_only(&mode);
        let err = rollback_for_seq(&ring, seq, &targets).unwrap_err();
        match err {
            RollbackError::ApplyFailed(msg) => {
                assert!(msg.contains("risk store not wired"), "got: {msg}");
            }
            other => panic!("expected ApplyFailed, got {other:?}"),
        }
    }

    #[test]
    fn risk_thresholds_missing_subfield_surfaces_error() {
        let ring = Arc::new(AuditRing::new());
        let mut ev = risk_thresholds_event(40, 80, 100, 30, 60, 100);
        ev.fields = serde_json::json!({ "diff": { "before": { "challenge_at": 40 } } });
        let seq = ring.record(ev);
        let mode = ModeStore::new(Mode::Enforce);
        let risk_cfg = aegis_core::config::RiskConfig::default();
        let risk = aegis_security::risk::RiskTracker::new(&risk_cfg);
        let targets = RollbackTargets {
            mode_store: &mode, risk: Some(&risk), allowed_sans: None,
        };
        let err = rollback_for_seq(&ring, seq, &targets).unwrap_err();
        match err {
            RollbackError::MissingBefore(path) => {
                assert!(path.contains("block_at"), "got: {path}");
            }
            other => panic!("expected MissingBefore, got {other:?}"),
        }
    }

    // ---------------- v2 — mtls_sans_set / mtls_sans_removed ----------------

    fn mtls_sans_set_event(before: Vec<&str>, after: Vec<&str>) -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "req-sans".into(),
            class: AuditClass::Admin,
            tenant_id: None,
            tier: None,
            action: "mtls_sans_set".into(),
            reason: "operator updated allowed SAN list".into(),
            client_ip: String::new(),
            route_id: None,
            rule_id: None,
            risk_score: None,
            fields: serde_json::json!({
                "actor": "admin",
                "diff": {
                    "before": { "allowed": before },
                    "after":  { "allowed": after  },
                },
                "resource": "/api/mtls/sans",
            }),
        }
    }

    #[test]
    fn mtls_sans_rollback_re_applies_full_list() {
        let ring = Arc::new(AuditRing::new());
        // Operator went [a, b] → [a, b, c]. Roll back to [a, b].
        let seq = ring.record(mtls_sans_set_event(
            vec!["a.example.com", "b.example.com"],
            vec!["a.example.com", "b.example.com", "c.example.com"],
        ));
        let mode = ModeStore::new(Mode::Enforce);
        let sans = AllowedSansStore::from(vec![
            "a.example.com".into(),
            "b.example.com".into(),
            "c.example.com".into(),
        ]);
        let targets = RollbackTargets {
            mode_store: &mode, risk: None, allowed_sans: Some(&sans),
        };
        let outcome = rollback_for_seq(&ring, seq, &targets).unwrap();

        assert_eq!(outcome.action, "mtls_sans_set");
        let before_arr: Vec<&str> = outcome.before["allowed"]
            .as_array().unwrap().iter().filter_map(|v| v.as_str()).collect();
        assert_eq!(before_arr, vec!["a.example.com", "b.example.com"]);
        let after_arr: Vec<&str> = outcome.after["allowed"]
            .as_array().unwrap().iter().filter_map(|v| v.as_str()).collect();
        assert_eq!(after_arr, vec!["a.example.com", "b.example.com", "c.example.com"]);

        // Live store should now have the rolled-back 2-entry list.
        let live = sans.current();
        assert_eq!(live, vec!["a.example.com".to_string(), "b.example.com".into()]);
    }

    #[test]
    fn mtls_sans_removed_rollback_re_adds_entry() {
        let ring = Arc::new(AuditRing::new());
        // Operator removed `c.example.com` from [a, b, c] → [a, b].
        // The handler stamps before with the FULL pre-remove list.
        let mut ev = mtls_sans_set_event(
            vec!["a.example.com", "b.example.com", "c.example.com"],
            vec!["a.example.com", "b.example.com"],
        );
        ev.action = "mtls_sans_removed".into();
        let seq = ring.record(ev);

        let mode = ModeStore::new(Mode::Enforce);
        let sans = AllowedSansStore::from(vec![
            "a.example.com".into(),
            "b.example.com".into(),
        ]);
        let targets = RollbackTargets {
            mode_store: &mode, risk: None, allowed_sans: Some(&sans),
        };
        let outcome = rollback_for_seq(&ring, seq, &targets).unwrap();

        assert_eq!(outcome.action, "mtls_sans_removed");
        // After rolling back, the store should contain all 3 again.
        let live = sans.current();
        assert_eq!(live.len(), 3);
        assert!(live.contains(&"c.example.com".to_string()));
    }

    #[test]
    fn mtls_sans_rollback_without_store_fails() {
        let ring = Arc::new(AuditRing::new());
        let seq = ring.record(mtls_sans_set_event(vec!["a"], vec!["a", "b"]));
        let mode = ModeStore::new(Mode::Enforce);
        let targets = RollbackTargets::mode_only(&mode);
        let err = rollback_for_seq(&ring, seq, &targets).unwrap_err();
        match err {
            RollbackError::ApplyFailed(msg) => {
                assert!(msg.contains("allowed-SANs store not wired"), "got: {msg}");
            }
            other => panic!("expected ApplyFailed, got {other:?}"),
        }
    }

    #[test]
    fn mtls_sans_rollback_to_empty_list() {
        // Operator went [] → [a]; rolling back drops [a] back to [].
        let ring = Arc::new(AuditRing::new());
        let seq = ring.record(mtls_sans_set_event(vec![], vec!["a.example.com"]));
        let mode = ModeStore::new(Mode::Enforce);
        let sans = AllowedSansStore::from(vec!["a.example.com".to_string()]);
        let targets = RollbackTargets {
            mode_store: &mode, risk: None, allowed_sans: Some(&sans),
        };
        let outcome = rollback_for_seq(&ring, seq, &targets).unwrap();
        assert!(outcome.before["allowed"].as_array().unwrap().is_empty());
        assert!(sans.current().is_empty());
    }
}
