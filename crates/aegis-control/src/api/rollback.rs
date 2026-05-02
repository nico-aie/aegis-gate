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
use crate::interop::headers::Mode;
use crate::interop::mode::ModeStore;

/// Action labels the v1 dispatcher knows how to roll back.
/// Grow this list one entry at a time per follow-up.
const ROLLBACKABLE_ACTIONS: &[&str] = &["mode_set"];

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
/// before+after diff so the caller can emit the rollback
/// audit event with the same payload.
///
/// Pass the live [`ModeStore`] reference; v2 will accept a
/// trait object that owns each rollback target's apply path.
pub fn rollback_for_seq(
    ring: &Arc<AuditRing>,
    seq: u64,
    mode_store: &ModeStore,
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
        "mode_set" => apply_mode_rollback(seq, &event, mode_store),
        // Future cases land here. The const ROLLBACKABLE_ACTIONS
        // gate makes this match exhaustive in practice.
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
        let err = rollback_for_seq(&ring, 999, &mode).unwrap_err();
        assert!(matches!(err, RollbackError::NotFound(999)));
    }

    #[test]
    fn rejects_detection_class_event() {
        let ring = Arc::new(AuditRing::new());
        let seq = ring.record(detection_event());
        let mode = ModeStore::new(Mode::Enforce);
        let err = rollback_for_seq(&ring, seq, &mode).unwrap_err();
        assert!(matches!(err, RollbackError::NotAdminClass { .. }));
    }

    #[test]
    fn rejects_unsupported_action_with_explanation() {
        let ring = Arc::new(AuditRing::new());
        let seq = ring.record(admin_event_with_action("rule_upserted"));
        let mode = ModeStore::new(Mode::Enforce);
        let err = rollback_for_seq(&ring, seq, &mode).unwrap_err();
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

        let outcome = rollback_for_seq(&ring, seq, &mode_store).unwrap();
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

        let outcome = rollback_for_seq(&ring, seq, &mode_store).unwrap();
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

        let err = rollback_for_seq(&ring, seq, &mode_store).unwrap_err();
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

        let err = rollback_for_seq(&ring, seq, &mode_store).unwrap_err();
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
        let outcome = rollback_for_seq(&ring, seq, &mode_store).unwrap();
        let json = serde_json::to_value(&outcome).unwrap();
        assert_eq!(json["rolled_back_to_seq"], seq);
        assert_eq!(json["action"], "mode_set");
        assert_eq!(json["before"]["mode"], "enforce");
        assert_eq!(json["after"]["mode"], "log_only");
    }
}
