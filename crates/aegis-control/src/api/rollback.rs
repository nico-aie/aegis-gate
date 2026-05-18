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
use crate::api::blacklist::AccessListStore;
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
/// **v3** — adds `blacklist_add`, `blacklist_remove`,
///          `whitelist_add`, `whitelist_remove`.
/// **v4** — adds `detector_mask_set` (base mask + per-tier overrides).
/// **v5** — adds `verbosity_set` and `loadmode_set` (operator pin
///          / unset).
pub const ROLLBACKABLE_ACTIONS: &[&str] = &[
    "mode_set",
    "risk_thresholds_set",
    "mtls_sans_set",
    "mtls_sans_removed",
    "blacklist_add",
    "blacklist_remove",
    "whitelist_add",
    "whitelist_remove",
    "detector_mask_set",
    "verbosity_set",
    "loadmode_set",
    // v6 — rule CRUD. Each captures full `{id, body, enabled}`
    // in the audit event's `before` field, so re-apply is
    // straightforward (delete-on-create / upsert-on-delete /
    // upsert-on-update). `rule_toggle` reads the current
    // `body` from the live store and re-upserts with the
    // before-toggle `enabled` value.
    "rule_create",
    "rule_update",
    "rule_delete",
    "rule_toggle",
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
    pub blacklist: Option<&'a AccessListStore>,
    pub whitelist: Option<&'a AccessListStore>,
    pub detector_mask: Option<&'a aegis_security::detectors::SharedDetectorMask>,
    pub verbosity: Option<&'a aegis_core::SharedVerbosity>,
    pub load_gauge: Option<&'a aegis_core::LoadGauge>,
    /// v6 — live rule store for `rule_{create,update,delete,toggle}`
    /// rollback. None for tests / older deployments; the dispatcher
    /// returns `ApplyFailed` with a clear message when the action
    /// requires this store and it's absent.
    pub rules: Option<&'a crate::api::rules::RuleStore>,
}

impl<'a> RollbackTargets<'a> {
    /// Convenience constructor — only mode-store wired (v1 shape).
    pub fn mode_only(mode_store: &'a ModeStore) -> Self {
        Self {
            mode_store,
            risk: None,
            allowed_sans: None,
            blacklist: None,
            whitelist: None,
            detector_mask: None,
            verbosity: None,
            load_gauge: None,
            rules: None,
        }
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
        return Err(RollbackError::NotRollbackable(event.action.as_str().to_string()));
    }

    match event.action.as_str() {
        "mode_set" => apply_mode_rollback(seq, &event, targets.mode_store),
        "risk_thresholds_set" => apply_risk_thresholds_rollback(seq, &event, targets.risk),
        "mtls_sans_set" | "mtls_sans_removed" => {
            apply_mtls_sans_rollback(seq, &event, targets.allowed_sans)
        }
        "blacklist_add" | "blacklist_remove" => {
            apply_access_list_rollback(seq, &event, "blacklist", targets.blacklist)
        }
        "whitelist_add" | "whitelist_remove" => {
            apply_access_list_rollback(seq, &event, "whitelist", targets.whitelist)
        }
        "detector_mask_set" => {
            apply_detector_mask_rollback(seq, &event, targets.detector_mask)
        }
        "verbosity_set" => apply_verbosity_rollback(seq, &event, targets.verbosity),
        "loadmode_set" => apply_loadmode_rollback(seq, &event, targets.load_gauge),
        "rule_create" | "rule_update" | "rule_delete" | "rule_toggle" => {
            apply_rule_rollback(seq, &event, targets.rules)
        }
        // Future cases land here. The const ROLLBACKABLE_ACTIONS
        // gate keeps this match aligned.
        other => Err(RollbackError::NotRollbackable(other.to_string())),
    }
}

/// v6 — rules CRUD rollback. Each rule action captures the full
/// `{id, body, enabled}` in the audit event's `fields.diff.before`
/// (or `fields.diff.after` is null for create/delete; we read
/// from before for the inverse).
///
/// | Original action | `before` shape          | Inverse                      |
/// |-----------------|-------------------------|------------------------------|
/// | rule_create     | null                    | `delete(id)`                 |
/// | rule_update     | {id, body, enabled}     | `upsert(before)`             |
/// | rule_delete     | {id, body, enabled}     | `upsert(before)`             |
/// | rule_toggle     | {id, enabled}           | read live body + `upsert`    |
fn apply_rule_rollback(
    seq: u64,
    event: &AuditEvent,
    rules: Option<&crate::api::rules::RuleStore>,
) -> Result<RollbackOutcome, RollbackError> {
    let store = rules.ok_or_else(|| {
        RollbackError::ApplyFailed(format!(
            "{} rollback unavailable: no rules store wired",
            event.action,
        ))
    })?;

    let diff = event
        .fields
        .get("diff")
        .ok_or_else(|| RollbackError::MissingBefore("diff".into()))?;
    let before = diff.get("before").cloned().unwrap_or(serde_json::Value::Null);
    let after = diff.get("after").cloned().unwrap_or(serde_json::Value::Null);

    match event.action.as_str() {
        "rule_create" => {
            // Inverse: delete the rule that the original create added.
            let id = after
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| RollbackError::MissingBefore("after.id".into()))?;
            let live_before = store.get(id).map(|r| {
                serde_json::json!({"id": r.id, "body": r.body, "enabled": r.enabled})
            });
            store.delete(id);
            Ok(RollbackOutcome {
                rolled_back_to_seq: seq,
                action: event.action.as_str().to_string(),
                before: serde_json::Value::Null,
                after: live_before.unwrap_or(serde_json::Value::Null),
            })
        }
        "rule_update" | "rule_delete" => {
            // Inverse: re-upsert the prior version.
            let id = before
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| RollbackError::MissingBefore("before.id".into()))?;
            let body = before
                .get("body")
                .and_then(|v| v.as_str())
                .ok_or_else(|| RollbackError::MissingBefore("before.body".into()))?;
            let enabled = before
                .get("enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let live_before = store.get(id).map(|r| {
                serde_json::json!({"id": r.id, "body": r.body, "enabled": r.enabled})
            });
            let v = store.upsert(id, body, enabled);
            if !v.ok {
                return Err(RollbackError::ApplyFailed(format!(
                    "rule re-validation failed: {}",
                    v.errors
                        .first()
                        .map(|m| format!("line {}: {}", m.line, m.message))
                        .unwrap_or_else(|| "unknown".into()),
                )));
            }
            Ok(RollbackOutcome {
                rolled_back_to_seq: seq,
                action: event.action.as_str().to_string(),
                before: serde_json::json!({"id": id, "body": body, "enabled": enabled}),
                after: live_before.unwrap_or(serde_json::Value::Null),
            })
        }
        "rule_toggle" => {
            // The toggle audit event captures only `{id, enabled}`
            // (body unchanged). Read live body from the store and
            // re-upsert with the prior enabled value.
            let id = before
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| RollbackError::MissingBefore("before.id".into()))?;
            let prior_enabled = before
                .get("enabled")
                .and_then(|v| v.as_bool())
                .ok_or_else(|| RollbackError::MissingBefore("before.enabled".into()))?;
            let live = store.get(id).ok_or_else(|| {
                RollbackError::ApplyFailed(format!(
                    "rule_toggle rollback: rule `{id}` no longer exists in the store",
                ))
            })?;
            let live_before = serde_json::json!({"id": live.id, "enabled": live.enabled});
            let _ = store.upsert(id, &live.body, prior_enabled);
            Ok(RollbackOutcome {
                rolled_back_to_seq: seq,
                action: event.action.as_str().to_string(),
                before: serde_json::json!({"id": id, "enabled": prior_enabled}),
                after: live_before,
            })
        }
        // The match arm in `rollback_for_seq` is exhaustive for
        // these four — anything else is a programmer error.
        other => Err(RollbackError::ApplyFailed(format!(
            "apply_rule_rollback called with non-rule action `{other}`",
        ))),
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
        action: event.action.as_str().to_string(),
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
        action: event.action.as_str().to_string(),
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
        action: event.action.as_str().to_string(),
        before: serde_json::json!({ "allowed": before_list }),
        after: serde_json::json!({ "allowed": live }),
    })
}

/// `{kind}_add` / `{kind}_remove` rollback for blacklist + whitelist.
/// The audit payloads carry single entries, not whole lists:
/// - `_add`    audit: `before = null`,  `after  = entry` →
///                    inverse = delete(entry.id)
/// - `_remove` audit: `before = entry`, `after  = null`  →
///                    inverse = put(entry)
///
/// Validation matches the live store's contract: bad-shape audit
/// payloads (parse fail / kind mismatch / missing id) surface as
/// `ApplyFailed` with a clear message.
fn apply_access_list_rollback(
    seq: u64,
    event: &AuditEvent,
    label: &'static str,  // "blacklist" or "whitelist"
    store: Option<&AccessListStore>,
) -> Result<RollbackOutcome, RollbackError> {
    let store = store.ok_or_else(|| {
        RollbackError::ApplyFailed(format!("{label} store not wired into rollback targets"))
    })?;

    let diff = event
        .fields
        .get("diff")
        .ok_or_else(|| RollbackError::MissingBefore("diff".into()))?;

    let is_add = event.action.as_str().ends_with("_add");

    if is_add {
        // Roll back an add → DELETE the entry that was added.
        // The audit's `after` carries the entry; pull its id.
        let entry_val = diff
            .get("after")
            .ok_or_else(|| RollbackError::MissingBefore("diff.after".into()))?;
        let id = entry_val
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RollbackError::MissingBefore("diff.after.id".into()))?;
        if !store.delete(id) {
            // Already gone — operator may have manually deleted.
            // Idempotent: report success with empty after.
            return Ok(RollbackOutcome {
                rolled_back_to_seq: seq,
                action: event.action.as_str().to_string(),
                before: serde_json::json!({ "removed_id": id, "already_gone": true }),
                after: serde_json::Value::Null,
            });
        }
        Ok(RollbackOutcome {
            rolled_back_to_seq: seq,
            action: event.action.as_str().to_string(),
            before: serde_json::json!({ "removed_id": id }),
            after: serde_json::Value::Null,
        })
    } else {
        // Roll back a remove → PUT the entry back.
        let entry_val = diff
            .get("before")
            .ok_or_else(|| RollbackError::MissingBefore("diff.before".into()))?;
        let entry: crate::api::blacklist::AccessListEntry =
            serde_json::from_value(entry_val.clone()).map_err(|e| {
                RollbackError::ApplyFailed(format!(
                    "diff.before is not an AccessListEntry: {e}"
                ))
            })?;
        let restored = store
            .put(entry.clone())
            .map_err(RollbackError::ApplyFailed)?;
        Ok(RollbackOutcome {
            rolled_back_to_seq: seq,
            action: event.action.as_str().to_string(),
            before: serde_json::to_value(&restored).unwrap_or(serde_json::Value::Null),
            after: serde_json::Value::Null,
        })
    }
}

/// `detector_mask_set` rollback — re-apply the captured base
/// mask + per-tier overrides snapshot. The audit-chain payload
/// shape (from `mask_state_to_json` in admin_mutate.rs):
///
/// ```json
/// "diff": {
///   "before": {
///     "base":      { "sqli": true, "xss": true, … },
///     "overrides": { "high":  { … }, "critical": { … } }
///   },
///   "after": { … same shape … }
/// }
/// ```
///
/// The inverse is a single full-state replace via
/// `SharedDetectorMask::store_state`. Per-tier overrides
/// not present in `before.overrides` are cleared.
fn apply_detector_mask_rollback(
    seq: u64,
    event: &AuditEvent,
    mask: Option<&aegis_security::detectors::SharedDetectorMask>,
) -> Result<RollbackOutcome, RollbackError> {
    use aegis_security::detectors::{
        DetectorMask, DetectorMaskBody, MaskState, ALL_TIERS,
    };

    let mask = mask.ok_or_else(|| {
        RollbackError::ApplyFailed("detector_mask store not wired into rollback targets".into())
    })?;

    let before = event
        .fields
        .get("diff")
        .and_then(|d| d.get("before"))
        .ok_or_else(|| RollbackError::MissingBefore("diff.before".into()))?;

    let base_val = before
        .get("base")
        .ok_or_else(|| RollbackError::MissingBefore("diff.before.base".into()))?;
    let base_body: DetectorMaskBody = serde_json::from_value(base_val.clone())
        .map_err(|e| RollbackError::ApplyFailed(format!("diff.before.base parse: {e}")))?;
    let base_mask: DetectorMask = base_body.into();

    let mut state = MaskState::new(base_mask);

    if let Some(overrides) = before.get("overrides").and_then(|v| v.as_object()) {
        for (tier_name, body_val) in overrides {
            let tier = crate::api::detectors::parse_tier_str(tier_name)
                .ok_or_else(|| {
                    RollbackError::ApplyFailed(format!(
                        "diff.before.overrides has unknown tier `{tier_name}`",
                    ))
                })?;
            let body: DetectorMaskBody = serde_json::from_value(body_val.clone())
                .map_err(|e| {
                    RollbackError::ApplyFailed(format!(
                        "diff.before.overrides.{tier_name} parse: {e}"
                    ))
                })?;
            state = state.with_override(tier, Some(body.into()));
        }
    }

    // Snapshot live for the after-payload before swapping.
    let live_state = mask.load_state();
    let live_base_body: DetectorMaskBody = live_state.base.into();
    let mut live_overrides = serde_json::Map::new();
    for tier in ALL_TIERS {
        if let Some(m) = live_state.override_for(tier) {
            let body: DetectorMaskBody = m.into();
            live_overrides.insert(
                aegis_security::detectors::tier_str(tier).to_string(),
                serde_json::to_value(body).unwrap_or(serde_json::Value::Null),
            );
        }
    }

    mask.store_state(state);

    Ok(RollbackOutcome {
        rolled_back_to_seq: seq,
        action: event.action.as_str().to_string(),
        before: before.clone(),
        after: serde_json::json!({
            "base": live_base_body,
            "overrides": serde_json::Value::Object(live_overrides),
        }),
    })
}

/// `verbosity_set` rollback. Audit shape:
/// ```json
/// "diff": {
///   "before": { "level": "info", "levels": [...] },
///   "after":  { "level": "debug" }
/// }
/// ```
fn apply_verbosity_rollback(
    seq: u64,
    event: &AuditEvent,
    verbosity: Option<&aegis_core::SharedVerbosity>,
) -> Result<RollbackOutcome, RollbackError> {
    let v = verbosity.ok_or_else(|| {
        RollbackError::ApplyFailed("verbosity store not wired into rollback targets".into())
    })?;
    let level_str = event
        .fields
        .get("diff")
        .and_then(|d| d.get("before"))
        .and_then(|b| b.get("level"))
        .and_then(|l| l.as_str())
        .ok_or_else(|| RollbackError::MissingBefore("diff.before.level".into()))?;
    let target = parse_verbosity(level_str).ok_or_else(|| {
        RollbackError::ApplyFailed(format!("unknown verbosity level `{level_str}`"))
    })?;

    let live = v.current();
    v.set(target);

    Ok(RollbackOutcome {
        rolled_back_to_seq: seq,
        action: event.action.as_str().to_string(),
        before: serde_json::json!({ "level": verbosity_str(target) }),
        after: serde_json::json!({ "level": verbosity_str(live) }),
    })
}

fn parse_verbosity(s: &str) -> Option<aegis_core::VerbosityLevel> {
    use aegis_core::VerbosityLevel;
    match s.to_ascii_lowercase().as_str() {
        "silent" => Some(VerbosityLevel::Silent),
        "error"  => Some(VerbosityLevel::Error),
        "warn"   => Some(VerbosityLevel::Warn),
        "info"   => Some(VerbosityLevel::Info),
        "debug"  => Some(VerbosityLevel::Debug),
        "trace"  => Some(VerbosityLevel::Trace),
        _        => None,
    }
}

fn verbosity_str(l: aegis_core::VerbosityLevel) -> &'static str {
    use aegis_core::VerbosityLevel;
    match l {
        VerbosityLevel::Silent => "silent",
        VerbosityLevel::Error  => "error",
        VerbosityLevel::Warn   => "warn",
        VerbosityLevel::Info   => "info",
        VerbosityLevel::Debug  => "debug",
        VerbosityLevel::Trace  => "trace",
    }
}

/// `loadmode_set` rollback. Audit shape from
/// `LoadGauge::snapshot()`:
/// ```json
/// "diff": {
///   "before": {
///     "mode": "Normal",
///     "effective_mode": "Elevated",
///     "rps_last_sample": 1234,
///     "override_active": true,
///     "elevated_rps": 1500,
///     "critical_rps": 4000
///   },
///   ...
/// }
/// ```
/// The rollback target is the `before.override_active` +
/// `before.effective_mode` pair: when override was active,
/// re-pin to that mode; when it wasn't, clear the override
/// (return to auto).
fn apply_loadmode_rollback(
    seq: u64,
    event: &AuditEvent,
    gauge: Option<&aegis_core::LoadGauge>,
) -> Result<RollbackOutcome, RollbackError> {
    let g = gauge.ok_or_else(|| {
        RollbackError::ApplyFailed("load_gauge not wired into rollback targets".into())
    })?;
    let before = event
        .fields
        .get("diff")
        .and_then(|d| d.get("before"))
        .ok_or_else(|| RollbackError::MissingBefore("diff.before".into()))?;
    let override_active = before
        .get("override_active")
        .and_then(|v| v.as_bool())
        .ok_or_else(|| RollbackError::MissingBefore("diff.before.override_active".into()))?;

    let target_override = if override_active {
        let mode_str = before
            .get("effective_mode")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RollbackError::MissingBefore("diff.before.effective_mode".into()))?;
        let mode = parse_load_mode(mode_str).ok_or_else(|| {
            RollbackError::ApplyFailed(format!("unknown load mode `{mode_str}`"))
        })?;
        Some(mode)
    } else {
        None
    };

    let live_override = g.override_value();
    g.set_override(target_override);

    Ok(RollbackOutcome {
        rolled_back_to_seq: seq,
        action: event.action.as_str().to_string(),
        before: serde_json::json!({
            "override_active": override_active,
            "effective_mode": target_override.map(load_mode_str),
        }),
        after: serde_json::json!({
            "override_active": live_override.is_some(),
            "effective_mode": live_override.map(load_mode_str),
        }),
    })
}

fn parse_load_mode(s: &str) -> Option<aegis_core::LoadMode> {
    use aegis_core::LoadMode;
    match s {
        "Normal"   | "normal"   => Some(LoadMode::Normal),
        "Elevated" | "elevated" => Some(LoadMode::Elevated),
        "Critical" | "critical" => Some(LoadMode::Critical),
        _ => None,
    }
}

fn load_mode_str(m: aegis_core::LoadMode) -> &'static str {
    use aegis_core::LoadMode;
    match m {
        LoadMode::Normal   => "Normal",
        LoadMode::Elevated => "Elevated",
        LoadMode::Critical => "Critical",
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
            method: None,
            path: None,
            mode: None,
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
            method: None,
            path: None,
            mode: None,
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
            method: None,
            path: None,
            mode: None,
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
            method: None,
            path: None,
            mode: None,
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
            canary_paths: Vec::new(),
        };
        let risk = aegis_security::risk::RiskTracker::new(&risk_cfg);

        let targets = RollbackTargets {
            mode_store: &mode, risk: Some(&risk),
            allowed_sans: None, blacklist: None, whitelist: None,
            detector_mask: None,
            verbosity: None, load_gauge: None,
            rules: None,
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
            mode_store: &mode, risk: Some(&risk),
            allowed_sans: None, blacklist: None, whitelist: None,
            detector_mask: None,
            verbosity: None, load_gauge: None,
            rules: None,
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
            method: None,
            path: None,
            mode: None,
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
            mode_store: &mode, risk: None,
            allowed_sans: Some(&sans),
            blacklist: None, whitelist: None, detector_mask: None,
            verbosity: None, load_gauge: None,
            rules: None,
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
            mode_store: &mode, risk: None,
            allowed_sans: Some(&sans),
            blacklist: None, whitelist: None, detector_mask: None,
            verbosity: None, load_gauge: None,
            rules: None,
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

    // ---------------- v3 — blacklist / whitelist add+remove ----------------

    fn access_list_event(
        action: &str,
        kind: &str,
        id: &str,
        value: &str,
    ) -> AuditEvent {
        let entry = serde_json::json!({
            "id": id,
            "kind": "ip",
            "value": value,
            "note": "qa",
            "expires_at": null,
            "bypass": [],
            "created_at": "2026-05-02T00:00:00Z",
        });
        let (before, after) = if action.ends_with("_add") {
            (serde_json::Value::Null, entry)
        } else {
            (entry, serde_json::Value::Null)
        };
        AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: format!("req-{action}-{id}"),
            class: AuditClass::Admin,
            tenant_id: None,
            tier: None,
            action: action.into(),
            reason: format!("operator {} access-list entry", if action.ends_with("_add") { "added" } else { "removed" }),
            client_ip: String::new(),
            route_id: None,
            rule_id: None,
            risk_score: None,
            method: None,
            path: None,
            mode: None,
            fields: serde_json::json!({
                "actor": "admin",
                "diff": { "before": before, "after": after },
                "resource": format!("/api/{kind}"),
            }),
        }
    }

    #[test]
    fn blacklist_add_rollback_deletes_the_entry() {
        let ring = Arc::new(AuditRing::new());
        let blacklist = AccessListStore::new();
        // Pretend operator added "bl-1" → 203.0.113.7. Live store
        // mirrors that.
        blacklist.put(crate::api::blacklist::AccessListEntry {
            id: "bl-1".into(),
            kind: "ip".into(),
            value: "203.0.113.7".into(),
            note: "qa".into(),
            expires_at: None,
            bypass: vec![],
            created_at: chrono::Utc::now(),
        }).unwrap();
        assert_eq!(blacklist.list().len(), 1);

        let seq = ring.record(access_list_event(
            "blacklist_add", "blacklist", "bl-1", "203.0.113.7",
        ));
        let mode = ModeStore::new(Mode::Enforce);
        let targets = RollbackTargets {
            mode_store: &mode,
            risk: None,
            allowed_sans: None,
            blacklist: Some(&blacklist),
            whitelist: None,
            detector_mask: None,
            verbosity: None, load_gauge: None,
            rules: None,
        };
        let outcome = rollback_for_seq(&ring, seq, &targets).unwrap();
        assert_eq!(outcome.action, "blacklist_add");
        assert_eq!(outcome.before["removed_id"], "bl-1");
        assert_eq!(blacklist.list().len(), 0);
    }

    #[test]
    fn blacklist_remove_rollback_re_adds_entry() {
        let ring = Arc::new(AuditRing::new());
        let blacklist = AccessListStore::new();
        // Operator just removed "bl-1"; live store is empty.
        let seq = ring.record(access_list_event(
            "blacklist_remove", "blacklist", "bl-1", "203.0.113.7",
        ));
        let mode = ModeStore::new(Mode::Enforce);
        let targets = RollbackTargets {
            mode_store: &mode,
            risk: None,
            allowed_sans: None,
            blacklist: Some(&blacklist),
            whitelist: None,
            detector_mask: None,
            verbosity: None, load_gauge: None,
            rules: None,
        };
        let outcome = rollback_for_seq(&ring, seq, &targets).unwrap();
        assert_eq!(outcome.action, "blacklist_remove");
        assert_eq!(blacklist.list().len(), 1);
        assert_eq!(blacklist.list()[0].value, "203.0.113.7");
    }

    #[test]
    fn whitelist_add_rollback_deletes_via_whitelist_store() {
        let ring = Arc::new(AuditRing::new());
        let blacklist = AccessListStore::new();
        let whitelist = AccessListStore::new();
        whitelist.put(crate::api::blacklist::AccessListEntry {
            id: "wl-1".into(),
            kind: "cidr".into(),
            value: "10.0.0.0/8".into(),
            note: "internal".into(),
            expires_at: None,
            bypass: vec!["all".into()],
            created_at: chrono::Utc::now(),
        }).unwrap();
        let seq = ring.record(access_list_event(
            "whitelist_add", "whitelist", "wl-1", "10.0.0.0/8",
        ));
        let mode = ModeStore::new(Mode::Enforce);
        let targets = RollbackTargets {
            mode_store: &mode,
            risk: None,
            allowed_sans: None,
            blacklist: Some(&blacklist),
            whitelist: Some(&whitelist),
            detector_mask: None,
            verbosity: None, load_gauge: None,
            rules: None,
        };
        let outcome = rollback_for_seq(&ring, seq, &targets).unwrap();
        assert_eq!(outcome.action, "whitelist_add");
        // Whitelist now empty; blacklist untouched.
        assert_eq!(whitelist.list().len(), 0);
        assert_eq!(blacklist.list().len(), 0);
    }

    #[test]
    fn access_list_rollback_without_store_fails() {
        let ring = Arc::new(AuditRing::new());
        let seq = ring.record(access_list_event(
            "blacklist_add", "blacklist", "bl-1", "1.2.3.4",
        ));
        let mode = ModeStore::new(Mode::Enforce);
        let err = rollback_for_seq(
            &ring, seq, &RollbackTargets::mode_only(&mode),
        ).unwrap_err();
        match err {
            RollbackError::ApplyFailed(msg) => {
                assert!(msg.contains("blacklist store not wired"), "got: {msg}");
            }
            other => panic!("expected ApplyFailed, got {other:?}"),
        }
    }

    #[test]
    fn access_list_add_rollback_idempotent_when_already_gone() {
        // Operator added bl-1, then manually removed it before
        // hitting the rollback button. The rollback should still
        // succeed with `already_gone: true` rather than 404.
        let ring = Arc::new(AuditRing::new());
        let blacklist = AccessListStore::new();
        let seq = ring.record(access_list_event(
            "blacklist_add", "blacklist", "bl-orphan", "1.2.3.4",
        ));
        let mode = ModeStore::new(Mode::Enforce);
        let targets = RollbackTargets {
            mode_store: &mode,
            risk: None,
            allowed_sans: None,
            blacklist: Some(&blacklist),
            whitelist: None,
            detector_mask: None,
            verbosity: None, load_gauge: None,
            rules: None,
        };
        let outcome = rollback_for_seq(&ring, seq, &targets).unwrap();
        assert_eq!(outcome.before["already_gone"], true);
    }

    #[test]
    fn mtls_sans_rollback_to_empty_list() {
        // Operator went [] → [a]; rolling back drops [a] back to [].
        let ring = Arc::new(AuditRing::new());
        let seq = ring.record(mtls_sans_set_event(vec![], vec!["a.example.com"]));
        let mode = ModeStore::new(Mode::Enforce);
        let sans = AllowedSansStore::from(vec!["a.example.com".to_string()]);
        let targets = RollbackTargets {
            mode_store: &mode, risk: None,
            allowed_sans: Some(&sans),
            blacklist: None, whitelist: None, detector_mask: None,
            verbosity: None, load_gauge: None,
            rules: None,
        };
        let outcome = rollback_for_seq(&ring, seq, &targets).unwrap();
        assert!(outcome.before["allowed"].as_array().unwrap().is_empty());
        assert!(sans.current().is_empty());
    }

    // ---------------- v4 — detector_mask_set ----------------

    fn full_mask_body(all_on: bool) -> serde_json::Value {
        serde_json::json!({
            "sqli": all_on, "xss": all_on, "path_traversal": all_on,
            "ssrf": all_on, "header_injection": all_on, "body_abuse": all_on,
            "recon": all_on, "brute_force": all_on,
        })
    }

    fn detector_mask_event(
        before: serde_json::Value,
        after: serde_json::Value,
    ) -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "req-mask".into(),
            class: AuditClass::Admin,
            tenant_id: None,
            tier: None,
            action: "detector_mask_set".into(),
            reason: "operator updated detector mask".into(),
            client_ip: String::new(),
            route_id: None,
            rule_id: None,
            risk_score: None,
            method: None,
            path: None,
            mode: None,
            fields: serde_json::json!({
                "actor": "admin",
                "diff": { "before": before, "after": after },
                "resource": "/api/detectors",
            }),
        }
    }

    #[test]
    fn detector_mask_rollback_re_applies_base() {
        use aegis_security::detectors::{DetectorMask, SharedDetectorMask};
        let ring = Arc::new(AuditRing::new());
        // Operator went all-on → recon-off. Roll back to all-on.
        let mut after_body = full_mask_body(true);
        after_body["recon"] = serde_json::json!(false);
        let seq = ring.record(detector_mask_event(
            serde_json::json!({ "base": full_mask_body(true), "overrides": {} }),
            serde_json::json!({ "base": after_body,           "overrides": {} }),
        ));
        let mode = ModeStore::new(Mode::Enforce);
        // Live mask currently has recon: false (post-mutation).
        let live_mask = DetectorMask::all_enabled();
        let mut live_recon_off = live_mask;
        live_recon_off.set(aegis_security::detectors::DetectorClass::Recon, false);
        let mask = SharedDetectorMask::new(live_recon_off);

        let targets = RollbackTargets {
            mode_store: &mode, risk: None, allowed_sans: None,
            blacklist: None, whitelist: None,
            detector_mask: Some(&mask),
            verbosity: None, load_gauge: None,
            rules: None,
        };
        let outcome = rollback_for_seq(&ring, seq, &targets).unwrap();
        assert_eq!(outcome.action, "detector_mask_set");

        // After rollback, the live mask should have recon=true again.
        let restored = mask.load_state();
        assert!(restored
            .base
            .is_enabled(aegis_security::detectors::DetectorClass::Recon));
    }

    #[test]
    fn detector_mask_rollback_re_applies_overrides() {
        use aegis_security::detectors::{DetectorMask, SharedDetectorMask};
        let ring = Arc::new(AuditRing::new());
        // Before: base all-on + `high` override with recon-off.
        // After: base all-on + no overrides (operator cleared the override).
        // Rollback should re-add the `high` override.
        let mut high_override = full_mask_body(true);
        high_override["recon"] = serde_json::json!(false);
        let seq = ring.record(detector_mask_event(
            serde_json::json!({
                "base": full_mask_body(true),
                "overrides": { "high": high_override },
            }),
            serde_json::json!({
                "base": full_mask_body(true),
                "overrides": {},
            }),
        ));
        let mode = ModeStore::new(Mode::Enforce);
        let mask = SharedDetectorMask::new(DetectorMask::all_enabled());

        let targets = RollbackTargets {
            mode_store: &mode, risk: None, allowed_sans: None,
            blacklist: None, whitelist: None,
            detector_mask: Some(&mask),
            verbosity: None, load_gauge: None,
            rules: None,
        };
        let outcome = rollback_for_seq(&ring, seq, &targets).unwrap();
        assert_eq!(outcome.action, "detector_mask_set");

        let restored = mask.load_state();
        let high_mask = restored.override_for(
            aegis_core::Tier::High,
        ).expect("high override should be restored");
        assert!(!high_mask.is_enabled(
            aegis_security::detectors::DetectorClass::Recon
        ));
    }

    #[test]
    fn detector_mask_rollback_without_store_fails() {
        let ring = Arc::new(AuditRing::new());
        let seq = ring.record(detector_mask_event(
            serde_json::json!({ "base": full_mask_body(true), "overrides": {} }),
            serde_json::json!({ "base": full_mask_body(false), "overrides": {} }),
        ));
        let mode = ModeStore::new(Mode::Enforce);
        let err = rollback_for_seq(
            &ring, seq, &RollbackTargets::mode_only(&mode),
        ).unwrap_err();
        match err {
            RollbackError::ApplyFailed(msg) => {
                assert!(msg.contains("detector_mask store not wired"), "got: {msg}");
            }
            other => panic!("expected ApplyFailed, got {other:?}"),
        }
    }

    #[test]
    fn detector_mask_rollback_unknown_tier_surfaces_error() {
        use aegis_security::detectors::{DetectorMask, SharedDetectorMask};
        let ring = Arc::new(AuditRing::new());
        let seq = ring.record(detector_mask_event(
            serde_json::json!({
                "base": full_mask_body(true),
                "overrides": { "garbage_tier": full_mask_body(false) },
            }),
            serde_json::json!({ "base": full_mask_body(true), "overrides": {} }),
        ));
        let mode = ModeStore::new(Mode::Enforce);
        let mask = SharedDetectorMask::new(DetectorMask::all_enabled());
        let targets = RollbackTargets {
            mode_store: &mode, risk: None, allowed_sans: None,
            blacklist: None, whitelist: None,
            detector_mask: Some(&mask),
            verbosity: None, load_gauge: None,
            rules: None,
        };
        let err = rollback_for_seq(&ring, seq, &targets).unwrap_err();
        match err {
            RollbackError::ApplyFailed(msg) => {
                assert!(msg.contains("garbage_tier"), "got: {msg}");
            }
            other => panic!("expected ApplyFailed, got {other:?}"),
        }
    }

    // ---------------- v5 — verbosity_set / loadmode_set ----------------

    fn verbosity_event(before: &str, after: &str) -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: format!("req-v-{before}"),
            class: AuditClass::Admin,
            tenant_id: None,
            tier: None,
            action: "verbosity_set".into(),
            reason: "operator changes verbosity".into(),
            client_ip: String::new(),
            route_id: None,
            rule_id: None,
            risk_score: None,
            method: None,
            path: None,
            mode: None,
            fields: serde_json::json!({
                "actor": "admin",
                "diff": {
                    "before": { "level": before, "levels": ["silent","error","warn","info","debug","trace"] },
                    "after":  { "level": after  },
                },
                "resource": "/api/logging",
            }),
        }
    }

    #[test]
    fn verbosity_rollback_re_applies_before_level() {
        let ring = Arc::new(AuditRing::new());
        let seq = ring.record(verbosity_event("info", "trace"));
        let mode = ModeStore::new(Mode::Enforce);
        let v = aegis_core::SharedVerbosity::new(aegis_core::VerbosityLevel::Trace);
        let targets = RollbackTargets {
            mode_store: &mode, risk: None, allowed_sans: None,
            blacklist: None, whitelist: None, detector_mask: None,
            verbosity: Some(&v), load_gauge: None,
            rules: None,
        };
        let outcome = rollback_for_seq(&ring, seq, &targets).unwrap();
        assert_eq!(outcome.action, "verbosity_set");
        assert_eq!(outcome.before["level"], "info");
        assert_eq!(outcome.after["level"], "trace");
        assert_eq!(v.current(), aegis_core::VerbosityLevel::Info);
    }

    #[test]
    fn verbosity_rollback_unknown_level_surfaces_error() {
        let ring = Arc::new(AuditRing::new());
        let seq = ring.record(verbosity_event("yelling", "info"));
        let mode = ModeStore::new(Mode::Enforce);
        let v = aegis_core::SharedVerbosity::new(aegis_core::VerbosityLevel::Info);
        let targets = RollbackTargets {
            mode_store: &mode, risk: None, allowed_sans: None,
            blacklist: None, whitelist: None, detector_mask: None,
            verbosity: Some(&v), load_gauge: None,
            rules: None,
        };
        let err = rollback_for_seq(&ring, seq, &targets).unwrap_err();
        match err {
            RollbackError::ApplyFailed(msg) => {
                assert!(msg.contains("yelling"), "got: {msg}");
            }
            other => panic!("expected ApplyFailed, got {other:?}"),
        }
    }

    #[test]
    fn verbosity_rollback_without_store_fails() {
        let ring = Arc::new(AuditRing::new());
        let seq = ring.record(verbosity_event("info", "debug"));
        let mode = ModeStore::new(Mode::Enforce);
        let err = rollback_for_seq(
            &ring, seq, &RollbackTargets::mode_only(&mode),
        ).unwrap_err();
        match err {
            RollbackError::ApplyFailed(msg) => {
                assert!(msg.contains("verbosity store not wired"), "got: {msg}");
            }
            other => panic!("expected ApplyFailed, got {other:?}"),
        }
    }

    fn loadmode_event(
        before_active: bool, before_mode: &str,
        after_active: bool, after_mode: &str,
    ) -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "req-lm".into(),
            class: AuditClass::Admin,
            tenant_id: None,
            tier: None,
            action: "loadmode_set".into(),
            reason: "operator pins load mode".into(),
            client_ip: String::new(),
            route_id: None,
            rule_id: None,
            risk_score: None,
            method: None,
            path: None,
            mode: None,
            fields: serde_json::json!({
                "actor": "admin",
                "diff": {
                    "before": {
                        "mode": "Normal",
                        "effective_mode": before_mode,
                        "rps_last_sample": 1234,
                        "override_active": before_active,
                        "elevated_rps": 1500,
                        "critical_rps": 4000,
                    },
                    "after": {
                        "mode": "Normal",
                        "effective_mode": after_mode,
                        "rps_last_sample": 1234,
                        "override_active": after_active,
                        "elevated_rps": 1500,
                        "critical_rps": 4000,
                    },
                },
                "resource": "/api/loadmode",
            }),
        }
    }

    fn fresh_load_gauge() -> aegis_core::LoadGauge {
        aegis_core::LoadGauge::new(aegis_core::LoadModeConfig {
            elevated_rps: 1500,
            critical_rps: 4000,
            sample_interval: std::time::Duration::from_secs(1),
            hysteresis: 0.1,
        })
    }

    #[test]
    fn loadmode_rollback_re_pins_override() {
        // Operator went (override:true, Elevated) → (override:false).
        // Roll back should re-pin to Elevated.
        let ring = Arc::new(AuditRing::new());
        let seq = ring.record(loadmode_event(true, "Elevated", false, "Normal"));
        let mode = ModeStore::new(Mode::Enforce);
        let g = fresh_load_gauge();
        // Live: no override active.
        assert_eq!(g.override_value(), None);
        let targets = RollbackTargets {
            mode_store: &mode, risk: None, allowed_sans: None,
            blacklist: None, whitelist: None, detector_mask: None,
            verbosity: None, load_gauge: Some(&g),
            rules: None,
        };
        let outcome = rollback_for_seq(&ring, seq, &targets).unwrap();
        assert_eq!(outcome.action, "loadmode_set");
        assert_eq!(outcome.before["override_active"], true);
        assert_eq!(outcome.before["effective_mode"], "Elevated");
        assert_eq!(g.override_value(), Some(aegis_core::LoadMode::Elevated));
    }

    #[test]
    fn loadmode_rollback_clears_override() {
        // Operator went (override:false) → (override:true, Critical).
        // Roll back should clear the override.
        let ring = Arc::new(AuditRing::new());
        let seq = ring.record(loadmode_event(false, "Normal", true, "Critical"));
        let mode = ModeStore::new(Mode::Enforce);
        let g = fresh_load_gauge();
        g.set_override(Some(aegis_core::LoadMode::Critical));
        let targets = RollbackTargets {
            mode_store: &mode, risk: None, allowed_sans: None,
            blacklist: None, whitelist: None, detector_mask: None,
            verbosity: None, load_gauge: Some(&g),
            rules: None,
        };
        let outcome = rollback_for_seq(&ring, seq, &targets).unwrap();
        assert_eq!(outcome.before["override_active"], false);
        assert_eq!(g.override_value(), None);
    }

    #[test]
    fn loadmode_rollback_without_store_fails() {
        let ring = Arc::new(AuditRing::new());
        let seq = ring.record(loadmode_event(true, "Elevated", false, "Normal"));
        let mode = ModeStore::new(Mode::Enforce);
        let err = rollback_for_seq(
            &ring, seq, &RollbackTargets::mode_only(&mode),
        ).unwrap_err();
        match err {
            RollbackError::ApplyFailed(msg) => {
                assert!(msg.contains("load_gauge not wired"), "got: {msg}");
            }
            other => panic!("expected ApplyFailed, got {other:?}"),
        }
    }

    // ============== v6 rule rollback tests ==============

    fn rule_event(action: &str, before: serde_json::Value, after: serde_json::Value) -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "test".into(),
            class: AuditClass::Admin,
            tenant_id: None,
            tier: None,
            action: action.into(),
            reason: format!("test {action}"),
            client_ip: "1.1.1.1".into(),
            route_id: None,
            rule_id: None,
            risk_score: None,
            method: None,
            path: None,
            mode: None,
            fields: serde_json::json!({"diff": {"before": before, "after": after}}),
        }
    }

    #[test]
    fn rule_create_rollback_deletes_the_rule() {
        let ring = Arc::new(AuditRing::new());
        let store = crate::api::rules::RuleStore::new();
        // Simulate the live state after a rule_create.
        store.upsert("custom-1", "match path == \"/admin\"", true);
        let seq = ring.record(rule_event(
            "rule_create",
            serde_json::Value::Null,
            serde_json::json!({"id": "custom-1", "body": "match path == \"/admin\"", "enabled": true}),
        ));
        let mode = ModeStore::new(Mode::Enforce);
        let targets = RollbackTargets {
            mode_store: &mode, risk: None, allowed_sans: None,
            blacklist: None, whitelist: None, detector_mask: None,
            verbosity: None, load_gauge: None, rules: Some(&store),
        };
        let outcome = rollback_for_seq(&ring, seq, &targets).unwrap();
        assert_eq!(outcome.action, "rule_create");
        assert!(store.get("custom-1").is_none());
    }

    #[test]
    fn rule_delete_rollback_restores_the_rule() {
        let ring = Arc::new(AuditRing::new());
        let store = crate::api::rules::RuleStore::new();
        // Simulate live state after rule_delete: rule is gone.
        let seq = ring.record(rule_event(
            "rule_delete",
            serde_json::json!({"id": "deleted-1", "body": "match path == \"/x\"", "enabled": true}),
            serde_json::Value::Null,
        ));
        let mode = ModeStore::new(Mode::Enforce);
        let targets = RollbackTargets {
            mode_store: &mode, risk: None, allowed_sans: None,
            blacklist: None, whitelist: None, detector_mask: None,
            verbosity: None, load_gauge: None, rules: Some(&store),
        };
        let outcome = rollback_for_seq(&ring, seq, &targets).unwrap();
        assert_eq!(outcome.action, "rule_delete");
        let restored = store.get("deleted-1").expect("rule should be restored");
        assert_eq!(restored.body, "match path == \"/x\"");
        assert!(restored.enabled);
    }

    #[test]
    fn rule_update_rollback_reapplies_prior_body() {
        let ring = Arc::new(AuditRing::new());
        let store = crate::api::rules::RuleStore::new();
        store.upsert("r1", "match path == \"/new\"", false);
        let seq = ring.record(rule_event(
            "rule_update",
            serde_json::json!({"id": "r1", "body": "match path == \"/old\"", "enabled": true}),
            serde_json::json!({"id": "r1", "body": "match path == \"/new\"", "enabled": false}),
        ));
        let mode = ModeStore::new(Mode::Enforce);
        let targets = RollbackTargets {
            mode_store: &mode, risk: None, allowed_sans: None,
            blacklist: None, whitelist: None, detector_mask: None,
            verbosity: None, load_gauge: None, rules: Some(&store),
        };
        let outcome = rollback_for_seq(&ring, seq, &targets).unwrap();
        assert_eq!(outcome.action, "rule_update");
        let now = store.get("r1").unwrap();
        assert_eq!(now.body, "match path == \"/old\"");
        assert!(now.enabled);
    }

    #[test]
    fn rule_toggle_rollback_flips_enabled_back() {
        let ring = Arc::new(AuditRing::new());
        let store = crate::api::rules::RuleStore::new();
        // Live state after a toggle: enabled=true (was false).
        store.upsert("r1", "match path == \"/login\"", true);
        let seq = ring.record(rule_event(
            "rule_toggle",
            serde_json::json!({"id": "r1", "enabled": false}),
            serde_json::json!({"id": "r1", "enabled": true}),
        ));
        let mode = ModeStore::new(Mode::Enforce);
        let targets = RollbackTargets {
            mode_store: &mode, risk: None, allowed_sans: None,
            blacklist: None, whitelist: None, detector_mask: None,
            verbosity: None, load_gauge: None, rules: Some(&store),
        };
        let outcome = rollback_for_seq(&ring, seq, &targets).unwrap();
        assert_eq!(outcome.action, "rule_toggle");
        let now = store.get("r1").unwrap();
        assert!(!now.enabled);
        // Body must be preserved — the toggle audit event didn't
        // capture body, so the rollback reads it from live.
        assert_eq!(now.body, "match path == \"/login\"");
    }

    #[test]
    fn rule_rollback_without_store_fails() {
        let ring = Arc::new(AuditRing::new());
        let seq = ring.record(rule_event(
            "rule_create",
            serde_json::Value::Null,
            serde_json::json!({"id": "x", "body": "match true", "enabled": true}),
        ));
        let mode = ModeStore::new(Mode::Enforce);
        let err = rollback_for_seq(
            &ring, seq, &RollbackTargets::mode_only(&mode),
        ).unwrap_err();
        match err {
            RollbackError::ApplyFailed(msg) => {
                assert!(msg.contains("rules store"), "got: {msg}");
            }
            other => panic!("expected ApplyFailed, got {other:?}"),
        }
    }
}
