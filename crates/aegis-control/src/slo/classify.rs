//! SLO-P1 — request-outcome classification for the availability SLI.
//!
//! Maps an audit-bus event to its effect on the data-plane
//! availability SLO:
//!
//! * [`SliClass::Good`] / [`SliClass::Bad`] — an availability
//!   sample. Bad means the WAF failed to *serve*: a gateway
//!   failure verdict (`timeout`, `circuit_breaker`) or a forwarded
//!   response whose origin status was 5xx (`fields.status`,
//!   stamped on every listener `allow` emit).
//! * [`SliClass::Enforcement`] — the WAF *worked* (`block` /
//!   `challenge` / `rate_limit`). Excluded from availability so a
//!   blocked attack wave doesn't page on-call as an outage;
//!   counted separately via
//!   [`crate::slo::SloEngine::record_enforcement`].
//! * `None` — not a request verdict (admin / system
//!   `AuditAction::Other` events). Pre-P1 the drain recorded
//!   these as 0.0 availability samples.

use aegis_core::audit::{AuditAction, AuditEvent};

/// Lowest `fields.status` treated as an availability failure on
/// the `allow` path. A forwarded origin 5xx is a failure the
/// client experienced even though the WAF verdict was allow.
const BAD_STATUS_FLOOR: u64 = 500;

/// Effect of one audit-bus event on the availability SLI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SliClass {
    /// Served successfully — a 1.0 availability sample.
    Good,
    /// Service failure — a 0.0 availability sample.
    Bad,
    /// Security enforcement — excluded from availability,
    /// tracked on the enforcement counter instead.
    Enforcement,
}

/// Classify an audit-bus event for the availability SLI.
///
/// Returns `None` when the event is not a request verdict and
/// must not touch the SLI at all.
pub fn classify_event(ev: &AuditEvent) -> Option<SliClass> {
    match ev.action {
        AuditAction::Allow => {
            let origin_5xx = ev
                .fields
                .get("status")
                .and_then(|v| v.as_u64())
                .is_some_and(|s| s >= BAD_STATUS_FLOOR);
            Some(if origin_5xx {
                SliClass::Bad
            } else {
                SliClass::Good
            })
        }
        AuditAction::Timeout | AuditAction::CircuitBreaker => Some(SliClass::Bad),
        AuditAction::Block | AuditAction::Challenge | AuditAction::RateLimit => {
            Some(SliClass::Enforcement)
        }
        AuditAction::Other(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::audit::AuditClass;

    /// Minimal audit event with the given wire action and
    /// `fields` payload — mirrors what the listener emits.
    fn event(action: &str, fields: serde_json::Value) -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "test-req".into(),
            class: AuditClass::Access,
            tenant_id: None,
            tier: None,
            action: action.into(),
            reason: String::new(),
            client_ip: "127.0.0.1".into(),
            route_id: None,
            rule_id: None,
            risk_score: None,
            method: None,
            path: None,
            mode: None,
            fields,
        }
    }

    // -- allow path: origin status decides ---------------------------------

    #[test]
    fn allow_with_2xx_status_is_good() {
        let ev = event("allow", serde_json::json!({ "status": 200 }));
        assert_eq!(classify_event(&ev), Some(SliClass::Good));
    }

    #[test]
    fn allow_with_origin_5xx_is_bad() {
        for status in [500, 502, 503, 599] {
            let ev = event("allow", serde_json::json!({ "status": status }));
            assert_eq!(
                classify_event(&ev),
                Some(SliClass::Bad),
                "forwarded origin {status} must count as unavailability",
            );
        }
    }

    #[test]
    fn allow_with_4xx_status_is_good() {
        // Client errors (404, 499) are the origin answering, not
        // the service failing.
        for status in [400, 404, 499] {
            let ev = event("allow", serde_json::json!({ "status": status }));
            assert_eq!(classify_event(&ev), Some(SliClass::Good));
        }
    }

    #[test]
    fn allow_without_status_field_is_good() {
        // Streamed/SSE rows may omit status — match pre-P1
        // behavior for those (verdict allow = good).
        let ev = event("allow", serde_json::json!({}));
        assert_eq!(classify_event(&ev), Some(SliClass::Good));
    }

    #[test]
    fn allow_with_non_numeric_status_is_good() {
        let ev = event("allow", serde_json::json!({ "status": "weird" }));
        assert_eq!(classify_event(&ev), Some(SliClass::Good));
    }

    // -- gateway failure verdicts -------------------------------------------

    #[test]
    fn timeout_and_circuit_breaker_are_bad() {
        for action in ["timeout", "circuit_breaker"] {
            let ev = event(action, serde_json::json!({}));
            assert_eq!(
                classify_event(&ev),
                Some(SliClass::Bad),
                "{action} is a gateway failure",
            );
        }
    }

    // -- security enforcement ------------------------------------------------

    #[test]
    fn block_challenge_rate_limit_are_enforcement_not_availability() {
        for action in ["block", "challenge", "rate_limit"] {
            let ev = event(action, serde_json::json!({}));
            assert_eq!(
                classify_event(&ev),
                Some(SliClass::Enforcement),
                "{action} is the WAF working, not an outage",
            );
        }
    }

    // -- non-verdict events ----------------------------------------------------

    #[test]
    fn admin_and_system_events_are_ignored() {
        for action in ["rule_create", "mode_set", "config_publish"] {
            let ev = event(action, serde_json::json!({}));
            assert_eq!(
                classify_event(&ev),
                None,
                "{action} is not a request verdict",
            );
        }
    }
}
