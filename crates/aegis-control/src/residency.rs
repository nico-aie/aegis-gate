//! Data residency, retention sweep, right-to-erasure.
//!
//! Region pin (strict / preferred) is enforced at write time against state
//! backend and audit spool writes. Retention is enforced per
//! [`AuditClass`] by a background sweep. Erasure pseudonymizes events for a
//! given subject id and re-stitches the audit hash chain so that
//! [`crate::audit::verify::verify_entries`] still returns
//! [`crate::audit::verify::VerifyResult::Clean`].

use std::time::Duration;

use aegis_core::{audit::AuditClass, error::WafError, Result};
use serde::{Deserialize, Serialize};

use crate::audit::chain::{chain_hash, genesis_hash, ChainEntry};

/// Region pin policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum RegionPin {
    /// Only writes from the pinned region are accepted.
    Strict { region: String },
    /// Pinned region is preferred but other regions are allowed.
    Preferred { region: String },
}

impl RegionPin {
    /// Returns true if a write originating in `region` is allowed.
    pub fn allows(&self, region: &str) -> bool {
        match self {
            RegionPin::Strict { region: pinned } => pinned == region,
            RegionPin::Preferred { .. } => true,
        }
    }

    /// Returns the pinned region.
    pub fn region(&self) -> &str {
        match self {
            RegionPin::Strict { region } | RegionPin::Preferred { region } => region,
        }
    }
}

/// Retention policy by audit class.
#[derive(Clone, Debug)]
pub struct RetentionPolicy {
    pub detection: Duration,
    pub admin: Duration,
    pub access: Duration,
    pub system: Duration,
}

impl RetentionPolicy {
    /// Uniform retention across all classes.
    pub fn uniform(d: Duration) -> Self {
        Self {
            detection: d,
            admin: d,
            access: d,
            system: d,
        }
    }

    /// Retention for a particular class.
    pub fn for_class(&self, class: AuditClass) -> Duration {
        match class {
            AuditClass::Detection => self.detection,
            AuditClass::Admin => self.admin,
            AuditClass::Access => self.access,
            AuditClass::System => self.system,
        }
    }
}

/// Drop entries that fall outside their per-class retention window.
///
/// Returns the surviving entries, **already chained from genesis**. The chain
/// is recomputed so [`crate::audit::verify::verify_entries`] continues to
/// return [`crate::audit::verify::VerifyResult::Clean`].
pub fn sweep(
    entries: &[ChainEntry],
    policy: &RetentionPolicy,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<ChainEntry> {
    let kept: Vec<ChainEntry> = entries
        .iter()
        .filter(|e| {
            let age = now.signed_duration_since(e.event.ts);
            age.to_std()
                .map(|a| a <= policy.for_class(e.event.class))
                .unwrap_or(true)
        })
        .cloned()
        .collect();
    rechain(kept)
}

/// Erasure outcome for a single subject.
#[derive(Clone, Debug)]
pub struct ErasureOutcome {
    pub erased_count: usize,
    pub entries: Vec<ChainEntry>,
}

/// Pseudonym placeholder used in erased events.
pub const ERASED_PSEUDONYM: &str = "<erased>";

/// Field key written into `event.fields` after erasure.
pub const ERASED_AT_KEY: &str = "erased_at";

/// Pseudonymize all events that contain `subject_id` in `event.fields`,
/// stamp `erased_at`, and rebuild the chain so verification still passes.
///
/// `subject_id` matches:
/// - The exact value of `event.fields["subject_id"]`.
/// - Any value of `event.fields["actor"]` (admin trail).
/// - Any value of `event.fields["client_id"]`.
pub fn erase_subject(
    entries: &[ChainEntry],
    subject_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<ErasureOutcome> {
    if subject_id.is_empty() {
        return Err(WafError::Other("erase_subject: empty subject_id".into()));
    }

    let mut erased_count = 0;
    let mut updated: Vec<ChainEntry> = entries
        .iter()
        .map(|e| {
            let mut entry = e.clone();
            if event_matches_subject(&entry.event, subject_id) {
                pseudonymize_event_fields(&mut entry.event, subject_id, now);
                if entry.event.client_ip == subject_id {
                    entry.event.client_ip = ERASED_PSEUDONYM.into();
                }
                erased_count += 1;
            }
            entry
        })
        .collect();

    if erased_count > 0 {
        updated = rechain(updated);
    }

    Ok(ErasureOutcome {
        erased_count,
        entries: updated,
    })
}

/// Re-stitch a list of chain entries from genesis.
pub fn rechain(mut entries: Vec<ChainEntry>) -> Vec<ChainEntry> {
    let mut prev = genesis_hash();
    for entry in entries.iter_mut() {
        let new_hash = chain_hash(&prev, &entry.event);
        entry.hash = new_hash.clone();
        prev = new_hash;
    }
    entries
}

fn event_matches_subject(event: &aegis_core::audit::AuditEvent, subject_id: &str) -> bool {
    if event.client_ip == subject_id {
        return true;
    }
    if let Some(obj) = event.fields.as_object() {
        for key in ["subject_id", "actor", "client_id", "user", "user_id"] {
            if obj.get(key).and_then(|v| v.as_str()) == Some(subject_id) {
                return true;
            }
        }
    }
    false
}

fn pseudonymize_event_fields(
    event: &mut aegis_core::audit::AuditEvent,
    subject_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) {
    if let Some(obj) = event.fields.as_object_mut() {
        for key in ["subject_id", "actor", "client_id", "user", "user_id"] {
            if obj.get(key).and_then(|v| v.as_str()) == Some(subject_id) {
                obj.insert(key.to_string(), serde_json::Value::String(ERASED_PSEUDONYM.into()));
            }
        }
        obj.insert(
            ERASED_AT_KEY.to_string(),
            serde_json::Value::String(now.to_rfc3339()),
        );
    } else {
        event.fields = serde_json::json!({
            ERASED_AT_KEY: now.to_rfc3339(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::chain::ChainWriter;
    use crate::audit::verify::{verify_entries, VerifyResult};
    use aegis_core::audit::{AuditClass, AuditEvent};

    fn ts(rfc: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(rfc)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    fn ev(id: &str, class: AuditClass, t: chrono::DateTime<chrono::Utc>, fields: serde_json::Value) -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts: t,
            request_id: id.into(),
            class,
            tenant_id: None,
            tier: None,
            action: "test".into(),
            reason: "test".into(),
            client_ip: "10.0.0.1".into(),
            route_id: None,
            rule_id: None,
            risk_score: None,
            fields,
        }
    }

    // ---------- RegionPin ----------

    #[test]
    fn region_pin_strict_only_allows_pinned() {
        let pin = RegionPin::Strict {
            region: "eu-west-1".into(),
        };
        assert!(pin.allows("eu-west-1"));
        assert!(!pin.allows("us-east-1"));
        assert_eq!(pin.region(), "eu-west-1");
    }

    #[test]
    fn region_pin_preferred_allows_anything() {
        let pin = RegionPin::Preferred {
            region: "eu-west-1".into(),
        };
        assert!(pin.allows("eu-west-1"));
        assert!(pin.allows("us-east-1"));
    }

    #[test]
    fn region_pin_serializes() {
        let pin = RegionPin::Strict {
            region: "eu-west-1".into(),
        };
        let json = serde_json::to_string(&pin).unwrap();
        assert!(json.contains("strict"));
        assert!(json.contains("eu-west-1"));
    }

    #[test]
    fn region_pin_deserializes() {
        let json = r#"{"mode":"preferred","region":"us-east-1"}"#;
        let pin: RegionPin = serde_json::from_str(json).unwrap();
        assert_eq!(pin.region(), "us-east-1");
        assert!(matches!(pin, RegionPin::Preferred { .. }));
    }

    // ---------- RetentionPolicy ----------

    #[test]
    fn retention_uniform_returns_same_value() {
        let p = RetentionPolicy::uniform(Duration::from_secs(3600));
        assert_eq!(p.for_class(AuditClass::Detection), Duration::from_secs(3600));
        assert_eq!(p.for_class(AuditClass::Admin), Duration::from_secs(3600));
        assert_eq!(p.for_class(AuditClass::Access), Duration::from_secs(3600));
        assert_eq!(p.for_class(AuditClass::System), Duration::from_secs(3600));
    }

    #[test]
    fn retention_per_class() {
        let p = RetentionPolicy {
            detection: Duration::from_secs(60),
            admin: Duration::from_secs(120),
            access: Duration::from_secs(180),
            system: Duration::from_secs(240),
        };
        assert_eq!(p.for_class(AuditClass::Admin), Duration::from_secs(120));
    }

    // ---------- sweep ----------

    #[test]
    fn sweep_drops_old_entries() {
        let mut writer = ChainWriter::new();
        let now = ts("2024-01-15T12:00:00Z");
        // Two old entries (admin), one fresh.
        writer.append(ev(
            "old-1",
            AuditClass::Admin,
            ts("2023-01-01T00:00:00Z"),
            serde_json::Value::Null,
        ));
        writer.append(ev(
            "old-2",
            AuditClass::Detection,
            ts("2023-06-01T00:00:00Z"),
            serde_json::Value::Null,
        ));
        writer.append(ev(
            "fresh",
            AuditClass::System,
            ts("2024-01-15T11:00:00Z"),
            serde_json::Value::Null,
        ));

        let policy = RetentionPolicy::uniform(Duration::from_secs(7 * 24 * 3600));
        let kept = sweep(writer.entries(), &policy, now);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].event.request_id, "fresh");
    }

    #[test]
    fn sweep_preserves_chain_integrity() {
        let mut writer = ChainWriter::new();
        let now = ts("2024-01-15T12:00:00Z");
        writer.append(ev(
            "old",
            AuditClass::Detection,
            ts("2022-01-01T00:00:00Z"),
            serde_json::Value::Null,
        ));
        writer.append(ev(
            "fresh-1",
            AuditClass::Detection,
            ts("2024-01-15T11:00:00Z"),
            serde_json::Value::Null,
        ));
        writer.append(ev(
            "fresh-2",
            AuditClass::Detection,
            ts("2024-01-15T11:30:00Z"),
            serde_json::Value::Null,
        ));

        let policy = RetentionPolicy::uniform(Duration::from_secs(7 * 24 * 3600));
        let kept = sweep(writer.entries(), &policy, now);
        assert_eq!(kept.len(), 2);
        assert_eq!(verify_entries(&kept), VerifyResult::Clean { entries: 2 });
    }

    #[test]
    fn sweep_per_class_retention() {
        let mut writer = ChainWriter::new();
        let now = ts("2024-01-15T12:00:00Z");
        writer.append(ev(
            "admin-old",
            AuditClass::Admin,
            ts("2024-01-08T11:59:00Z"),
            serde_json::Value::Null,
        ));
        writer.append(ev(
            "detection-old",
            AuditClass::Detection,
            ts("2024-01-08T11:59:00Z"),
            serde_json::Value::Null,
        ));

        let policy = RetentionPolicy {
            detection: Duration::from_secs(24 * 3600), // 1 day
            admin: Duration::from_secs(30 * 24 * 3600), // 30 days
            access: Duration::from_secs(24 * 3600),
            system: Duration::from_secs(24 * 3600),
        };
        let kept = sweep(writer.entries(), &policy, now);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].event.request_id, "admin-old");
    }

    #[test]
    fn sweep_empty_returns_empty() {
        let policy = RetentionPolicy::uniform(Duration::from_secs(60));
        let kept = sweep(&[], &policy, ts("2024-01-15T12:00:00Z"));
        assert!(kept.is_empty());
    }

    // ---------- erase_subject ----------

    #[test]
    fn erase_subject_pseudonymizes_matching_events() {
        let mut writer = ChainWriter::new();
        let now = ts("2024-01-15T12:00:00Z");
        writer.append(ev(
            "req-1",
            AuditClass::Admin,
            ts("2024-01-01T10:00:00Z"),
            serde_json::json!({"actor": "alice", "resource": "/api/config"}),
        ));
        writer.append(ev(
            "req-2",
            AuditClass::Admin,
            ts("2024-01-02T10:00:00Z"),
            serde_json::json!({"actor": "bob", "resource": "/api/rules"}),
        ));
        writer.append(ev(
            "req-3",
            AuditClass::Admin,
            ts("2024-01-03T10:00:00Z"),
            serde_json::json!({"actor": "alice", "resource": "/api/audit"}),
        ));

        let outcome = erase_subject(writer.entries(), "alice", now).unwrap();
        assert_eq!(outcome.erased_count, 2);

        for entry in &outcome.entries {
            let actor = entry.event.fields.get("actor").and_then(|v| v.as_str());
            if entry.event.request_id == "req-2" {
                assert_eq!(actor, Some("bob"));
            } else {
                assert_eq!(actor, Some(ERASED_PSEUDONYM));
                assert!(entry.event.fields.get(ERASED_AT_KEY).is_some());
            }
        }
    }

    #[test]
    fn erase_subject_keeps_chain_verifiable() {
        let mut writer = ChainWriter::new();
        let now = ts("2024-01-15T12:00:00Z");
        writer.append(ev(
            "req-1",
            AuditClass::Admin,
            ts("2024-01-01T10:00:00Z"),
            serde_json::json!({"actor": "carol"}),
        ));
        writer.append(ev(
            "req-2",
            AuditClass::Admin,
            ts("2024-01-02T10:00:00Z"),
            serde_json::json!({"actor": "carol"}),
        ));
        writer.append(ev(
            "req-3",
            AuditClass::Admin,
            ts("2024-01-03T10:00:00Z"),
            serde_json::json!({"actor": "dave"}),
        ));

        let outcome = erase_subject(writer.entries(), "carol", now).unwrap();
        assert_eq!(outcome.erased_count, 2);
        assert_eq!(
            verify_entries(&outcome.entries),
            VerifyResult::Clean { entries: 3 }
        );
    }

    #[test]
    fn erase_subject_no_match_returns_zero() {
        let mut writer = ChainWriter::new();
        let now = ts("2024-01-15T12:00:00Z");
        writer.append(ev(
            "req-1",
            AuditClass::Admin,
            ts("2024-01-01T10:00:00Z"),
            serde_json::json!({"actor": "eve"}),
        ));
        let outcome = erase_subject(writer.entries(), "nobody", now).unwrap();
        assert_eq!(outcome.erased_count, 0);
        // Chain stays untouched.
        assert_eq!(outcome.entries[0].hash, writer.entries()[0].hash);
    }

    #[test]
    fn erase_subject_rejects_empty_id() {
        let writer = ChainWriter::new();
        let now = ts("2024-01-15T12:00:00Z");
        let err = erase_subject(writer.entries(), "", now).unwrap_err();
        assert!(err.to_string().contains("empty subject_id"));
    }

    #[test]
    fn erase_matches_client_ip() {
        let mut writer = ChainWriter::new();
        let now = ts("2024-01-15T12:00:00Z");
        let mut e = ev(
            "req-ip",
            AuditClass::Detection,
            ts("2024-01-01T10:00:00Z"),
            serde_json::Value::Null,
        );
        e.client_ip = "192.0.2.5".into();
        writer.append(e);

        let outcome = erase_subject(writer.entries(), "192.0.2.5", now).unwrap();
        assert_eq!(outcome.erased_count, 1);
        assert_eq!(outcome.entries[0].event.client_ip, ERASED_PSEUDONYM);
        assert_eq!(
            verify_entries(&outcome.entries),
            VerifyResult::Clean { entries: 1 }
        );
    }

    #[test]
    fn rechain_recomputes_from_genesis() {
        let mut writer = ChainWriter::new();
        writer.append(ev(
            "req-1",
            AuditClass::System,
            ts("2024-01-01T00:00:00Z"),
            serde_json::Value::Null,
        ));
        writer.append(ev(
            "req-2",
            AuditClass::System,
            ts("2024-01-02T00:00:00Z"),
            serde_json::Value::Null,
        ));

        let mut entries = writer.entries().to_vec();
        // Tamper with hashes; rechain should fix them.
        entries[0].hash = "garbage".into();
        entries[1].hash = "more-garbage".into();
        let fixed = rechain(entries);
        assert_eq!(verify_entries(&fixed), VerifyResult::Clean { entries: 2 });
    }
}
