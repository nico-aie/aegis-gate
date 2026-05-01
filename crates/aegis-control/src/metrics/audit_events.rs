//! Audit event counter — `waf_audit_events_total{class}` (PROM-T3).
//!
//! Records every event that flows through the [`AuditBus`].
//! Implementation intentionally avoids touching every
//! `bus.emit()` call site — instead the proxy boot path
//! subscribes one extra metrics-only consumer that drains every
//! emit and bumps the counter. The cost is exactly the same as
//! the existing dashboard SSE drain task: one tokio task, one
//! bounded broadcast Receiver.
//!
//! ## Cardinality
//!
//! Four `class` values mirroring `AuditClass`: `detection`,
//! `admin`, `access`, `system`. Pre-allocated.

use prometheus::CounterVec;

use aegis_core::audit::AuditClass;

use super::MetricsRegistry;

pub mod class_label {
    pub const DETECTION: &str = "detection";
    pub const ADMIN: &str = "admin";
    pub const ACCESS: &str = "access";
    pub const SYSTEM: &str = "system";

    pub const ALL: [&str; 4] = [DETECTION, ADMIN, ACCESS, SYSTEM];
}

/// Translate the `AuditClass` enum to the wire label. Stable
/// snake_case strings — the enum's own `serde(rename_all)`
/// produces these too, but doing the match here keeps the
/// metric layer free of a serde round-trip on the hot path.
pub fn class_to_label(class: AuditClass) -> &'static str {
    match class {
        AuditClass::Detection => class_label::DETECTION,
        AuditClass::Admin => class_label::ADMIN,
        AuditClass::Access => class_label::ACCESS,
        AuditClass::System => class_label::SYSTEM,
    }
}

#[derive(Clone)]
pub struct AuditEventMetrics {
    events_total: CounterVec,
}

impl AuditEventMetrics {
    pub fn register(reg: &MetricsRegistry) -> prometheus::Result<Self> {
        let cv = reg.register_counter_vec(
            "waf_audit_events_total",
            "Total events emitted to the AuditBus, labelled by class (detection / admin / access / system).",
            &["class"],
        )?;
        for v in class_label::ALL {
            cv.with_label_values(&[v]);
        }
        Ok(Self { events_total: cv })
    }

    pub fn record(&self, class: AuditClass) {
        self.events_total
            .with_label_values(&[class_to_label(class)])
            .inc();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn series_value(reg: &MetricsRegistry, class: &str) -> f64 {
        reg.inner()
            .gather()
            .into_iter()
            .find(|f| f.get_name() == "waf_audit_events_total")
            .and_then(|f| {
                f.get_metric()
                    .iter()
                    .find(|m| {
                        m.get_label()
                            .iter()
                            .any(|l| l.get_name() == "class" && l.get_value() == class)
                    })
                    .map(|m| m.get_counter().get_value())
            })
            .unwrap_or(0.0)
    }

    #[test]
    fn register_pre_allocates_all_four_classes() {
        let reg = MetricsRegistry::init();
        let _m = AuditEventMetrics::register(&reg).unwrap();
        for c in class_label::ALL {
            assert_eq!(series_value(&reg, c), 0.0, "class {c} starts at 0");
        }
    }

    #[test]
    fn record_increments_correct_class() {
        let reg = MetricsRegistry::init();
        let m = AuditEventMetrics::register(&reg).unwrap();
        m.record(AuditClass::Detection);
        m.record(AuditClass::Detection);
        m.record(AuditClass::Admin);
        m.record(AuditClass::Access);
        m.record(AuditClass::System);
        assert_eq!(series_value(&reg, "detection"), 2.0);
        assert_eq!(series_value(&reg, "admin"), 1.0);
        assert_eq!(series_value(&reg, "access"), 1.0);
        assert_eq!(series_value(&reg, "system"), 1.0);
    }

    #[test]
    fn class_to_label_covers_every_variant() {
        assert_eq!(class_to_label(AuditClass::Detection), "detection");
        assert_eq!(class_to_label(AuditClass::Admin), "admin");
        assert_eq!(class_to_label(AuditClass::Access), "access");
        assert_eq!(class_to_label(AuditClass::System), "system");
    }

    #[test]
    fn duplicate_register_fails() {
        let reg = MetricsRegistry::init();
        AuditEventMetrics::register(&reg).unwrap();
        assert!(AuditEventMetrics::register(&reg).is_err());
    }
}
