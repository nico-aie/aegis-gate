//! Per-class detector-hit counter — `waf_detector_hits_total{class}`
//! (PROM-T2).
//!
//! Lights up the WAF Overview "Detector hits" panel. Each
//! detector class (sqli / xss / path_traversal / ssrf /
//! header_injection / body_abuse / recon / brute_force) gets one
//! pre-allocated series so Grafana renders a stable legend even
//! before any detector fires.
//!
//! ## Hot-path cost
//!
//! `record(class)` is one `CounterVec::with_label_values` lookup
//! plus one atomic inc — same shape as
//! [`crate::metrics::decisions::DecisionMetrics`]. The proxy
//! calls it once per fired detector per request via the
//! `fired` slice returned by
//! `aegis_security::detectors::run_all_filtered_observed`.
//!
//! ## Cardinality
//!
//! Eight fixed `class` values, hard-coded against
//! `DetectorClass::ALL`. Drift is caught by the
//! `class_constants_match_detector_enum` regression test.

use prometheus::CounterVec;

use super::MetricsRegistry;

/// Stable label values mirroring [`aegis_security::detectors::DetectorClass::as_str`].
pub mod class_label {
    pub const SQLI: &str = "sqli";
    pub const XSS: &str = "xss";
    pub const PATH_TRAVERSAL: &str = "path_traversal";
    pub const SSRF: &str = "ssrf";
    pub const HEADER_INJECTION: &str = "header_injection";
    pub const BODY_ABUSE: &str = "body_abuse";
    pub const RECON: &str = "recon";
    pub const BRUTE_FORCE: &str = "brute_force";
    pub const COMMAND_INJECTION: &str = "command_injection";
    pub const TEMPLATE_INJECTION: &str = "template_injection";
    pub const NOSQL_INJECTION: &str = "nosql_injection";

    pub const ALL: [&str; 11] = [
        SQLI, XSS, PATH_TRAVERSAL, SSRF, HEADER_INJECTION, BODY_ABUSE, RECON, BRUTE_FORCE,
        COMMAND_INJECTION, TEMPLATE_INJECTION, NOSQL_INJECTION,
    ];
}

/// Wrapper around the registered `CounterVec`.
#[derive(Clone)]
pub struct DetectorHitMetrics {
    hits_total: CounterVec,
}

impl DetectorHitMetrics {
    pub fn register(reg: &MetricsRegistry) -> prometheus::Result<Self> {
        let cv = reg.register_counter_vec(
            "waf_detector_hits_total",
            "Total detector firings per detector class. Incremented once per detector that emits at least one Signal on a given request, regardless of how many sub-tags the detector reported. Mirrors aegis_security::detectors::DetectorClass values.",
            &["class"],
        )?;
        for v in class_label::ALL {
            cv.with_label_values(&[v]);
        }
        Ok(Self { hits_total: cv })
    }

    /// Hot-path: record one detector firing. Caller passes the
    /// stable id from `Detector::id()` (e.g., `"sqli"`).
    /// Unknown ids would create new series; the
    /// `class_constants_match_detector_enum` test guards against
    /// drift, but in production the proxy always passes ids
    /// from the `default_detectors` set.
    pub fn record(&self, class: &str) {
        self.hits_total.with_label_values(&[class]).inc();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn series_count(reg: &MetricsRegistry) -> usize {
        reg.inner()
            .gather()
            .into_iter()
            .find(|f| f.get_name() == "waf_detector_hits_total")
            .map(|f| f.get_metric().len())
            .unwrap_or(0)
    }

    fn series_value(reg: &MetricsRegistry, class: &str) -> f64 {
        reg.inner()
            .gather()
            .into_iter()
            .find(|f| f.get_name() == "waf_detector_hits_total")
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
    fn register_pre_allocates_all_class_series() {
        let reg = MetricsRegistry::init();
        let _m = DetectorHitMetrics::register(&reg).unwrap();
        assert_eq!(series_count(&reg), class_label::ALL.len());
        for c in class_label::ALL {
            assert_eq!(series_value(&reg, c), 0.0, "class {c} starts at 0");
        }
    }

    #[test]
    fn record_increments_correct_class() {
        let reg = MetricsRegistry::init();
        let m = DetectorHitMetrics::register(&reg).unwrap();
        m.record("sqli");
        m.record("sqli");
        m.record("xss");
        assert_eq!(series_value(&reg, "sqli"), 2.0);
        assert_eq!(series_value(&reg, "xss"), 1.0);
        assert_eq!(series_value(&reg, "path_traversal"), 0.0);
    }

    #[test]
    fn unknown_class_creates_new_series() {
        // The behaviour is unwanted but documented: production
        // callers always pass a `Detector::id()` that's in
        // class_label::ALL. This test pins the spillover behaviour
        // so we notice if a typo escapes the type system.
        let reg = MetricsRegistry::init();
        let m = DetectorHitMetrics::register(&reg).unwrap();
        m.record("typo");
        assert_eq!(
            series_count(&reg),
            class_label::ALL.len() + 1,
            "typo created an extra series past the known classes",
        );
    }

    #[test]
    fn duplicate_register_fails() {
        let reg = MetricsRegistry::init();
        DetectorHitMetrics::register(&reg).unwrap();
        assert!(DetectorHitMetrics::register(&reg).is_err());
    }

    #[test]
    fn cheap_clone_shares_storage() {
        let reg = MetricsRegistry::init();
        let m1 = DetectorHitMetrics::register(&reg).unwrap();
        let m2 = m1.clone();
        m1.record("xss");
        m2.record("xss");
        assert_eq!(series_value(&reg, "xss"), 2.0);
    }

    /// Pin the constants against `aegis_security::detectors::DetectorClass`.
    #[test]
    fn class_constants_match_detector_enum() {
        use aegis_security::detectors::DetectorClass;
        let mut from_enum: Vec<&str> =
            DetectorClass::ALL.iter().map(|c| c.as_str()).collect();
        from_enum.sort();
        let mut from_const: Vec<&str> = class_label::ALL.to_vec();
        from_const.sort();
        assert_eq!(
            from_enum, from_const,
            "class_label::ALL drifted from DetectorClass — sync the list",
        );
    }
}
