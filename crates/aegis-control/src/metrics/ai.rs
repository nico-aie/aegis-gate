//! AI-T6 — AI detector metrics.
//!
//! Three series, all registered at boot when the binary
//! carries the `ai` Cargo feature AND `cfg.ai.enabled`:
//!
//! - `aegis_ai_predictions_total{verdict}` (Counter) —
//!   incremented once per inference.  `verdict` is `attack` or
//!   `normal`; future binary-classifier swap doesn't change
//!   the label set.
//! - `aegis_ai_inference_duration_seconds` (Histogram) —
//!   wall-clock per-prediction latency.  Buckets target the
//!   sub-millisecond shape the dataset report measured (p50
//!   ~0.5 ms, p99 ~1 ms) plus headroom up to 100 ms so a
//!   stalled session is visible.
//! - `aegis_ai_fallback_total{reason}` (Counter) —
//!   inference failures + safety fall-throughs.  `reason` is
//!   one of `inference_error`, `low_confidence`, `tensor_build`.
//!   Pre-allocates every series so /metrics shows them at zero
//!   on a fresh boot — operators can chart "AI is healthy" by
//!   watching `inference_error` stay at 0.
//!
//! Hot-path cost: one `with_label_values` lookup per metric +
//! one atomic inc/observe — single-digit ns per call,
//! dwarfed by the inference itself.

use prometheus::{CounterVec, HistogramVec};

use super::MetricsRegistry;

// Implement the cross-crate sink trait so the AI detector in
// `aegis-security` can record into our Prometheus registry
// without `aegis-security` taking a dependency on us.
impl aegis_security::detectors::ai::AiMetricsSink for AiMetrics {
    fn record_prediction(&self, is_attack: bool, latency_seconds: f64) {
        AiMetrics::record_prediction(self, is_attack, latency_seconds);
    }
    fn record_fallback(&self, reason: &'static str) {
        AiMetrics::record_fallback(self, reason);
    }
}

/// Verdict label values — kept in sync with `AiDetector`'s
/// [`is_attack`] flag.
pub mod verdict_label {
    pub const ATTACK: &str = "attack";
    pub const NORMAL: &str = "normal";
    pub const ALL: [&str; 2] = [ATTACK, NORMAL];
}

/// Fallback reason label values — single source of truth so a
/// typo in one call site can't spawn a dashboard-invisible
/// series.
pub mod reason_label {
    pub const INFERENCE_ERROR: &str = "inference_error";
    pub const LOW_CONFIDENCE: &str = "low_confidence";
    pub const TENSOR_BUILD: &str = "tensor_build";
    pub const ALL: [&str; 3] = [INFERENCE_ERROR, LOW_CONFIDENCE, TENSOR_BUILD];
}

/// Cheap-to-clone wrapper around the registered metric handles.
#[derive(Clone)]
pub struct AiMetrics {
    predictions_total: CounterVec,
    inference_duration: HistogramVec,
    fallback_total: CounterVec,
}

impl AiMetrics {
    pub fn register(reg: &MetricsRegistry) -> prometheus::Result<Self> {
        let predictions_total = reg.register_counter_vec(
            "aegis_ai_predictions_total",
            "AI detector predictions, labelled by verdict (attack | normal). One increment per inference.",
            &["verdict"],
        )?;
        for v in verdict_label::ALL {
            predictions_total.with_label_values(&[v]);
        }

        let inference_duration = reg.register_histogram_vec(
            "aegis_ai_inference_duration_seconds",
            "AI inference wall-clock duration (one observation per inference). Buckets cover the sub-millisecond model envelope plus headroom for stalls.",
            &["verdict"],
            // Buckets: 100 µs, 250 µs, 500 µs, 1 ms, 2.5 ms,
            // 5 ms, 10 ms, 25 ms, 100 ms.  Sub-ms granular to
            // catch the model's normal range; 100 ms top end
            // surfaces stalls without exploding the bucket
            // count.
            vec![0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.1],
        )?;
        for v in verdict_label::ALL {
            inference_duration.with_label_values(&[v]);
        }

        let fallback_total = reg.register_counter_vec(
            "aegis_ai_fallback_total",
            "AI detector fall-through count by reason. Increments when the WAF can't or shouldn't trust an AI verdict (inference error, below-threshold confidence, tensor-shape mismatch).",
            &["reason"],
        )?;
        for r in reason_label::ALL {
            fallback_total.with_label_values(&[r]);
        }

        Ok(Self {
            predictions_total,
            inference_duration,
            fallback_total,
        })
    }

    /// Record a successful inference.  Hot-path: one
    /// `with_label_values` lookup + one `inc` + one
    /// `observe`.
    pub fn record_prediction(&self, is_attack: bool, latency_seconds: f64) {
        let v = if is_attack {
            verdict_label::ATTACK
        } else {
            verdict_label::NORMAL
        };
        self.predictions_total.with_label_values(&[v]).inc();
        self.inference_duration
            .with_label_values(&[v])
            .observe(latency_seconds);
    }

    /// Record a fall-through (inference failed, confidence
    /// below threshold, or tensor build error).
    pub fn record_fallback(&self, reason: &'static str) {
        self.fallback_total.with_label_values(&[reason]).inc();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_creates_three_series() {
        let reg = MetricsRegistry::init();
        let _m = AiMetrics::register(&reg).unwrap();
        let names: Vec<String> = reg
            .inner()
            .gather()
            .iter()
            .map(|f| f.get_name().to_string())
            .collect();
        assert!(names.contains(&"aegis_ai_predictions_total".to_string()));
        assert!(names.contains(&"aegis_ai_inference_duration_seconds".to_string()));
        assert!(names.contains(&"aegis_ai_fallback_total".to_string()));
    }

    #[test]
    fn pre_allocates_every_label_so_grafana_panels_render_on_fresh_boot() {
        let reg = MetricsRegistry::init();
        let _m = AiMetrics::register(&reg).unwrap();
        let predictions = reg
            .inner()
            .gather()
            .into_iter()
            .find(|f| f.get_name() == "aegis_ai_predictions_total")
            .unwrap();
        assert_eq!(
            predictions.get_metric().len(),
            verdict_label::ALL.len(),
            "every verdict pre-allocated"
        );
        let fallback = reg
            .inner()
            .gather()
            .into_iter()
            .find(|f| f.get_name() == "aegis_ai_fallback_total")
            .unwrap();
        assert_eq!(
            fallback.get_metric().len(),
            reason_label::ALL.len(),
            "every reason pre-allocated"
        );
    }

    #[test]
    fn record_prediction_increments_correct_verdict() {
        let reg = MetricsRegistry::init();
        let m = AiMetrics::register(&reg).unwrap();
        m.record_prediction(true, 0.0006);
        m.record_prediction(true, 0.0004);
        m.record_prediction(false, 0.0003);

        let metric = reg
            .inner()
            .gather()
            .into_iter()
            .find(|f| f.get_name() == "aegis_ai_predictions_total")
            .unwrap();
        let mut by_label = std::collections::HashMap::new();
        for s in metric.get_metric() {
            let lab = s
                .get_label()
                .iter()
                .find(|l| l.get_name() == "verdict")
                .unwrap()
                .get_value()
                .to_string();
            by_label.insert(lab, s.get_counter().get_value());
        }
        assert_eq!(by_label.get("attack"), Some(&2.0));
        assert_eq!(by_label.get("normal"), Some(&1.0));
    }

    #[test]
    fn duplicate_register_fails() {
        let reg = MetricsRegistry::init();
        AiMetrics::register(&reg).unwrap();
        assert!(AiMetrics::register(&reg).is_err());
    }

    #[test]
    fn cheap_clone_shares_underlying_counters() {
        let reg = MetricsRegistry::init();
        let m1 = AiMetrics::register(&reg).unwrap();
        let m2 = m1.clone();
        m1.record_prediction(true, 0.0005);
        m2.record_prediction(true, 0.0005);
        let metric = reg
            .inner()
            .gather()
            .into_iter()
            .find(|f| f.get_name() == "aegis_ai_predictions_total")
            .unwrap();
        let attack = metric
            .get_metric()
            .iter()
            .find(|s| {
                s.get_label()
                    .iter()
                    .any(|l| l.get_name() == "verdict" && l.get_value() == "attack")
            })
            .unwrap();
        assert_eq!(attack.get_counter().get_value(), 2.0);
    }
}
