//! Per-detector evaluation-duration histogram.
//!
//! Pairs with the per-class `DetectorHitMetrics` counter (which
//! tells you *how often* each detector fires) by adding the
//! *cost* dimension — how long sqli / xss / path_traversal /
//! ssrf / etc. spent in `Detector::inspect` per request.
//!
//! ## Cardinality
//!
//! Labelled by `class` only. The class space is fixed at compile
//! time (see `aegis-security::detectors::default_detectors`); a
//! typo in a hot-path call site can't push a metric series the
//! dashboard doesn't know how to read.
//!
//! ## Hot-path cost
//!
//! `record(class, elapsed)` is one `HistogramVec::with_label_values`
//! lookup (HashMap by label string) plus one atomic float add to
//! the bucket counters. ~30 ns per call.

use std::time::Duration;

use prometheus::HistogramVec;

use super::request_duration::{LatencyPercentiles, BUCKETS_MS};
use super::MetricsRegistry;

/// Wrapper around a `HistogramVec` labelled by `class`. Cheap
/// to clone; the inner HistogramVec is `Arc`-shared inside
/// the `prometheus` crate.
#[derive(Clone)]
pub struct DetectorLatencyHistogram {
    inner: HistogramVec,
}

impl DetectorLatencyHistogram {
    /// Register the histogram on the shared registry. Series
    /// materialise lazily on first `record(class, _)`.
    pub fn register(reg: &MetricsRegistry) -> prometheus::Result<Self> {
        let inner = reg.register_histogram_vec(
            "waf_detector_evaluation_duration_ms",
            "Per-detector evaluation time (milliseconds). Labelled \
             by `class` (sqli, xss, path_traversal, ssrf, \
             header_injection, body_abuse, recon, brute_force).",
            &["class"],
            BUCKETS_MS.to_vec(),
        )?;
        Ok(Self { inner })
    }

    /// Hot-path: record one detector's evaluation time. Cheap.
    pub fn record(&self, class: &str, elapsed: Duration) {
        let ms = elapsed.as_secs_f64() * 1_000.0;
        self.inner.with_label_values(&[class]).observe(ms);
    }

    /// Compute p50 / p95 / p99 percentiles in milliseconds for one
    /// class from the histogram's cumulative bucket counts. Same
    /// algorithm as `RequestStageHistogram::percentiles_ms` /
    /// `RouteLatencyHistogram::percentiles_ms`.
    pub fn percentiles_ms(&self, class: &str) -> Option<LatencyPercentiles> {
        use prometheus::core::Collector;
        let h = self.inner.with_label_values(&[class]);
        let families = h.collect();
        let metric = families.first()?.get_metric().first()?;
        let proto = metric.get_histogram();
        let total = proto.get_sample_count();
        if total == 0 {
            return None;
        }
        let buckets = proto.get_bucket();
        if buckets.is_empty() {
            return None;
        }
        Some(LatencyPercentiles {
            p50_ms: super::request_duration::quantile_ms(buckets, total, 0.50),
            p95_ms: super::request_duration::quantile_ms(buckets, total, 0.95),
            p99_ms: super::request_duration::quantile_ms(buckets, total, 0.99),
            samples: total,
        })
    }

    /// List every detector class that has at least one recorded
    /// sample. Used by the API to enumerate active series without
    /// the operator having to know class names.
    pub fn known_classes(&self) -> Vec<String> {
        use prometheus::core::Collector;
        self.inner
            .collect()
            .into_iter()
            .flat_map(|f| f.get_metric().to_vec())
            .filter_map(|m| {
                m.get_label()
                    .iter()
                    .find(|l| l.get_name() == "class")
                    .map(|l| l.get_value().to_string())
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_creates_per_class_series() {
        let reg = MetricsRegistry::init();
        let h = DetectorLatencyHistogram::register(&reg).unwrap();
        h.record("sqli", Duration::from_micros(50));
        h.record("xss", Duration::from_micros(100));
        let classes = h.known_classes();
        assert!(classes.contains(&"sqli".to_string()));
        assert!(classes.contains(&"xss".to_string()));
    }

    #[test]
    fn percentiles_returns_none_for_empty_class() {
        let reg = MetricsRegistry::init();
        let h = DetectorLatencyHistogram::register(&reg).unwrap();
        assert!(h.percentiles_ms("never-seen").is_none());
    }

    #[test]
    fn percentiles_reflects_recorded_samples() {
        let reg = MetricsRegistry::init();
        let h = DetectorLatencyHistogram::register(&reg).unwrap();
        for _ in 0..200 {
            h.record("sqli", Duration::from_micros(500));
        }
        let p = h.percentiles_ms("sqli").unwrap();
        assert_eq!(p.samples, 200);
        // Bucket layout has [0.25, 0.5, ...] — every sample at
        // 0.5ms lands in the 0.5 bucket. Linear interpolation
        // puts every percentile at exactly 0.5 (or just under).
        assert!(p.p50_ms <= 0.5 + 0.001);
        assert!(p.p99_ms <= 0.5 + 0.001);
    }

    #[test]
    fn separate_classes_have_independent_distributions() {
        let reg = MetricsRegistry::init();
        let h = DetectorLatencyHistogram::register(&reg).unwrap();
        for _ in 0..50 {
            h.record("fast", Duration::from_micros(50));
        }
        for _ in 0..50 {
            h.record("slow", Duration::from_millis(20));
        }
        let fast = h.percentiles_ms("fast").unwrap();
        let slow = h.percentiles_ms("slow").unwrap();
        assert!(fast.p99_ms < slow.p99_ms);
    }

    #[test]
    fn double_register_into_same_registry_is_an_error() {
        let reg = MetricsRegistry::init();
        let _first = DetectorLatencyHistogram::register(&reg).unwrap();
        let second = DetectorLatencyHistogram::register(&reg);
        assert!(second.is_err());
    }
}
