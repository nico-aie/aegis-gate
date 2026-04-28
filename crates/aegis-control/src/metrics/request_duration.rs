//! Per-stage request duration histogram (F-T10).
//!
//! Splits the WAF-internal time the data plane spends on each
//! request into named pipeline stages. Operators reading
//! `tests/load/baseline.js` results can attribute a p99 slip to
//! a specific stage instead of one opaque RTT number.
//!
//! # Stages
//!
//! | label        | covers |
//! |--------------|--------|
//! | `rate_limit` | `IpRateLimiter::consume` call only |
//! | `detect`     | `run_all_filtered` (all enabled detectors for the resolved tier) |
//! | `respond`    | response builder + `bus.emit` for the audit event |
//! | `total`      | entry to response built — a single sample per request |
//!
//! Buckets cover the realistic WAF-internal range (0.05 ms → 250 ms).
//! Anything beyond that is host noise — see
//! `tests/load/README-perf.md`.

use std::time::Duration;

use prometheus::HistogramVec;

use super::MetricsRegistry;

/// Stable label values. Pinned at compile time so a typo in
/// the hot path can't push a metric series the dashboard
/// doesn't know how to read.
pub mod stage {
    pub const RATE_LIMIT: &str = "rate_limit";
    pub const DETECT: &str = "detect";
    pub const RESPOND: &str = "respond";
    pub const TOTAL: &str = "total";
}

/// Histogram bucket layout in **milliseconds**. Same shape as
/// the standard prometheus `DEFAULT_BUCKETS` but shifted
/// downward — the WAF p99 contract is `≤ 5 ms` on dedicated
/// hardware, so the resolution under 10 ms matters most.
pub const BUCKETS_MS: &[f64] = &[
    0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 25.0, 50.0,
    100.0, 250.0,
];

/// Wrapper around the registered `HistogramVec`. Cheap to
/// clone (the inner `HistogramVec` is `Arc`-shared inside
/// prometheus).
#[derive(Clone)]
pub struct RequestStageHistogram {
    inner: HistogramVec,
}

impl RequestStageHistogram {
    /// Register on a `MetricsRegistry`. Idempotent across
    /// `init()` calls because each registry is fresh.
    pub fn register(reg: &MetricsRegistry) -> prometheus::Result<Self> {
        let inner = reg.register_histogram_vec(
            "waf_request_duration_ms",
            "Time spent in each WAF pipeline stage (milliseconds).",
            &["stage"],
            BUCKETS_MS.to_vec(),
        )?;
        Ok(Self { inner })
    }

    /// Record one sample. Hot-path safe — prometheus
    /// `HistogramVec::with_label_values(...).observe(...)`
    /// is one HashMap lookup + one atomic `fetch_add`.
    pub fn record(&self, stage: &str, elapsed: Duration) {
        let ms = elapsed.as_secs_f64() * 1_000.0;
        self.inner
            .with_label_values(&[stage])
            .observe(ms);
    }

    /// Test seam — read back the count of samples recorded
    /// for a given stage. Production code never needs this.
    #[doc(hidden)]
    pub fn sample_count(&self, stage: &str) -> u64 {
        self.inner.with_label_values(&[stage]).get_sample_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_creates_histogram() {
        let reg = MetricsRegistry::init();
        let h = RequestStageHistogram::register(&reg).unwrap();
        // Recording onto unknown stage labels still works —
        // prometheus auto-creates the series. The `stage::*`
        // constants exist to discipline call sites, not to
        // restrict prometheus.
        h.record("rate_limit", Duration::from_micros(100));
        assert_eq!(h.sample_count("rate_limit"), 1);
    }

    #[test]
    fn each_stage_label_independent() {
        let reg = MetricsRegistry::init();
        let h = RequestStageHistogram::register(&reg).unwrap();
        for _ in 0..5 {
            h.record(stage::RATE_LIMIT, Duration::from_micros(50));
        }
        for _ in 0..3 {
            h.record(stage::DETECT, Duration::from_millis(2));
        }
        h.record(stage::RESPOND, Duration::from_micros(20));
        assert_eq!(h.sample_count(stage::RATE_LIMIT), 5);
        assert_eq!(h.sample_count(stage::DETECT), 3);
        assert_eq!(h.sample_count(stage::RESPOND), 1);
        assert_eq!(h.sample_count(stage::TOTAL), 0);
    }

    #[test]
    fn record_converts_duration_to_milliseconds() {
        let reg = MetricsRegistry::init();
        let h = RequestStageHistogram::register(&reg).unwrap();
        h.record(stage::TOTAL, Duration::from_millis(7));
        // sum == 7 ms (within float epsilon)
        let s = h.inner.with_label_values(&[stage::TOTAL]).get_sample_sum();
        assert!((s - 7.0).abs() < 0.001);
    }

    #[test]
    fn buckets_cover_under_ten_ms_range() {
        // Property: the bucket layout has at least 7 buckets in
        // the [0, 10] ms range. Loss of resolution under 10 ms
        // would defeat the p99 < 5 ms attribution that's
        // F-T10's whole point.
        let under_ten = BUCKETS_MS.iter().filter(|&&b| b <= 10.0).count();
        assert!(
            under_ten >= 7,
            "must keep dense buckets under 10ms, got {under_ten}"
        );
    }

    #[test]
    fn stage_constants_are_unique_strings() {
        // Each label value must be its own series; a duplicate
        // would silently merge measurements.
        let labels = [
            stage::RATE_LIMIT,
            stage::DETECT,
            stage::RESPOND,
            stage::TOTAL,
        ];
        let mut sorted: Vec<&str> = labels.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), labels.len(), "stage labels must be unique");
    }
}
