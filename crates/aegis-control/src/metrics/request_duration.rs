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
//! | `rate_limit`   | `IpRateLimiter::consume` call only |
//! | `detect`       | `run_all_filtered` (all enabled detectors for the resolved tier) |
//! | `respond`      | response builder + `bus.emit` for the audit event |
//! | `waf_overhead` | WAF processing only — entry up to the upstream forward (== `total` for blocked/early-exit requests that never forward). Excludes the backend round-trip, so this is the WAF's own cost. |
//! | `total`        | entry to response built, **incl. upstream forward** — one sample per request |
//!
//! Buckets keep dense sub-10 ms resolution for the WAF-internal stages
//! (`waf_overhead` / `detect` / `rate_limit`; p99 ≤ 5 ms contract) **and**
//! extend to 10 s so the `total` stage — which includes the upstream
//! forward — doesn't saturate its top bucket when a slow backend pushes
//! end-to-end latency past 250 ms (otherwise every `total` percentile
//! clamps to the old 250 ms top bound). See `tests/load/README-perf.md`.

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
    /// WAF processing cost, excluding the upstream backend round-trip
    /// (entry → just before the upstream forward; == `TOTAL` for
    /// blocked/early-exit requests that never forward).
    pub const WAF_OVERHEAD: &str = "waf_overhead";
    pub const TOTAL: &str = "total";
}

/// Histogram bucket layout in **milliseconds**. Dense under 10 ms (the
/// WAF p99 ≤ 5 ms contract is what matters most for the WAF-internal
/// stages), then a coarse tail out to 10 s. The tail (≥ 500 ms) exists
/// for the `total` stage, which includes the upstream forward: without
/// it, a slow backend overflows the top bucket and `histogram_quantile`
/// clamps every `total` percentile to the last finite bound (the old
/// 250 ms ceiling). Adding high buckets costs nothing for the
/// sub-millisecond stages — their samples never reach them.
pub const BUCKETS_MS: &[f64] = &[
    0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 25.0, 50.0,
    100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0, 10000.0,
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

    /// Compute p50 / p95 / p99 percentiles in milliseconds from
    /// the Prometheus histogram's cumulative bucket counts. Same
    /// algorithm PromQL `histogram_quantile` uses (linear
    /// interpolation between bucket boundaries).
    ///
    /// Returns `None` when the histogram has zero samples for the
    /// stage. The returned values are total-cumulative — they
    /// reflect every sample recorded since the process started.
    /// For windowed percentiles the dashboard polls this on a
    /// schedule and the difference between adjacent calls is
    /// what's recently happening; the absolute curve is fine for
    /// "is the WAF healthy" headline.
    pub fn percentiles_ms(&self, stage: &str) -> Option<LatencyPercentiles> {
        use prometheus::core::Collector;
        let h = self.inner.with_label_values(&[stage]);
        let families = h.collect();
        // HistogramVec.with_label_values returns a Histogram which
        // collects exactly one MetricFamily containing one Metric.
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
            p50_ms: quantile(buckets, total, 0.50),
            p95_ms: quantile(buckets, total, 0.95),
            p99_ms: quantile(buckets, total, 0.99),
            samples: total,
        })
    }
}

/// p50/p95/p99 in milliseconds plus the sample count behind them.
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct LatencyPercentiles {
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub samples: u64,
}

/// Linear-interpolation `histogram_quantile`. `buckets` carries
/// cumulative counts per `upper_bound` (the format
/// `prometheus::Histogram::proto()` produces). Same shape as
/// PromQL's `histogram_quantile`. Public so the per-route
/// histogram (`crate::metrics::route_latency`) can reuse the
/// same algorithm.
pub fn quantile_ms(buckets: &[prometheus::proto::Bucket], total: u64, p: f64) -> f64 {
    quantile(buckets, total, p)
}

fn quantile(buckets: &[prometheus::proto::Bucket], total: u64, p: f64) -> f64 {
    let target = (total as f64) * p;
    let mut prev_count = 0u64;
    let mut prev_bound = 0.0f64;
    for b in buckets {
        let cum = b.get_cumulative_count();
        let upper = b.get_upper_bound();
        if (cum as f64) >= target {
            // Linear interpolation between prev_bound and upper.
            if cum == prev_count {
                return upper;
            }
            let frac = (target - prev_count as f64) / (cum - prev_count) as f64;
            return prev_bound + (upper - prev_bound) * frac;
        }
        prev_count = cum;
        prev_bound = upper;
    }
    // Past the last bucket — return the highest bound (capped).
    buckets.last().map(|b| b.get_upper_bound()).unwrap_or(0.0)
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
    fn total_stage_does_not_saturate_above_250ms() {
        // Regression (2026-06-04): the `total` stage includes the
        // upstream forward. Before the bucket tail extended past 250ms,
        // a ~400ms end-to-end request overflowed the top bucket and
        // every percentile clamped to 250. With the wider tail it
        // interpolates above 250 instead.
        let reg = MetricsRegistry::init();
        let h = RequestStageHistogram::register(&reg).unwrap();
        for _ in 0..100 {
            h.record(stage::TOTAL, Duration::from_millis(400));
        }
        let p = h.percentiles_ms(stage::TOTAL).unwrap();
        assert!(
            p.p50_ms > 250.0,
            "p50 must exceed the old 250ms ceiling, got {}",
            p.p50_ms
        );
        assert!(
            p.p99_ms > 250.0 && p.p99_ms <= 1000.0,
            "p99 should land in the (250, 1000]ms band (the 250→500 bucket), got {}",
            p.p99_ms
        );
    }

    #[test]
    fn buckets_extend_past_250ms_for_end_to_end_total() {
        // The tail must cover end-to-end latencies so `total` (incl.
        // upstream) doesn't saturate at the WAF-internal ceiling.
        let max = BUCKETS_MS.last().copied().unwrap_or(0.0);
        assert!(max >= 5000.0, "top bucket must reach multi-second, got {max}");
        assert!(
            BUCKETS_MS.iter().any(|&b| b > 250.0),
            "must have buckets above the old 250ms ceiling"
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
