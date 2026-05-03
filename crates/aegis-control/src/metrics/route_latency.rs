//! Per-route request-duration histogram.
//!
//! Pairs with the per-stage `RequestStageHistogram` (which gives
//! global p50/p95/p99 across all routes by stage). This module
//! adds the *route* dimension — each configured route gets its
//! own series so the dashboard can show "p99 latency for /login
//! vs /api/transactions".
//!
//! ## Cardinality
//!
//! Labelled by `route` only. The route key space is bounded by
//! the number of `routes:` entries in the YAML config (typically
//! < 50). Path-level labels (which would be unbounded) are NOT
//! used — the dashboard's `/api/analytics/routes` already
//! aggregates by route_id from the audit ring.
//!
//! ## Hot-path cost
//!
//! Same as `RequestStageHistogram::record` — one
//! `HistogramVec::with_label_values` lookup (HashMap by label
//! string) plus one atomic float add to the bucket counters.
//! Per-request cost ~30 ns.

use std::time::Duration;

use prometheus::HistogramVec;

use super::request_duration::{LatencyPercentiles, BUCKETS_MS};
use super::MetricsRegistry;

/// Wrapper around a `HistogramVec` labelled by `route`. Cheap
/// to clone; the inner HistogramVec is `Arc`-shared inside
/// the `prometheus` crate.
#[derive(Clone)]
pub struct RouteLatencyHistogram {
    inner: HistogramVec,
}

impl RouteLatencyHistogram {
    /// Register the histogram on the shared registry. One
    /// histogram per route surfaces lazily — the data plane's
    /// `record(route, elapsed)` triggers the first
    /// `with_label_values` call which materialises that series.
    pub fn register(reg: &MetricsRegistry) -> prometheus::Result<Self> {
        let inner = reg.register_histogram_vec(
            "waf_route_request_duration_ms",
            "Per-route end-to-end request duration (milliseconds). \
             Labelled by `route` (the route_id from the matched \
             route table entry). Bucket layout matches \
             `waf_request_duration_ms` so dashboards can compose \
             both sources.",
            &["route"],
            BUCKETS_MS.to_vec(),
        )?;
        Ok(Self { inner })
    }

    /// Hot-path: record one per-route sample. Cheap.
    pub fn record(&self, route: &str, elapsed: Duration) {
        let ms = elapsed.as_secs_f64() * 1_000.0;
        self.inner.with_label_values(&[route]).observe(ms);
    }

    /// Compute p50 / p95 / p99 percentiles in milliseconds for
    /// one route from the histogram's cumulative bucket counts.
    /// Same algorithm as `RequestStageHistogram::percentiles_ms`.
    pub fn percentiles_ms(&self, route: &str) -> Option<LatencyPercentiles> {
        use prometheus::core::Collector;
        let h = self.inner.with_label_values(&[route]);
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

    /// List every route that has at least one recorded sample.
    /// Used by `/api/analytics/latency/routes` to enumerate the
    /// active series without the operator having to know route
    /// IDs in advance.
    pub fn known_routes(&self) -> Vec<String> {
        use prometheus::core::Collector;
        self.inner
            .collect()
            .into_iter()
            .flat_map(|f| f.get_metric().to_vec())
            .filter_map(|m| {
                m.get_label()
                    .iter()
                    .find(|l| l.get_name() == "route")
                    .map(|l| l.get_value().to_string())
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_creates_per_route_series() {
        let reg = MetricsRegistry::init();
        let h = RouteLatencyHistogram::register(&reg).unwrap();
        h.record("login", Duration::from_micros(500));
        h.record("login", Duration::from_micros(800));
        h.record("api", Duration::from_millis(2));
        let routes = h.known_routes();
        assert!(routes.contains(&"login".to_string()));
        assert!(routes.contains(&"api".to_string()));
    }

    #[test]
    fn percentiles_returns_none_for_empty_route() {
        let reg = MetricsRegistry::init();
        let h = RouteLatencyHistogram::register(&reg).unwrap();
        assert!(h.percentiles_ms("never-seen").is_none());
    }

    #[test]
    fn percentiles_reflects_recorded_samples() {
        let reg = MetricsRegistry::init();
        let h = RouteLatencyHistogram::register(&reg).unwrap();
        // 100 samples at 1 ms — every percentile should land
        // within the 1 ms bucket boundary (linear interpolation).
        for _ in 0..100 {
            h.record("api", Duration::from_micros(1_000));
        }
        let p = h.percentiles_ms("api").unwrap();
        assert_eq!(p.samples, 100);
        // Bucket layout has [..., 1.0, 2.5, ...] — p50 / p95 / p99
        // should land in [0.5, 1.0] (linear interp puts them
        // exactly at 1.0 when every sample falls into the 1.0 bucket).
        assert!(p.p50_ms <= 1.0 + 0.001);
        assert!(p.p99_ms <= 1.0 + 0.001);
    }

    #[test]
    fn separate_routes_have_independent_distributions() {
        let reg = MetricsRegistry::init();
        let h = RouteLatencyHistogram::register(&reg).unwrap();
        for _ in 0..50 {
            h.record("fast", Duration::from_micros(100));
        }
        for _ in 0..50 {
            h.record("slow", Duration::from_millis(50));
        }
        let fast = h.percentiles_ms("fast").unwrap();
        let slow = h.percentiles_ms("slow").unwrap();
        assert!(fast.p99_ms < slow.p99_ms);
    }

    #[test]
    fn double_register_into_same_registry_is_an_error() {
        let reg = MetricsRegistry::init();
        let _first = RouteLatencyHistogram::register(&reg).unwrap();
        let second = RouteLatencyHistogram::register(&reg);
        assert!(second.is_err());
    }
}
