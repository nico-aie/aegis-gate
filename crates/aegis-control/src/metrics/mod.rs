pub mod exporter;

use prometheus::Registry;
use std::sync::Arc;

/// Shared metrics registry.
///
/// Must be created before proxy/security boot so they can register
/// metric families into the shared registry.
#[derive(Clone)]
pub struct MetricsRegistry(pub Arc<Registry>);

impl MetricsRegistry {
    /// Create a new metrics registry.
    pub fn init() -> Self {
        Self(Arc::new(Registry::new()))
    }

    /// Register a counter.
    pub fn register_counter(
        &self,
        name: &str,
        help: &str,
    ) -> prometheus::Result<prometheus::Counter> {
        let c = prometheus::Counter::new(name, help)?;
        self.0.register(Box::new(c.clone()))?;
        Ok(c)
    }

    /// Register a counter vec.
    pub fn register_counter_vec(
        &self,
        name: &str,
        help: &str,
        labels: &[&str],
    ) -> prometheus::Result<prometheus::CounterVec> {
        let opts = prometheus::Opts::new(name, help);
        let c = prometheus::CounterVec::new(opts, labels)?;
        self.0.register(Box::new(c.clone()))?;
        Ok(c)
    }

    /// Register a histogram.
    pub fn register_histogram(
        &self,
        name: &str,
        help: &str,
        buckets: Vec<f64>,
    ) -> prometheus::Result<prometheus::Histogram> {
        let opts = prometheus::HistogramOpts::new(name, help).buckets(buckets);
        let h = prometheus::Histogram::with_opts(opts)?;
        self.0.register(Box::new(h.clone()))?;
        Ok(h)
    }

    /// Register a histogram vec.
    pub fn register_histogram_vec(
        &self,
        name: &str,
        help: &str,
        labels: &[&str],
        buckets: Vec<f64>,
    ) -> prometheus::Result<prometheus::HistogramVec> {
        let opts = prometheus::HistogramOpts::new(name, help).buckets(buckets);
        let h = prometheus::HistogramVec::new(opts, labels)?;
        self.0.register(Box::new(h.clone()))?;
        Ok(h)
    }

    /// Register a gauge.
    pub fn register_gauge(
        &self,
        name: &str,
        help: &str,
    ) -> prometheus::Result<prometheus::Gauge> {
        let g = prometheus::Gauge::new(name, help)?;
        self.0.register(Box::new(g.clone()))?;
        Ok(g)
    }

    /// Register a gauge vec.
    pub fn register_gauge_vec(
        &self,
        name: &str,
        help: &str,
        labels: &[&str],
    ) -> prometheus::Result<prometheus::GaugeVec> {
        let opts = prometheus::Opts::new(name, help);
        let g = prometheus::GaugeVec::new(opts, labels)?;
        self.0.register(Box::new(g.clone()))?;
        Ok(g)
    }

    /// Get the inner prometheus registry.
    pub fn inner(&self) -> &Registry {
        &self.0
    }

    /// Standard WAF histogram buckets (seconds).
    pub fn waf_latency_buckets() -> Vec<f64> {
        vec![0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_creates_registry() {
        let reg = MetricsRegistry::init();
        assert!(reg.inner().gather().is_empty());
    }

    #[test]
    fn register_counter() {
        let reg = MetricsRegistry::init();
        let c = reg.register_counter("test_total", "test counter").unwrap();
        c.inc();
        assert_eq!(c.get() as u64, 1);
        assert_eq!(reg.inner().gather().len(), 1);
    }

    #[test]
    fn register_counter_vec() {
        let reg = MetricsRegistry::init();
        let cv = reg.register_counter_vec("req_total", "requests", &["method"]).unwrap();
        cv.with_label_values(&["GET"]).inc();
        cv.with_label_values(&["POST"]).inc();
        assert_eq!(cv.with_label_values(&["GET"]).get() as u64, 1);
    }

    #[test]
    fn register_histogram() {
        let reg = MetricsRegistry::init();
        let h = reg
            .register_histogram("latency", "lat", MetricsRegistry::waf_latency_buckets())
            .unwrap();
        h.observe(0.05);
        assert_eq!(h.get_sample_count(), 1);
    }

    #[test]
    fn register_histogram_vec() {
        let reg = MetricsRegistry::init();
        let hv = reg
            .register_histogram_vec("lat_by_route", "lat", &["route"], MetricsRegistry::waf_latency_buckets())
            .unwrap();
        hv.with_label_values(&["api"]).observe(0.01);
        assert_eq!(hv.with_label_values(&["api"]).get_sample_count(), 1);
    }

    #[test]
    fn register_gauge() {
        let reg = MetricsRegistry::init();
        let g = reg.register_gauge("active", "active").unwrap();
        g.set(42.0);
        assert_eq!(g.get() as u64, 42);
    }

    #[test]
    fn register_gauge_vec() {
        let reg = MetricsRegistry::init();
        let gv = reg.register_gauge_vec("pool_size", "pool", &["pool"]).unwrap();
        gv.with_label_values(&["upstream"]).set(5.0);
        assert_eq!(gv.with_label_values(&["upstream"]).get() as u64, 5);
    }

    #[test]
    fn duplicate_register_fails() {
        let reg = MetricsRegistry::init();
        reg.register_counter("dup", "dup").unwrap();
        assert!(reg.register_counter("dup", "dup").is_err());
    }

    #[test]
    fn clone_shares_registry() {
        let r1 = MetricsRegistry::init();
        let r2 = r1.clone();
        r1.register_counter("shared_total", "shared").unwrap();
        assert_eq!(r2.inner().gather().len(), 1);
    }

    #[test]
    fn waf_latency_buckets_correct() {
        let buckets = MetricsRegistry::waf_latency_buckets();
        assert_eq!(buckets.len(), 10);
        assert!((buckets[0] - 0.001).abs() < f64::EPSILON);
        assert!((buckets[9] - 1.0).abs() < f64::EPSILON);
    }
}
