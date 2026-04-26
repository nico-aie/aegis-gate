use prometheus::Encoder;

use super::MetricsRegistry;

/// Render all metrics from the shared registry as Prometheus text format.
pub fn render(registry: &MetricsRegistry) -> String {
    let encoder = prometheus::TextEncoder::new();
    let metric_families = registry.inner().gather();
    let mut buf = Vec::new();
    encoder.encode(&metric_families, &mut buf).unwrap();
    String::from_utf8(buf).unwrap()
}

/// Content type for Prometheus text format.
pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_empty_registry() {
        let reg = MetricsRegistry::init();
        let output = render(&reg);
        assert!(output.is_empty());
    }

    #[test]
    fn render_counter() {
        let reg = MetricsRegistry::init();
        let c = reg.register_counter("waf_requests_total", "total requests").unwrap();
        c.inc_by(42.0);
        let output = render(&reg);
        assert!(output.contains("waf_requests_total"));
        assert!(output.contains("42"));
    }

    #[test]
    fn render_histogram() {
        let reg = MetricsRegistry::init();
        let h = reg
            .register_histogram(
                "waf_upstream_latency_seconds",
                "upstream latency",
                MetricsRegistry::waf_latency_buckets(),
            )
            .unwrap();
        h.observe(0.05);
        let output = render(&reg);
        assert!(output.contains("waf_upstream_latency_seconds"));
        assert!(output.contains("_bucket"));
        assert!(output.contains("_count"));
        assert!(output.contains("_sum"));
    }

    #[test]
    fn render_gauge() {
        let reg = MetricsRegistry::init();
        let g = reg.register_gauge("waf_admin_sessions_active", "active sessions").unwrap();
        g.set(3.0);
        let output = render(&reg);
        assert!(output.contains("waf_admin_sessions_active"));
        assert!(output.contains("3"));
    }

    #[test]
    fn render_counter_vec() {
        let reg = MetricsRegistry::init();
        let cv = reg
            .register_counter_vec("waf_audit_events_total", "audit events", &["class", "sink"])
            .unwrap();
        cv.with_label_values(&["detection", "jsonl"]).inc_by(10.0);
        cv.with_label_values(&["admin", "syslog"]).inc_by(5.0);
        let output = render(&reg);
        assert!(output.contains("detection"));
        assert!(output.contains("jsonl"));
        assert!(output.contains("admin"));
        assert!(output.contains("syslog"));
    }

    #[test]
    fn render_multiple_metrics() {
        let reg = MetricsRegistry::init();
        reg.register_counter("m1_total", "m1").unwrap();
        reg.register_counter("m2_total", "m2").unwrap();
        let output = render(&reg);
        assert!(output.contains("m1_total"));
        assert!(output.contains("m2_total"));
    }

    #[test]
    fn content_type_correct() {
        assert!(CONTENT_TYPE.starts_with("text/plain"));
    }
}
