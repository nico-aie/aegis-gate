//! SSE streaming metrics (SSE plan §7).
//!
//! Four series so operators can spot stream leaks / runaways — each live
//! stream pins an upstream connection for its lifetime, which the legacy
//! client pool (idle-only) does not bound:
//!
//! - `aegis_responses_streamed_total` (Counter) — streamed (vs buffered).
//! - `aegis_active_streams` (Gauge) — currently-live streams.
//! - `aegis_stream_duration_seconds` (Histogram) — per-stream lifetime.
//! - `aegis_stream_bytes_sent` (Histogram) — bytes delivered per stream.

use prometheus::{Counter, Gauge, Histogram};

use super::MetricsRegistry;

/// Registered streaming metric handles. Cheap to clone (inner prometheus
/// handles are `Arc`-shared).
#[derive(Clone)]
pub struct StreamingMetrics {
    responses_streamed_total: Counter,
    active_streams: Gauge,
    stream_duration_seconds: Histogram,
    stream_bytes_sent: Histogram,
}

impl StreamingMetrics {
    /// Register the four series. Called once at boot from
    /// `aegis-proxy::run` next to the other metric registrations.
    pub fn register(reg: &MetricsRegistry) -> prometheus::Result<Self> {
        let responses_streamed_total = reg.register_counter(
            "aegis_responses_streamed_total",
            "Total responses streamed through (header-inspected only) rather than buffered.",
        )?;
        let active_streams = reg.register_gauge(
            "aegis_active_streams",
            "Currently-active streamed responses. Each pins an upstream connection for its \
             lifetime — watch for leaks / runaways against streaming.max_concurrent.",
        )?;
        let stream_duration_seconds = reg.register_histogram(
            "aegis_stream_duration_seconds",
            "Lifetime of a streamed response in seconds (start to body drop).",
            vec![0.1, 0.5, 1.0, 5.0, 15.0, 30.0, 60.0, 300.0, 900.0, 3600.0],
        )?;
        let stream_bytes_sent = reg.register_histogram(
            "aegis_stream_bytes_sent",
            "Bytes delivered over a streamed response (sum of data frames).",
            vec![
                256.0, 1024.0, 10240.0, 102400.0, 1048576.0, 10485760.0, 104857600.0,
            ],
        )?;
        Ok(Self {
            responses_streamed_total,
            active_streams,
            stream_duration_seconds,
            stream_bytes_sent,
        })
    }

    /// A stream began: bump the total + the active gauge.
    pub fn on_stream_start(&self) {
        self.responses_streamed_total.inc();
        self.active_streams.inc();
    }

    /// A stream ended (body dropped — clean end, error, or client
    /// disconnect): release the active gauge and observe its lifetime +
    /// total bytes delivered.
    pub fn on_stream_end(&self, duration_secs: f64, bytes: u64) {
        self.active_streams.dec();
        self.stream_duration_seconds.observe(duration_secs);
        self.stream_bytes_sent.observe(bytes as f64);
    }

    /// Snapshot the current active-stream count.
    pub fn active(&self) -> f64 {
        self.active_streams.get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_creates_the_metric_families() {
        let reg = MetricsRegistry::init();
        let _m = StreamingMetrics::register(&reg).unwrap();
        let names: Vec<String> = reg
            .inner()
            .gather()
            .iter()
            .map(|f| f.get_name().to_string())
            .collect();
        assert!(names.contains(&"aegis_responses_streamed_total".to_string()));
        assert!(names.contains(&"aegis_active_streams".to_string()));
        assert!(names.contains(&"aegis_stream_duration_seconds".to_string()));
        assert!(names.contains(&"aegis_stream_bytes_sent".to_string()));
    }

    #[test]
    fn start_and_end_move_the_active_gauge() {
        let reg = MetricsRegistry::init();
        let m = StreamingMetrics::register(&reg).unwrap();
        assert_eq!(m.active(), 0.0);
        m.on_stream_start();
        m.on_stream_start();
        assert_eq!(m.active(), 2.0);
        m.on_stream_end(1.5, 4096);
        assert_eq!(m.active(), 1.0, "ending one stream releases one active slot");
    }
}
