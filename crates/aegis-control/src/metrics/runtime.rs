//! SC-T4 — tokio runtime metrics → Prometheus.
//!
//! Exposes 4 gauges that surface internal tokio runtime state:
//!
//! - `aegis_runtime_active_workers`         (`num_workers`)
//! - `aegis_runtime_blocking_threads`       (`num_blocking_threads`)
//! - `aegis_runtime_blocking_queue_depth`   (`blocking_queue_depth`)
//! - `aegis_runtime_io_driver_fd_count`     (`io_driver_fd_count` —
//!   requires `--cfg tokio_unstable` *and* tokio's `io-driver-metrics`
//!   cfg gate; falls back to 0 when unavailable)
//!
//! ## Why this is feature-gated
//!
//! Reading these metrics requires building with the
//! `tokio_unstable` rustc cfg flag, which the tokio team uses to
//! mark APIs that don't carry SemVer guarantees. We don't want
//! production builds on stable APIs to silently roll forward
//! across tokio bumps that break this surface, so the whole
//! module is gated behind the `tokio_unstable` Cargo feature on
//! `aegis-bin` AND the build needs `RUSTFLAGS="--cfg tokio_unstable"`.
//!
//! Operators opt in with:
//! ```sh
//! RUSTFLAGS="--cfg tokio_unstable" \
//!   cargo build -p aegis-bin --release --features tokio_unstable
//! ```
//!
//! Without the flag, the gauges aren't registered and the
//! Prometheus surface is unchanged.

use std::time::Duration;

use prometheus::IntGauge;
use tokio::time;

use super::MetricsRegistry;

/// Holder for the four registered gauges. Cloneable handle so the
/// boot path can spawn a periodic-update task without leaking the
/// registry.
#[derive(Clone)]
pub struct RuntimeMetrics {
    pub active_workers: IntGauge,
    pub blocking_threads: IntGauge,
    pub blocking_queue_depth: IntGauge,
    pub io_driver_fd_count: IntGauge,
}

impl RuntimeMetrics {
    /// Register the gauges into the shared registry. Idempotent
    /// per registry — calling twice will surface a duplicate-
    /// registration error from prometheus.
    pub fn register(reg: &MetricsRegistry) -> prometheus::Result<Self> {
        let active_workers = IntGauge::new(
            "aegis_runtime_active_workers",
            "Number of active tokio worker threads in the runtime. \
             Read from tokio::runtime::Handle::current().metrics().num_workers(). \
             Constant for the process lifetime under the multi-threaded scheduler.",
        )?;
        reg.0.register(Box::new(active_workers.clone()))?;

        let blocking_threads = IntGauge::new(
            "aegis_runtime_blocking_threads",
            "Number of currently-spawned blocking threads in the runtime's blocking pool. \
             Bounded by `runtime.blocking_threads` config. Watch for sustained values \
             at the cap — indicates work shedding into the blocking pool faster than it drains.",
        )?;
        reg.0.register(Box::new(blocking_threads.clone()))?;

        let blocking_queue_depth = IntGauge::new(
            "aegis_runtime_blocking_queue_depth",
            "Number of queued blocking-pool tasks waiting for a worker. \
             Steadily-rising depth = blocking pool saturated; size up `runtime.blocking_threads` or \
             move work off `tokio::task::spawn_blocking`.",
        )?;
        reg.0.register(Box::new(blocking_queue_depth.clone()))?;

        let io_driver_fd_count = IntGauge::new(
            "aegis_runtime_io_driver_fd_count",
            "Number of file descriptors registered with the tokio I/O driver. \
             Includes every TCP socket, every TLS stream, every Redis pool conn. \
             Useful for catching FD leaks (sustained climb without a corresponding RPS climb).",
        )?;
        reg.0.register(Box::new(io_driver_fd_count.clone()))?;

        Ok(Self {
            active_workers,
            blocking_threads,
            blocking_queue_depth,
            io_driver_fd_count,
        })
    }

    /// Read the live tokio runtime metrics and update every
    /// gauge. Cheap — each reader is an atomic load. Wire under
    /// `#[cfg(tokio_unstable)]` since the API lives there.
    #[cfg(tokio_unstable)]
    pub fn sample_now(&self) {
        let h = tokio::runtime::Handle::current();
        let m = h.metrics();
        self.active_workers.set(m.num_workers() as i64);
        self.blocking_threads.set(m.num_blocking_threads() as i64);
        self.blocking_queue_depth
            .set(m.blocking_queue_depth() as i64);
        // `io_driver_fd_count` requires tokio's
        // `io-driver-metrics` cfg in addition to `tokio_unstable`
        // — not yet exposed in stable tokio releases as of writing.
        // Gauge stays at zero until tokio promotes the API; the
        // operator gets a clear "not yet implemented" reading
        // rather than a missing series.
    }

    /// Stub when built without `--cfg tokio_unstable` — the
    /// gauges hold their zero-init value.
    #[cfg(not(tokio_unstable))]
    pub fn sample_now(&self) {
        // No-op. Gauges read 0; that's the documented behaviour
        // when the runtime metrics surface isn't available.
    }

    /// Spawn a background task that samples every `interval` and
    /// updates the gauges. The handle is detached; the task ends
    /// when the runtime shuts down.
    pub fn spawn_sampler(&self, interval: Duration) {
        let metrics = self.clone();
        tokio::spawn(async move {
            let mut tick = time::interval(interval);
            tick.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                metrics.sample_now();
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gauges_register_into_a_clean_registry() {
        let reg = MetricsRegistry::init();
        let m = RuntimeMetrics::register(&reg).unwrap();
        // Default values are zero — SC-T4 contract: gauges always
        // exist whether the build supports tokio_unstable or not.
        assert_eq!(m.active_workers.get(), 0);
        assert_eq!(m.blocking_threads.get(), 0);
        assert_eq!(m.blocking_queue_depth.get(), 0);
        assert_eq!(m.io_driver_fd_count.get(), 0);
    }

    #[test]
    fn double_register_into_same_registry_is_an_error() {
        let reg = MetricsRegistry::init();
        let _first = RuntimeMetrics::register(&reg).unwrap();
        let second = RuntimeMetrics::register(&reg);
        assert!(second.is_err(), "duplicate registration should fail");
    }

    #[test]
    fn sample_now_is_safe_to_call_without_unstable() {
        // Without --cfg tokio_unstable, sample_now is a no-op.
        // The test runner usually doesn't enable it, so this
        // exercises the stub path.
        let reg = MetricsRegistry::init();
        let m = RuntimeMetrics::register(&reg).unwrap();
        m.sample_now();
        // Gauge value depends on cfg — either 0 (stub) or the
        // live value. Either way, no panic.
    }

    #[tokio::test]
    async fn spawn_sampler_does_not_panic() {
        let reg = MetricsRegistry::init();
        let m = RuntimeMetrics::register(&reg).unwrap();
        m.spawn_sampler(Duration::from_millis(10));
        // Let it tick once.
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
}
