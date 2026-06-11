//! WS-T6 — WebSocket bridge metrics.
//!
//! Two surfaces, both registered in the shared
//! [`MetricsRegistry`] at boot:
//!
//! - `aegis_websocket_open_total` (Counter) — total successful
//!   WS upgrades the data plane bridged.  Incremented once per
//!   bridge spawn (after the upstream returned 101 and the
//!   client `OnUpgrade` task was queued).  Pairs with
//!   `aegis_websocket_close_total` to give bridge-rate +
//!   in-flight derivation; pairs with the audit-bus
//!   `websocket_open` / `websocket_close` events for
//!   timestamped per-tunnel context.
//! - `aegis_websocket_close_total` (Counter) — total bridge
//!   close events.  Incremented when `copy_bidirectional`
//!   returns (clean close, error, or upstream EOF — all
//!   collapse to one counter; detailed reasons live in the
//!   audit-bus `websocket_close.fields.reason`).
//! - `aegis_websocket_active` (Gauge) — currently-active WS
//!   tunnels.  Incremented on bridge spawn, decremented when
//!   the bridge task exits.  Cardinality-free; safe to read
//!   on every dashboard tick.
//!
//! ## Hot-path cost
//!
//! `record_open` / `record_close` are each one atomic add +
//! one gauge inc/dec — single-digit nanoseconds per call.  The
//! bridge is the rare case in WAF traffic so even an
//! observably-slower implementation wouldn't matter; the
//! counters are simple.

use prometheus::{IntCounter, IntCounterVec, IntGauge};

use super::MetricsRegistry;

/// Wrapper around the registered metric handles.  Cheap to
/// clone — inner `IntCounter` / `IntGauge` are `Arc`-shared.
#[derive(Clone)]
pub struct WebSocketMetrics {
    open_total: IntCounter,
    close_total: IntCounter,
    active: IntGauge,
    /// WS-MSG4 — `aegis_websocket_frame_block_total{route,tag}`. One
    /// increment per inspected text message that crossed the block
    /// threshold (both `enforce` and `log_only` — the data plane's
    /// `mode` distinguishes them on the audit event).
    frame_block_total: IntCounterVec,
}

impl WebSocketMetrics {
    /// Register the three series.  Called once at boot from
    /// `aegis-proxy::run` next to the other metric registrations.
    pub fn register(reg: &MetricsRegistry) -> prometheus::Result<Self> {
        let open_total = prometheus::IntCounter::new(
            "aegis_websocket_open_total",
            "Total successful WebSocket upgrades the data plane bridged.",
        )?;
        reg.inner()
            .register(Box::new(open_total.clone()))?;

        let close_total = prometheus::IntCounter::new(
            "aegis_websocket_close_total",
            "Total WebSocket bridge close events (clean + error + EOF). Pair with aegis_websocket_open_total to derive in-flight; per-tunnel reasons live on the audit-bus websocket_close event.",
        )?;
        reg.inner()
            .register(Box::new(close_total.clone()))?;

        let active = prometheus::IntGauge::new(
            "aegis_websocket_active",
            "Currently-active WebSocket tunnels bridged by the WAF. Incremented on upgrade, decremented when the bridge task exits.",
        )?;
        reg.inner().register(Box::new(active.clone()))?;

        let frame_block_total = IntCounterVec::new(
            prometheus::Opts::new(
                "aegis_websocket_frame_block_total",
                "WebSocket text messages that crossed the inspection block threshold, labelled by route and top detector tag (enforce + log_only; see the websocket_frame_block audit event's mode).",
            ),
            &["route", "tag"],
        )?;
        reg.inner().register(Box::new(frame_block_total.clone()))?;

        Ok(Self {
            open_total,
            close_total,
            active,
            frame_block_total,
        })
    }

    /// WS-MSG4 — record one inspected text message that crossed the
    /// block threshold, labelled by route id + the top detector tag.
    pub fn record_frame_block(&self, route: &str, tag: &str) {
        self.frame_block_total
            .with_label_values(&[route, tag])
            .inc();
    }

    /// Record a successful upgrade.  Called from the data plane
    /// right after the bridge task is spawned + before the 101
    /// response is returned to the client.
    pub fn record_open(&self) {
        self.open_total.inc();
        self.active.inc();
    }

    /// Record a bridge close.  Called from the spawned bridge
    /// task after `copy_bidirectional` returns (any branch).
    pub fn record_close(&self) {
        self.close_total.inc();
        self.active.dec();
    }

    /// Snapshot the current active count.  Cheap atomic read.
    pub fn active(&self) -> i64 {
        self.active.get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_creates_the_metric_families() {
        let reg = MetricsRegistry::init();
        let _m = WebSocketMetrics::register(&reg).unwrap();
        let names: Vec<String> = reg
            .inner()
            .gather()
            .iter()
            .map(|f| f.get_name().to_string())
            .collect();
        assert!(names.contains(&"aegis_websocket_open_total".to_string()));
        assert!(names.contains(&"aegis_websocket_close_total".to_string()));
        assert!(names.contains(&"aegis_websocket_active".to_string()));
        // frame_block_total only materialises a series once a label set
        // is touched (CounterVec); record one and confirm it appears.
        _m.record_frame_block("chat", "sqli");
        let names: Vec<String> = reg
            .inner()
            .gather()
            .iter()
            .map(|f| f.get_name().to_string())
            .collect();
        assert!(names.contains(&"aegis_websocket_frame_block_total".to_string()));
    }

    #[test]
    fn record_frame_block_increments_route_tag_series() {
        let reg = MetricsRegistry::init();
        let m = WebSocketMetrics::register(&reg).unwrap();
        m.record_frame_block("chat", "sqli");
        m.record_frame_block("chat", "sqli");
        m.record_frame_block("chat", "xss");
        assert_eq!(m.frame_block_total.with_label_values(&["chat", "sqli"]).get(), 2);
        assert_eq!(m.frame_block_total.with_label_values(&["chat", "xss"]).get(), 1);
    }

    #[test]
    fn open_close_round_trip_keeps_active_zero() {
        let reg = MetricsRegistry::init();
        let m = WebSocketMetrics::register(&reg).unwrap();
        assert_eq!(m.active(), 0);
        m.record_open();
        m.record_open();
        assert_eq!(m.active(), 2);
        m.record_close();
        assert_eq!(m.active(), 1);
        m.record_close();
        assert_eq!(m.active(), 0);
    }

    #[test]
    fn open_increments_open_total_separately_from_active() {
        let reg = MetricsRegistry::init();
        let m = WebSocketMetrics::register(&reg).unwrap();
        m.record_open();
        m.record_open();
        m.record_open();
        m.record_close();
        // open_total is monotonic — closes don't decrement it.
        assert_eq!(m.open_total.get(), 3);
        assert_eq!(m.close_total.get(), 1);
        // active = open - close
        assert_eq!(m.active(), 2);
    }

    #[test]
    fn cheap_clone_shares_underlying_counter() {
        let reg = MetricsRegistry::init();
        let m1 = WebSocketMetrics::register(&reg).unwrap();
        let m2 = m1.clone();
        m1.record_open();
        m2.record_open();
        assert_eq!(m1.active(), 2);
        assert_eq!(m2.active(), 2);
    }

    #[test]
    fn duplicate_register_fails() {
        let reg = MetricsRegistry::init();
        WebSocketMetrics::register(&reg).unwrap();
        assert!(WebSocketMetrics::register(&reg).is_err());
    }
}
