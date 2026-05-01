//! State-backend operation counter — `waf_state_backend_ops_total{op,outcome}`
//! (PROM-T3).
//!
//! Wraps the data-plane `Arc<dyn StateBackend>` with a delegating
//! impl that records one counter increment per call. Used by
//! the proxy boot path to stamp every Redis / in-memory /
//! reconciling-backend dispatch — operators see the steady-state
//! op mix in Grafana plus a clear error spike when Redis flakes.
//!
//! ## Cardinality
//!
//! Eleven ops × two outcomes = **22 fixed series**. All
//! pre-allocated at registration so `/metrics` shows the full
//! shape before any traffic; drift is caught by
//! `op_constants_match_state_backend_methods` (a doc-test-shaped
//! reminder; the actual list is hand-mirrored against
//! `StateBackend` in `aegis-core::state`).
//!
//! ## Hot-path cost
//!
//! One `CounterVec::with_label_values` lookup + one atomic inc
//! per state-backend call (~30 ns). Each call is already async
//! (Redis round-trip is ms-class), so the metric overhead is
//! immaterial — the wrap exists to make Redis behaviour visible,
//! not to compete with it.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use prometheus::CounterVec;

use aegis_core::risk::RiskKey;
use aegis_core::state::{SlidingWindowResult, StateBackend};
use aegis_core::Result;

use super::MetricsRegistry;

/// Stable label values mirroring the `StateBackend` trait
/// surface. Adding a new method to the trait means adding a
/// constant here too.
pub mod op_label {
    pub const GET: &str = "get";
    pub const SET: &str = "set";
    pub const DEL: &str = "del";
    pub const INCR_WINDOW: &str = "incr_window";
    pub const TOKEN_BUCKET: &str = "token_bucket";
    pub const GET_RISK: &str = "get_risk";
    pub const ADD_RISK: &str = "add_risk";
    pub const AUTO_BLOCK: &str = "auto_block";
    pub const IS_AUTO_BLOCKED: &str = "is_auto_blocked";
    pub const PUT_NONCE: &str = "put_nonce";
    pub const CONSUME_NONCE: &str = "consume_nonce";

    pub const ALL: [&str; 11] = [
        GET, SET, DEL, INCR_WINDOW, TOKEN_BUCKET, GET_RISK, ADD_RISK,
        AUTO_BLOCK, IS_AUTO_BLOCKED, PUT_NONCE, CONSUME_NONCE,
    ];
}

pub mod outcome_label {
    pub const OK: &str = "ok";
    pub const ERROR: &str = "error";

    pub const ALL: [&str; 2] = [OK, ERROR];
}

/// Wrapper around the registered `CounterVec`.
#[derive(Clone)]
pub struct StateOpMetrics {
    ops_total: CounterVec,
}

impl StateOpMetrics {
    pub fn register(reg: &MetricsRegistry) -> prometheus::Result<Self> {
        let cv = reg.register_counter_vec(
            "waf_state_backend_ops_total",
            "Total state-backend operations performed by the WAF, labelled by op (get / set / del / incr_window / token_bucket / get_risk / add_risk / auto_block / is_auto_blocked / put_nonce / consume_nonce) and outcome (ok / error).",
            &["op", "outcome"],
        )?;
        // Pre-allocate every series so /metrics shows the full
        // grid even before any state-backend op runs.
        for op in op_label::ALL {
            for out in outcome_label::ALL {
                cv.with_label_values(&[op, out]);
            }
        }
        Ok(Self { ops_total: cv })
    }

    pub fn record(&self, op: &str, ok: bool) {
        let outcome = if ok { outcome_label::OK } else { outcome_label::ERROR };
        self.ops_total.with_label_values(&[op, outcome]).inc();
    }
}

/// Delegating `StateBackend` impl that records every dispatch.
/// The proxy wraps the resolved state backend with this at boot
/// so every downstream consumer of `Arc<dyn StateBackend>` is
/// instrumented automatically — no per-call-site touch.
pub struct MeteredStateBackend {
    inner: Arc<dyn StateBackend>,
    metrics: StateOpMetrics,
}

impl MeteredStateBackend {
    pub fn new(inner: Arc<dyn StateBackend>, metrics: StateOpMetrics) -> Self {
        Self { inner, metrics }
    }
}

#[async_trait]
impl StateBackend for MeteredStateBackend {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let r = self.inner.get(key).await;
        self.metrics.record(op_label::GET, r.is_ok());
        r
    }

    async fn set(&self, key: &str, val: &[u8], ttl: Duration) -> Result<()> {
        let r = self.inner.set(key, val, ttl).await;
        self.metrics.record(op_label::SET, r.is_ok());
        r
    }

    async fn del(&self, key: &str) -> Result<()> {
        let r = self.inner.del(key).await;
        self.metrics.record(op_label::DEL, r.is_ok());
        r
    }

    async fn incr_window(
        &self,
        key: &str,
        window: Duration,
        limit: u64,
    ) -> Result<SlidingWindowResult> {
        let r = self.inner.incr_window(key, window, limit).await;
        self.metrics.record(op_label::INCR_WINDOW, r.is_ok());
        r
    }

    async fn token_bucket(
        &self,
        key: &str,
        rate_per_s: u32,
        burst: u32,
    ) -> Result<bool> {
        let r = self.inner.token_bucket(key, rate_per_s, burst).await;
        self.metrics.record(op_label::TOKEN_BUCKET, r.is_ok());
        r
    }

    async fn get_risk(&self, key: &RiskKey) -> Result<u32> {
        let r = self.inner.get_risk(key).await;
        self.metrics.record(op_label::GET_RISK, r.is_ok());
        r
    }

    async fn add_risk(&self, key: &RiskKey, delta: i32, max: u32) -> Result<u32> {
        let r = self.inner.add_risk(key, delta, max).await;
        self.metrics.record(op_label::ADD_RISK, r.is_ok());
        r
    }

    async fn auto_block(&self, ip: IpAddr, ttl: Duration) -> Result<()> {
        let r = self.inner.auto_block(ip, ttl).await;
        self.metrics.record(op_label::AUTO_BLOCK, r.is_ok());
        r
    }

    async fn is_auto_blocked(&self, ip: IpAddr) -> Result<bool> {
        let r = self.inner.is_auto_blocked(ip).await;
        self.metrics.record(op_label::IS_AUTO_BLOCKED, r.is_ok());
        r
    }

    async fn put_nonce(&self, nonce: &str, ttl: Duration) -> Result<bool> {
        let r = self.inner.put_nonce(nonce, ttl).await;
        self.metrics.record(op_label::PUT_NONCE, r.is_ok());
        r
    }

    async fn consume_nonce(&self, nonce: &str) -> Result<bool> {
        let r = self.inner.consume_nonce(nonce).await;
        self.metrics.record(op_label::CONSUME_NONCE, r.is_ok());
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::WafError;

    fn series_value(reg: &MetricsRegistry, op: &str, outcome: &str) -> f64 {
        reg.inner()
            .gather()
            .into_iter()
            .find(|f| f.get_name() == "waf_state_backend_ops_total")
            .and_then(|f| {
                f.get_metric()
                    .iter()
                    .find(|m| {
                        let mut has_op = false;
                        let mut has_outcome = false;
                        for l in m.get_label() {
                            if l.get_name() == "op" && l.get_value() == op {
                                has_op = true;
                            }
                            if l.get_name() == "outcome" && l.get_value() == outcome {
                                has_outcome = true;
                            }
                        }
                        has_op && has_outcome
                    })
                    .map(|m| m.get_counter().get_value())
            })
            .unwrap_or(0.0)
    }

    fn series_count(reg: &MetricsRegistry) -> usize {
        reg.inner()
            .gather()
            .into_iter()
            .find(|f| f.get_name() == "waf_state_backend_ops_total")
            .map(|f| f.get_metric().len())
            .unwrap_or(0)
    }

    #[test]
    fn register_pre_allocates_22_series() {
        let reg = MetricsRegistry::init();
        let _m = StateOpMetrics::register(&reg).unwrap();
        // 11 ops × 2 outcomes
        assert_eq!(series_count(&reg), 22);
    }

    #[test]
    fn record_increments_correct_label_combo() {
        let reg = MetricsRegistry::init();
        let m = StateOpMetrics::register(&reg).unwrap();
        m.record(op_label::GET, true);
        m.record(op_label::GET, true);
        m.record(op_label::SET, false);
        assert_eq!(series_value(&reg, "get", "ok"), 2.0);
        assert_eq!(series_value(&reg, "get", "error"), 0.0);
        assert_eq!(series_value(&reg, "set", "ok"), 0.0);
        assert_eq!(series_value(&reg, "set", "error"), 1.0);
    }

    // ----- MeteredStateBackend ------------------------------------------

    /// In-memory mock so we can assert the wrapper records both
    /// success and error paths without a real Redis.
    struct MockBackend {
        fail: std::sync::atomic::AtomicBool,
    }
    impl MockBackend {
        fn new() -> Self {
            Self {
                fail: std::sync::atomic::AtomicBool::new(false),
            }
        }
        fn set_failing(&self, v: bool) {
            self.fail.store(v, std::sync::atomic::Ordering::Relaxed);
        }
        fn err<T>(&self) -> Result<T> {
            if self.fail.load(std::sync::atomic::Ordering::Relaxed) {
                Err(WafError::State("mock failure".into()))
            } else {
                panic!("ok-path branch not gated");
            }
        }
    }
    #[async_trait]
    impl StateBackend for MockBackend {
        async fn get(&self, _key: &str) -> Result<Option<Vec<u8>>> {
            if self.fail.load(std::sync::atomic::Ordering::Relaxed) {
                self.err::<Option<Vec<u8>>>()
            } else {
                Ok(None)
            }
        }
        async fn set(&self, _key: &str, _val: &[u8], _ttl: Duration) -> Result<()> {
            if self.fail.load(std::sync::atomic::Ordering::Relaxed) {
                self.err::<()>()
            } else {
                Ok(())
            }
        }
        async fn del(&self, _key: &str) -> Result<()> {
            Ok(())
        }
        async fn incr_window(&self, _: &str, _: Duration, _: u64) -> Result<SlidingWindowResult> {
            Ok(SlidingWindowResult { count: 1, allowed: true, retry_after: None })
        }
        async fn token_bucket(&self, _: &str, _: u32, _: u32) -> Result<bool> {
            Ok(true)
        }
        async fn get_risk(&self, _: &RiskKey) -> Result<u32> {
            Ok(0)
        }
        async fn add_risk(&self, _: &RiskKey, _: i32, _: u32) -> Result<u32> {
            Ok(0)
        }
        async fn auto_block(&self, _: IpAddr, _: Duration) -> Result<()> {
            Ok(())
        }
        async fn is_auto_blocked(&self, _: IpAddr) -> Result<bool> {
            Ok(false)
        }
        async fn put_nonce(&self, _: &str, _: Duration) -> Result<bool> {
            Ok(true)
        }
        async fn consume_nonce(&self, _: &str) -> Result<bool> {
            Ok(true)
        }
    }

    #[tokio::test]
    async fn metered_wrap_records_ok_on_success() {
        let reg = MetricsRegistry::init();
        let m = StateOpMetrics::register(&reg).unwrap();
        let backend = MeteredStateBackend::new(Arc::new(MockBackend::new()), m);
        backend.get("k").await.unwrap();
        backend.get("k").await.unwrap();
        assert_eq!(series_value(&reg, "get", "ok"), 2.0);
        assert_eq!(series_value(&reg, "get", "error"), 0.0);
    }

    #[tokio::test]
    async fn metered_wrap_records_error_on_failure() {
        let reg = MetricsRegistry::init();
        let m = StateOpMetrics::register(&reg).unwrap();
        let mock = Arc::new(MockBackend::new());
        mock.set_failing(true);
        let backend = MeteredStateBackend::new(mock, m);
        let _ = backend.set("k", b"v", Duration::from_secs(1)).await;
        assert_eq!(series_value(&reg, "set", "error"), 1.0);
        assert_eq!(series_value(&reg, "set", "ok"), 0.0);
    }

    #[tokio::test]
    async fn metered_wrap_covers_every_trait_method() {
        // Each method increments its own op label exactly once.
        let reg = MetricsRegistry::init();
        let m = StateOpMetrics::register(&reg).unwrap();
        let backend = MeteredStateBackend::new(Arc::new(MockBackend::new()), m);

        let _ = backend.get("k").await;
        let _ = backend.set("k", b"v", Duration::from_secs(1)).await;
        let _ = backend.del("k").await;
        let _ = backend.incr_window("k", Duration::from_secs(60), 100).await;
        let _ = backend.token_bucket("k", 10, 20).await;
        let key = RiskKey {
            ip: "1.1.1.1".parse().unwrap(),
            device_fp: None,
            session: None,
            tenant_id: None,
        };
        let _ = backend.get_risk(&key).await;
        let _ = backend.add_risk(&key, 5, 100).await;
        let _ = backend.auto_block("1.1.1.1".parse().unwrap(), Duration::from_secs(60)).await;
        let _ = backend.is_auto_blocked("1.1.1.1".parse().unwrap()).await;
        let _ = backend.put_nonce("n", Duration::from_secs(60)).await;
        let _ = backend.consume_nonce("n").await;

        for op in op_label::ALL {
            assert_eq!(
                series_value(&reg, op, "ok"),
                1.0,
                "op {op} should have one ok increment",
            );
        }
    }

    #[test]
    fn duplicate_register_fails() {
        let reg = MetricsRegistry::init();
        StateOpMetrics::register(&reg).unwrap();
        assert!(StateOpMetrics::register(&reg).is_err());
    }
}
