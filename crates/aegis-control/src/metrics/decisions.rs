//! Per-decision counter — `waf_requests_total{action}` (PROM-T1).
//!
//! Pairs with the per-stage `waf_request_duration_ms` histogram.
//! Where the histogram tells you *how long* requests took, this
//! counter tells you *what happened* — the data plane increments
//! exactly one bucket per request, labelled by the contract
//! [`Action`] the decision pipeline emitted.
//!
//! ## Cardinality
//!
//! Six fixed `action` values: `allow`, `block`, `challenge`,
//! `rate_limit`, `timeout`, `circuit_breaker`. Pre-allocated at
//! registration so Prometheus + Grafana see the full series set
//! immediately on `/metrics` (zero counts before traffic) — the
//! WAF Overview dashboard's "Decision mix" panel is no longer
//! empty on a fresh boot.
//!
//! ## Hot-path cost
//!
//! `record(Action)` is one `CounterVec::with_label_values` lookup
//! (a `DashMap` get on a string key) plus one atomic `inc`.
//! Combined cost is ~30 ns on commodity hardware — well below
//! the per-request budget.

use prometheus::CounterVec;

use super::MetricsRegistry;
use crate::interop::headers::Action;

/// Stable label values mirroring [`Action::as_str`]. Pinned in
/// one place so a typo in the hot path can't spawn a dashboard-
/// invisible series.
pub mod action_label {
    pub const ALLOW: &str = "allow";
    pub const BLOCK: &str = "block";
    pub const CHALLENGE: &str = "challenge";
    pub const RATE_LIMIT: &str = "rate_limit";
    pub const TIMEOUT: &str = "timeout";
    pub const CIRCUIT_BREAKER: &str = "circuit_breaker";

    pub const ALL: [&str; 6] = [
        ALLOW, BLOCK, CHALLENGE, RATE_LIMIT, TIMEOUT, CIRCUIT_BREAKER,
    ];
}

/// Wrapper around the registered `CounterVec`. Cheap to clone;
/// inner `CounterVec` is `Arc`-shared by the `prometheus` crate.
#[derive(Clone)]
pub struct DecisionMetrics {
    requests_total: CounterVec,
}

impl DecisionMetrics {
    /// Register the counter family in the shared registry. Called
    /// once at boot from `aegis-proxy::run` next to
    /// `RequestStageHistogram::register`.
    pub fn register(reg: &MetricsRegistry) -> prometheus::Result<Self> {
        let cv = reg.register_counter_vec(
            "waf_requests_total",
            "Total data-plane requests handled by the WAF, labelled by the decision action emitted (allow / block / challenge / rate_limit / timeout / circuit_breaker).",
            &["action"],
        )?;
        // Pre-allocate every series so /metrics renders the full
        // label set even before the first request — Grafana
        // can't draw a panel for a series it hasn't seen yet.
        for v in action_label::ALL {
            cv.with_label_values(&[v]);
        }
        Ok(Self {
            requests_total: cv,
        })
    }

    /// Hot-path: record one decision. Called once per request
    /// after `handle_data_request` returns, using the
    /// `DecisionTag` the pipeline emitted.
    pub fn record(&self, action: Action) {
        self.requests_total
            .with_label_values(&[action.as_str()])
            .inc();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_creates_one_metric_family() {
        let reg = MetricsRegistry::init();
        let _m = DecisionMetrics::register(&reg).unwrap();
        let families = reg.inner().gather();
        assert_eq!(families.len(), 1);
        assert_eq!(families[0].get_name(), "waf_requests_total");
    }

    #[test]
    fn pre_allocates_all_six_action_series() {
        let reg = MetricsRegistry::init();
        let _m = DecisionMetrics::register(&reg).unwrap();
        let metric = reg
            .inner()
            .gather()
            .into_iter()
            .find(|f| f.get_name() == "waf_requests_total")
            .unwrap();
        assert_eq!(
            metric.get_metric().len(),
            6,
            "expected one series per action; got {:?}",
            metric.get_metric()
                .iter()
                .map(|m| {
                    m.get_label()
                        .iter()
                        .map(|l| format!("{}={}", l.get_name(), l.get_value()))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>(),
        );
        // All zero on registration — counters surface in scrape
        // output even with no traffic.
        for s in metric.get_metric() {
            assert_eq!(s.get_counter().get_value(), 0.0);
        }
    }

    #[test]
    fn record_increments_correct_label() {
        let reg = MetricsRegistry::init();
        let m = DecisionMetrics::register(&reg).unwrap();

        m.record(Action::Allow);
        m.record(Action::Allow);
        m.record(Action::Block);
        m.record(Action::Challenge);

        let metric = reg
            .inner()
            .gather()
            .into_iter()
            .find(|f| f.get_name() == "waf_requests_total")
            .unwrap();

        let mut by_label: std::collections::HashMap<String, f64> = std::collections::HashMap::new();
        for s in metric.get_metric() {
            let lab = s
                .get_label()
                .iter()
                .find(|l| l.get_name() == "action")
                .unwrap()
                .get_value()
                .to_string();
            by_label.insert(lab, s.get_counter().get_value());
        }
        assert_eq!(by_label.get("allow"), Some(&2.0));
        assert_eq!(by_label.get("block"), Some(&1.0));
        assert_eq!(by_label.get("challenge"), Some(&1.0));
        assert_eq!(by_label.get("rate_limit"), Some(&0.0));
        assert_eq!(by_label.get("timeout"), Some(&0.0));
        assert_eq!(by_label.get("circuit_breaker"), Some(&0.0));
    }

    #[test]
    fn label_constants_match_action_as_str() {
        assert_eq!(action_label::ALLOW, Action::Allow.as_str());
        assert_eq!(action_label::BLOCK, Action::Block.as_str());
        assert_eq!(action_label::CHALLENGE, Action::Challenge.as_str());
        assert_eq!(action_label::RATE_LIMIT, Action::RateLimit.as_str());
        assert_eq!(action_label::TIMEOUT, Action::Timeout.as_str());
        assert_eq!(action_label::CIRCUIT_BREAKER, Action::CircuitBreaker.as_str());
    }

    #[test]
    fn duplicate_register_fails() {
        let reg = MetricsRegistry::init();
        DecisionMetrics::register(&reg).unwrap();
        assert!(DecisionMetrics::register(&reg).is_err());
    }

    #[test]
    fn cheap_clone_shares_underlying_counter() {
        let reg = MetricsRegistry::init();
        let m1 = DecisionMetrics::register(&reg).unwrap();
        let m2 = m1.clone();
        m1.record(Action::Allow);
        m2.record(Action::Allow);

        let metric = reg.inner().gather()
            .into_iter()
            .find(|f| f.get_name() == "waf_requests_total")
            .unwrap();
        let allow = metric
            .get_metric()
            .iter()
            .find(|s| {
                s.get_label()
                    .iter()
                    .any(|l| l.get_name() == "action" && l.get_value() == "allow")
            })
            .unwrap();
        assert_eq!(allow.get_counter().get_value(), 2.0);
    }
}
