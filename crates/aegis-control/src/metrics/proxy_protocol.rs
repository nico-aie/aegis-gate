//! PROXY-protocol event counter — `waf_proxy_protocol_events_total{result}`.
//!
//! One bucket is incremented per connection on a listener with
//! `accept_proxy` enabled, labelled by the disposition of the pre-TLS
//! PROXY-header read (design §3.6 failure-mode table + the trust
//! decision). Lets an operator see, on a PROXY-fronted listener, how
//! many connections carried a valid header vs. were closed for an
//! untrusted source / malformed header / strict miss / timeout.
//!
//! ## Cardinality
//!
//! Ten fixed `result` values, mirroring
//! [`listener::proxy_protocol::METRIC_LABELS`] in `aegis-proxy`:
//! `parsed`, `local_command`, `unspec_family`, `absent_optional`,
//! `missing_strict`, `untrusted_source`, `malformed`, `oversize`,
//! `read_timeout`, `eof`. Pre-allocated at registration so the full
//! series set renders on `/metrics` from boot (zero counts before
//! traffic), and the label set lives in `aegis-proxy` so the hot path
//! and the registration can't drift.
//!
//! ## Hot-path cost
//!
//! `record(label)` is one `CounterVec::with_label_values` lookup plus an
//! atomic `inc`, and runs at most once per connection (never per
//! request) — and only on opted-in listeners.

use prometheus::CounterVec;

use super::MetricsRegistry;

/// Wrapper around the registered `CounterVec`. Cheap to clone; the inner
/// `CounterVec` is `Arc`-shared by the `prometheus` crate.
#[derive(Clone)]
pub struct ProxyProtocolMetrics {
    events_total: CounterVec,
}

impl ProxyProtocolMetrics {
    /// Register the counter family in the shared registry. Called once
    /// at boot from `aegis-proxy::run`. `labels` is
    /// `listener::proxy_protocol::METRIC_LABELS` — passed in rather than
    /// duplicated here so the two crates share one source of truth.
    pub fn register(reg: &MetricsRegistry, labels: &[&str]) -> prometheus::Result<Self> {
        let cv = reg.register_counter_vec(
            "waf_proxy_protocol_events_total",
            "PROXY-protocol header reads on accept_proxy listeners, labelled by result \
             (parsed / local_command / unspec_family / absent_optional / missing_strict / \
             untrusted_source / malformed / oversize / read_timeout / eof).",
            &["result"],
        )?;
        // Pre-allocate every series so /metrics renders the full label
        // set even before the first PROXY connection.
        for label in labels {
            cv.with_label_values(&[label]);
        }
        Ok(Self { events_total: cv })
    }

    /// Record one PROXY-protocol read outcome. `result` must be one of
    /// the registered labels (see `METRIC_LABELS`).
    pub fn record(&self, result: &str) {
        self.events_total.with_label_values(&[result]).inc();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LABELS: [&str; 10] = [
        "parsed",
        "local_command",
        "unspec_family",
        "absent_optional",
        "missing_strict",
        "untrusted_source",
        "malformed",
        "oversize",
        "read_timeout",
        "eof",
    ];

    #[test]
    fn register_creates_one_metric_family() {
        let reg = MetricsRegistry::init();
        let _m = ProxyProtocolMetrics::register(&reg, &LABELS).unwrap();
        let families = reg.inner().gather();
        let family = families
            .iter()
            .find(|f| f.get_name() == "waf_proxy_protocol_events_total")
            .expect("counter family registered");
        assert_eq!(family.get_metric().len(), LABELS.len());
        for s in family.get_metric() {
            assert_eq!(
                s.get_counter().get_value(),
                0.0,
                "pre-allocated series start at 0"
            );
        }
    }

    #[test]
    fn record_increments_correct_label() {
        let reg = MetricsRegistry::init();
        let m = ProxyProtocolMetrics::register(&reg, &LABELS).unwrap();
        m.record("untrusted_source");
        m.record("untrusted_source");
        m.record("parsed");

        let family = reg
            .inner()
            .gather()
            .into_iter()
            .find(|f| f.get_name() == "waf_proxy_protocol_events_total")
            .unwrap();
        let value_for = |label: &str| {
            family
                .get_metric()
                .iter()
                .find(|m| m.get_label().iter().any(|l| l.get_value() == label))
                .map(|m| m.get_counter().get_value())
                .unwrap_or(-1.0)
        };
        assert_eq!(value_for("untrusted_source"), 2.0);
        assert_eq!(value_for("parsed"), 1.0);
        assert_eq!(value_for("malformed"), 0.0);
    }
}
