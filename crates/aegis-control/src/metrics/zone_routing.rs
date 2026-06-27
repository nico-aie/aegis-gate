//! Zone-aware load balancing P3 — served-local-vs-cross-zone routing counter.
//!
//! `waf_upstream_zone_routing_total{pool, outcome}` — counts how many requests
//! the LB served from the node's **own** zone (`outcome="local"`) vs spilled to
//! another zone (`outcome="cross_zone"`). Only incremented when locality is
//! enabled for the pool AND the node has a self-zone, so the ratio is a direct
//! read on how often a pool is forced to spill. Mirrors the `upstream_pools`
//! metric's construction.

use crate::metrics::MetricsRegistry;

/// Outcome label values. Stable strings the dashboards key on.
pub const OUTCOME_LOCAL: &str = "local";
pub const OUTCOME_CROSS_ZONE: &str = "cross_zone";

#[derive(Clone)]
pub struct ZoneRoutingMetrics {
    served: prometheus::CounterVec,
}

impl ZoneRoutingMetrics {
    pub fn register(reg: &MetricsRegistry) -> prometheus::Result<Self> {
        let served = reg.register_counter_vec(
            "waf_upstream_zone_routing_total",
            "Requests routed by zone-aware LB, labelled by pool and whether the picked member was in the node's own zone (local) or a spillover zone (cross_zone).",
            &["pool", "outcome"],
        )?;
        Ok(Self { served })
    }

    /// Record one routed request. `outcome` must be [`OUTCOME_LOCAL`] or
    /// [`OUTCOME_CROSS_ZONE`].
    pub fn record(&self, pool: &str, outcome: &str) {
        self.served.with_label_values(&[pool, outcome]).inc();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_local_and_cross_zone_separately() {
        let reg = MetricsRegistry::init();
        let m = ZoneRoutingMetrics::register(&reg).unwrap();
        m.record("api", OUTCOME_LOCAL);
        m.record("api", OUTCOME_LOCAL);
        m.record("api", OUTCOME_CROSS_ZONE);

        assert_eq!(m.served.with_label_values(&["api", OUTCOME_LOCAL]).get(), 2.0);
        assert_eq!(
            m.served.with_label_values(&["api", OUTCOME_CROSS_ZONE]).get(),
            1.0
        );
    }
}
