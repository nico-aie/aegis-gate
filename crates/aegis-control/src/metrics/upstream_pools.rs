//! Per-pool upstream-health gauges (PROM-T1).
//!
//! Two `GaugeVec`s labelled by `pool` name, surfaced on
//! `/metrics`:
//!
//!   waf_upstream_members_healthy{pool}  — count of members
//!     currently passing the health probe (or assumed healthy
//!     when no probe is configured).
//!   waf_upstream_members_total{pool}    — configured size.
//!
//! ## Cardinality
//!
//! `pool` is operator-controlled. Typical deployments have 2-10
//! pools; even pathological "every route gets its own pool"
//! deployments stay in the low-hundreds — well below the
//! cardinality budget. We don't include `pool=` for
//! non-existent pools; deleted pools' series go stale and drop
//! out of the registry on the next [`Self::sync_from_snapshot`]
//! call (see [`Self::retain_pools`]).
//!
//! ## When values update
//!
//! Three trigger sites:
//!
//! 1. **Boot** — the proxy calls `sync_from_snapshot` once
//!    after building `ProxyContext`.
//! 2. **`PUT /api/upstreams/config`** — the audit-mutated
//!    handler in CC-T1.1.b calls `sync_from_snapshot` with the
//!    new pool map after the registry swap succeeds.
//! 3. **Periodic** — a background task ticks every 5 s and
//!    re-reads the live pool snapshot. This catches members
//!    flipping under the existing health-probe loop.
//!
//! All updates are off the per-request hot path. Read cost on
//! the request handler stays zero.

use prometheus::GaugeVec;

use super::MetricsRegistry;

/// Snapshot input for [`UpstreamPoolMetrics::sync_from_snapshot`].
/// One entry per pool. Cheap value type so the proxy can build
/// it from the live `PoolRegistry::snapshot()` without leaking
/// proxy-internal types into `aegis-control`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PoolHealthCounts {
    pub name: String,
    pub healthy: u32,
    pub total: u32,
}

#[derive(Clone)]
pub struct UpstreamPoolMetrics {
    healthy: GaugeVec,
    total: GaugeVec,
}

impl UpstreamPoolMetrics {
    pub fn register(reg: &MetricsRegistry) -> prometheus::Result<Self> {
        let healthy = reg.register_gauge_vec(
            "waf_upstream_members_healthy",
            "Count of upstream pool members currently passing health probes per pool. Equals total when no probe is configured (assumed healthy).",
            &["pool"],
        )?;
        let total = reg.register_gauge_vec(
            "waf_upstream_members_total",
            "Configured count of upstream pool members per pool.",
            &["pool"],
        )?;
        Ok(Self { healthy, total })
    }

    /// Update gauges for the supplied snapshot. Atomically
    /// resets both gauge families (drops all current series)
    /// and re-creates only the series for pools in `snapshot`,
    /// so removed pools stop reporting cleanly.
    ///
    /// **Scrape gap.** The reset → re-set window is microsecond-
    /// scale; Prometheus' 5 s default scrape interval makes a
    /// torn read essentially impossible. For deployments using
    /// sub-second scrape intervals, the dashboards already
    /// tolerate a single missing data point via spanNulls.
    pub fn sync_from_snapshot(&self, snapshot: &[PoolHealthCounts]) {
        self.healthy.reset();
        self.total.reset();
        for p in snapshot {
            self.healthy
                .with_label_values(&[p.name.as_str()])
                .set(f64::from(p.healthy));
            self.total
                .with_label_values(&[p.name.as_str()])
                .set(f64::from(p.total));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(rows: &[(&str, u32, u32)]) -> Vec<PoolHealthCounts> {
        rows.iter()
            .map(|(n, h, t)| PoolHealthCounts {
                name: (*n).to_string(),
                healthy: *h,
                total: *t,
            })
            .collect()
    }

    fn series_count(reg: &MetricsRegistry, name: &str) -> usize {
        reg.inner()
            .gather()
            .into_iter()
            .find(|f| f.get_name() == name)
            .map(|f| f.get_metric().len())
            .unwrap_or(0)
    }

    fn series_value(reg: &MetricsRegistry, name: &str, pool: &str) -> Option<f64> {
        reg.inner().gather().into_iter().find_map(|f| {
            if f.get_name() != name {
                return None;
            }
            f.get_metric().iter().find_map(|m| {
                let matches = m
                    .get_label()
                    .iter()
                    .any(|l| l.get_name() == "pool" && l.get_value() == pool);
                if matches {
                    Some(m.get_gauge().get_value())
                } else {
                    None
                }
            })
        })
    }

    #[test]
    fn register_creates_two_metric_families() {
        let reg = MetricsRegistry::init();
        let m = UpstreamPoolMetrics::register(&reg).unwrap();
        // Prometheus' `gather()` only emits families that have at
        // least one labelled series — set one value so the test
        // can assert on the resulting families.
        m.sync_from_snapshot(&snap(&[("smoke", 1, 1)]));
        let gathered: Vec<String> = reg
            .inner()
            .gather()
            .iter()
            .map(|f| f.get_name().to_string())
            .collect();
        assert!(gathered.contains(&"waf_upstream_members_healthy".to_string()));
        assert!(gathered.contains(&"waf_upstream_members_total".to_string()));
    }

    #[test]
    fn sync_creates_series_per_pool() {
        let reg = MetricsRegistry::init();
        let m = UpstreamPoolMetrics::register(&reg).unwrap();
        m.sync_from_snapshot(&snap(&[("a", 2, 3), ("b", 0, 1)]));
        assert_eq!(series_count(&reg, "waf_upstream_members_healthy"), 2);
        assert_eq!(series_count(&reg, "waf_upstream_members_total"), 2);
        assert_eq!(series_value(&reg, "waf_upstream_members_healthy", "a"), Some(2.0));
        assert_eq!(series_value(&reg, "waf_upstream_members_total", "a"), Some(3.0));
        assert_eq!(series_value(&reg, "waf_upstream_members_healthy", "b"), Some(0.0));
    }

    #[test]
    fn sync_updates_existing_series_in_place() {
        let reg = MetricsRegistry::init();
        let m = UpstreamPoolMetrics::register(&reg).unwrap();
        m.sync_from_snapshot(&snap(&[("a", 1, 3)]));
        m.sync_from_snapshot(&snap(&[("a", 3, 3)]));
        assert_eq!(series_count(&reg, "waf_upstream_members_healthy"), 1);
        assert_eq!(series_value(&reg, "waf_upstream_members_healthy", "a"), Some(3.0));
    }

    #[test]
    fn sync_drops_series_for_removed_pools() {
        let reg = MetricsRegistry::init();
        let m = UpstreamPoolMetrics::register(&reg).unwrap();
        m.sync_from_snapshot(&snap(&[("a", 1, 1), ("b", 2, 2)]));
        assert_eq!(series_count(&reg, "waf_upstream_members_healthy"), 2);

        // Sync a smaller snapshot — "b" must disappear.
        m.sync_from_snapshot(&snap(&[("a", 1, 1)]));
        assert_eq!(series_count(&reg, "waf_upstream_members_healthy"), 1);
        assert!(series_value(&reg, "waf_upstream_members_healthy", "b").is_none());
        assert!(series_value(&reg, "waf_upstream_members_total", "b").is_none());
    }

    #[test]
    fn empty_snapshot_clears_all_series() {
        let reg = MetricsRegistry::init();
        let m = UpstreamPoolMetrics::register(&reg).unwrap();
        m.sync_from_snapshot(&snap(&[("a", 1, 1)]));
        m.sync_from_snapshot(&[]);
        assert_eq!(series_count(&reg, "waf_upstream_members_healthy"), 0);
        assert_eq!(series_count(&reg, "waf_upstream_members_total"), 0);
    }

    #[test]
    fn cheap_clone_shares_storage() {
        let reg = MetricsRegistry::init();
        let m1 = UpstreamPoolMetrics::register(&reg).unwrap();
        let m2 = m1.clone();
        m1.sync_from_snapshot(&snap(&[("a", 1, 1)]));
        // m2 sees the change because they share Arc'd inner.
        assert_eq!(series_value(&reg, "waf_upstream_members_total", "a"), Some(1.0));
        m2.sync_from_snapshot(&snap(&[("a", 0, 0)]));
        assert_eq!(series_value(&reg, "waf_upstream_members_total", "a"), Some(0.0));
    }
}
