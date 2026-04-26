use serde::Serialize;

/// Overview dashboard data.
#[derive(Clone, Debug, Serialize)]
pub struct OverviewData {
    pub request_rate: f64,
    pub block_count: u64,
    pub allow_count: u64,
    pub slo_budget_pct: f64,
    pub peers: Vec<PeerInfo>,
}

/// Cluster peer info.
#[derive(Clone, Debug, Serialize)]
pub struct PeerInfo {
    pub id: String,
    pub address: String,
    pub healthy: bool,
    pub version: String,
}

impl OverviewData {
    /// Block rate as a percentage.
    pub fn block_rate_pct(&self) -> f64 {
        let total = self.block_count + self.allow_count;
        if total == 0 {
            return 0.0;
        }
        (self.block_count as f64 / total as f64) * 100.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_rate_zero_when_no_traffic() {
        let d = OverviewData {
            request_rate: 0.0,
            block_count: 0,
            allow_count: 0,
            slo_budget_pct: 100.0,
            peers: vec![],
        };
        assert!((d.block_rate_pct() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn block_rate_50_percent() {
        let d = OverviewData {
            request_rate: 100.0,
            block_count: 50,
            allow_count: 50,
            slo_budget_pct: 99.0,
            peers: vec![],
        };
        assert!((d.block_rate_pct() - 50.0).abs() < f64::EPSILON);
    }

    #[test]
    fn overview_serializes() {
        let d = OverviewData {
            request_rate: 42.5,
            block_count: 10,
            allow_count: 90,
            slo_budget_pct: 98.5,
            peers: vec![PeerInfo {
                id: "node-1".into(),
                address: "10.0.0.1:9090".into(),
                healthy: true,
                version: "0.1.0".into(),
            }],
        };
        let json = serde_json::to_string(&d).unwrap();
        assert!(json.contains("42.5"));
        assert!(json.contains("node-1"));
    }
}
