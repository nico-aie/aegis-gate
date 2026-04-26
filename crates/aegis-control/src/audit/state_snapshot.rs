/// State backend snapshot exporter.
///
/// Hourly leader-only task: trigger state backend snapshot and ship
/// to configured archive target. Tracks freshness metric.
use serde::{Deserialize, Serialize};

/// Snapshot metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotMeta {
    pub ts: chrono::DateTime<chrono::Utc>,
    pub node_id: String,
    pub backend: String,
    pub size_bytes: u64,
    pub archive_path: String,
}

/// Snapshot freshness tracker.
pub struct SnapshotTracker {
    last_snapshot: std::sync::Mutex<Option<SnapshotMeta>>,
}

impl Default for SnapshotTracker {
    fn default() -> Self {
        Self {
            last_snapshot: std::sync::Mutex::new(None),
        }
    }
}

impl SnapshotTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a completed snapshot.
    pub fn record(&self, meta: SnapshotMeta) {
        *self.last_snapshot.lock().unwrap() = Some(meta);
    }

    /// Get the last snapshot metadata.
    pub fn last(&self) -> Option<SnapshotMeta> {
        self.last_snapshot.lock().unwrap().clone()
    }

    /// Compute lag in seconds since last snapshot.
    pub fn lag_seconds(&self) -> f64 {
        match self.last() {
            Some(meta) => {
                let now = chrono::Utc::now();
                (now - meta.ts).num_seconds() as f64
            }
            None => f64::INFINITY,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_meta() -> SnapshotMeta {
        SnapshotMeta {
            ts: chrono::Utc::now(),
            node_id: "node-1".into(),
            backend: "redis".into(),
            size_bytes: 1024 * 1024,
            archive_path: "/backups/snap-001.rdb".into(),
        }
    }

    #[test]
    fn tracker_initially_empty() {
        let t = SnapshotTracker::new();
        assert!(t.last().is_none());
    }

    #[test]
    fn tracker_records_snapshot() {
        let t = SnapshotTracker::new();
        t.record(test_meta());
        assert!(t.last().is_some());
        assert_eq!(t.last().unwrap().node_id, "node-1");
    }

    #[test]
    fn tracker_lag_infinity_when_none() {
        let t = SnapshotTracker::new();
        assert!(t.lag_seconds().is_infinite());
    }

    #[test]
    fn tracker_lag_small_after_record() {
        let t = SnapshotTracker::new();
        t.record(test_meta());
        assert!(t.lag_seconds() < 2.0);
    }

    #[test]
    fn meta_serializes() {
        let meta = test_meta();
        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains("node-1"));
        assert!(json.contains("redis"));
    }

    #[test]
    fn meta_roundtrip() {
        let meta = test_meta();
        let json = serde_json::to_string(&meta).unwrap();
        let parsed: SnapshotMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.backend, "redis");
        assert_eq!(parsed.size_bytes, 1024 * 1024);
    }
}
