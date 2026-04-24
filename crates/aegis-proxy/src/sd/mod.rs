//! Service discovery backends.
//!
//! Backends: `file` watcher, `dns_srv`, `consul`, `etcd`, `k8s` (feature-gated).
//! Safety limits: `min_members`, `max_churn_per_interval`.
//! New members enter `probing` until active health confirms them.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Discovery event: member added or removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryEvent {
    Added(SocketAddr),
    Removed(SocketAddr),
}

/// Status of a discovered member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberStatus {
    /// Just discovered, awaiting health probe.
    Probing,
    /// Health probe passed, ready to receive traffic.
    Active,
    /// Marked for removal.
    Draining,
}

/// Safety limits for discovery updates.
#[derive(Debug, Clone)]
pub struct SafetyLimits {
    /// Minimum members a pool must keep — prevents empty pools from bad SD.
    pub min_members: usize,
    /// Maximum number of changes allowed per interval.
    pub max_churn_per_interval: usize,
    /// Interval for churn measurement.
    pub churn_interval: Duration,
}

impl Default for SafetyLimits {
    fn default() -> Self {
        Self {
            min_members: 1,
            max_churn_per_interval: 10,
            churn_interval: Duration::from_secs(30),
        }
    }
}

/// Churn tracker — enforces max_churn_per_interval.
pub struct ChurnTracker {
    events: Vec<Instant>,
    limits: SafetyLimits,
}

impl ChurnTracker {
    pub fn new(limits: SafetyLimits) -> Self {
        Self {
            events: Vec::new(),
            limits,
        }
    }

    /// Record a churn event. Returns `false` if the churn cap is exceeded.
    pub fn record(&mut self) -> bool {
        let now = Instant::now();
        // Prune old events.
        self.events
            .retain(|t| now.duration_since(*t) < self.limits.churn_interval);

        if self.events.len() >= self.limits.max_churn_per_interval {
            return false;
        }

        self.events.push(now);
        true
    }

    /// Current churn count in the current interval.
    pub fn current_churn(&self) -> usize {
        let now = Instant::now();
        self.events
            .iter()
            .filter(|t| now.duration_since(**t) < self.limits.churn_interval)
            .count()
    }
}

/// File-based service discovery: reads a text file with one `addr:port` per line.
pub fn parse_file_members(contents: &str) -> Vec<SocketAddr> {
    contents
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                None
            } else {
                trimmed.parse().ok()
            }
        })
        .collect()
}

/// Diff old and new member sets to produce discovery events.
pub fn diff_members(
    old: &HashSet<SocketAddr>,
    new: &HashSet<SocketAddr>,
) -> Vec<DiscoveryEvent> {
    let mut events = Vec::new();
    for addr in new.difference(old) {
        events.push(DiscoveryEvent::Added(*addr));
    }
    for addr in old.difference(new) {
        events.push(DiscoveryEvent::Removed(*addr));
    }
    events
}

/// Apply safety limits to a proposed removal set.  Returns the removals
/// that are allowed (may be empty if it would drop below min_members).
pub fn safe_removals(
    current_count: usize,
    removals: &[SocketAddr],
    min_members: usize,
) -> Vec<SocketAddr> {
    if current_count <= min_members {
        return Vec::new();
    }
    let max_removable = current_count - min_members;
    removals[..removals.len().min(max_removable)].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_file_members_basic() {
        let contents = "127.0.0.1:3000\n127.0.0.1:3001\n# comment\n\n127.0.0.1:3002";
        let members = parse_file_members(contents);
        assert_eq!(members.len(), 3);
    }

    #[test]
    fn parse_file_members_empty() {
        assert!(parse_file_members("").is_empty());
        assert!(parse_file_members("# only comments\n").is_empty());
    }

    #[test]
    fn diff_detects_additions() {
        let old: HashSet<_> = ["127.0.0.1:3000".parse().unwrap()].into();
        let new: HashSet<_> = [
            "127.0.0.1:3000".parse().unwrap(),
            "127.0.0.1:3001".parse().unwrap(),
        ]
        .into();
        let events = diff_members(&old, &new);
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], DiscoveryEvent::Added(_)));
    }

    #[test]
    fn diff_detects_removals() {
        let old: HashSet<_> = [
            "127.0.0.1:3000".parse().unwrap(),
            "127.0.0.1:3001".parse().unwrap(),
        ]
        .into();
        let new: HashSet<_> = ["127.0.0.1:3000".parse().unwrap()].into();
        let events = diff_members(&old, &new);
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], DiscoveryEvent::Removed(_)));
    }

    #[test]
    fn diff_no_changes() {
        let set: HashSet<_> = ["127.0.0.1:3000".parse().unwrap()].into();
        let events = diff_members(&set, &set);
        assert!(events.is_empty());
    }

    #[test]
    fn churn_tracker_within_limit() {
        let limits = SafetyLimits {
            max_churn_per_interval: 3,
            ..Default::default()
        };
        let mut tracker = ChurnTracker::new(limits);
        assert!(tracker.record());
        assert!(tracker.record());
        assert!(tracker.record());
        // 4th should be blocked.
        assert!(!tracker.record());
    }

    #[test]
    fn safe_removals_respects_min() {
        let removals: Vec<SocketAddr> = vec![
            "127.0.0.1:3000".parse().unwrap(),
            "127.0.0.1:3001".parse().unwrap(),
        ];
        // 3 current members, min 2 — can remove at most 1.
        let allowed = safe_removals(3, &removals, 2);
        assert_eq!(allowed.len(), 1);
    }

    #[test]
    fn safe_removals_blocks_all_at_min() {
        let removals: Vec<SocketAddr> = vec!["127.0.0.1:3000".parse().unwrap()];
        // 1 member at min=1 — cannot remove any.
        let allowed = safe_removals(1, &removals, 1);
        assert!(allowed.is_empty());
    }

    #[test]
    fn member_status_variants() {
        assert_ne!(MemberStatus::Probing, MemberStatus::Active);
        assert_ne!(MemberStatus::Active, MemberStatus::Draining);
    }
}
