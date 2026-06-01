use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ipnet::IpNet;

#[cfg(feature = "taxii")]
pub mod taxii;

/// Threat intel indicator.
#[derive(Clone, Debug)]
pub struct Indicator {
    pub value: String,
    pub indicator_type: IndicatorType,
    pub confidence: u8,
    pub severity: Severity,
    pub feed_id: String,
    pub expires_at: Instant,
}

/// Type of threat indicator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IndicatorType {
    Ip,
    Cidr,
    Domain,
    Url,
    Sha256,
    JA3,
}

/// Severity level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Feed format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FeedFormat {
    PlainText,
    Csv,
    Json,
    Stix21,
}

/// Feed configuration.
#[derive(Clone, Debug)]
pub struct FeedConfig {
    pub id: String,
    pub url: String,
    pub format: FeedFormat,
    pub default_confidence: u8,
    pub default_severity: Severity,
    pub ttl: Duration,
    pub enabled: bool,
}

/// Threat intel store.
pub struct ThreatIntelStore {
    /// Exact-match IP indicators keyed by IP string. Only used for
    /// `IndicatorType::Ip` (single-host) feeds.
    ip_indicators: Mutex<HashMap<String, Indicator>>,
    /// 2026-05-11 PR #8 (SEC-18) — CIDR indicators kept in a
    /// separate parsed-network list. Previously these lived in
    /// `ip_indicators` keyed by the original CIDR string (e.g.
    /// `"10.0.0.0/8"`), and `check_ip(10.5.5.5)` looked up
    /// `"10.5.5.5"` — so CIDR feeds never matched anything
    /// outside the exact-string case. Now each CIDR entry is
    /// parsed once at ingest time and `check_ip` does a linear
    /// scan with `IpNet::contains`. Linear is fine for the
    /// expected feed sizes (low-thousands of nets); a CIDR-tree
    /// can replace this if we ever ingest BGP-table-scale
    /// blocklists.
    cidr_indicators: Mutex<Vec<(IpNet, Indicator)>>,
    /// Domain indicators.
    domain_indicators: Mutex<HashMap<String, Indicator>>,
    /// Local override list (always wins).
    local_overrides: Mutex<HashMap<String, OverrideAction>>,
    /// Max indicators.
    max_indicators: usize,
}

/// Local override action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OverrideAction {
    Allow,
    Block,
}

/// Match result when checking an indicator.
#[derive(Clone, Debug)]
pub struct ThreatMatch {
    pub indicator: Indicator,
    pub action: ThreatAction,
}

/// Action from threat intel match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ThreatAction {
    Block,
    RaiseRisk(u32),
    Monitor,
}

impl ThreatIntelStore {
    pub fn new(max_indicators: usize) -> Self {
        Self {
            ip_indicators: Mutex::new(HashMap::new()),
            cidr_indicators: Mutex::new(Vec::new()),
            domain_indicators: Mutex::new(HashMap::new()),
            local_overrides: Mutex::new(HashMap::new()),
            max_indicators,
        }
    }

    /// Add a local override (always wins over feeds).
    pub fn add_override(&self, key: &str, action: OverrideAction) {
        self.local_overrides.lock().unwrap().insert(key.to_string(), action);
    }

    /// Ingest an indicator from a feed.
    pub fn ingest(&self, indicator: Indicator) {
        match indicator.indicator_type {
            IndicatorType::Ip => {
                let mut map = self.ip_indicators.lock().unwrap();
                if map.len() >= self.max_indicators {
                    evict_expired(&mut map);
                }
                map.insert(indicator.value.clone(), indicator);
            }
            IndicatorType::Cidr => {
                // SEC-18 — parse the CIDR exactly once at ingest
                // time. Malformed entries are dropped (with a
                // warning) so we don't pay re-parse cost on the
                // hot `check_ip` path.
                match indicator.value.parse::<IpNet>() {
                    Ok(net) => {
                        let mut vec = self.cidr_indicators.lock().unwrap();
                        if vec.len() >= self.max_indicators {
                            vec.retain(|(_, ind)| ind.expires_at > Instant::now());
                        }
                        vec.push((net, indicator));
                    }
                    Err(e) => {
                        tracing::warn!(
                            value = %indicator.value,
                            feed_id = %indicator.feed_id,
                            error = %e,
                            "threat_intel: dropping malformed CIDR indicator",
                        );
                    }
                }
            }
            IndicatorType::Domain | IndicatorType::Url => {
                let mut map = self.domain_indicators.lock().unwrap();
                if map.len() >= self.max_indicators {
                    evict_expired(&mut map);
                }
                map.insert(indicator.value.clone(), indicator);
            }
            _ => {
                // SHA256 and JA3 stored in ip_indicators for simplicity.
                let mut map = self.ip_indicators.lock().unwrap();
                if map.len() >= self.max_indicators {
                    evict_expired(&mut map);
                }
                map.insert(indicator.value.clone(), indicator);
            }
        }
    }

    /// Check an IP against threat intel.
    pub fn check_ip(&self, ip: IpAddr) -> Option<ThreatMatch> {
        let ip_str = ip.to_string();

        // Local override wins.
        if let Some(action) = self.local_overrides.lock().unwrap().get(&ip_str) {
            return match action {
                OverrideAction::Allow => None,
                OverrideAction::Block => Some(ThreatMatch {
                    indicator: Indicator {
                        value: ip_str.clone(),
                        indicator_type: IndicatorType::Ip,
                        confidence: 100,
                        severity: Severity::Critical,
                        feed_id: "local".into(),
                        expires_at: Instant::now() + Duration::from_secs(86400),
                    },
                    action: ThreatAction::Block,
                }),
            };
        }

        let now = Instant::now();
        // Exact-host match first — cheaper than the CIDR scan.
        {
            let map = self.ip_indicators.lock().unwrap();
            if let Some(ind) = map.get(&ip_str) {
                if ind.expires_at > now {
                    let action = severity_to_action(ind.severity, ind.confidence);
                    return Some(ThreatMatch {
                        indicator: ind.clone(),
                        action,
                    });
                }
            }
        }
        // SEC-18 — linear scan of CIDR indicators. `IpNet::contains`
        // does the prefix-bit math for v4 + v6 in one call. Returns
        // the *first* matching entry; the contract doesn't specify
        // an ordering preference so feed order wins.
        let vec = self.cidr_indicators.lock().unwrap();
        for (net, ind) in vec.iter() {
            if ind.expires_at <= now {
                continue;
            }
            if net.contains(&ip) {
                let action = severity_to_action(ind.severity, ind.confidence);
                return Some(ThreatMatch {
                    indicator: ind.clone(),
                    action,
                });
            }
        }

        None
    }

    /// Check a domain against threat intel.
    pub fn check_domain(&self, domain: &str) -> Option<ThreatMatch> {
        // Local override.
        if let Some(action) = self.local_overrides.lock().unwrap().get(domain) {
            return match action {
                OverrideAction::Allow => None,
                OverrideAction::Block => Some(ThreatMatch {
                    indicator: Indicator {
                        value: domain.into(),
                        indicator_type: IndicatorType::Domain,
                        confidence: 100,
                        severity: Severity::Critical,
                        feed_id: "local".into(),
                        expires_at: Instant::now() + Duration::from_secs(86400),
                    },
                    action: ThreatAction::Block,
                }),
            };
        }

        // Suffix walk: a feed entry for `evil.com` must also catch
        // `c2.evil.com` / `a.b.evil.com`. Check the full domain first
        // (most specific wins), then drop the leftmost label one at a
        // time. Stops before the bare public-suffix label so a feed
        // entry for a TLD can't blanket-match. Matching is on label
        // boundaries, so `notevil.com` never matches `evil.com`.
        let map = self.domain_indicators.lock().unwrap();
        let now = Instant::now();
        let mut candidate = domain;
        loop {
            if let Some(ind) = map.get(candidate) {
                if ind.expires_at > now {
                    let action = severity_to_action(ind.severity, ind.confidence);
                    return Some(ThreatMatch {
                        indicator: ind.clone(),
                        action,
                    });
                }
            }
            match candidate.split_once('.') {
                Some((_, rest)) if rest.contains('.') => candidate = rest,
                _ => break,
            }
        }

        None
    }

    /// Number of stored indicators.
    pub fn indicator_count(&self) -> usize {
        self.ip_indicators.lock().unwrap().len()
            + self.cidr_indicators.lock().unwrap().len()
            + self.domain_indicators.lock().unwrap().len()
    }

    /// Clear all indicators.
    pub fn clear(&self) {
        self.ip_indicators.lock().unwrap().clear();
        self.cidr_indicators.lock().unwrap().clear();
        self.domain_indicators.lock().unwrap().clear();
    }
}

fn severity_to_action(severity: Severity, confidence: u8) -> ThreatAction {
    match (severity, confidence) {
        (Severity::Critical, _) => ThreatAction::Block,
        (Severity::High, c) if c >= 70 => ThreatAction::Block,
        (Severity::High, _) => ThreatAction::RaiseRisk(40),
        (Severity::Medium, c) if c >= 80 => ThreatAction::RaiseRisk(30),
        (Severity::Medium, _) => ThreatAction::RaiseRisk(20),
        (Severity::Low, _) => ThreatAction::Monitor,
    }
}

fn evict_expired(map: &mut HashMap<String, Indicator>) {
    let now = Instant::now();
    map.retain(|_, v| v.expires_at > now);
}

impl Default for ThreatIntelStore {
    fn default() -> Self {
        Self::new(100_000)
    }
}

/// Parse a plain-text IP feed (one IP per line, `#` comments).
pub fn parse_plaintext_feed(
    text: &str,
    feed_id: &str,
    confidence: u8,
    severity: Severity,
    ttl: Duration,
) -> Vec<Indicator> {
    let now = Instant::now();
    text.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|line| {
            // Validate it's an IP.
            if line.parse::<IpAddr>().is_ok() {
                Some(Indicator {
                    value: line.to_string(),
                    indicator_type: IndicatorType::Ip,
                    confidence,
                    severity,
                    feed_id: feed_id.to_string(),
                    expires_at: now + ttl,
                })
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_indicator(ip: &str, feed: &str, sev: Severity, conf: u8) -> Indicator {
        Indicator {
            value: ip.into(),
            indicator_type: IndicatorType::Ip,
            confidence: conf,
            severity: sev,
            feed_id: feed.into(),
            expires_at: Instant::now() + Duration::from_secs(3600),
        }
    }

    #[test]
    fn ingest_and_check_ip() {
        let store = ThreatIntelStore::default();
        store.ingest(make_indicator("1.2.3.4", "feed-1", Severity::High, 90));
        let m = store.check_ip("1.2.3.4".parse().unwrap());
        assert!(m.is_some());
        let m = m.unwrap();
        assert_eq!(m.indicator.feed_id, "feed-1");
        assert_eq!(m.action, ThreatAction::Block);
    }

    #[test]
    fn unknown_ip_returns_none() {
        let store = ThreatIntelStore::default();
        assert!(store.check_ip("9.9.9.9".parse().unwrap()).is_none());
    }

    #[test]
    fn local_override_allow_wins() {
        let store = ThreatIntelStore::default();
        store.ingest(make_indicator("1.2.3.4", "feed-1", Severity::Critical, 100));
        store.add_override("1.2.3.4", OverrideAction::Allow);
        assert!(store.check_ip("1.2.3.4".parse().unwrap()).is_none());
    }

    #[test]
    fn local_override_block() {
        let store = ThreatIntelStore::default();
        store.add_override("5.6.7.8", OverrideAction::Block);
        let m = store.check_ip("5.6.7.8".parse().unwrap()).unwrap();
        assert_eq!(m.action, ThreatAction::Block);
        assert_eq!(m.indicator.feed_id, "local");
    }

    #[test]
    fn expired_indicator_ignored() {
        let store = ThreatIntelStore::default();
        let expired = Indicator {
            value: "1.2.3.4".into(),
            indicator_type: IndicatorType::Ip,
            confidence: 100,
            severity: Severity::Critical,
            feed_id: "old".into(),
            expires_at: Instant::now() - Duration::from_secs(1),
        };
        store.ingest(expired);
        assert!(store.check_ip("1.2.3.4".parse().unwrap()).is_none());
    }

    #[test]
    fn domain_check() {
        let store = ThreatIntelStore::default();
        store.ingest(Indicator {
            value: "evil.example.com".into(),
            indicator_type: IndicatorType::Domain,
            confidence: 95,
            severity: Severity::High,
            feed_id: "feed-2".into(),
            expires_at: Instant::now() + Duration::from_secs(3600),
        });
        let m = store.check_domain("evil.example.com").unwrap();
        assert_eq!(m.action, ThreatAction::Block);
    }

    fn ingest_domain(store: &ThreatIntelStore, domain: &str, feed: &str) {
        store.ingest(Indicator {
            value: domain.into(),
            indicator_type: IndicatorType::Domain,
            confidence: 95,
            severity: Severity::High,
            feed_id: feed.into(),
            expires_at: Instant::now() + Duration::from_secs(3600),
        });
    }

    #[test]
    fn domain_feed_matches_subdomain() {
        // A feed entry for the parent domain should also catch its
        // subdomains — `evil.com` blocks `c2.evil.com`, `a.b.evil.com`.
        let store = ThreatIntelStore::default();
        ingest_domain(&store, "evil.com", "feed-3");

        let m = store.check_domain("c2.evil.com").expect("subdomain must hit parent feed entry");
        assert_eq!(m.action, ThreatAction::Block);
        assert_eq!(m.indicator.value, "evil.com", "matched indicator is the feed entry");

        assert!(store.check_domain("a.b.evil.com").is_some(), "deep subdomain still hits");
        assert!(store.check_domain("evil.com").is_some(), "exact match still hits");
    }

    #[test]
    fn domain_feed_subdomain_walk_respects_label_boundaries() {
        // The walk drops whole labels — it must not match on a bare
        // substring (`notevil.com`) or a sibling (`good.com`), and a
        // domain that merely *contains* the feed entry as a prefix
        // (`evil.com.attacker.net`) is not a subdomain of it.
        let store = ThreatIntelStore::default();
        ingest_domain(&store, "evil.com", "feed-3");

        assert!(store.check_domain("notevil.com").is_none(), "substring is not a label suffix");
        assert!(store.check_domain("good.com").is_none(), "sibling domain must not match");
        assert!(
            store.check_domain("evil.com.attacker.net").is_none(),
            "feed entry as a prefix is not a suffix match",
        );
    }

    #[test]
    fn severity_action_mapping() {
        assert_eq!(severity_to_action(Severity::Critical, 50), ThreatAction::Block);
        assert_eq!(severity_to_action(Severity::High, 90), ThreatAction::Block);
        assert_eq!(severity_to_action(Severity::High, 50), ThreatAction::RaiseRisk(40));
        assert_eq!(severity_to_action(Severity::Medium, 85), ThreatAction::RaiseRisk(30));
        assert_eq!(severity_to_action(Severity::Medium, 50), ThreatAction::RaiseRisk(20));
        assert_eq!(severity_to_action(Severity::Low, 100), ThreatAction::Monitor);
    }

    #[test]
    fn parse_plaintext() {
        let text = r#"
# Malicious IPs
1.2.3.4
5.6.7.8
# Comment
not-an-ip
9.10.11.12
"#;
        let indicators = parse_plaintext_feed(text, "test-feed", 80, Severity::Medium, Duration::from_secs(3600));
        assert_eq!(indicators.len(), 3);
        assert_eq!(indicators[0].value, "1.2.3.4");
        assert_eq!(indicators[1].value, "5.6.7.8");
        assert_eq!(indicators[2].value, "9.10.11.12");
    }

    #[test]
    fn indicator_count() {
        let store = ThreatIntelStore::default();
        store.ingest(make_indicator("1.1.1.1", "f", Severity::Low, 50));
        store.ingest(make_indicator("2.2.2.2", "f", Severity::Low, 50));
        assert_eq!(store.indicator_count(), 2);
    }

    #[test]
    fn clear_removes_all() {
        let store = ThreatIntelStore::default();
        store.ingest(make_indicator("1.1.1.1", "f", Severity::Low, 50));
        store.clear();
        assert_eq!(store.indicator_count(), 0);
    }

    #[test]
    fn cidr_indicator_matches_in_range() {
        // SEC-18 — a /24 CIDR indicator should match any IP in the
        // covered range, not just the exact `10.0.0.0` string.
        let store = ThreatIntelStore::default();
        store.ingest(Indicator {
            value: "10.0.0.0/24".into(),
            indicator_type: IndicatorType::Cidr,
            confidence: 90,
            severity: Severity::High,
            feed_id: "cidr-feed".into(),
            expires_at: Instant::now() + Duration::from_secs(3600),
        });
        // First-in-range hit.
        let m = store.check_ip("10.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(m.action, ThreatAction::Block);
        assert_eq!(m.indicator.feed_id, "cidr-feed");
        // Mid-range hit.
        let m = store.check_ip("10.0.0.128".parse().unwrap()).unwrap();
        assert_eq!(m.indicator.feed_id, "cidr-feed");
        // Outside the range — no match.
        assert!(store.check_ip("10.0.1.1".parse().unwrap()).is_none());
    }

    #[test]
    fn cidr_indicator_handles_ipv6() {
        let store = ThreatIntelStore::default();
        store.ingest(Indicator {
            value: "2001:db8::/32".into(),
            indicator_type: IndicatorType::Cidr,
            confidence: 80,
            severity: Severity::Medium,
            feed_id: "v6-feed".into(),
            expires_at: Instant::now() + Duration::from_secs(3600),
        });
        let m = store.check_ip("2001:db8:1::1".parse().unwrap()).unwrap();
        assert_eq!(m.indicator.feed_id, "v6-feed");
        assert!(store.check_ip("2001:db9::1".parse().unwrap()).is_none());
    }

    #[test]
    fn malformed_cidr_dropped_without_panic() {
        let store = ThreatIntelStore::default();
        store.ingest(Indicator {
            value: "not-a-cidr".into(),
            indicator_type: IndicatorType::Cidr,
            confidence: 90,
            severity: Severity::High,
            feed_id: "broken".into(),
            expires_at: Instant::now() + Duration::from_secs(3600),
        });
        assert_eq!(store.indicator_count(), 0);
    }

    #[test]
    fn provenance_in_match() {
        let store = ThreatIntelStore::default();
        store.ingest(make_indicator("1.2.3.4", "abuse-ch", Severity::High, 85));
        let m = store.check_ip("1.2.3.4".parse().unwrap()).unwrap();
        assert_eq!(m.indicator.feed_id, "abuse-ch");
        assert_eq!(m.indicator.confidence, 85);
    }
}
