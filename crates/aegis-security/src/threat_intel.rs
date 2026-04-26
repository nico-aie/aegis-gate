use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

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
    /// IP indicators keyed by IP string.
    ip_indicators: Mutex<HashMap<String, Indicator>>,
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
            IndicatorType::Ip | IndicatorType::Cidr => {
                let mut map = self.ip_indicators.lock().unwrap();
                if map.len() >= self.max_indicators {
                    evict_expired(&mut map);
                }
                map.insert(indicator.value.clone(), indicator);
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

        let map = self.ip_indicators.lock().unwrap();
        if let Some(ind) = map.get(&ip_str) {
            if ind.expires_at > Instant::now() {
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

        let map = self.domain_indicators.lock().unwrap();
        if let Some(ind) = map.get(domain) {
            if ind.expires_at > Instant::now() {
                let action = severity_to_action(ind.severity, ind.confidence);
                return Some(ThreatMatch {
                    indicator: ind.clone(),
                    action,
                });
            }
        }

        None
    }

    /// Number of stored indicators.
    pub fn indicator_count(&self) -> usize {
        self.ip_indicators.lock().unwrap().len()
            + self.domain_indicators.lock().unwrap().len()
    }

    /// Clear all indicators.
    pub fn clear(&self) {
        self.ip_indicators.lock().unwrap().clear();
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
    fn provenance_in_match() {
        let store = ThreatIntelStore::default();
        store.ingest(make_indicator("1.2.3.4", "abuse-ch", Severity::High, 85));
        let m = store.check_ip("1.2.3.4".parse().unwrap()).unwrap();
        assert_eq!(m.indicator.feed_id, "abuse-ch");
        assert_eq!(m.indicator.confidence, 85);
    }
}
