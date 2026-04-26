use std::collections::HashMap;
use std::sync::Mutex;

/// Bot classification tier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BotTier {
    Human,
    GoodBot,
    LikelyBot,
    KnownBad,
    Unknown,
}

/// Signals used for bot classification.
#[derive(Clone, Debug, Default)]
pub struct BotSignals {
    pub ja4_fingerprint: Option<String>,
    pub h2_fingerprint: Option<String>,
    pub user_agent: Option<String>,
    pub has_cookies: bool,
    pub has_js_challenge_pass: bool,
    pub failed_challenges: u32,
    pub reverse_dns: Option<String>,
}

/// Known good-bot reverse DNS patterns for forward-confirmed reverse DNS (FCrDNS).
const GOOD_BOT_RDNS: &[(&str, &str)] = &[
    ("googlebot.com", "Googlebot"),
    ("google.com", "Google"),
    ("search.msn.com", "Bingbot"),
    ("crawl.yahoo.net", "Yahoo Slurp"),
    ("crawl.baidu.com", "Baiduspider"),
    ("yandex.com", "YandexBot"),
    ("applebot.apple.com", "Applebot"),
    ("facebookexternalhit", "Facebook"),
    ("twitterbot", "Twitterbot"),
    ("linkedinbot", "LinkedInBot"),
    ("duckduckgo.com", "DuckDuckBot"),
];

/// Known bad user-agent patterns.
const BAD_UA_PATTERNS: &[&str] = &[
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "dirbuster",
    "gobuster",
    "hydra",
    "medusa",
    "havij",
    "w3af",
];

/// Bot classifier with optional reverse DNS cache.
pub struct BotClassifier {
    /// Cache of reverse DNS results: IP string → rDNS.
    rdns_cache: Mutex<HashMap<String, Option<String>>>,
    /// Max cache size.
    max_cache: usize,
}

impl BotClassifier {
    pub fn new(max_cache: usize) -> Self {
        Self {
            rdns_cache: Mutex::new(HashMap::new()),
            max_cache,
        }
    }

    /// Classify a request's bot tier from available signals.
    pub fn classify(&self, signals: &BotSignals) -> BotTier {
        // 1. Check for known bad UA.
        if let Some(ua) = &signals.user_agent {
            let ua_lower = ua.to_lowercase();
            for pattern in BAD_UA_PATTERNS {
                if ua_lower.contains(pattern) {
                    return BotTier::KnownBad;
                }
            }
        }

        // 2. Check for known good bot via reverse DNS.
        if let Some(rdns) = &signals.reverse_dns {
            let rdns_lower = rdns.to_lowercase();
            for (domain, _name) in GOOD_BOT_RDNS {
                if rdns_lower.ends_with(domain) {
                    return BotTier::GoodBot;
                }
            }
        }

        // 3. Multiple failed challenges → likely bot.
        if signals.failed_challenges >= 3 {
            return BotTier::LikelyBot;
        }

        // 4. Has cookies + passed JS challenge → likely human.
        if signals.has_cookies && signals.has_js_challenge_pass {
            return BotTier::Human;
        }

        // 5. No UA or empty UA → likely bot.
        if signals.user_agent.is_none() || signals.user_agent.as_deref() == Some("") {
            return BotTier::LikelyBot;
        }

        // 6. Low UA entropy (very short or generic) → suspicious.
        if let Some(ua) = &signals.user_agent {
            if ua.len() < 20 {
                return BotTier::LikelyBot;
            }
        }

        BotTier::Unknown
    }

    /// Store a reverse DNS result in cache.
    pub fn cache_rdns(&self, ip: &str, rdns: Option<String>) {
        let mut cache = self.rdns_cache.lock().unwrap();
        if cache.len() >= self.max_cache {
            // Simple eviction: clear all.
            cache.clear();
        }
        cache.insert(ip.to_string(), rdns);
    }

    /// Get cached reverse DNS result.
    pub fn get_cached_rdns(&self, ip: &str) -> Option<Option<String>> {
        self.rdns_cache.lock().unwrap().get(ip).cloned()
    }
}

impl Default for BotClassifier {
    fn default() -> Self {
        Self::new(10_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn human_signals() -> BotSignals {
        BotSignals {
            ja4_fingerprint: Some("t13d0910_abc123_def456".into()),
            h2_fingerprint: Some("h2fp_chrome".into()),
            user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".into()),
            has_cookies: true,
            has_js_challenge_pass: true,
            failed_challenges: 0,
            reverse_dns: None,
        }
    }

    // Good bots.
    #[test]
    fn googlebot_classified() {
        let sig = BotSignals {
            user_agent: Some("Mozilla/5.0 (compatible; Googlebot/2.1)".into()),
            reverse_dns: Some("crawl-66-249-66-1.googlebot.com".into()),
            ..Default::default()
        };
        let c = BotClassifier::default();
        assert_eq!(c.classify(&sig), BotTier::GoodBot);
    }

    #[test]
    fn bingbot_classified() {
        let sig = BotSignals {
            user_agent: Some("Mozilla/5.0 (compatible; bingbot/2.0)".into()),
            reverse_dns: Some("msnbot-207-46-13-37.search.msn.com".into()),
            ..Default::default()
        };
        let c = BotClassifier::default();
        assert_eq!(c.classify(&sig), BotTier::GoodBot);
    }

    #[test]
    fn yandexbot_classified() {
        let sig = BotSignals {
            user_agent: Some("Mozilla/5.0 (compatible; YandexBot/3.0)".into()),
            reverse_dns: Some("spider-141-8-142-36.yandex.com".into()),
            ..Default::default()
        };
        let c = BotClassifier::default();
        assert_eq!(c.classify(&sig), BotTier::GoodBot);
    }

    #[test]
    fn applebot_classified() {
        let sig = BotSignals {
            user_agent: Some("Mozilla/5.0 (Macintosh; Applebot/0.1)".into()),
            reverse_dns: Some("17-58-98-71.applebot.apple.com".into()),
            ..Default::default()
        };
        let c = BotClassifier::default();
        assert_eq!(c.classify(&sig), BotTier::GoodBot);
    }

    #[test]
    fn duckduckbot_classified() {
        let sig = BotSignals {
            user_agent: Some("DuckDuckBot/1.0".into()),
            reverse_dns: Some("crawl1.duckduckgo.com".into()),
            ..Default::default()
        };
        let c = BotClassifier::default();
        assert_eq!(c.classify(&sig), BotTier::GoodBot);
    }

    // Human browsers.
    #[test]
    fn chrome_human() {
        let c = BotClassifier::default();
        assert_eq!(c.classify(&human_signals()), BotTier::Human);
    }

    #[test]
    fn firefox_human() {
        let sig = BotSignals {
            user_agent: Some("Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0".into()),
            has_cookies: true,
            has_js_challenge_pass: true,
            ..Default::default()
        };
        let c = BotClassifier::default();
        assert_eq!(c.classify(&sig), BotTier::Human);
    }

    #[test]
    fn safari_human() {
        let sig = BotSignals {
            user_agent: Some("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 Safari/605.1.15".into()),
            has_cookies: true,
            has_js_challenge_pass: true,
            ..Default::default()
        };
        let c = BotClassifier::default();
        assert_eq!(c.classify(&sig), BotTier::Human);
    }

    // Known bad.
    #[test]
    fn sqlmap_known_bad() {
        let sig = BotSignals {
            user_agent: Some("sqlmap/1.5#stable".into()),
            ..Default::default()
        };
        let c = BotClassifier::default();
        assert_eq!(c.classify(&sig), BotTier::KnownBad);
    }

    #[test]
    fn nikto_known_bad() {
        let sig = BotSignals {
            user_agent: Some("Nikto/2.1.6".into()),
            ..Default::default()
        };
        let c = BotClassifier::default();
        assert_eq!(c.classify(&sig), BotTier::KnownBad);
    }

    #[test]
    fn nmap_known_bad() {
        let sig = BotSignals {
            user_agent: Some("Nmap Scripting Engine".into()),
            ..Default::default()
        };
        let c = BotClassifier::default();
        assert_eq!(c.classify(&sig), BotTier::KnownBad);
    }

    #[test]
    fn hydra_known_bad() {
        let sig = BotSignals {
            user_agent: Some("Mozilla/5.0 Hydra/9.4".into()),
            ..Default::default()
        };
        let c = BotClassifier::default();
        assert_eq!(c.classify(&sig), BotTier::KnownBad);
    }

    // Likely bots.
    #[test]
    fn no_ua_likely_bot() {
        let sig = BotSignals::default();
        let c = BotClassifier::default();
        assert_eq!(c.classify(&sig), BotTier::LikelyBot);
    }

    #[test]
    fn empty_ua_likely_bot() {
        let sig = BotSignals {
            user_agent: Some("".into()),
            ..Default::default()
        };
        let c = BotClassifier::default();
        assert_eq!(c.classify(&sig), BotTier::LikelyBot);
    }

    #[test]
    fn short_ua_likely_bot() {
        let sig = BotSignals {
            user_agent: Some("curl/7.88".into()),
            ..Default::default()
        };
        let c = BotClassifier::default();
        assert_eq!(c.classify(&sig), BotTier::LikelyBot);
    }

    #[test]
    fn failed_challenges_likely_bot() {
        let sig = BotSignals {
            user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120".into()),
            failed_challenges: 5,
            ..Default::default()
        };
        let c = BotClassifier::default();
        assert_eq!(c.classify(&sig), BotTier::LikelyBot);
    }

    // Unknown.
    #[test]
    fn legitimate_ua_no_challenge_unknown() {
        let sig = BotSignals {
            user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".into()),
            has_cookies: false,
            has_js_challenge_pass: false,
            ..Default::default()
        };
        let c = BotClassifier::default();
        assert_eq!(c.classify(&sig), BotTier::Unknown);
    }

    // Cache tests.
    #[test]
    fn rdns_cache_store_and_get() {
        let c = BotClassifier::default();
        c.cache_rdns("1.2.3.4", Some("host.example.com".into()));
        let cached = c.get_cached_rdns("1.2.3.4");
        assert_eq!(cached, Some(Some("host.example.com".into())));
    }

    #[test]
    fn rdns_cache_miss() {
        let c = BotClassifier::default();
        assert_eq!(c.get_cached_rdns("9.9.9.9"), None);
    }

    #[test]
    fn rdns_cache_eviction() {
        let c = BotClassifier::new(3);
        c.cache_rdns("1.1.1.1", Some("a".into()));
        c.cache_rdns("2.2.2.2", Some("b".into()));
        c.cache_rdns("3.3.3.3", Some("c".into()));
        // At capacity, next insert triggers clear.
        c.cache_rdns("4.4.4.4", Some("d".into()));
        assert_eq!(c.get_cached_rdns("1.1.1.1"), None); // evicted
        assert!(c.get_cached_rdns("4.4.4.4").is_some());
    }
}
