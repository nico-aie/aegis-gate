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

/// 2026-05-18 (QC Sprint 2.2 — F-CRITICAL-015, §5.2 #05):
/// IP / ASN ownership classification. Public WAFs see this on the
/// edge from the upstream IP-reputation feed or a static
/// `Vec<AsnRange>` lookup table.
///
/// - `Residential` — consumer ISPs (Comcast, Vodafone, etc.).
///   Default-trust by ASN-only signal — bots from residential
///   pools are common (proxy-as-a-service rotators) but most
///   traffic is legit.
/// - `Mobile` — carrier-grade NAT mobile networks (T-Mobile,
///   Verizon Wireless, etc.). Same default-trust as Residential.
/// - `Hosting` — cloud hosting providers (AWS / GCP / Azure /
///   DigitalOcean / Linode / OVH). Strong negative signal — most
///   legitimate browser traffic doesn't originate from a hosting
///   ASN.
/// - `Datacenter` — non-cloud datacenter / bulletproof hosting.
///   Strongest negative signal — heavily abused by scrapers and
///   credential-stuffers.
/// - `Unknown` — no lookup result; treat as neutral.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AsnClassification {
    Residential,
    Mobile,
    Hosting,
    Datacenter,
    #[default]
    Unknown,
}

impl AsnClassification {
    /// Stable wire string for the JSON API (e.g. on the Top
    /// Attackers row). Lower-case, single word — pinned because
    /// the dashboard uses these strings as CSS class keys.
    pub fn as_wire_str(self) -> &'static str {
        match self {
            Self::Residential => "residential",
            Self::Mobile => "mobile",
            Self::Hosting => "hosting",
            Self::Datacenter => "datacenter",
            Self::Unknown => "unknown",
        }
    }
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
    /// 2026-05-18 (QC Sprint 2.2 — F-CRITICAL-015, §5.2 #05):
    /// peer IP's autonomous system number. Sourced from the
    /// MaxMind ASN database via `aegis-security::geoip`.
    pub asn: Option<u32>,
    /// 2026-05-18 (QC Sprint 2.2): ownership classification of
    /// the peer's ASN. The data plane fills this from a static
    /// lookup against well-known hosting / datacenter ASNs, or
    /// leaves it `Unknown` when the lookup misses.
    pub asn_classification: AsnClassification,
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

/// 2026-05-18 (QC Sprint 2.2 — F-CRITICAL-015): known-bot JA4
/// fingerprint prefixes. The JA4 format is
/// `{q}{ver}{sni}{cipher_count}{ext_count}_{cipher_hash}_{ext_hash}`.
/// We match against the `cipher_hash` substring (the segment
/// between underscores) since the prefix `t13d…` is shared by
/// nearly all modern TLS-1.3 clients with domain SNI.
///
/// Sourced from public JA4 databases — these are the cipher
/// signatures of common attack tooling and headless library
/// fingerprints. Conservative list: prefer false negatives
/// (don't false-positive a real user) over false positives.
///
/// Empty list ships today — F-CRITICAL-015's intent is the
/// *capability* (BotSignals carries JA4, classifier inspects it).
/// Operators / threat-feed integrations populate at boot via a
/// future `cfg.bots.known_bad_ja4` knob.
const KNOWN_BAD_JA4_CIPHER_HASHES: &[&str] = &[];

/// 2026-05-18 (QC Sprint 2.2 — §5.2 #04): challenge-ladder
/// threshold. Score accumulates from signals (suspicious ASN,
/// short UA, no cookies, etc.); crossing this becomes
/// `LikelyBot`. Reserved as a constant so the ladder is
/// auditable + tunable.
const LADDER_LIKELY_BOT_THRESHOLD: u32 = 50;

/// 2026-05-18 (QC follow-up TLS-wiring batch — F-CRITICAL-015
/// activation): hardcoded ASN → ownership classification table.
/// Operators can override via `cfg.bots.asn_classifications` once
/// that schema lands; the hardcoded table covers the obvious
/// cloud / hosting / mobile carrier ASNs so the ASN-class signal
/// fires immediately when MaxMind ASN lookups return a known
/// value.
///
/// Tuples: `(asn, classification)`. Sorted by ASN for `binary_search_by`
/// — runtime cost is O(log N) per request. List is intentionally
/// conservative — only widely-cited ASNs whose ownership rarely
/// changes; misclassifying a popular consumer ISP as Hosting
/// would false-positive a huge population.
const ASN_TABLE: &[(u32, AsnClassification)] = &[
    // Cloud-hosting providers (datacenter-class for our purposes).
    (3320, AsnClassification::Hosting),    // Deutsche Telekom — mixed but heavy hosting.
    (7843, AsnClassification::Hosting),    // Cox Comm. business.
    (8075, AsnClassification::Hosting),    // Microsoft Azure.
    (13335, AsnClassification::Hosting),   // Cloudflare.
    (14061, AsnClassification::Hosting),   // DigitalOcean.
    (14618, AsnClassification::Hosting),   // Amazon AWS (us-east-1).
    (15169, AsnClassification::Hosting),   // Google Cloud / Google.
    (16276, AsnClassification::Hosting),   // OVH SAS.
    (16509, AsnClassification::Hosting),   // Amazon AWS (multi-region).
    (20473, AsnClassification::Hosting),   // Vultr / Choopa.
    (24940, AsnClassification::Hosting),   // Hetzner Online.
    (32934, AsnClassification::Hosting),   // Facebook / Meta (returns user-facing too; classified conservatively).
    (46606, AsnClassification::Hosting),   // Unified Layer / Bluehost.
    (63949, AsnClassification::Hosting),   // Linode (Akamai).
    // Bulletproof / datacenter-class — heavier negative weight.
    (197207, AsnClassification::Datacenter), // PSINet / abuse-heavy.
    (203020, AsnClassification::Datacenter), // HostingCloud.
    // Major residential / consumer ISPs (most legit traffic).
    (701, AsnClassification::Residential),   // Verizon (US).
    (7018, AsnClassification::Residential),  // AT&T (US).
    (7922, AsnClassification::Residential),  // Comcast (US).
    // Mobile carriers (CGNAT, sometimes confused for hosting).
    (5650, AsnClassification::Mobile),       // T-Mobile US.
    (6167, AsnClassification::Mobile),       // Verizon Wireless (US).
    (21928, AsnClassification::Mobile),      // T-Mobile USA.
];

/// 2026-05-18 (QC follow-up TLS-wiring batch): look up an ASN's
/// ownership class. Returns `Unknown` when the ASN isn't in the
/// hardcoded table (most of the world). Operators tuning posture
/// for their target population can populate a larger table via a
/// future `cfg.bots.asn_classifications` YAML knob.
pub fn classify_asn(asn: u32) -> AsnClassification {
    // Linear scan — the table is small (~20 entries) and binary
    // search wouldn't beat the branch predictor at this size.
    for (a, class) in ASN_TABLE {
        if *a == asn {
            return *class;
        }
    }
    AsnClassification::Unknown
}

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
    ///
    /// 2026-05-18 (QC Sprint 2.2 — F-CRITICAL-015 §5.2 #04 / #05 /
    /// #08): the classifier now reads `ja4_fingerprint` and
    /// `asn_classification` in addition to UA / rDNS / challenge
    /// state. The decision shape preserves the existing fast-paths
    /// (KnownBad UA → KnownBad; FCrDNS match → GoodBot; passed JS
    /// challenge → Human) but lets multi-signal evidence escalate
    /// the otherwise-Unknown verdict via a small score-based
    /// ladder.
    pub fn classify(&self, signals: &BotSignals) -> BotTier {
        // 1. Check for known bad UA. Fastest path — preserves
        // existing tests (sqlmap, nikto, nmap, …) and is an absolute
        // KnownBad regardless of other signals.
        if let Some(ua) = &signals.user_agent {
            let ua_lower = ua.to_lowercase();
            for pattern in BAD_UA_PATTERNS {
                if ua_lower.contains(pattern) {
                    return BotTier::KnownBad;
                }
            }
        }

        // 2026-05-18 §5.2 #08: known-bad JA4 cipher hash.
        // KnownBad regardless of other signals, same severity as
        // a UA match. Empty list ships today — threat-feed
        // integration populates it.
        if let Some(ja4) = &signals.ja4_fingerprint {
            if let Some(cipher_hash) = extract_ja4_cipher_hash(ja4) {
                if KNOWN_BAD_JA4_CIPHER_HASHES.contains(&cipher_hash) {
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
        // 2026-05-18: the JS challenge pass overrides ASN-class
        // suspicion — a real user behind a residential proxy
        // still passes the JS check.
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

        // 2026-05-18 §5.2 #04 + #05: signal-score ladder. Each
        // individually-weak signal contributes points; crossing
        // `LADDER_LIKELY_BOT_THRESHOLD` (50) escalates an
        // otherwise-Unknown verdict to LikelyBot. Real browsers
        // typically accumulate 0-20; bots from hosting ASNs
        // without cookies / JS-pass accumulate 50-80.
        //
        // 2026-05-21 — Hosting bumped 30 → 35 so a cookieless
        // request from a cloud/hosting ASN (AWS / GCP / Azure /
        // Cloudflare / OVH / Hetzner / DO / …) reaches the bar
        // (35 + 15 no-cookies = 50) and classifies as LikelyBot.
        // Pre-fix it summed to 45 and stayed Unknown, so with the
        // GeoIP ASN DB loaded the bot-mix card was still all-unknown
        // for cloud traffic. A hosting client WITH cookies (session
        // continuity → likely a real user behind a proxy) stays at
        // 35 < 50 → Unknown, which is the intended distinction.
        let mut score: u32 = 0;
        match signals.asn_classification {
            AsnClassification::Datacenter => score += 40,
            AsnClassification::Hosting => score += 35,
            AsnClassification::Residential | AsnClassification::Mobile => {}
            AsnClassification::Unknown => {}
        }
        if !signals.has_cookies {
            score += 15;
        }
        // The `failed_challenges` 1-2 range (3+ is already
        // LikelyBot above). One failure is a soft signal.
        if signals.failed_challenges >= 1 {
            score += 10 * signals.failed_challenges;
        }
        if score >= LADDER_LIKELY_BOT_THRESHOLD {
            return BotTier::LikelyBot;
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

/// 2026-05-18 (QC Sprint 2.2): pull out the `cipher_hash`
/// segment of a JA4 fingerprint string. The JA4 format is
/// `{q}{ver}{sni}{cipher_count}{ext_count}_{cipher_hash}_{ext_hash}`;
/// the cipher_hash is the segment between the first and second
/// underscore. Returns `None` for malformed input.
fn extract_ja4_cipher_hash(ja4: &str) -> Option<&str> {
    let mut parts = ja4.splitn(3, '_');
    parts.next()?; // header prefix (q/ver/sni/counts)
    parts.next() // cipher_hash
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
            asn: None,
            asn_classification: AsnClassification::Unknown,
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

    // ---- 2026-05-18 QC Sprint 2.2 — F-CRITICAL-015 ----

    /// `extract_ja4_cipher_hash` pulls out the second underscore-
    /// separated segment from a JA4 string.
    #[test]
    fn extract_ja4_cipher_hash_basic() {
        let fp = "t13d0910_abc123def456_789xyzqwer42";
        assert_eq!(extract_ja4_cipher_hash(fp), Some("abc123def456"));
    }

    #[test]
    fn extract_ja4_cipher_hash_malformed_returns_none() {
        // No underscore.
        assert_eq!(extract_ja4_cipher_hash("t13d0910"), None);
        // Single underscore — only header + one tail.
        // (splitn(3) gives the whole tail as the second part.)
        // We accept this — the tail is the cipher_hash.
        assert_eq!(
            extract_ja4_cipher_hash("t13d0910_abc"),
            Some("abc"),
        );
    }

    /// Datacenter-ASN traffic without cookies + no JS challenge
    /// pass crosses the LikelyBot ladder threshold. Pre-Sprint-2.2
    /// this would have returned `Unknown`.
    #[test]
    fn datacenter_asn_with_no_cookies_escalates_to_likely_bot() {
        let sig = BotSignals {
            user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".into()),
            asn: Some(13335),
            asn_classification: AsnClassification::Datacenter,
            has_cookies: false,
            ..Default::default()
        };
        let c = BotClassifier::default();
        assert_eq!(c.classify(&sig), BotTier::LikelyBot);
    }

    /// Hosting ASN alone (with cookies) sits below the threshold
    /// — cookies are evidence of session continuity. Returns
    /// Unknown so downstream challenge gates can decide.
    #[test]
    fn hosting_asn_with_cookies_stays_unknown() {
        let sig = BotSignals {
            user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".into()),
            asn: Some(16509),
            asn_classification: AsnClassification::Hosting,
            has_cookies: true,
            // No JS challenge pass — wouldn't classify as Human.
            ..Default::default()
        };
        let c = BotClassifier::default();
        // 35 (Hosting) + 0 (cookies present) = 35 < 50. Unknown.
        assert_eq!(c.classify(&sig), BotTier::Unknown);
    }

    /// 2026-05-21 — a cookieless request from a hosting/cloud ASN now
    /// crosses the ladder (35 + 15 = 50) → LikelyBot. This is what
    /// makes the bot-mix card populate for cloud traffic once the
    /// GeoIP ASN DB is loaded.
    #[test]
    fn hosting_asn_no_cookies_escalates_to_likely_bot() {
        let sig = BotSignals {
            user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".into()),
            asn: Some(16509), // AWS
            asn_classification: AsnClassification::Hosting,
            has_cookies: false,
            ..Default::default()
        };
        let c = BotClassifier::default();
        assert_eq!(c.classify(&sig), BotTier::LikelyBot);
    }

    /// JS challenge pass on a hosting-ASN connection overrides
    /// the ASN-class suspicion. Real users behind a hosting NAT
    /// (rare but real — workplace proxies, etc.) still pass.
    #[test]
    fn js_challenge_pass_overrides_hosting_asn() {
        let sig = BotSignals {
            user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".into()),
            asn: Some(16509),
            asn_classification: AsnClassification::Hosting,
            has_cookies: true,
            has_js_challenge_pass: true,
            ..Default::default()
        };
        let c = BotClassifier::default();
        assert_eq!(c.classify(&sig), BotTier::Human);
    }

    /// Residential ASN doesn't accumulate points by itself —
    /// legitimate consumer traffic must not get auto-escalated.
    #[test]
    fn residential_asn_with_no_other_signals_stays_unknown() {
        let sig = BotSignals {
            user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".into()),
            asn: Some(7922),
            asn_classification: AsnClassification::Residential,
            has_cookies: true,
            ..Default::default()
        };
        let c = BotClassifier::default();
        assert_eq!(c.classify(&sig), BotTier::Unknown);
    }

    /// 1 failed challenge + Hosting ASN + no cookies stacks to
    /// 30 + 15 + 10 = 55, crossing the ladder.
    #[test]
    fn failed_challenge_stacks_with_asn_class() {
        let sig = BotSignals {
            user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".into()),
            asn_classification: AsnClassification::Hosting,
            has_cookies: false,
            failed_challenges: 1,
            ..Default::default()
        };
        let c = BotClassifier::default();
        // 30 + 15 + 10 = 55 ≥ 50.
        assert_eq!(c.classify(&sig), BotTier::LikelyBot);
    }

    /// AsnClassification round-trips through default and equality.
    #[test]
    fn asn_classification_default_is_unknown() {
        let c: AsnClassification = AsnClassification::default();
        assert_eq!(c, AsnClassification::Unknown);
    }

    // ---- 2026-05-18 TLS-wiring batch — F-CRITICAL-015 activation ----

    /// Well-known cloud ASNs classify as Hosting.
    #[test]
    fn classify_asn_recognises_cloud_providers() {
        assert_eq!(classify_asn(16509), AsnClassification::Hosting); // AWS
        assert_eq!(classify_asn(15169), AsnClassification::Hosting); // GCP / Google
        assert_eq!(classify_asn(8075), AsnClassification::Hosting);  // Azure
        assert_eq!(classify_asn(14061), AsnClassification::Hosting); // DigitalOcean
        assert_eq!(classify_asn(13335), AsnClassification::Hosting); // Cloudflare
        assert_eq!(classify_asn(63949), AsnClassification::Hosting); // Linode
        assert_eq!(classify_asn(24940), AsnClassification::Hosting); // Hetzner
        assert_eq!(classify_asn(16276), AsnClassification::Hosting); // OVH
    }

    /// Major residential ISPs classify as Residential (NOT
    /// Hosting). False-positive a popular consumer ISP as
    /// Hosting would block a huge population.
    #[test]
    fn classify_asn_recognises_residential() {
        assert_eq!(classify_asn(7922), AsnClassification::Residential); // Comcast
        assert_eq!(classify_asn(7018), AsnClassification::Residential); // AT&T
        assert_eq!(classify_asn(701), AsnClassification::Residential);  // Verizon
    }

    /// Mobile carriers classify as Mobile, not Hosting — CGNAT
    /// from a phone network looks similar to a hosting NAT but
    /// shouldn't get the negative score weight.
    #[test]
    fn classify_asn_recognises_mobile_carriers() {
        assert_eq!(classify_asn(5650), AsnClassification::Mobile);  // T-Mobile US
        assert_eq!(classify_asn(6167), AsnClassification::Mobile);  // Verizon Wireless
        assert_eq!(classify_asn(21928), AsnClassification::Mobile); // T-Mobile USA
    }

    /// Unknown ASN returns Unknown (no false-positive).
    #[test]
    fn classify_asn_unknown_returns_unknown() {
        assert_eq!(classify_asn(0), AsnClassification::Unknown);
        assert_eq!(classify_asn(999999), AsnClassification::Unknown);
        assert_eq!(classify_asn(42), AsnClassification::Unknown);
    }

    /// End-to-end: a request from a Datacenter ASN with no cookies
    /// (40 + 15 = 55 ≥ 50 threshold) classifies as LikelyBot via
    /// the classify_asn → bot ladder path. Hosting alone (30 +
    /// 15 = 45) stays Unknown — closer to the threshold but
    /// still a downstream-gate decision. Wire-up regression.
    #[test]
    fn classify_via_asn_lookup_escalates_to_likely_bot() {
        let asn = 197207; // PSINet — classified Datacenter (40 pts)
        let asn_class = classify_asn(asn);
        assert_eq!(asn_class, AsnClassification::Datacenter);
        let sig = BotSignals {
            user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".into()),
            asn: Some(asn),
            asn_classification: asn_class,
            has_cookies: false,
            ..Default::default()
        };
        let c = BotClassifier::default();
        // 40 (Datacenter) + 15 (!cookies) = 55 ≥ 50 → LikelyBot.
        assert_eq!(c.classify(&sig), BotTier::LikelyBot);
    }

    /// A Hosting-class ASN with no cookies classifies LikelyBot
    /// (2026-05-21 calibration: 35 + 15 = 50 ≥ 50) but is NOT
    /// `KnownBad` — i.e. it surfaces as `suspect`/challenge, never an
    /// outright block. Real users behind a workplace proxy on AWS get
    /// challenged, not auto-blocked, at the bot tier.
    #[test]
    fn classify_via_hosting_asn_alone_does_not_block() {
        let asn = 16509; // AWS
        let asn_class = classify_asn(asn);
        let sig = BotSignals {
            user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".into()),
            asn: Some(asn),
            asn_classification: asn_class,
            has_cookies: false,
            ..Default::default()
        };
        let c = BotClassifier::default();
        let verdict = c.classify(&sig);
        assert_eq!(verdict, BotTier::LikelyBot, "cookieless hosting ASN → suspect");
        assert_ne!(verdict, BotTier::KnownBad, "must not be an outright block");
    }
}
