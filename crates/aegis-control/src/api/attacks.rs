//! `/api/attacks/distribution` data layer (D-M2-T2.4).
//!
//! Maintains a per-detector counter over a 15-minute sliding window
//! driven by the audit bus. Every `class=Detection` event is bucketed
//! by detector name; ratios are computed at query time so the
//! response always sums to 100 (within rounding) regardless of how
//! many detectors are active.
//!
//! Detector name extraction (priority order):
//! 1. `event.fields["detector"]` if present and a string. This is
//!    the convention used by the security pipeline detectors —
//!    see the `audit_event_serializes_to_json` test in
//!    `aegis-core::audit` for the canonical shape.
//! 2. The portion of `event.rule_id` before the first `-`, `_`, or
//!    `/`. So `"sqli-12"` and `"sqli/owasp-3"` both bucket as `sqli`.
//! 3. `"unknown"` fallback so the response is always non-empty
//!    when there are detection events.
//!
//! Spec: `docs/dashboard-enterprise/api.md` §"Attack analytics".

#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aegis_core::audit::{AuditClass, AuditEvent};
use serde::Serialize;

/// Maximum retention. Equal to the largest documented window so
/// `distribution(window_seconds)` can answer any query without
/// retaining unused history.
const RETENTION: Duration = Duration::from_secs(900);
/// Default response cache TTL.
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(1);

/// One row of the distribution chart — name, raw count, percentage.
#[derive(Clone, Debug, Serialize)]
pub struct Category {
    pub name: String,
    pub count: u64,
    pub pct: f64,
}

/// JSON shape returned by `GET /api/attacks/distribution`.
#[derive(Clone, Debug, Serialize)]
pub struct DistributionResponse {
    pub window_seconds: u32,
    pub categories: Vec<Category>,
}

/// One row of the top-attackers table.
#[derive(Clone, Debug, Serialize)]
pub struct Attacker {
    /// `client_ip` for public addresses, otherwise `fp:<ja4>`.
    pub identifier: String,
    pub hits: u64,
    /// Distinct detector names that fired against this attacker,
    /// sorted alphabetically for stable output.
    pub categories: Vec<String>,
    /// Highest risk score this attacker reached in the window.
    pub risk: u32,
    /// RFC 3339 (with `Z`) timestamp of the most recent hit.
    pub last_seen: chrono::DateTime<chrono::Utc>,
}

/// JSON shape returned by `GET /api/attacks/top`.
#[derive(Clone, Debug, Serialize)]
pub struct TopResponse {
    pub window_seconds: u32,
    pub limit: u32,
    pub attackers: Vec<Attacker>,
}

/// Single retained event. Carries everything any current endpoint
/// might want — detector name (distribution), identifier + risk +
/// ts (top attackers).
#[derive(Clone, Debug)]
struct AttackEntry {
    when: Instant,
    ts: chrono::DateTime<chrono::Utc>,
    detector: String,
    identifier: String,
    risk: u32,
}

#[derive(Default)]
struct AggregatorState {
    /// Retained `AttackEntry`s in the broadest documented window
    /// (`RETENTION`); oldest entries are dropped on each record.
    events: VecDeque<AttackEntry>,
}

/// Sliding-window detector-distribution aggregator. Cheap to share
/// (`Arc<Mutex<…>>`) between the audit subscriber task and the
/// HTTP handler.
#[derive(Clone, Default)]
pub struct AttacksAggregator {
    inner: Arc<Mutex<AggregatorState>>,
}

impl AttacksAggregator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest one audit event. Non-`Detection` events are ignored —
    /// admin / access / system events don't represent attacks.
    pub fn record(&self, ev: &AuditEvent) {
        if !matches!(ev.class, AuditClass::Detection) {
            return;
        }
        let entry = AttackEntry {
            when: Instant::now(),
            ts: ev.ts,
            detector: detector_name(ev),
            identifier: attacker_identifier(ev),
            risk: ev.risk_score.unwrap_or(0),
        };

        let mut state = self.inner.lock().expect("attacks mutex poisoned");
        let now = entry.when;
        state.events.push_back(entry);
        // Drop anything outside the retention window.
        while let Some(front) = state.events.front() {
            if now.duration_since(front.when) > RETENTION {
                state.events.pop_front();
            } else {
                break;
            }
        }
    }

    /// Compute the distribution for the requested window. `window_seconds`
    /// is clamped to `[1, RETENTION_SECS]` (the broadest retention).
    pub fn distribution(&self, window_seconds: u32) -> DistributionResponse {
        let retention_secs = RETENTION.as_secs() as u32;
        let window = window_seconds.clamp(1, retention_secs);
        let window_dur = Duration::from_secs(u64::from(window));

        let state = self.inner.lock().expect("attacks mutex poisoned");
        let now = Instant::now();
        let mut counts: HashMap<String, u64> = HashMap::new();
        // Walk newest-first; stop when out of window.
        for entry in state.events.iter().rev() {
            if now.duration_since(entry.when) > window_dur {
                break;
            }
            *counts.entry(entry.detector.clone()).or_insert(0) += 1;
        }

        let total: u64 = counts.values().sum();
        let mut categories: Vec<Category> = counts
            .into_iter()
            .map(|(name, count)| {
                // Round to 1 decimal so the chart legend is readable.
                let pct = if total > 0 {
                    let raw = (count as f64) * 100.0 / (total as f64);
                    (raw * 10.0).round() / 10.0
                } else {
                    0.0
                };
                Category { name, count, pct }
            })
            .collect();
        // Sort by count desc, then name asc for stable output.
        categories.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));

        DistributionResponse {
            window_seconds: window,
            categories,
        }
    }

    /// Compute the top-N attackers for the requested window.
    /// `limit` is clamped to `[1, 100]`. `window_seconds` is clamped
    /// the same way as [`distribution`].
    pub fn top(&self, window_seconds: u32, limit: u32) -> TopResponse {
        let retention_secs = RETENTION.as_secs() as u32;
        let window = window_seconds.clamp(1, retention_secs);
        let limit = limit.clamp(1, 100);
        let window_dur = Duration::from_secs(u64::from(window));

        // Per-attacker accumulator. Keyed by identifier; values track
        // hits, distinct categories, max risk, latest ts.
        struct Acc {
            hits: u64,
            categories: std::collections::BTreeSet<String>,
            risk: u32,
            last_seen: chrono::DateTime<chrono::Utc>,
        }

        let state = self.inner.lock().expect("attacks mutex poisoned");
        let now = Instant::now();
        let mut acc: HashMap<String, Acc> = HashMap::new();
        for entry in state.events.iter().rev() {
            if now.duration_since(entry.when) > window_dur {
                break;
            }
            let slot = acc.entry(entry.identifier.clone()).or_insert(Acc {
                hits: 0,
                categories: std::collections::BTreeSet::new(),
                risk: 0,
                last_seen: entry.ts,
            });
            slot.hits = slot.hits.saturating_add(1);
            slot.categories.insert(entry.detector.clone());
            if entry.risk > slot.risk {
                slot.risk = entry.risk;
            }
            if entry.ts > slot.last_seen {
                slot.last_seen = entry.ts;
            }
        }

        let mut attackers: Vec<Attacker> = acc
            .into_iter()
            .map(|(identifier, a)| Attacker {
                identifier,
                hits: a.hits,
                categories: a.categories.into_iter().collect(),
                risk: a.risk,
                last_seen: a.last_seen,
            })
            .collect();
        // Sort by hits desc, then identifier asc for stable output.
        attackers.sort_by(|a, b| {
            b.hits
                .cmp(&a.hits)
                .then_with(|| a.identifier.cmp(&b.identifier))
        });
        attackers.truncate(limit as usize);

        TopResponse {
            window_seconds: window,
            limit,
            attackers,
        }
    }
}

/// Resolve the attacker identifier for an audit event. Prefers a
/// public client IP; falls back to `fp:<ja4>` (or `fp:<fingerprint>`)
/// when the IP is private/loopback/empty so a NAT'd benchmark run
/// doesn't collapse into one giant "attacker".
fn attacker_identifier(ev: &AuditEvent) -> String {
    let ip = ev.client_ip.trim();
    if !ip.is_empty() && !is_rfc1918_or_loopback(ip) {
        return ip.to_string();
    }
    if let Some(fp) = fingerprint_from_fields(&ev.fields) {
        return format!("fp:{fp}");
    }
    if !ip.is_empty() {
        return ip.to_string();
    }
    "unknown".to_string()
}

fn fingerprint_from_fields(fields: &serde_json::Value) -> Option<String> {
    for key in ["ja4", "fingerprint"] {
        if let Some(s) = fields.get(key).and_then(|v| v.as_str()) {
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    None
}

/// `true` for IPs that shouldn't anchor a top-attacker bucket on
/// their own — RFC 1918 private space, loopback, link-local,
/// unspecified, IPv6 ULAs / link-local. Unparseable strings are
/// treated as "bouncy" (return `true`) so the caller falls back to
/// the fingerprint identifier.
fn is_rfc1918_or_loopback(ip: &str) -> bool {
    use std::net::IpAddr;
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
        }
        Ok(IpAddr::V6(v6)) => {
            if v6.is_loopback() || v6.is_unspecified() {
                return true;
            }
            // Unique local fc00::/7
            let octets = v6.octets();
            if octets[0] & 0xfe == 0xfc {
                return true;
            }
            // Link-local fe80::/10
            v6.segments()[0] & 0xffc0 == 0xfe80
        }
        Err(_) => true,
    }
}

/// Resolve the detector name for an audit event.
fn detector_name(ev: &AuditEvent) -> String {
    if let Some(name) = ev.fields.get("detector").and_then(|v| v.as_str()) {
        if !name.is_empty() {
            return name.to_string();
        }
    }
    if let Some(rule_id) = ev.rule_id.as_deref() {
        let prefix = rule_id.split(['-', '_', '/']).next().unwrap_or("");
        if !prefix.is_empty() {
            return prefix.to_string();
        }
    }
    "unknown".to_string()
}

/// HTTP-side wrapper. Caches the rendered JSON body for `cache_ttl`
/// (default 1 s — Tracking page polls quickly; Cache-Control headers
/// can extend client-side caching independently).
pub struct AttacksHandler {
    agg: Arc<AttacksAggregator>,
    distribution_cache: Mutex<Option<(Instant, u32, DistributionResponse)>>,
    top_cache: Mutex<Option<(Instant, u32, u32, TopResponse)>>,
    cache_ttl: Duration,
}

impl AttacksHandler {
    pub fn new(agg: Arc<AttacksAggregator>) -> Self {
        Self::with_ttl(agg, DEFAULT_CACHE_TTL)
    }

    pub fn with_ttl(agg: Arc<AttacksAggregator>, cache_ttl: Duration) -> Self {
        Self {
            agg,
            distribution_cache: Mutex::new(None),
            top_cache: Mutex::new(None),
            cache_ttl,
        }
    }

    /// Render `GET /api/attacks/distribution?window=<seconds>`. The
    /// cache is keyed on `(timestamp, window)` so a query with a
    /// different window still recomputes.
    pub fn render(&self, window_seconds: u32) -> String {
        let now = Instant::now();
        {
            let cache = self
                .distribution_cache
                .lock()
                .expect("attacks cache poisoned");
            if let Some((stamped_at, cached_window, response)) = cache.as_ref() {
                if *cached_window == window_seconds
                    && now.duration_since(*stamped_at) < self.cache_ttl
                {
                    return serde_json::to_string(response)
                        .unwrap_or_else(|_| String::from("{}"));
                }
            }
        }

        let response = self.agg.distribution(window_seconds);
        let body = serde_json::to_string(&response).unwrap_or_else(|_| String::from("{}"));
        let mut cache = self
            .distribution_cache
            .lock()
            .expect("attacks cache poisoned");
        *cache = Some((now, window_seconds, response));
        body
    }

    /// Render `GET /api/attacks/top?window=<seconds>&limit=<n>`.
    /// Cache keyed on `(timestamp, window, limit)`.
    pub fn render_top(&self, window_seconds: u32, limit: u32) -> String {
        let now = Instant::now();
        {
            let cache = self.top_cache.lock().expect("attacks cache poisoned");
            if let Some((stamped_at, cached_window, cached_limit, response)) = cache.as_ref() {
                if *cached_window == window_seconds
                    && *cached_limit == limit
                    && now.duration_since(*stamped_at) < self.cache_ttl
                {
                    return serde_json::to_string(response)
                        .unwrap_or_else(|_| String::from("{}"));
                }
            }
        }

        let response = self.agg.top(window_seconds, limit);
        let body = serde_json::to_string(&response).unwrap_or_else(|_| String::from("{}"));
        let mut cache = self.top_cache.lock().expect("attacks cache poisoned");
        *cache = Some((now, window_seconds, limit, response));
        body
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det_event(detector: Option<&str>, rule_id: Option<&str>) -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "test".into(),
            class: AuditClass::Detection,
            tenant_id: None,
            tier: None,
            action: "block".into(),
            reason: "test".into(),
            client_ip: "1.1.1.1".into(),
            route_id: None,
            rule_id: rule_id.map(|s| s.into()),
            risk_score: Some(80),
            fields: match detector {
                Some(name) => serde_json::json!({"detector": name}),
                None => serde_json::Value::Null,
            },
        }
    }

    fn admin_event() -> AuditEvent {
        let mut ev = det_event(Some("sqli"), None);
        ev.class = AuditClass::Admin;
        ev
    }

    #[test]
    fn empty_aggregator_returns_no_categories() {
        let agg = AttacksAggregator::new();
        let r = agg.distribution(900);
        assert_eq!(r.window_seconds, 900);
        assert!(r.categories.is_empty());
    }

    #[test]
    fn detector_name_extracted_from_fields() {
        let ev = det_event(Some("sqli"), None);
        assert_eq!(detector_name(&ev), "sqli");
    }

    #[test]
    fn detector_name_falls_back_to_rule_id_prefix() {
        // No fields.detector → split on '-' / '_' / '/'.
        let cases = &[
            ("sqli-12", "sqli"),
            ("xss_owasp_3", "xss"),
            ("recon/probe-1", "recon"),
            ("ssrf", "ssrf"),
        ];
        for (rule_id, expected) in cases {
            let ev = det_event(None, Some(rule_id));
            assert_eq!(detector_name(&ev), *expected, "rule_id={rule_id}");
        }
    }

    #[test]
    fn detector_name_falls_back_to_unknown() {
        let ev = det_event(None, None);
        assert_eq!(detector_name(&ev), "unknown");
    }

    #[test]
    fn fields_detector_wins_over_rule_id() {
        // If both are present, fields.detector takes precedence —
        // detectors set their own canonical name.
        let ev = det_event(Some("sqli"), Some("rule-2003"));
        assert_eq!(detector_name(&ev), "sqli");
    }

    #[test]
    fn record_ignores_non_detection_events() {
        // Admin / access / system events don't represent attacks
        // and must not pollute the distribution.
        let agg = AttacksAggregator::new();
        agg.record(&admin_event());
        agg.record(&admin_event());
        let r = agg.distribution(900);
        assert!(r.categories.is_empty());
    }

    #[test]
    fn counts_sum_to_total_events_recorded() {
        let agg = AttacksAggregator::new();
        for _ in 0..5 {
            agg.record(&det_event(Some("sqli"), None));
        }
        for _ in 0..3 {
            agg.record(&det_event(Some("xss"), None));
        }
        for _ in 0..2 {
            agg.record(&det_event(Some("ssrf"), None));
        }
        let r = agg.distribution(900);
        let total: u64 = r.categories.iter().map(|c| c.count).sum();
        assert_eq!(total, 10);
    }

    #[test]
    fn percentages_sum_to_approximately_100() {
        let agg = AttacksAggregator::new();
        for name in ["sqli", "xss", "ssrf", "path", "cmdi", "lfi"] {
            for _ in 0..7 {
                agg.record(&det_event(Some(name), None));
            }
        }
        let r = agg.distribution(900);
        let total_pct: f64 = r.categories.iter().map(|c| c.pct).sum();
        assert!(
            (total_pct - 100.0).abs() < 0.5,
            "percentages should sum to ~100, got {total_pct}"
        );
    }

    #[test]
    fn categories_sorted_by_count_desc() {
        let agg = AttacksAggregator::new();
        for _ in 0..3 {
            agg.record(&det_event(Some("xss"), None));
        }
        for _ in 0..7 {
            agg.record(&det_event(Some("sqli"), None));
        }
        for _ in 0..1 {
            agg.record(&det_event(Some("ssrf"), None));
        }
        let r = agg.distribution(900);
        let counts: Vec<u64> = r.categories.iter().map(|c| c.count).collect();
        assert_eq!(counts, vec![7, 3, 1]);
        assert_eq!(r.categories[0].name, "sqli");
    }

    #[test]
    fn distinct_detectors_each_get_their_own_category() {
        let agg = AttacksAggregator::new();
        agg.record(&det_event(Some("sqli"), None));
        agg.record(&det_event(Some("xss"), None));
        agg.record(&det_event(Some("ssrf"), None));
        let r = agg.distribution(900);
        assert_eq!(r.categories.len(), 3);
    }

    #[test]
    fn response_serializes_to_documented_shape() {
        let agg = AttacksAggregator::new();
        agg.record(&det_event(Some("sqli"), None));
        let r = agg.distribution(900);
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        let obj = json.as_object().expect("top-level object");
        for key in ["window_seconds", "categories"] {
            assert!(obj.contains_key(key), "response missing {key}");
        }
        let cats = obj["categories"].as_array().expect("categories array");
        let first = cats[0].as_object().expect("category object");
        for key in ["name", "count", "pct"] {
            assert!(first.contains_key(key), "category missing {key}");
        }
    }

    #[test]
    fn window_clamped_to_retention() {
        // Queries beyond retention are clamped to RETENTION (=900s).
        let agg = AttacksAggregator::new();
        agg.record(&det_event(Some("sqli"), None));
        let r = agg.distribution(7200);
        assert!(
            r.window_seconds <= 900,
            "window must clamp to retention, got {}",
            r.window_seconds
        );
    }

    #[test]
    fn handler_caches_response_within_ttl() {
        let agg = Arc::new(AttacksAggregator::new());
        agg.record(&det_event(Some("sqli"), None));
        let h = AttacksHandler::with_ttl(Arc::clone(&agg), Duration::from_secs(1));
        let first = h.render(900);
        // Mutate the aggregator; cached response should not reflect it.
        agg.record(&det_event(Some("xss"), None));
        let second = h.render(900);
        assert_eq!(first, second);
    }

    #[test]
    fn handler_recomputes_for_different_window() {
        // Cache is keyed on window; a different window-size query
        // must NOT return the cached response from a previous window.
        let agg = Arc::new(AttacksAggregator::new());
        agg.record(&det_event(Some("sqli"), None));
        let h = AttacksHandler::with_ttl(Arc::clone(&agg), Duration::from_secs(1));
        let r1 = h.render(900);
        let r2 = h.render(60);
        // Bodies should both be valid JSON; window_seconds field differs.
        let v1: serde_json::Value = serde_json::from_str(&r1).unwrap();
        let v2: serde_json::Value = serde_json::from_str(&r2).unwrap();
        assert_eq!(v1["window_seconds"].as_u64(), Some(900));
        assert_eq!(v2["window_seconds"].as_u64(), Some(60));
    }

    // ---------- D-M2-T2.5: /api/attacks/top -----------------------------

    fn det_event_full(
        ip: &str,
        detector: Option<&str>,
        ja4: Option<&str>,
        risk: u32,
    ) -> AuditEvent {
        let mut fields = serde_json::Map::new();
        if let Some(d) = detector {
            fields.insert("detector".into(), serde_json::Value::String(d.into()));
        }
        if let Some(f) = ja4 {
            fields.insert("ja4".into(), serde_json::Value::String(f.into()));
        }
        AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "test".into(),
            class: AuditClass::Detection,
            tenant_id: None,
            tier: None,
            action: "block".into(),
            reason: "test".into(),
            client_ip: ip.into(),
            route_id: None,
            rule_id: None,
            risk_score: Some(risk),
            fields: serde_json::Value::Object(fields),
        }
    }

    #[test]
    fn rfc1918_check_recognises_private_ips() {
        for ip in &[
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "fd00::1",
        ] {
            assert!(is_rfc1918_or_loopback(ip), "{ip} should be private/loopback");
        }
    }

    #[test]
    fn rfc1918_check_admits_public_ips() {
        for ip in &["1.1.1.1", "8.8.8.8", "203.0.113.42", "2001:4860::1"] {
            assert!(!is_rfc1918_or_loopback(ip), "{ip} should be public");
        }
    }

    #[test]
    fn attacker_identifier_uses_public_ip() {
        let ev = det_event_full("8.8.8.8", Some("sqli"), Some("ja4-abc"), 80);
        assert_eq!(attacker_identifier(&ev), "8.8.8.8");
    }

    #[test]
    fn attacker_identifier_falls_back_to_ja4_when_ip_is_private() {
        let ev = det_event_full("10.0.0.1", Some("sqli"), Some("ja4-abc"), 80);
        assert_eq!(attacker_identifier(&ev), "fp:ja4-abc");
    }

    #[test]
    fn attacker_identifier_falls_back_to_ja4_when_ip_is_empty() {
        let ev = det_event_full("", Some("sqli"), Some("ja4-abc"), 80);
        assert_eq!(attacker_identifier(&ev), "fp:ja4-abc");
    }

    #[test]
    fn attacker_identifier_unknown_when_no_ip_or_fp() {
        let ev = det_event_full("", Some("sqli"), None, 0);
        assert_eq!(attacker_identifier(&ev), "unknown");
    }

    #[test]
    fn top_empty_aggregator_returns_no_attackers() {
        let agg = AttacksAggregator::new();
        let r = agg.top(900, 5);
        assert_eq!(r.window_seconds, 900);
        assert_eq!(r.limit, 5);
        assert!(r.attackers.is_empty());
    }

    #[test]
    fn top_groups_hits_per_attacker() {
        let agg = AttacksAggregator::new();
        for _ in 0..3 {
            agg.record(&det_event_full("8.8.8.8", Some("sqli"), None, 80));
        }
        for _ in 0..5 {
            agg.record(&det_event_full("1.1.1.1", Some("xss"), None, 60));
        }
        let r = agg.top(900, 5);
        assert_eq!(r.attackers.len(), 2);
        let total_hits: u64 = r.attackers.iter().map(|a| a.hits).sum();
        assert_eq!(total_hits, 8);
    }

    #[test]
    fn top_sorted_by_hits_descending() {
        let agg = AttacksAggregator::new();
        for _ in 0..2 {
            agg.record(&det_event_full("8.8.8.8", Some("sqli"), None, 80));
        }
        for _ in 0..7 {
            agg.record(&det_event_full("1.1.1.1", Some("xss"), None, 60));
        }
        for _ in 0..5 {
            agg.record(&det_event_full("4.4.4.4", Some("ssrf"), None, 50));
        }
        let r = agg.top(900, 5);
        let hits: Vec<u64> = r.attackers.iter().map(|a| a.hits).collect();
        assert_eq!(hits, vec![7, 5, 2]);
        assert_eq!(r.attackers[0].identifier, "1.1.1.1");
    }

    #[test]
    fn top_limit_caps_attacker_count() {
        let agg = AttacksAggregator::new();
        for ip in &["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"] {
            agg.record(&det_event_full(ip, Some("sqli"), None, 80));
        }
        let r = agg.top(900, 3);
        assert_eq!(r.attackers.len(), 3);
    }

    #[test]
    fn top_collects_distinct_categories_per_attacker() {
        let agg = AttacksAggregator::new();
        agg.record(&det_event_full("8.8.8.8", Some("sqli"), None, 80));
        agg.record(&det_event_full("8.8.8.8", Some("xss"), None, 70));
        agg.record(&det_event_full("8.8.8.8", Some("sqli"), None, 90)); // duplicate
        let r = agg.top(900, 5);
        assert_eq!(r.attackers.len(), 1);
        let cats = &r.attackers[0].categories;
        assert_eq!(cats.len(), 2, "expected distinct categories, got {cats:?}");
        // Sorted alphabetically for stability.
        assert_eq!(cats, &vec!["sqli".to_string(), "xss".to_string()]);
    }

    #[test]
    fn top_reports_max_risk_per_attacker() {
        let agg = AttacksAggregator::new();
        agg.record(&det_event_full("8.8.8.8", Some("sqli"), None, 50));
        agg.record(&det_event_full("8.8.8.8", Some("sqli"), None, 90));
        agg.record(&det_event_full("8.8.8.8", Some("sqli"), None, 70));
        let r = agg.top(900, 5);
        assert_eq!(r.attackers[0].risk, 90);
    }

    #[test]
    fn top_response_serializes_to_documented_shape() {
        let agg = AttacksAggregator::new();
        agg.record(&det_event_full("8.8.8.8", Some("sqli"), None, 80));
        let r = agg.top(900, 5);
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        let obj = json.as_object().expect("top object");
        for key in ["window_seconds", "limit", "attackers"] {
            assert!(obj.contains_key(key), "top response missing {key}");
        }
        let attackers = obj["attackers"].as_array().unwrap();
        let a = attackers[0].as_object().unwrap();
        for key in ["identifier", "hits", "categories", "risk", "last_seen"] {
            assert!(a.contains_key(key), "attacker missing {key}");
        }
    }

    #[test]
    fn top_limit_clamped_to_one() {
        // limit=0 must collapse to 1, not panic on Vec::truncate(0).
        let agg = AttacksAggregator::new();
        agg.record(&det_event_full("8.8.8.8", Some("sqli"), None, 80));
        let r = agg.top(900, 0);
        assert_eq!(r.limit, 1);
        assert_eq!(r.attackers.len(), 1);
    }

    #[test]
    fn top_handler_caches_response_per_window_and_limit() {
        let agg = Arc::new(AttacksAggregator::new());
        agg.record(&det_event_full("8.8.8.8", Some("sqli"), None, 80));
        let h = AttacksHandler::with_ttl(Arc::clone(&agg), Duration::from_secs(1));
        let first = h.render_top(900, 5);
        agg.record(&det_event_full("1.1.1.1", Some("xss"), None, 60));
        let second = h.render_top(900, 5);
        assert_eq!(first, second, "cache hit should return identical bytes");

        // Different limit → cache miss → recomputes.
        let third = h.render_top(900, 10);
        let v: serde_json::Value = serde_json::from_str(&third).unwrap();
        assert_eq!(v["limit"].as_u64(), Some(10));
    }

    #[test]
    fn top_and_distribution_caches_are_independent() {
        let agg = Arc::new(AttacksAggregator::new());
        agg.record(&det_event_full("8.8.8.8", Some("sqli"), None, 80));
        let h = AttacksHandler::with_ttl(Arc::clone(&agg), Duration::from_secs(1));
        let dist = h.render(900);
        let top = h.render_top(900, 5);
        let v_dist: serde_json::Value = serde_json::from_str(&dist).unwrap();
        let v_top: serde_json::Value = serde_json::from_str(&top).unwrap();
        assert!(v_dist.get("categories").is_some());
        assert!(v_top.get("attackers").is_some());
    }
}
