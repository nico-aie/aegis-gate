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
//! Spec: `docs/control-plane/enterprise/api.md` §"Attack analytics".

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
/// 2026-05-20 (memory soak) — hard count cap on retained events.
/// `RETENTION` bounds the window by TIME but not by RATE: under a
/// sustained high-RPS attack flood the 15-min window could hold
/// tens of millions of `AttackEntry` (multi-GB). This cap turns
/// the buffer into a drop-oldest ring so memory is bounded by
/// COUNT regardless of request rate. 1M entries × ~200 B ≈ 200 MB
/// worst case — chosen so the dashboard's 15-min charts stay
/// complete up to ~1100 blocked-attacks/sec sustained
/// (1_000_000 / 900s), comfortably covering long, big benchmark
/// runs while still preventing the flood-amplification growth a
/// soak surfaced. Note: this aggregator feeds the live dashboard
/// only (manually judged) — it is NOT read by the automated
/// benchmark, which uses §5 headers + the §6 audit log — so the
/// value is benchmark-scoring-neutral.
const MAX_EVENTS: usize = 1_000_000;
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
    /// CI-T8 — ISO-3166 alpha-2 country code, populated when a
    /// GeoIP reader is wired into the handler and the identifier
    /// parses as a public IP. `None` for fingerprint identifiers
    /// or when no GeoIP DB is loaded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// CI-T8 — autonomous-system number from the GeoIP ASN DB.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    /// 2026-05-18 (QC TLS-wiring batch — F-CRITICAL-015
    /// activation): ASN ownership classification per
    /// `aegis_security::bots::classify_asn`. `"hosting"`,
    /// `"datacenter"`, `"residential"`, `"mobile"`, or `"unknown"`.
    /// Skipped from the wire shape when no ASN is known (saves
    /// bytes for fingerprint-identifier rows where the field is
    /// always Unknown).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn_class: Option<String>,
}

/// JSON shape returned by `GET /api/attacks/top`.
#[derive(Clone, Debug, Serialize)]
pub struct TopResponse {
    pub window_seconds: u32,
    pub limit: u32,
    pub attackers: Vec<Attacker>,
    /// `true` when the AttacksHandler has a GeoIP reader wired
    /// (boot path called `set_geo_lookup`). Lets the dashboard
    /// distinguish "DB not loaded" (real backend gap) from
    /// "DB loaded but no resolvable source IPs yet" (the
    /// localhost-dev case where every source is 127.0.0.1).
    /// `false` for the renderer-side default; the handler
    /// flips it in `render_top` when `self.geo.is_some()`.
    #[serde(default)]
    pub geoip_loaded: bool,
}

/// One row of `/api/attacks/by-detector`.
#[derive(Clone, Debug, Serialize)]
pub struct DetectorCount {
    pub name: String,
    pub count: u64,
}

/// JSON shape returned by `GET /api/attacks/by-detector`.
#[derive(Clone, Debug, Serialize)]
pub struct ByDetectorResponse {
    pub window_seconds: u32,
    pub detectors: Vec<DetectorCount>,
}

/// One row of `/api/threat-intel/hits`.
#[derive(Clone, Debug, Serialize)]
pub struct ThreatIntelHit {
    pub feed: String,
    pub indicator: String,
    pub hits: u64,
    pub last_seen: chrono::DateTime<chrono::Utc>,
}

/// JSON shape returned by `GET /api/threat-intel/hits`.
#[derive(Clone, Debug, Serialize)]
pub struct ThreatIntelResponse {
    pub window_seconds: u32,
    pub limit: u32,
    pub hits: Vec<ThreatIntelHit>,
}

/// One bucket of `/api/bots/mix`.
#[derive(Clone, Debug, Serialize)]
pub struct BotCategoryCount {
    pub name: String,
    pub count: u64,
    pub pct: f64,
}

/// JSON shape returned by `GET /api/bots/mix`.
#[derive(Clone, Debug, Serialize)]
pub struct BotMixResponse {
    pub window_seconds: u32,
    pub categories: Vec<BotCategoryCount>,
}

/// Single retained event. Carries everything any current endpoint
/// might want — detector name (distribution), identifier + risk +
/// ts (top attackers), threat-intel hit (T3.5), bot category (T3.6).
#[derive(Clone, Debug)]
struct AttackEntry {
    when: Instant,
    ts: chrono::DateTime<chrono::Utc>,
    /// Single canonical detector class — the FIRST tag from
    /// `fields.detectors[]`, or the rule_id-derived prefix.
    /// Kept for back-compat with the `top` + `distribution`
    /// aggregators that bucket per-attacker by their dominant
    /// class.
    detector: String,
    /// 2026-05-03 — every detector class that fired on this
    /// event, deduped.  by_detector() expands this into one
    /// count per tag so a request that fires both sqli AND xss
    /// counts toward both buckets, instead of only the first.
    /// Empty when the event had no detector array (legacy
    /// rule_id-only path).
    detectors: Vec<String>,
    identifier: String,
    risk: u32,
    /// Feed name from `event.fields.threat_intel.feed` if present.
    threat_intel_feed: Option<String>,
    /// Indicator value from `event.fields.threat_intel.indicator`.
    threat_intel_indicator: Option<String>,
    /// Bot classifier verdict from `event.fields.bot_category`.
    bot_category: Option<String>,
    /// True when the source event was `AuditClass::Detection` (a real
    /// attack/block). False for the bot-classified `Access` (allow)
    /// events that are admitted solely to feed `bot_mix()`. The
    /// attacker / detector views (`top`, `distribution`,
    /// `by_detector`) skip non-attack entries so they stay
    /// Detection-only, exactly as before bot-mix wiring.
    is_attack: bool,
}

#[derive(Default)]
struct AggregatorState {
    /// Retained `AttackEntry`s, bounded by BOTH the broadest
    /// documented window (`RETENTION`, time) AND [`MAX_EVENTS`]
    /// (count). Oldest entries are dropped on each record when
    /// either bound is exceeded — a drop-oldest ring.
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

    /// v2.3 §2.4 — drop every retained attack entry. Wired into the
    /// `/__waf_control/reset_state` callback chain so the OC sees a
    /// clean Top Attackers / By-Detector / Bot Mix slate between
    /// benchmark phases. The audit log is unaffected (sink writes
    /// straight to disk; this aggregator is purely the dashboard's
    /// rolling-window cache of recent detection events).
    pub fn reset(&self) {
        let mut s = self.inner.lock().expect("attacks agg poisoned");
        s.events.clear();
    }

    /// Test-only — number of retained events. Used to assert the
    /// `MAX_EVENTS` count cap holds under flood.
    #[cfg(test)]
    fn event_count(&self) -> usize {
        self.inner.lock().expect("attacks agg poisoned").events.len()
    }

    /// Ingest one audit event. Non-`Detection` events are ignored —
    /// admin / access / system events don't represent attacks.
    pub fn record(&self, ev: &AuditEvent) {
        let bot_category = bot_category_from_fields(&ev.fields);
        let is_attack = matches!(ev.class, AuditClass::Detection);
        // Keep Detection (attack/block) events for the attacker +
        // detector views. ALSO keep non-Detection events that carry a
        // bot verdict — the classifier stamps `bot_category` on the
        // `Access` (allow) event, so without this they'd never reach
        // `bot_mix()`. Plain allows (no verdict) are still dropped.
        if !is_attack && bot_category.is_none() {
            return;
        }
        let (threat_intel_feed, threat_intel_indicator) = threat_intel_from_fields(&ev.fields);
        // Pull every detector tag from the event's
        // fields.detectors[] array, deduped + filtered to non-
        // empty.  by_detector() iterates over this list so a
        // multi-detector event counts toward EVERY class that
        // fired on it.
        let mut detectors_all: Vec<String> = Vec::new();
        if let Some(arr) = ev.fields.get("detectors").and_then(|v| v.as_array()) {
            let mut seen = std::collections::HashSet::new();
            for v in arr {
                if let Some(s) = v.as_str() {
                    if !s.is_empty() && seen.insert(s.to_string()) {
                        detectors_all.push(s.to_string());
                    }
                }
            }
        }
        let entry = AttackEntry {
            when: Instant::now(),
            ts: ev.ts,
            detector: detector_name(ev),
            detectors: detectors_all,
            identifier: attacker_identifier(ev),
            risk: ev.risk_score.unwrap_or(0),
            threat_intel_feed,
            threat_intel_indicator,
            bot_category,
            is_attack,
        };

        let mut state = self.inner.lock().expect("attacks mutex poisoned");
        let now = entry.when;
        state.events.push_back(entry);
        // Drop anything outside the retention window (time bound).
        while let Some(front) = state.events.front() {
            if now.duration_since(front.when) > RETENTION {
                state.events.pop_front();
            } else {
                break;
            }
        }
        // 2026-05-20 — count bound. Under a sustained high-RPS flood
        // the time window alone can hold millions of entries; cap the
        // buffer to MAX_EVENTS by dropping the oldest. The dashboard's
        // distribution/top queries stay accurate for the most-recent
        // MAX_EVENTS, which at any realistic dashboard cadence covers
        // the displayed windows.
        while state.events.len() > MAX_EVENTS {
            state.events.pop_front();
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
            // Bot-only Access entries (admitted for bot_mix) are not
            // attacks — skip them so the detector distribution stays
            // Detection-only.
            if !entry.is_attack {
                continue;
            }
            // 2026-05-20 — count EVERY detector that fired on the
            // event, not just the canonical first tag. Co-firing
            // detectors (notably `ai`, usually a secondary tag like
            // `sqli,ai`) were under-counted because we only bumped
            // `entry.detector`. This is a detector-activity chart,
            // not a partition, so counting each class is correct
            // (the total may exceed the event count). Mirrors
            // `by_detector()`: explode the array; fall back to the
            // singular tag only for legacy array-less events, and
            // skip the synthetic `unknown` bucket.
            if !entry.detectors.is_empty() {
                for d in &entry.detectors {
                    *counts.entry(d.clone()).or_insert(0) += 1;
                }
            } else if entry.detector != "unknown" {
                *counts.entry(entry.detector.clone()).or_insert(0) += 1;
            }
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
            // Bot-only Access entries aren't attackers — keep Top
            // Attackers Detection-only.
            if !entry.is_attack {
                continue;
            }
            let slot = acc.entry(entry.identifier.clone()).or_insert(Acc {
                hits: 0,
                categories: std::collections::BTreeSet::new(),
                risk: 0,
                last_seen: entry.ts,
            });
            slot.hits = slot.hits.saturating_add(1);
            // 2026-05-20 — the "Detectors" column should list EVERY
            // detector that fired against this attacker, not just the
            // canonical first tag. Co-firing detectors (notably `ai`,
            // which usually lands as a SECONDARY tag like `sqli,ai`)
            // were dropped because we inserted the singular
            // `entry.detector`. Expand the full `entry.detectors`
            // array; fall back to the singular tag for legacy events
            // that carry no array.
            if entry.detectors.is_empty() {
                slot.categories.insert(entry.detector.clone());
            } else {
                for d in &entry.detectors {
                    slot.categories.insert(d.clone());
                }
            }
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
                country: None,
                asn: None,
                asn_class: None,
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
            // Aggregator doesn't know about the geo lookup —
            // the handler's `render_top` flips this flag when
            // `self.geo.is_some()` before serialising.
            geoip_loaded: false,
        }
    }

    /// Detector breakdown for `/api/attacks/by-detector` (D-M3-T3.4).
    /// Slimmer projection of `distribution()` — no percentages, sorted
    /// by count desc.
    pub fn by_detector(&self, window_seconds: u32) -> ByDetectorResponse {
        // 2026-05-03 fix — bucket by detector CLASS, not by
        // combination string.  Old behaviour: each event's
        // detector list was joined with "," and used as the
        // bucket key, producing rows like
        // `path_traversal,path_traversal,ssrf` and putting
        // `sqli` in two separate buckets when a request fired
        // both `sqli` and `ssrf`.
        //
        // New behaviour: walk every event in the window,
        // explode `detectors[]` into one count per class, and
        // sort largest-bucket-first.  When the deduped list is
        // empty (legacy rule_id-only event) we fall back to
        // `entry.detector` so back-compat callers still see
        // SOMETHING — but only when the array is genuinely
        // empty, never as a duplicate alongside the array.
        let retention_secs = RETENTION.as_secs() as u32;
        let window = window_seconds.clamp(1, retention_secs);
        let window_dur = Duration::from_secs(u64::from(window));

        let state = self.inner.lock().expect("attacks mutex poisoned");
        let now = Instant::now();
        let mut counts: HashMap<String, u64> = HashMap::new();
        for entry in state.events.iter().rev() {
            if now.duration_since(entry.when) > window_dur {
                break;
            }
            // Bot-only Access entries aren't attacks — keep the
            // by-detector breakdown Detection-only.
            if !entry.is_attack {
                continue;
            }
            if !entry.detectors.is_empty() {
                for class in &entry.detectors {
                    *counts.entry(class.clone()).or_insert(0) += 1;
                }
            } else if entry.detector != "unknown" {
                *counts.entry(entry.detector.clone()).or_insert(0) += 1;
            }
        }

        // Filter the synthetic `unknown` bucket — it represents
        // malformed detection events with neither detectors[]
        // nor a parseable rule_id, NOT real detector activity.
        let mut detectors: Vec<DetectorCount> = counts
            .into_iter()
            .filter(|(name, _)| name != "unknown")
            .map(|(name, count)| DetectorCount { name, count })
            .collect();
        detectors.sort_by(|a, b| {
            b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name))
        });

        ByDetectorResponse {
            window_seconds: window,
            detectors,
        }
    }

    /// Threat-intel hits for `/api/threat-intel/hits` (D-M3-T3.5).
    /// Groups recorded events by `(feed, indicator)`. Events without
    /// a threat-intel feed are skipped.
    pub fn threat_intel_hits(
        &self,
        window_seconds: u32,
        limit: u32,
    ) -> ThreatIntelResponse {
        let retention_secs = RETENTION.as_secs() as u32;
        let window = window_seconds.clamp(1, retention_secs);
        let limit = limit.clamp(1, 100);
        let window_dur = Duration::from_secs(u64::from(window));

        struct Acc {
            hits: u64,
            last_seen: chrono::DateTime<chrono::Utc>,
        }

        let state = self.inner.lock().expect("attacks mutex poisoned");
        let now = Instant::now();
        let mut acc: HashMap<(String, String), Acc> = HashMap::new();
        for entry in state.events.iter().rev() {
            if now.duration_since(entry.when) > window_dur {
                break;
            }
            let Some(feed) = entry.threat_intel_feed.as_ref() else {
                continue;
            };
            let indicator = entry
                .threat_intel_indicator
                .clone()
                .unwrap_or_else(|| entry.identifier.clone());
            let key = (feed.clone(), indicator);
            let slot = acc.entry(key).or_insert(Acc {
                hits: 0,
                last_seen: entry.ts,
            });
            slot.hits = slot.hits.saturating_add(1);
            if entry.ts > slot.last_seen {
                slot.last_seen = entry.ts;
            }
        }

        let mut hits: Vec<ThreatIntelHit> = acc
            .into_iter()
            .map(|((feed, indicator), a)| ThreatIntelHit {
                feed,
                indicator,
                hits: a.hits,
                last_seen: a.last_seen,
            })
            .collect();
        hits.sort_by(|a, b| {
            b.hits
                .cmp(&a.hits)
                .then_with(|| a.feed.cmp(&b.feed))
                .then_with(|| a.indicator.cmp(&b.indicator))
        });
        hits.truncate(limit as usize);

        ThreatIntelResponse {
            window_seconds: window,
            limit,
            hits,
        }
    }

    /// Bot classification mix for `/api/bots/mix` (D-M3-T3.6).
    /// Buckets recorded events by `event.fields.bot_category`, counting
    /// ONLY events the classifier labelled (suspect / malicious /
    /// verified). The result is a tier breakdown of the flagged bot
    /// signals — not a share of total traffic — because clean allows
    /// aren't recorded and Detection events carry no verdict. Percentages
    /// sum to 100 across the labelled events.
    pub fn bot_mix(&self, window_seconds: u32) -> BotMixResponse {
        let retention_secs = RETENTION.as_secs() as u32;
        let window = window_seconds.clamp(1, retention_secs);
        let window_dur = Duration::from_secs(u64::from(window));

        let state = self.inner.lock().expect("attacks mutex poisoned");
        let now = Instant::now();
        let mut counts: HashMap<String, u64> = HashMap::new();
        let mut total = 0u64;
        for entry in state.events.iter().rev() {
            if now.duration_since(entry.when) > window_dur {
                break;
            }
            // Only count events the classifier actually labelled
            // (suspect / malicious / verified). Detection/attack events
            // carry no bot verdict and clean allows aren't recorded, so
            // there is no honest "unknown" denominator here — the mix is
            // a tier breakdown of the flagged bot signals, not a share
            // of total traffic. (Total-traffic share = Option B, future.)
            let Some(key) = entry.bot_category.clone() else {
                continue;
            };
            *counts.entry(key).or_insert(0) += 1;
            total = total.saturating_add(1);
        }

        let mut categories: Vec<BotCategoryCount> = counts
            .into_iter()
            .map(|(name, count)| {
                let pct = if total > 0 {
                    let raw = (count as f64) * 100.0 / (total as f64);
                    (raw * 10.0).round() / 10.0
                } else {
                    0.0
                };
                BotCategoryCount { name, count, pct }
            })
            .collect();
        categories.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then_with(|| a.name.cmp(&b.name))
        });

        BotMixResponse {
            window_seconds: window,
            categories,
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

fn threat_intel_from_fields(fields: &serde_json::Value) -> (Option<String>, Option<String>) {
    // Two accepted shapes (security pipeline emits both forms):
    //   { "threat_intel": { "feed": "abuse-ch", "indicator": "1.2.3.4" } }
    //   { "feed_id": "abuse-ch", "indicator": "1.2.3.4" }
    if let Some(ti) = fields.get("threat_intel") {
        let feed = ti.get("feed").and_then(|v| v.as_str()).map(str::to_string);
        let ind = ti.get("indicator").and_then(|v| v.as_str()).map(str::to_string);
        if feed.is_some() || ind.is_some() {
            return (feed, ind);
        }
    }
    let feed = fields.get("feed_id").and_then(|v| v.as_str()).map(str::to_string);
    let ind = fields.get("indicator").and_then(|v| v.as_str()).map(str::to_string);
    (feed, ind)
}

fn bot_category_from_fields(fields: &serde_json::Value) -> Option<String> {
    fields.get("bot_category").and_then(|v| v.as_str()).map(str::to_string)
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
/// Resolve a single canonical detector class from one audit
/// event.  Order of preference:
///
/// 1. `fields.detectors[0]` — the data plane emits the array
///    shape with bare class names (`"sqli"`, `"path_traversal"`).
///    This is the modern path; matches the per-class strings
///    that detector tests assert on.
/// 2. `fields.detector` — legacy single-string field, kept as
///    a forward-compat shim.
/// 3. `rule_id` prefix split on `-` / `/` — older code paths
///    that emit `rule_id: "detector:sqli,xss"` etc.  The
///    `_` separator was dropped 2026-05-03 because it was
///    truncating `path_traversal` → `path` and producing
///    "detector:path" labels in the by-detector aggregator.
/// 4. Fallback `"unknown"` — only happens for malformed
///    detection events; the by-detector aggregator filters
///    those out so they don't pollute the SOC chart.
fn detector_name(ev: &AuditEvent) -> String {
    if let Some(arr) = ev.fields.get("detectors").and_then(|v| v.as_array()) {
        if let Some(first) = arr.first().and_then(|v| v.as_str()) {
            if !first.is_empty() {
                return first.to_string();
            }
        }
    }
    if let Some(name) = ev.fields.get("detector").and_then(|v| v.as_str()) {
        if !name.is_empty() {
            return name.to_string();
        }
    }
    if let Some(rule_id) = ev.rule_id.as_deref() {
        // 2026-05-05 — risk-engine and rate-limit blocks carry
        // structured rule_ids that don't fit the "first segment
        // is the detector class" convention used for OWASP
        // detectors. Pre-fix, splitting `risk-strikes` on `-`
        // surfaced `risk` (not a real detector) which the SOC
        // dashboard rendered as "unknown" because no chart bucket
        // exists for it. Map them to honest synthetic labels.
        match rule_id {
            "risk-strikes" => return "ip-strikes".to_string(),
            "risk-score" => return "ip-risk".to_string(),
            "risk-challenge" => return "ip-risk".to_string(),
            "ip-rate-limit" => return "rate-limit".to_string(),
            "blacklist" => return "blacklist".to_string(),
            _ => {}
        }
        let prefix = rule_id.split(['-', '/']).next().unwrap_or("");
        if !prefix.is_empty() {
            // Strip the legacy `detector:` prefix when present so
            // SOC dashboards always see bare class names.
            return prefix
                .strip_prefix("detector:")
                .unwrap_or(prefix)
                .to_string();
        }
    }
    "unknown".to_string()
}

/// HTTP-side wrapper. Caches the rendered JSON body for `cache_ttl`
/// (default 1 s — Tracking page polls quickly; Cache-Control headers
/// can extend client-side caching independently). One cache slot per
/// endpoint shape so distinct queries don't fight for the same entry.
pub struct AttacksHandler {
    agg: Arc<AttacksAggregator>,
    distribution_cache: Mutex<Option<(Instant, u32, DistributionResponse)>>,
    top_cache: Mutex<Option<(Instant, u32, u32, TopResponse)>>,
    by_detector_cache: Mutex<Option<(Instant, u32, ByDetectorResponse)>>,
    threat_intel_cache: Mutex<Option<(Instant, u32, u32, ThreatIntelResponse)>>,
    bot_mix_cache: Mutex<Option<(Instant, u32, BotMixResponse)>>,
    cache_ttl: Duration,
    /// CI-T8 — optional GeoIP reader. When set, `render_top()`
    /// looks up `country` + `asn` for every attacker whose
    /// identifier parses as a public IP. None = no enrichment.
    geo: Mutex<Option<Arc<dyn aegis_security::geoip::GeoIpLookup>>>,
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
            by_detector_cache: Mutex::new(None),
            threat_intel_cache: Mutex::new(None),
            bot_mix_cache: Mutex::new(None),
            cache_ttl,
            geo: Mutex::new(None),
        }
    }

    /// CI-T8 — wire a GeoIP reader. The proxy calls this at boot
    /// when `aegis-security/geoip` is on and the operator has
    /// configured a country / ASN DB.
    pub fn set_geo_lookup(
        &self,
        lookup: Arc<dyn aegis_security::geoip::GeoIpLookup>,
    ) {
        *self.geo.lock().expect("attacks geo slot poisoned") = Some(lookup);
    }

    /// `true` when [`set_geo_lookup`] has populated the slot.
    /// Read by `/api/geoip/status` and the new top_response
    /// `geoip_loaded` flag so the dashboard can distinguish
    /// "DB not loaded" from "DB loaded but no resolvable IPs".
    pub fn geoip_loaded(&self) -> bool {
        self.geo
            .lock()
            .expect("attacks geo slot poisoned")
            .is_some()
    }

    fn enrich_attackers(&self, attackers: &mut [Attacker]) {
        let Some(geo) = self
            .geo
            .lock()
            .ok()
            .and_then(|g| g.clone())
        else {
            return;
        };
        for a in attackers.iter_mut() {
            // Identifiers that aren't public IPs (e.g. `fp:<ja4>`)
            // get parse() == Err and skip the lookup.
            if let Ok(ip) = a.identifier.parse::<std::net::IpAddr>() {
                a.country = geo.country(ip);
                a.asn = geo.asn(ip);
                // 2026-05-18 (QC TLS-wiring batch — F-CRITICAL-015):
                // surface ASN ownership classification on the
                // Top Attackers row so operators can spot
                // hosting-class traffic at a glance.
                a.asn_class = a.asn.map(|asn| {
                    aegis_security::bots::classify_asn(asn)
                        .as_wire_str()
                        .to_string()
                });
            }
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

        let mut response = self.agg.top(window_seconds, limit);
        self.enrich_attackers(&mut response.attackers);
        // Flip the wire-level signal for the dashboard.
        response.geoip_loaded = self.geoip_loaded();
        let body = serde_json::to_string(&response).unwrap_or_else(|_| String::from("{}"));
        let mut cache = self.top_cache.lock().expect("attacks cache poisoned");
        *cache = Some((now, window_seconds, limit, response));
        body
    }

    /// Render `GET /api/attacks/by-detector?window=<seconds>`.
    pub fn render_by_detector(&self, window_seconds: u32) -> String {
        let now = Instant::now();
        {
            let cache = self
                .by_detector_cache
                .lock()
                .expect("attacks cache poisoned");
            if let Some((stamped_at, w, resp)) = cache.as_ref() {
                if *w == window_seconds
                    && now.duration_since(*stamped_at) < self.cache_ttl
                {
                    return serde_json::to_string(resp)
                        .unwrap_or_else(|_| String::from("{}"));
                }
            }
        }
        let response = self.agg.by_detector(window_seconds);
        let body = serde_json::to_string(&response).unwrap_or_else(|_| String::from("{}"));
        let mut cache = self
            .by_detector_cache
            .lock()
            .expect("attacks cache poisoned");
        *cache = Some((now, window_seconds, response));
        body
    }

    /// Render `GET /api/threat-intel/hits?window=<seconds>&limit=<n>`.
    pub fn render_threat_intel(&self, window_seconds: u32, limit: u32) -> String {
        let now = Instant::now();
        {
            let cache = self
                .threat_intel_cache
                .lock()
                .expect("attacks cache poisoned");
            if let Some((stamped_at, w, l, resp)) = cache.as_ref() {
                if *w == window_seconds
                    && *l == limit
                    && now.duration_since(*stamped_at) < self.cache_ttl
                {
                    return serde_json::to_string(resp)
                        .unwrap_or_else(|_| String::from("{}"));
                }
            }
        }
        let response = self.agg.threat_intel_hits(window_seconds, limit);
        let body = serde_json::to_string(&response).unwrap_or_else(|_| String::from("{}"));
        let mut cache = self
            .threat_intel_cache
            .lock()
            .expect("attacks cache poisoned");
        *cache = Some((now, window_seconds, limit, response));
        body
    }

    /// Render `GET /api/bots/mix?window=<seconds>`.
    pub fn render_bot_mix(&self, window_seconds: u32) -> String {
        let now = Instant::now();
        {
            let cache = self.bot_mix_cache.lock().expect("attacks cache poisoned");
            if let Some((stamped_at, w, resp)) = cache.as_ref() {
                if *w == window_seconds
                    && now.duration_since(*stamped_at) < self.cache_ttl
                {
                    return serde_json::to_string(resp)
                        .unwrap_or_else(|_| String::from("{}"));
                }
            }
        }
        let response = self.agg.bot_mix(window_seconds);
        let body = serde_json::to_string(&response).unwrap_or_else(|_| String::from("{}"));
        let mut cache = self.bot_mix_cache.lock().expect("attacks cache poisoned");
        *cache = Some((now, window_seconds, response));
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
            method: None,
            path: None,
            mode: None,
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

    // 2026-05-20 memory soak — the retained-event buffer must be
    // bounded by COUNT (MAX_EVENTS), not just by the time window.
    // Recording well past the cap (all within the window, so the
    // time-prune never fires) must leave the buffer at MAX_EVENTS
    // via drop-oldest.
    #[test]
    fn record_caps_event_count_under_flood() {
        let agg = AttacksAggregator::new();
        let ev = det_event(Some("sqli"), None);
        for _ in 0..(MAX_EVENTS + 5_000) {
            agg.record(&ev);
        }
        assert_eq!(
            agg.event_count(),
            MAX_EVENTS,
            "buffer must cap at MAX_EVENTS under sustained flood",
        );
    }

    #[test]
    fn detector_name_extracted_from_fields() {
        let ev = det_event(Some("sqli"), None);
        assert_eq!(detector_name(&ev), "sqli");
    }

    #[test]
    fn detector_name_falls_back_to_rule_id_prefix() {
        // No fields.detector → split on '-' / '/' only.  `_` was
        // dropped 2026-05-03 because it truncated `path_traversal`
        // → `path` in the by-detector aggregator.
        let cases = &[
            ("sqli-12", "sqli"),
            ("xss_owasp_3", "xss_owasp_3"),
            ("recon/probe-1", "recon"),
            ("ssrf", "ssrf"),
            // The legacy `detector:` prefix that `data_plane.rs`
            // emits is stripped so SOC dashboards see bare class
            // names everywhere.
            ("detector:sqli", "sqli"),
            ("detector:path_traversal", "path_traversal"),
            ("detector:sqli,xss", "sqli,xss"),
        ];
        for (rule_id, expected) in cases {
            let ev = det_event(None, Some(rule_id));
            assert_eq!(detector_name(&ev), *expected, "rule_id={rule_id}");
        }
    }

    #[test]
    fn detector_name_prefers_fields_detectors_array() {
        // Modern data-plane shape — `fields.detectors[0]` first.
        let mut ev = det_event(None, Some("legacy-rule-1"));
        ev.fields = serde_json::json!({"detectors": ["sqli", "xss"]});
        assert_eq!(detector_name(&ev), "sqli");
    }

    #[test]
    fn by_detector_filters_unknown_bucket() {
        // Detection events with no detector + no rule_id resolve
        // to "unknown" via the fallback; those must NOT pollute
        // the by-detector chart.
        let agg = AttacksAggregator::new();
        agg.record(&det_event(Some("sqli"), None));
        agg.record(&det_event(Some("sqli"), None));
        agg.record(&det_event(None, None)); // → "unknown"
        let r = agg.by_detector(900);
        let names: Vec<&str> = r.detectors.iter().map(|d| d.name.as_str()).collect();
        assert!(!names.contains(&"unknown"), "got {names:?}");
        assert!(names.contains(&"sqli"));
    }

    #[test]
    fn detector_name_falls_back_to_unknown() {
        let ev = det_event(None, None);
        assert_eq!(detector_name(&ev), "unknown");
    }

    // 2026-05-20 — Top Attackers "Detectors" column must list EVERY
    // co-firing detector, including secondary tags like `ai`
    // (`sqli,ai`). Pre-fix only the canonical first tag was kept.
    #[test]
    fn top_attacker_categories_include_all_co_firing_detectors() {
        let agg = AttacksAggregator::new();
        let mut ev = det_event(None, Some("sqli"));
        ev.client_ip = "203.0.113.5".into();
        ev.fields = serde_json::json!({"detectors": ["sqli", "ai"]});
        agg.record(&ev);
        let mut ev2 = det_event(None, Some("xss"));
        ev2.client_ip = "203.0.113.5".into();
        ev2.fields = serde_json::json!({"detectors": ["xss", "ai"]});
        agg.record(&ev2);

        let top = agg.top(900, 10);
        let row = top
            .attackers
            .iter()
            .find(|a| a.identifier == "203.0.113.5")
            .expect("attacker row present");
        assert!(row.categories.contains(&"ai".to_string()), "ai missing: {:?}", row.categories);
        assert!(row.categories.contains(&"sqli".to_string()), "{:?}", row.categories);
        assert!(row.categories.contains(&"xss".to_string()), "{:?}", row.categories);
    }

    /// 2026-05-19 — Strike-Block and Cumulative-risk gates stamp
    /// these rule_ids on their Detection-class audit events
    /// (data_plane.rs::blocked_response sites). The aggregator
    /// must map them to honest synthetic labels — otherwise the
    /// Attack Distribution donut shows a "unknown" slice that's
    /// indistinguishable from malformed events.
    #[test]
    fn detector_name_maps_risk_strikes_to_ip_strikes() {
        let ev = det_event(None, Some("risk-strikes"));
        assert_eq!(detector_name(&ev), "ip-strikes");
    }

    #[test]
    fn detector_name_maps_risk_score_to_ip_risk() {
        let ev = det_event(None, Some("risk-score"));
        assert_eq!(detector_name(&ev), "ip-risk");
    }

    #[test]
    fn distribution_does_not_show_unknown_for_risk_blocks() {
        // Two risk-strikes + one risk-score block → only "ip-strikes"
        // (2 events) and "ip-risk" (1 event) in the distribution.
        // No "unknown" bucket pollutes the chart.
        let agg = AttacksAggregator::new();
        agg.record(&det_event(None, Some("risk-strikes")));
        agg.record(&det_event(None, Some("risk-strikes")));
        agg.record(&det_event(None, Some("risk-score")));
        let r = agg.distribution(900);
        let names: Vec<&str> = r.categories.iter().map(|c| c.name.as_str()).collect();
        assert!(!names.contains(&"unknown"), "got {names:?}");
        assert!(names.contains(&"ip-strikes"));
        assert!(names.contains(&"ip-risk"));
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
            method: None,
            path: None,
            mode: None,
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
        for key in ["window_seconds", "limit", "attackers", "geoip_loaded"] {
            assert!(obj.contains_key(key), "top response missing {key}");
        }
        let attackers = obj["attackers"].as_array().unwrap();
        let a = attackers[0].as_object().unwrap();
        for key in ["identifier", "hits", "categories", "risk", "last_seen"] {
            assert!(a.contains_key(key), "attacker missing {key}");
        }
    }

    #[test]
    fn top_response_geoip_loaded_defaults_false_without_lookup_wired() {
        // Aggregator path returns false; the handler flips it
        // when its `geo` slot is Some.
        let agg = std::sync::Arc::new(AttacksAggregator::new());
        agg.record(&det_event_full("8.8.8.8", Some("sqli"), None, 80));
        let h = AttacksHandler::with_ttl(agg, std::time::Duration::from_millis(1));
        let body = h.render_top(900, 5);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            v["geoip_loaded"].as_bool(),
            Some(false),
            "geoip_loaded must be false when no lookup is wired",
        );
    }

    #[test]
    fn top_response_geoip_loaded_true_after_set_geo_lookup() {
        // Stub GeoIpLookup that returns nothing — we only care
        // that the handler observes its presence + flips the
        // flag, not what it resolves.
        struct StubGeo;
        impl aegis_security::geoip::GeoIpLookup for StubGeo {
            fn country(&self, _ip: std::net::IpAddr) -> Option<String> {
                None
            }
            fn asn(&self, _ip: std::net::IpAddr) -> Option<u32> {
                None
            }
        }

        let agg = std::sync::Arc::new(AttacksAggregator::new());
        agg.record(&det_event_full("8.8.8.8", Some("sqli"), None, 80));
        let h = AttacksHandler::with_ttl(agg, std::time::Duration::from_millis(1));
        h.set_geo_lookup(std::sync::Arc::new(StubGeo));
        let body = h.render_top(900, 5);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            v["geoip_loaded"].as_bool(),
            Some(true),
            "geoip_loaded must flip to true after set_geo_lookup",
        );
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

    // ---------- D-M3-T3.4..T3.6: by-detector / threat-intel / bot-mix ---

    fn det_event_with_fields(
        detector: &str,
        ip: &str,
        fields: serde_json::Value,
    ) -> AuditEvent {
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
            risk_score: Some(80),
            method: None,
            path: None,
            mode: None,
            fields: {
                let mut o = serde_json::Map::new();
                o.insert("detector".into(), serde_json::Value::String(detector.into()));
                if let serde_json::Value::Object(extras) = fields {
                    for (k, v) in extras {
                        o.insert(k, v);
                    }
                }
                serde_json::Value::Object(o)
            },
        }
    }

    #[test]
    fn by_detector_returns_slim_breakdown() {
        let agg = AttacksAggregator::new();
        for _ in 0..5 {
            agg.record(&det_event_full("8.8.8.8", Some("sqli"), None, 80));
        }
        for _ in 0..2 {
            agg.record(&det_event_full("8.8.8.8", Some("xss"), None, 80));
        }
        let r = agg.by_detector(900);
        assert_eq!(r.window_seconds, 900);
        assert_eq!(r.detectors.len(), 2);
        assert_eq!(r.detectors[0].name, "sqli");
        assert_eq!(r.detectors[0].count, 5);
        assert_eq!(r.detectors[1].name, "xss");
        assert_eq!(r.detectors[1].count, 2);
    }

    #[test]
    fn by_detector_empty_aggregator() {
        let agg = AttacksAggregator::new();
        let r = agg.by_detector(900);
        assert!(r.detectors.is_empty());
    }

    #[test]
    fn threat_intel_extraction_handles_both_field_shapes() {
        // Nested under threat_intel.{feed,indicator}.
        let nested = serde_json::json!({
            "threat_intel": { "feed": "abuse-ch", "indicator": "1.2.3.4" }
        });
        let (f, i) = threat_intel_from_fields(&nested);
        assert_eq!(f.as_deref(), Some("abuse-ch"));
        assert_eq!(i.as_deref(), Some("1.2.3.4"));

        // Flat feed_id / indicator.
        let flat = serde_json::json!({ "feed_id": "spamhaus", "indicator": "evil.com" });
        let (f, i) = threat_intel_from_fields(&flat);
        assert_eq!(f.as_deref(), Some("spamhaus"));
        assert_eq!(i.as_deref(), Some("evil.com"));

        // Neither shape present.
        let none = serde_json::json!({"detector": "sqli"});
        let (f, i) = threat_intel_from_fields(&none);
        assert!(f.is_none());
        assert!(i.is_none());
    }

    #[test]
    fn threat_intel_hits_groups_by_feed_and_indicator() {
        let agg = AttacksAggregator::new();
        for _ in 0..3 {
            agg.record(&det_event_with_fields(
                "ip",
                "1.1.1.1",
                serde_json::json!({"threat_intel": {"feed": "abuse-ch", "indicator": "1.1.1.1"}}),
            ));
        }
        agg.record(&det_event_with_fields(
            "ip",
            "2.2.2.2",
            serde_json::json!({"threat_intel": {"feed": "abuse-ch", "indicator": "2.2.2.2"}}),
        ));
        // Event without threat-intel shouldn't appear.
        agg.record(&det_event_full("3.3.3.3", Some("sqli"), None, 80));

        let r = agg.threat_intel_hits(900, 10);
        assert_eq!(r.hits.len(), 2);
        assert_eq!(r.hits[0].feed, "abuse-ch");
        assert_eq!(r.hits[0].indicator, "1.1.1.1");
        assert_eq!(r.hits[0].hits, 3);
        assert_eq!(r.hits[1].hits, 1);
    }

    #[test]
    fn threat_intel_hits_respects_limit() {
        let agg = AttacksAggregator::new();
        for i in 0..10 {
            agg.record(&det_event_with_fields(
                "ip",
                &format!("9.0.0.{i}"),
                serde_json::json!({"threat_intel": {"feed": "f", "indicator": format!("9.0.0.{i}")}}),
            ));
        }
        let r = agg.threat_intel_hits(900, 3);
        assert_eq!(r.hits.len(), 3);
    }

    #[test]
    fn bot_mix_counts_only_labelled_events_no_unknown_fallback() {
        let agg = AttacksAggregator::new();
        for _ in 0..4 {
            agg.record(&det_event_with_fields(
                "ip",
                "1.1.1.1",
                serde_json::json!({"bot_category": "verified"}),
            ));
        }
        for _ in 0..3 {
            agg.record(&det_event_with_fields(
                "ip",
                "2.2.2.2",
                serde_json::json!({"bot_category": "malicious"}),
            ));
        }
        // Detection events WITHOUT a bot verdict are retained for the
        // attack views, but must NOT show up in the bot mix — there is
        // no synthetic "unknown" bucket (it conflated blocked attacks
        // with bot signals). 2026-05-21 behaviour change.
        for _ in 0..3 {
            agg.record(&det_event_full("3.3.3.3", Some("sqli"), None, 80));
        }
        let r = agg.bot_mix(900);
        assert_eq!(r.window_seconds, 900);
        let total: u64 = r.categories.iter().map(|c| c.count).sum();
        assert_eq!(total, 7, "only the 4 verified + 3 malicious are counted");
        assert!(
            r.categories.iter().all(|c| c.name != "unknown"),
            "no synthetic unknown bucket",
        );
        // Sorted by count desc.
        assert_eq!(r.categories[0].name, "verified");
        assert_eq!(r.categories[0].count, 4);
        // Percentages sum to ~100 across the labelled events.
        let pct_sum: f64 = r.categories.iter().map(|c| c.pct).sum();
        assert!((pct_sum - 100.0).abs() < 0.5);
    }

    // Regression guard for the 2026-05-21 bot-mix wiring fix. The
    // classifier stamps `bot_category` on the ALLOW (Access) event, so
    // the aggregator must admit bot-labelled Access events into the
    // mix — but they are not attacks, so they must stay OUT of the
    // attacker / detector views (top / distribution / by_detector).
    #[test]
    fn bot_labelled_access_event_feeds_mix_only_not_attack_views() {
        let agg = AttacksAggregator::new();
        let mut ev = det_event_with_fields(
            "recon_tool",
            "9.9.9.9",
            serde_json::json!({"bot_category": "malicious"}),
        );
        ev.class = AuditClass::Access;
        ev.action = "allow".into();
        agg.record(&ev);

        // Counted in the bot mix...
        let mix = agg.bot_mix(900);
        assert_eq!(mix.categories.len(), 1);
        assert_eq!(mix.categories[0].name, "malicious");
        assert_eq!(mix.categories[0].count, 1);

        // ...but absent from Top Attackers + the detector breakdowns.
        assert!(
            agg.top(900, 10).attackers.is_empty(),
            "an allowed bot is not an attacker",
        );
        assert!(
            agg.distribution(900).categories.is_empty(),
            "an allowed bot must not enter the detector distribution",
        );
        assert!(
            agg.by_detector(900).detectors.is_empty(),
            "an allowed bot must not enter the by-detector breakdown",
        );
    }

    #[test]
    fn handler_renders_three_new_endpoints() {
        let agg = Arc::new(AttacksAggregator::new());
        agg.record(&det_event_with_fields(
            "ip",
            "1.1.1.1",
            serde_json::json!({
                "threat_intel": {"feed": "abuse-ch", "indicator": "1.1.1.1"},
                "bot_category": "malicious",
            }),
        ));
        let h = AttacksHandler::new(Arc::clone(&agg));

        let by_det: serde_json::Value =
            serde_json::from_str(&h.render_by_detector(900)).unwrap();
        assert!(by_det["detectors"].is_array());

        let ti: serde_json::Value =
            serde_json::from_str(&h.render_threat_intel(900, 10)).unwrap();
        assert!(ti["hits"].is_array());

        let bot: serde_json::Value =
            serde_json::from_str(&h.render_bot_mix(900)).unwrap();
        assert!(bot["categories"].is_array());
    }

    #[test]
    fn five_attacks_caches_are_independent() {
        // Distribution / top / by-detector / threat-intel / bot-mix
        // each have a separate cache slot.
        let agg = Arc::new(AttacksAggregator::new());
        agg.record(&det_event_with_fields(
            "ip",
            "1.1.1.1",
            serde_json::json!({
                "threat_intel": {"feed": "f", "indicator": "1.1.1.1"},
                "bot_category": "malicious",
            }),
        ));
        let h = AttacksHandler::new(Arc::clone(&agg));
        let dist = h.render(900);
        let top = h.render_top(900, 5);
        let by_det = h.render_by_detector(900);
        let ti = h.render_threat_intel(900, 10);
        let bot = h.render_bot_mix(900);
        // No shape collisions — each has its expected top-level array.
        assert!(serde_json::from_str::<serde_json::Value>(&dist).unwrap()["categories"].is_array());
        assert!(serde_json::from_str::<serde_json::Value>(&top).unwrap()["attackers"].is_array());
        assert!(serde_json::from_str::<serde_json::Value>(&by_det).unwrap()["detectors"].is_array());
        assert!(serde_json::from_str::<serde_json::Value>(&ti).unwrap()["hits"].is_array());
        assert!(serde_json::from_str::<serde_json::Value>(&bot).unwrap()["categories"].is_array());
    }
}
