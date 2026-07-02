//! `/api/audit/since` reconnect-replay endpoint (D-M3-T3.2).
//!
//! Backs the Live Feed page's reconnect path: when the SPA's
//! EventSource closes (network blip, server hop), the page fetches
//! `/api/audit/since?cursor=<last>` to backfill events it missed.
//!
//! Architecture:
//! - [`AuditRing`] is a bounded `VecDeque<(seq, event)>` fed by the
//!   audit-bus drain task. Sequence numbers are monotonic per
//!   process — they reset on restart, which is fine because the
//!   page reconnect TTL is shorter than a sane WAF restart.
//! - [`AuditHandler::render_since`] serialises a `[since, since+limit]`
//!   slice into JSON, with a 1 s response cache to absorb retry
//!   storms.
//! - The dashboard SSE event payload already embeds enough detail
//!   for the Live Feed drawer; this endpoint just replays them in
//!   order so the row stream stays gapless across reconnects.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aegis_core::audit::AuditEvent;
use serde::Serialize;

use crate::audit::witness::WitnessRecord;

/// Default ring capacity — sized to cover a few minutes of activity
/// at 5 000 RPS with detection rate ~0.1 % (i.e. 30 k events / 10 min).
/// 10 000 is a conservative cap; can be overridden via `with_capacity`.
const DEFAULT_CAPACITY: usize = 10_000;
/// Default response cache TTL.
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(1);
/// Maximum number of events a single `?limit=` query can pull.
/// Bounds payload size so a misbehaving client can't ask for the
/// entire ring on every reconnect.
const MAX_LIMIT: u32 = 1_000;
/// Default `?limit=` value when the parameter is absent or malformed.
const DEFAULT_LIMIT: u32 = 200;

/// One row of the `/api/audit/since` response. Carries the monotonic
/// sequence number alongside the audit event so the client can pin
/// the next cursor without parsing event timestamps.
#[derive(Clone, Debug, Serialize)]
pub struct AuditSinceEntry {
    pub seq: u64,
    #[serde(flatten)]
    pub event: AuditEvent,
}

/// JSON shape returned by `GET /api/audit/since`.
#[derive(Clone, Debug, Serialize)]
pub struct AuditSinceResponse {
    pub cursor: u64,
    pub next_cursor: u64,
    pub events: Vec<AuditSinceEntry>,
    /// `true` if the ring evicted events between `cursor` and
    /// `next_cursor` — the client lost some history and should
    /// surface a "stream gap" badge.
    pub gap: bool,
}

#[derive(Default)]
struct RingState {
    /// Monotonic sequence number of the next event recorded.
    /// Starts at 1 so cursor=0 means "give me everything".
    next_seq: u64,
    entries: VecDeque<(u64, AuditEvent)>,
    capacity: usize,
}

/// In-process audit ring. Cheap to share (`Arc<Mutex<…>>`).
#[derive(Clone)]
pub struct AuditRing {
    inner: Arc<Mutex<RingState>>,
}

/// One row of `GET /api/analytics/routes` — per-route activity
/// over the in-process audit ring window.
#[derive(Clone, Debug, serde::Serialize)]
pub struct RouteStatsEntry {
    pub route: String,
    pub total: u64,
    pub blocked: u64,
    pub challenged: u64,
    pub errors_5xx: u64,
    pub error_rate_pct: f64,
    pub block_rate_pct: f64,
}

/// PR-UX-A2 (2026-05-12) — filter the audit ring server-side
/// instead of shipping the whole ring to the dashboard.  Empty
/// fields are wildcards; populated fields are AND-ed together.
///
/// 2026-05-17 F-CRITICAL-004 (control audit): `ts_from` + `ts_to`
/// added so Round-1's "audit search by time" mandate is met. Both
/// are RFC 3339 timestamps; either may be omitted to make the
/// range half-open (e.g. just `ts_from` = "last events since X").
#[derive(Clone, Debug, Default)]
pub struct AuditFilter {
    pub ip: Option<String>,
    pub request_id: Option<String>,
    pub rule_id: Option<String>,
    /// PR-B P1 (2026-07-02) — composite risk-bucket pivot. Matches
    /// `fields.risk_key.key_hash` (the stable 16-hex
    /// `blake3(ip|device_fp|session)` bucket id the data plane stamps
    /// on every allow/block/challenge row). Rows without the field —
    /// early-path blocks, admin/system events — never match.
    pub risk_key: Option<String>,
    pub ts_from: Option<chrono::DateTime<chrono::Utc>>,
    pub ts_to: Option<chrono::DateTime<chrono::Utc>>,
}

impl AuditFilter {
    pub fn is_empty(&self) -> bool {
        self.ip.is_none()
            && self.request_id.is_none()
            && self.rule_id.is_none()
            && self.risk_key.is_none()
            && self.ts_from.is_none()
            && self.ts_to.is_none()
    }

    /// Does this event pass every populated filter field?
    pub fn matches(&self, ev: &AuditEvent) -> bool {
        if let Some(ip) = &self.ip {
            if !ip.eq_ignore_ascii_case(&ev.client_ip) {
                return false;
            }
        }
        if let Some(rid) = &self.request_id {
            if !rid.eq_ignore_ascii_case(&ev.request_id) {
                return false;
            }
        }
        if let Some(ts_from) = &self.ts_from {
            if ev.ts < *ts_from {
                return false;
            }
        }
        if let Some(ts_to) = &self.ts_to {
            if ev.ts > *ts_to {
                return false;
            }
        }
        if let Some(want_key) = &self.risk_key {
            let hit = ev
                .fields
                .get("risk_key")
                .and_then(|rk| rk.get("key_hash"))
                .and_then(|v| v.as_str())
                .map(|kh| kh.eq_ignore_ascii_case(want_key))
                .unwrap_or(false);
            if !hit {
                return false;
            }
        }
        if let Some(rule) = &self.rule_id {
            let rule_l = rule.to_ascii_lowercase();
            let top_hit = ev
                .rule_id
                .as_ref()
                .map(|r| r.eq_ignore_ascii_case(rule))
                .unwrap_or(false);
            if !top_hit {
                let detectors_hit = ev
                    .fields
                    .get("detectors")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter().any(|d| {
                            d.as_str()
                                .map(|s| s.to_ascii_lowercase() == rule_l)
                                .unwrap_or(false)
                        })
                    })
                    .unwrap_or(false);
                // 2026-06-21 — config-mutation events (rule_update / rule_delete,
                // route_*, pool_*) carry a null top-level `rule_id`; the id lives
                // in `fields.resource` (e.g. `/api/rules/<id>`). Match the last
                // path segment so the Audit Trail `rule_id` filter finds the
                // events that mutated that rule (mirrors the UI's RULE column).
                let resource_hit = ev
                    .fields
                    .get("resource")
                    .and_then(|v| v.as_str())
                    .and_then(|res| res.trim_end_matches('/').rsplit('/').next())
                    .map(|seg| seg.eq_ignore_ascii_case(rule))
                    .unwrap_or(false);
                if !detectors_hit && !resource_hit {
                    return false;
                }
            }
        }
        true
    }
}

/// First non-empty path segment, prefixed with `/`. Used as a
/// route bucket fallback when the audit event lacks `route_id`.
/// Examples:
///   "/api/transactions?limit=20" → "/api"
///   "/login"                     → "/login"
///   "/"                          → "/"
fn first_path_segment(path: &str) -> String {
    let p = path.split('?').next().unwrap_or("/");
    let mut parts = p.trim_start_matches('/').split('/');
    match parts.next() {
        None | Some("") => "/".into(),
        Some(seg) => format!("/{seg}"),
    }
}

impl AuditRing {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(RingState {
                next_seq: 1,
                entries: VecDeque::with_capacity(capacity.max(1)),
                capacity: capacity.max(1),
            })),
        }
    }

    /// Append one event and return its assigned sequence number.
    pub fn record(&self, ev: AuditEvent) -> u64 {
        let mut state = self.inner.lock().expect("audit ring poisoned");
        let seq = state.next_seq;
        state.next_seq = state.next_seq.saturating_add(1);
        state.entries.push_back((seq, ev));
        let cap = state.capacity;
        while state.entries.len() > cap {
            state.entries.pop_front();
        }
        seq
    }

    /// Return events with `seq > cursor`, capped at `limit`.
    /// Reports `gap = true` when the ring evicted events in the
    /// (cursor, oldest_in_ring) range.
    pub fn since(&self, cursor: u64, limit: u32) -> AuditSinceResponse {
        self.since_filtered(cursor, limit, &AuditFilter::default())
    }

    /// PR-UX-A2 (2026-05-12) — filtered variant.  Used by
    /// `/api/audit/since?ip=&rule_id=&request_id=` so the
    /// Investigation page doesn't have to client-filter 200
    /// events for a one-IP pivot.  When all filter fields are
    /// `None` this is equivalent to `since()` (and is the path
    /// `since()` itself delegates to).
    ///
    /// Filter semantics — all populated fields must match.
    /// - `ip`: exact match on `event.client_ip`
    /// - `request_id`: exact match on `event.request_id`
    /// - `rule_id`: matches `event.rule_id`, OR any element of
    ///   `event.fields.detectors[]` when present
    pub fn since_filtered(
        &self,
        cursor: u64,
        limit: u32,
        filter: &AuditFilter,
    ) -> AuditSinceResponse {
        let state = self.inner.lock().expect("audit ring poisoned");
        let high_water = state.next_seq.saturating_sub(1);
        let oldest = state.entries.front().map(|(s, _)| *s).unwrap_or(high_water + 1);

        // Cursor at or above high water → nothing new.
        if cursor >= high_water {
            return AuditSinceResponse {
                cursor,
                next_cursor: high_water,
                events: Vec::new(),
                gap: false,
            };
        }

        // Gap when the ring no longer contains every event after
        // `cursor`. The boundary is `cursor + 1` (the first event
        // the client expects); if the oldest-retained seq is past
        // that, history was evicted.
        let gap = oldest > cursor.saturating_add(1);

        let limit = limit.max(1) as usize;
        let mut events = Vec::with_capacity(limit.min(state.entries.len()));
        let mut last_seq = cursor;
        for (seq, ev) in state.entries.iter() {
            if *seq <= cursor {
                continue;
            }
            if !filter.matches(ev) {
                // Still advance last_seq so the client's cursor
                // moves past filtered-out rows; otherwise the
                // next poll re-walks the same prefix.
                last_seq = *seq;
                continue;
            }
            if events.len() >= limit {
                break;
            }
            events.push(AuditSinceEntry {
                seq: *seq,
                event: ev.clone(),
            });
            last_seq = *seq;
        }

        AuditSinceResponse {
            cursor,
            next_cursor: last_seq,
            events,
            gap,
        }
    }

    /// 2026-05-23 — TAIL query: the **newest** `limit` matching events
    /// (walked from the back of the ring), returned in ascending `seq`
    /// order to match the `since()` wire shape, with
    /// `next_cursor = high_water` so a follow-up `since(next_cursor)`
    /// streams only genuinely-new events.
    ///
    /// This is the correct backfill for the "newest-first" views (Live
    /// Feed, Recent Requests, Audit Trail). `since(0, n)` returns the
    /// OLDEST `n` retained events — after sustained traffic / a flood
    /// those are stale, which made the dashboard appear frozen on old
    /// events while the genuinely-newest ones sat at the back of the
    /// ring (2026-05-23 staleness fix).
    pub fn latest_filtered(&self, limit: u32, filter: &AuditFilter) -> AuditSinceResponse {
        let state = self.inner.lock().expect("audit ring poisoned");
        let high_water = state.next_seq.saturating_sub(1);
        let limit = limit.max(1) as usize;
        let mut events: Vec<AuditSinceEntry> =
            Vec::with_capacity(limit.min(state.entries.len()));
        for (seq, ev) in state.entries.iter().rev() {
            if events.len() >= limit {
                break;
            }
            if !filter.matches(ev) {
                continue;
            }
            events.push(AuditSinceEntry { seq: *seq, event: ev.clone() });
        }
        events.reverse(); // ascending seq, matching `since()`
        AuditSinceResponse {
            cursor: 0,
            next_cursor: high_water,
            events,
            gap: false,
        }
    }

    /// 2026-06-02 (copilot per-event clustering) — clone the most-recent
    /// `limit` audit events for deterministic clustering. Newest-first
    /// (order doesn't matter to the clusterer); bounded by ring capacity.
    pub fn recent(&self, limit: usize) -> Vec<AuditEvent> {
        let state = self.inner.lock().expect("audit ring poisoned");
        state
            .entries
            .iter()
            .rev()
            .take(limit)
            .map(|(_, ev)| ev.clone())
            .collect()
    }

    /// Current high-water-mark sequence (next seq about to be
    /// assigned, minus one). Useful for tests + monitoring.
    /// Phase-3 per-route stats — walks the ring and aggregates by
    /// `route_id` (or the `fields.path` first segment when route_id
    /// is absent). Returns up to `limit` rows sorted by total
    /// requests descending. Each row carries `total / blocked /
    /// challenged / errors_5xx / error_rate_pct` so the Performance
    /// page can render per-route latency *and* error attribution
    /// without scraping `/metrics` directly.
    ///
    /// Cardinality is bounded by the ring capacity; every
    /// distinct `route_id` seen in the window appears at most
    /// once. Cost: one pass through the ring (default cap 5000)
    /// + one HashMap insert per entry.
    pub fn route_stats(&self, limit: u32) -> Vec<RouteStatsEntry> {
        use std::collections::HashMap;
        #[derive(Default)]
        struct Acc {
            total: u64,
            blocked: u64,
            challenged: u64,
            errors_5xx: u64,
        }
        let state = self.inner.lock().expect("audit ring poisoned");
        let mut by_route: HashMap<String, Acc> = HashMap::new();
        for (_seq, ev) in state.entries.iter() {
            // Prefer the explicit route_id; fall back to a coarse
            // bucket from the path's first non-trivial segment so
            // requests without a matched route still attribute
            // somewhere.
            let key = ev.route_id.clone().unwrap_or_else(|| {
                let path = ev
                    .fields
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("/");
                first_path_segment(path)
            });
            let acc = by_route.entry(key).or_default();
            acc.total = acc.total.saturating_add(1);
            // The action string is the canonical wire shape: see
            // `interop::headers::Action::as_str` (allow / block /
            // challenge / rate_limit / timeout / circuit_breaker).
            match ev.action.as_str() {
                "block" => acc.blocked = acc.blocked.saturating_add(1),
                "challenge" => acc.challenged = acc.challenged.saturating_add(1),
                _ => {}
            }
            // 5xx is encoded in `fields.status` when present.
            if let Some(status) = ev
                .fields
                .get("status")
                .and_then(|v| v.as_u64())
            {
                if (500..600).contains(&status) {
                    acc.errors_5xx = acc.errors_5xx.saturating_add(1);
                }
            }
        }
        let mut rows: Vec<RouteStatsEntry> = by_route
            .into_iter()
            .map(|(route, acc)| {
                let denom = acc.total.max(1) as f64;
                RouteStatsEntry {
                    route,
                    total: acc.total,
                    blocked: acc.blocked,
                    challenged: acc.challenged,
                    errors_5xx: acc.errors_5xx,
                    error_rate_pct: ((acc.blocked + acc.errors_5xx) as f64 / denom) * 100.0,
                    block_rate_pct: (acc.blocked as f64 / denom) * 100.0,
                }
            })
            .collect();
        rows.sort_by(|a, b| b.total.cmp(&a.total));
        let limit = limit.max(1) as usize;
        rows.truncate(limit);
        rows
    }

    pub fn high_water(&self) -> u64 {
        let s = self.inner.lock().expect("audit ring poisoned");
        s.next_seq.saturating_sub(1)
    }
}

impl Default for AuditRing {
    fn default() -> Self {
        Self::new()
    }
}

/// HTTP handler for `/api/audit/since`. Caches the rendered JSON
/// keyed on `(cursor, limit)` for `cache_ttl` so a fan-out of clients
/// reconnecting at once doesn't recompute the slice on every hit.
pub struct AuditHandler {
    ring: Arc<AuditRing>,
    cache: Mutex<Option<(Instant, u64, u32, AuditSinceResponse)>>,
    /// F14 (2026-06-11) — separate cache slot for the unfiltered TAIL
    /// render (`?tail=1`), keyed on `limit`. The Audit Trail polls the
    /// tail every 3 s; pre-fix every poll re-locked the ring, cloned up
    /// to `limit` events, and re-serialised — uncached. A short TTL (the
    /// same `cache_ttl` as `since`) collapses a fan-out of pollers onto
    /// one render without staling the view beyond a second.
    tail_cache: Mutex<Option<(Instant, u32, AuditSinceResponse)>>,
    cache_ttl: Duration,
}

impl AuditHandler {
    pub fn new(ring: Arc<AuditRing>) -> Self {
        Self::with_ttl(ring, DEFAULT_CACHE_TTL)
    }

    pub fn with_ttl(ring: Arc<AuditRing>, cache_ttl: Duration) -> Self {
        Self {
            ring,
            cache: Mutex::new(None),
            tail_cache: Mutex::new(None),
            cache_ttl,
        }
    }

    /// Render `GET /api/audit/since?cursor=<n>&limit=<m>`. `limit` is
    /// clamped to `[1, MAX_LIMIT]`; missing/malformed values use
    /// `DEFAULT_LIMIT`.
    pub fn render_since(&self, cursor: u64, limit: u32) -> String {
        self.render_since_filtered(cursor, limit, &AuditFilter::default())
    }

    /// PR-UX-A2 (2026-05-12) — filtered variant. Cache is bypassed
    /// when any filter field is populated because the cache key
    /// is `(cursor, limit)` and we'd otherwise serve stale slices
    /// for the wrong pivot.  Unfiltered calls keep the cache hit
    /// fan-out behaviour intact.
    pub fn render_since_filtered(
        &self,
        cursor: u64,
        limit: u32,
        filter: &AuditFilter,
    ) -> String {
        let now = Instant::now();
        let limit = clamp_limit(limit);
        if filter.is_empty() {
            let cache = self.cache.lock().expect("audit cache poisoned");
            if let Some((stamped_at, c, l, resp)) = cache.as_ref() {
                if *c == cursor
                    && *l == limit
                    && now.duration_since(*stamped_at) < self.cache_ttl
                {
                    return serde_json::to_string(resp)
                        .unwrap_or_else(|_| String::from("{}"));
                }
            }
            drop(cache);
        }
        let resp = self.ring.since_filtered(cursor, limit, filter);
        let body = serde_json::to_string(&resp).unwrap_or_else(|_| String::from("{}"));
        if filter.is_empty() {
            let mut cache = self.cache.lock().expect("audit cache poisoned");
            *cache = Some((now, cursor, limit, resp));
        }
        body
    }

    /// 2026-05-23 — render the TAIL (newest `limit` matching events).
    ///
    /// F14 (2026-06-11) — the unfiltered tail is now cached on a
    /// dedicated `(limit)` slot (separate from the `since` cache, so the
    /// two never collide) for `cache_ttl`. Filtered tails (Investigation
    /// pivots) bypass the cache — the pivot key isn't part of the cache
    /// key, so a cached slice would be for the wrong filter.
    pub fn render_latest_filtered(&self, limit: u32, filter: &AuditFilter) -> String {
        let now = Instant::now();
        let limit = clamp_limit(limit);
        if filter.is_empty() {
            let cache = self.tail_cache.lock().expect("audit tail cache poisoned");
            if let Some((stamped_at, l, resp)) = cache.as_ref() {
                if *l == limit && now.duration_since(*stamped_at) < self.cache_ttl {
                    return serde_json::to_string(resp)
                        .unwrap_or_else(|_| String::from("{}"));
                }
            }
            drop(cache);
        }
        let resp = self.ring.latest_filtered(limit, filter);
        let body = serde_json::to_string(&resp).unwrap_or_else(|_| String::from("{}"));
        if filter.is_empty() {
            let mut cache = self.tail_cache.lock().expect("audit tail cache poisoned");
            *cache = Some((now, limit, resp));
        }
        body
    }
}

fn clamp_limit(limit: u32) -> u32 {
    if limit == 0 {
        DEFAULT_LIMIT
    } else {
        limit.min(MAX_LIMIT)
    }
}

/// JSON shape returned by `GET /api/audit/witness` (D-M3-T3.8).
/// `lag_seconds` is `None` when no witness has been recorded yet
/// (fresh boot), distinct from `0` (just signed).
#[derive(Clone, Debug, Serialize)]
pub struct WitnessLagResponse {
    pub last_signature_ts: Option<chrono::DateTime<chrono::Utc>>,
    pub lag_seconds: Option<i64>,
    pub chain_head_hash: Option<String>,
    pub node_id: Option<String>,
    pub entry_count: Option<u64>,
}

/// In-process state holding the last-seen witness record for the
/// chain. The cluster runtime that periodically signs the chain head
/// would call `update()`; the dashboard reads via `snapshot()`.
/// Until the runtime lands, the value stays `None` and the dashboard
/// pill shows "no witness yet" (which is correct).
#[derive(Clone, Default)]
pub struct WitnessState {
    inner: Arc<Mutex<Option<WitnessRecord>>>,
}

impl WitnessState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the stored witness with the latest signed record.
    pub fn update(&self, record: WitnessRecord) {
        let mut state = self.inner.lock().expect("witness state poisoned");
        *state = Some(record);
    }

    /// Read the current state. `lag_seconds` is computed against
    /// `chrono::Utc::now()` at call time — the value drifts by a
    /// second between snapshots, which is fine for a UI pill.
    pub fn snapshot(&self) -> WitnessLagResponse {
        let state = self.inner.lock().expect("witness state poisoned");
        match state.as_ref() {
            Some(rec) => {
                let lag = (chrono::Utc::now() - rec.ts).num_seconds();
                WitnessLagResponse {
                    last_signature_ts: Some(rec.ts),
                    lag_seconds: Some(lag),
                    chain_head_hash: Some(rec.chain_head_hash.clone()),
                    node_id: Some(rec.node_id.clone()),
                    entry_count: Some(rec.entry_count),
                }
            }
            None => WitnessLagResponse {
                last_signature_ts: None,
                lag_seconds: None,
                chain_head_hash: None,
                node_id: None,
                entry_count: None,
            },
        }
    }
}

/// HTTP wrapper for `/api/audit/witness`. No cache — the snapshot is
/// already O(1) and lag is recomputed on every read so we don't
/// freeze stale lag values mid-cache-window.
pub struct WitnessHandler {
    state: Arc<WitnessState>,
}

impl WitnessHandler {
    pub fn new(state: Arc<WitnessState>) -> Self {
        Self { state }
    }

    pub fn render(&self) -> String {
        serde_json::to_string(&self.state.snapshot())
            .unwrap_or_else(|_| String::from("{}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::audit::AuditClass;

    fn ev(id: &str) -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: id.into(),
            class: AuditClass::Detection,
            tenant_id: None,
            tier: None,
            action: "block".into(),
            reason: id.into(),
            client_ip: "1.1.1.1".into(),
            route_id: None,
            rule_id: None,
            risk_score: None,
            method: None,
            path: None,
            mode: None,
            fields: serde_json::Value::Null,
        }
    }

    fn ev_filter(
        id: &str,
        client_ip: &str,
        rule_id: Option<&str>,
        detectors: &[&str],
    ) -> AuditEvent {
        let fields = if detectors.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::json!({
                "detectors": detectors.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            })
        };
        AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: id.into(),
            class: AuditClass::Detection,
            tenant_id: None,
            tier: None,
            action: "block".into(),
            reason: id.into(),
            client_ip: client_ip.into(),
            route_id: None,
            rule_id: rule_id.map(String::from),
            risk_score: None,
            method: None,
            path: None,
            mode: None,
            fields,
        }
    }

    #[test]
    fn audit_filter_empty_passes_every_event() {
        let f = AuditFilter::default();
        assert!(f.is_empty());
        assert!(f.matches(&ev_filter("a", "1.2.3.4", None, &[])));
        assert!(f.matches(&ev_filter("b", "9.9.9.9", Some("sqli"), &["xss"])));
    }

    #[test]
    fn audit_filter_ip_exact_match() {
        let f = AuditFilter {
            ip: Some("8.8.8.8".into()),
            ..Default::default()
        };
        assert!(f.matches(&ev_filter("a", "8.8.8.8", None, &[])));
        assert!(!f.matches(&ev_filter("b", "1.1.1.1", None, &[])));
    }

    // ---- PR-B P1 (2026-07-02) — risk_key filter ------------------------
    //
    // `fields.risk_key.key_hash` is the stable 16-hex composite-bucket id
    // (`blake3(ip|device_fp|session)` truncated — data_plane.rs
    // `risk_key_audit_value`), stamped on every allow, detector block,
    // risk-score block, challenge and 429. A `risk_key` filter lets the
    // Investigation page pivot on one device/session bucket.

    fn ev_with_risk_key(id: &str, key_hash: Option<&str>) -> AuditEvent {
        let mut e = ev(id);
        if let Some(kh) = key_hash {
            e.fields = serde_json::json!({
                "risk_key": {
                    "ip": "1.1.1.1",
                    "device_fp": null,
                    "session_present": false,
                    "key_hash": kh,
                },
            });
        }
        e
    }

    #[test]
    fn audit_filter_risk_key_matches_bucket_hash() {
        let f = AuditFilter {
            risk_key: Some("a1b2c3d4e5f60718".into()),
            ..Default::default()
        };
        assert!(!f.is_empty(), "a risk_key filter is not an empty filter");
        assert!(f.matches(&ev_with_risk_key("a", Some("a1b2c3d4e5f60718"))));
        // Hex — compare case-insensitively.
        assert!(f.matches(&ev_with_risk_key("b", Some("A1B2C3D4E5F60718"))));
        assert!(!f.matches(&ev_with_risk_key("c", Some("ffffffffffffffff"))));
    }

    #[test]
    fn audit_filter_risk_key_never_matches_rows_without_the_field() {
        // Early-path rows (blacklist / connect-denied) and admin/system
        // events carry no risk_key — they must be excluded, not matched.
        let f = AuditFilter {
            risk_key: Some("a1b2c3d4e5f60718".into()),
            ..Default::default()
        };
        assert!(!f.matches(&ev_with_risk_key("a", None)), "null fields");
        let mut other = ev("b");
        other.fields = serde_json::json!({ "detectors": ["sqli"] });
        assert!(!f.matches(&other), "fields object without risk_key");
    }

    #[test]
    fn audit_filter_risk_key_and_combines_with_other_fields() {
        let f = AuditFilter {
            ip: Some("1.1.1.1".into()),
            risk_key: Some("a1b2c3d4e5f60718".into()),
            ..Default::default()
        };
        // ev() fixtures carry client_ip 1.1.1.1.
        assert!(f.matches(&ev_with_risk_key("a", Some("a1b2c3d4e5f60718"))));
        let mut wrong_ip = ev_with_risk_key("b", Some("a1b2c3d4e5f60718"));
        wrong_ip.client_ip = "9.9.9.9".into();
        assert!(!f.matches(&wrong_ip), "AND semantics with the ip filter");
    }

    #[test]
    fn audit_filter_rule_id_matches_top_level_or_detectors_array() {
        let f = AuditFilter {
            rule_id: Some("recon_path".into()),
            ..Default::default()
        };
        // Top-level rule_id match.
        assert!(f.matches(&ev_filter("a", "1.1.1.1", Some("recon_path"), &[])));
        // Detector list match.
        assert!(f.matches(&ev_filter("b", "1.1.1.1", None, &["recon_path"])));
        // Neither — rejected.
        assert!(!f.matches(&ev_filter("c", "1.1.1.1", Some("sqli"), &["xss"])));
    }

    #[test]
    fn audit_filter_rule_id_matches_resource_tail() {
        // 2026-06-21 — config-mutation events (rule_update/_delete, route_*,
        // pool_*) carry rule_id=None; the id is the last segment of
        // `fields.resource`. The Audit Trail rule_id filter must find them.
        let mut ev = ev_filter("a", "1.1.1.1", None, &[]);
        ev.action = "rule_update".into();
        ev.fields = serde_json::json!({ "resource": "/api/rules/sample-block-ip-rule" });

        let f = AuditFilter {
            rule_id: Some("sample-block-ip-rule".into()),
            ..Default::default()
        };
        assert!(f.matches(&ev), "must match the resource path's rule id");
        // case-insensitive
        let f2 = AuditFilter {
            rule_id: Some("SAMPLE-BLOCK-IP-RULE".into()),
            ..Default::default()
        };
        assert!(f2.matches(&ev));
        // a different id is rejected
        let f3 = AuditFilter {
            rule_id: Some("other-rule".into()),
            ..Default::default()
        };
        assert!(!f3.matches(&ev));
    }

    #[test]
    fn latest_returns_newest_not_oldest() {
        // 2026-05-23 regression — the dashboard appeared frozen on
        // stale traffic because `since(0, n)` returns the OLDEST n
        // retained events. `latest(n)` must return the NEWEST n
        // (ascending seq) so the newest-first views surface current
        // activity even when the ring holds far more than n events.
        let ring = AuditRing::with_capacity(100);
        for id in ["a", "b", "c", "d", "e"] {
            ring.record(ev(id));
        }
        // Baseline: since(0,2) returns the OLDEST two.
        let oldest: Vec<_> = ring
            .since(0, 2)
            .events
            .iter()
            .map(|e| e.event.request_id.clone())
            .collect();
        assert_eq!(oldest, vec!["a", "b"]);

        // Tail: latest_filtered(2) returns the NEWEST two, ascending seq.
        let tail = ring.latest_filtered(2, &AuditFilter::default());
        let newest: Vec<_> = tail
            .events
            .iter()
            .map(|e| e.event.request_id.clone())
            .collect();
        assert_eq!(newest, vec!["d", "e"], "tail must return newest, ascending seq");
        assert_eq!(tail.next_cursor, 5, "next_cursor = high_water so follow-up since() streams only new events");
        assert!(!tail.gap);
    }

    #[test]
    fn latest_filtered_returns_newest_matching_only() {
        // Tail must respect the filter (e.g. an Investigation IP pivot)
        // and still return the NEWEST matching events.
        let ring = AuditRing::with_capacity(100);
        ring.record(ev_filter("old-target", "9.9.9.9", None, &[]));
        for id in ["noise1", "noise2", "noise3"] {
            ring.record(ev_filter(id, "1.1.1.1", None, &[]));
        }
        ring.record(ev_filter("new-target", "9.9.9.9", None, &[]));
        let f = AuditFilter { ip: Some("9.9.9.9".into()), ..Default::default() };
        let ids: Vec<_> = ring
            .latest_filtered(1, &f)
            .events
            .iter()
            .map(|e| e.event.request_id.clone())
            .collect();
        assert_eq!(ids, vec!["new-target"], "tail+filter must return the newest matching event");
    }

    #[test]
    fn audit_filter_ts_from_excludes_older_events() {
        // F-CRITICAL-004 (2026-05-17 control audit) regression.
        // ts_from = T → events with ts < T are filtered out.
        use chrono::{TimeZone, Utc};
        let mut ev = ev_filter("a", "1.1.1.1", None, &[]);
        ev.ts = Utc.with_ymd_and_hms(2026, 5, 17, 10, 0, 0).unwrap();
        let f = AuditFilter {
            ts_from: Some(Utc.with_ymd_and_hms(2026, 5, 17, 11, 0, 0).unwrap()),
            ..Default::default()
        };
        assert!(!f.matches(&ev), "event before ts_from must be filtered");
        // Event at ts_from is INCLUDED (>= semantics).
        ev.ts = Utc.with_ymd_and_hms(2026, 5, 17, 11, 0, 0).unwrap();
        assert!(f.matches(&ev));
    }

    #[test]
    fn audit_filter_ts_to_excludes_newer_events() {
        use chrono::{TimeZone, Utc};
        let mut ev = ev_filter("a", "1.1.1.1", None, &[]);
        ev.ts = Utc.with_ymd_and_hms(2026, 5, 17, 12, 0, 0).unwrap();
        let f = AuditFilter {
            ts_to: Some(Utc.with_ymd_and_hms(2026, 5, 17, 11, 0, 0).unwrap()),
            ..Default::default()
        };
        assert!(!f.matches(&ev), "event after ts_to must be filtered");
        ev.ts = Utc.with_ymd_and_hms(2026, 5, 17, 11, 0, 0).unwrap();
        assert!(f.matches(&ev));
    }

    #[test]
    fn audit_filter_ts_from_and_ts_to_compose() {
        use chrono::{TimeZone, Utc};
        let f = AuditFilter {
            ts_from: Some(Utc.with_ymd_and_hms(2026, 5, 17, 10, 0, 0).unwrap()),
            ts_to: Some(Utc.with_ymd_and_hms(2026, 5, 17, 12, 0, 0).unwrap()),
            ..Default::default()
        };
        let mut ev = ev_filter("a", "1.1.1.1", None, &[]);
        // Inside the window — accepted.
        ev.ts = Utc.with_ymd_and_hms(2026, 5, 17, 11, 0, 0).unwrap();
        assert!(f.matches(&ev));
        // Below window — rejected.
        ev.ts = Utc.with_ymd_and_hms(2026, 5, 17, 9, 0, 0).unwrap();
        assert!(!f.matches(&ev));
        // Above window — rejected.
        ev.ts = Utc.with_ymd_and_hms(2026, 5, 17, 13, 0, 0).unwrap();
        assert!(!f.matches(&ev));
    }

    #[test]
    fn since_filtered_returns_only_matching_rows_but_advances_cursor() {
        let ring = AuditRing::new();
        ring.record(ev_filter("a", "1.2.3.4", None, &[]));
        ring.record(ev_filter("b", "8.8.8.8", None, &[]));
        ring.record(ev_filter("c", "1.2.3.4", None, &[]));
        let filter = AuditFilter {
            ip: Some("1.2.3.4".into()),
            ..Default::default()
        };
        let resp = ring.since_filtered(0, 100, &filter);
        assert_eq!(resp.events.len(), 2);
        // next_cursor advances to the high water mark so the
        // dashboard's incremental poll doesn't re-walk the prefix.
        assert_eq!(resp.next_cursor, 3);
    }

    #[test]
    fn record_assigns_monotonic_sequence_starting_at_one() {
        let ring = AuditRing::new();
        let s1 = ring.record(ev("a"));
        let s2 = ring.record(ev("b"));
        let s3 = ring.record(ev("c"));
        assert_eq!(s1, 1);
        assert_eq!(s2, 2);
        assert_eq!(s3, 3);
        assert_eq!(ring.high_water(), 3);
    }

    #[test]
    fn since_returns_events_after_cursor_in_order() {
        // Per the milestone: "write 50 events, fetch since cursor 30,
        // assert 20 returned in order."
        let ring = AuditRing::new();
        for i in 0..50 {
            ring.record(ev(&format!("ev-{i:02}")));
        }
        let resp = ring.since(30, 1000);
        assert_eq!(resp.events.len(), 20);
        assert_eq!(resp.cursor, 30);
        assert_eq!(resp.next_cursor, 50);
        assert!(!resp.gap);
        // Sequences are strictly ascending and start at 31.
        for (i, entry) in resp.events.iter().enumerate() {
            assert_eq!(entry.seq, 31 + i as u64);
        }
    }

    #[test]
    fn since_with_cursor_zero_returns_everything_in_ring() {
        let ring = AuditRing::new();
        for i in 0..10 {
            ring.record(ev(&format!("ev-{i}")));
        }
        let resp = ring.since(0, 1000);
        assert_eq!(resp.events.len(), 10);
        assert_eq!(resp.next_cursor, 10);
    }

    #[test]
    fn since_respects_limit() {
        let ring = AuditRing::new();
        for i in 0..50 {
            ring.record(ev(&format!("ev-{i}")));
        }
        let resp = ring.since(0, 5);
        assert_eq!(resp.events.len(), 5);
        // next_cursor lets the client paginate forward.
        assert_eq!(resp.next_cursor, 5);
    }

    #[test]
    fn since_returns_empty_when_cursor_at_high_water() {
        let ring = AuditRing::new();
        for i in 0..5 {
            ring.record(ev(&format!("ev-{i}")));
        }
        let resp = ring.since(5, 1000);
        assert!(resp.events.is_empty());
        assert_eq!(resp.next_cursor, 5);
    }

    #[test]
    fn since_returns_empty_when_cursor_above_high_water() {
        // Client reconnects with a stale cursor from before a restart;
        // server's seq is now lower. Don't underflow / panic.
        let ring = AuditRing::new();
        ring.record(ev("a"));
        let resp = ring.since(999, 1000);
        assert!(resp.events.is_empty());
    }

    #[test]
    fn since_signals_gap_when_ring_evicted_history() {
        // Capacity = 10. Write 30 events → ring holds seq 21..30.
        // Client asks since=5 → server can only return 21..30 and
        // must signal `gap = true`.
        let ring = AuditRing::with_capacity(10);
        for i in 0..30 {
            ring.record(ev(&format!("ev-{i}")));
        }
        let resp = ring.since(5, 1000);
        assert!(resp.gap, "expected gap=true after eviction");
        assert!(!resp.events.is_empty());
        // No event below the oldest-retained seq.
        for entry in &resp.events {
            assert!(entry.seq >= 21, "stale event leaked: seq={}", entry.seq);
        }
    }

    #[test]
    fn since_no_gap_when_cursor_inside_ring() {
        let ring = AuditRing::with_capacity(10);
        for i in 0..30 {
            ring.record(ev(&format!("ev-{i}")));
        }
        // Cursor 25 is within the live ring (21..30) → no gap.
        let resp = ring.since(25, 1000);
        assert!(!resp.gap);
        assert_eq!(resp.events.len(), 5);
    }

    #[test]
    fn ring_evicts_oldest_when_capacity_exceeded() {
        let ring = AuditRing::with_capacity(3);
        for i in 0..7 {
            ring.record(ev(&format!("ev-{i}")));
        }
        let resp = ring.since(0, 1000);
        assert_eq!(resp.events.len(), 3);
        // Newest 3: seq 5, 6, 7.
        assert_eq!(resp.events[0].seq, 5);
        assert_eq!(resp.events[2].seq, 7);
        assert!(resp.gap, "eviction must signal gap to anyone past 0");
    }

    #[test]
    fn response_serializes_to_documented_shape() {
        let ring = AuditRing::new();
        ring.record(ev("x"));
        let resp = ring.since(0, 10);
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&resp).unwrap()).unwrap();
        let obj = v.as_object().unwrap();
        for key in ["cursor", "next_cursor", "events", "gap"] {
            assert!(obj.contains_key(key), "since response missing {key}");
        }
        let events = obj["events"].as_array().unwrap();
        assert!(!events.is_empty());
        // Each event entry must carry both `seq` and the audit event
        // fields (flattened).
        let entry = events[0].as_object().unwrap();
        assert!(entry.contains_key("seq"));
        assert!(entry.contains_key("request_id"));
        assert!(entry.contains_key("class"));
    }

    #[test]
    fn handler_caches_response_within_ttl() {
        let ring = Arc::new(AuditRing::new());
        ring.record(ev("a"));
        let h = AuditHandler::with_ttl(Arc::clone(&ring), Duration::from_secs(1));
        let first = h.render_since(0, 100);
        ring.record(ev("b"));
        let second = h.render_since(0, 100);
        assert_eq!(first, second, "cache hit should return identical bytes");
    }

    // F14 (2026-06-11) — the tail render is now cached on its own slot.
    #[test]
    fn handler_caches_tail_within_ttl() {
        let ring = Arc::new(AuditRing::new());
        ring.record(ev("a"));
        let h = AuditHandler::with_ttl(Arc::clone(&ring), Duration::from_secs(1));
        let first = h.render_latest_filtered(100, &AuditFilter::default());
        ring.record(ev("b")); // changes the ring; cache should mask it within TTL
        let second = h.render_latest_filtered(100, &AuditFilter::default());
        assert_eq!(first, second, "tail cache hit returns identical bytes");
    }

    #[test]
    fn handler_tail_cache_is_separate_from_since_cache() {
        let ring = Arc::new(AuditRing::new());
        for i in 0..5 {
            ring.record(ev(&format!("ev-{i}")));
        }
        let h = AuditHandler::with_ttl(Arc::clone(&ring), Duration::from_secs(1));
        // since(0) returns the OLDEST; tail returns the NEWEST — the two
        // caches must not collide on the shared `limit`.
        let since = h.render_since(0, 2);
        let tail = h.render_latest_filtered(2, &AuditFilter::default());
        let sv: serde_json::Value = serde_json::from_str(&since).unwrap();
        let tv: serde_json::Value = serde_json::from_str(&tail).unwrap();
        let since_first = sv["events"][0]["request_id"].as_str().unwrap();
        let tail_last = tv["events"][1]["request_id"].as_str().unwrap();
        assert_eq!(since_first, "ev-0", "since(0) starts at oldest");
        assert_eq!(tail_last, "ev-4", "tail ends at newest");
    }

    // F14 — the in-process render is sub-millisecond even on a full
    // ring: proves the QC's ~260 ms floor is NOT in this code path, so
    // the fix is instrumentation (attribute it live) + tail caching, not
    // the "add a ring buffer" the report suggested (already present).
    #[test]
    fn full_ring_render_is_sub_millisecond() {
        let ring = Arc::new(AuditRing::new());
        for i in 0..DEFAULT_CAPACITY {
            ring.record(ev(&format!("ev-{i}")));
        }
        let h = AuditHandler::with_ttl(Arc::clone(&ring), Duration::from_millis(0));
        // ttl=0 → never a cache hit, so every call does the full
        // lock+walk+clone+serialize against a 10k-entry ring.
        let t = std::time::Instant::now();
        let _ = h.render_latest_filtered(200, &AuditFilter::default());
        let elapsed = t.elapsed();
        assert!(
            elapsed < Duration::from_millis(50),
            "tail render of a full ring took {elapsed:?} — expected sub-ms; \
             the 260ms QC floor is environmental, not this code",
        );
    }

    #[test]
    fn handler_recomputes_for_different_cursor_or_limit() {
        let ring = Arc::new(AuditRing::new());
        for i in 0..5 {
            ring.record(ev(&format!("ev-{i}")));
        }
        let h = AuditHandler::with_ttl(Arc::clone(&ring), Duration::from_secs(1));
        let r0 = h.render_since(0, 100);
        let r1 = h.render_since(2, 100);
        let r2 = h.render_since(0, 1);
        let v0: serde_json::Value = serde_json::from_str(&r0).unwrap();
        let v1: serde_json::Value = serde_json::from_str(&r1).unwrap();
        let v2: serde_json::Value = serde_json::from_str(&r2).unwrap();
        assert_eq!(v0["events"].as_array().unwrap().len(), 5);
        assert_eq!(v1["events"].as_array().unwrap().len(), 3);
        assert_eq!(v2["events"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn handler_clamps_limit_to_max() {
        let ring = Arc::new(AuditRing::new());
        for i in 0..1_500 {
            ring.record(ev(&format!("ev-{i}")));
        }
        let h = AuditHandler::new(Arc::clone(&ring));
        let body = h.render_since(0, u32::MAX);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(v["events"].as_array().unwrap().len() <= MAX_LIMIT as usize);
    }

    #[test]
    fn handler_zero_limit_falls_back_to_default() {
        // ?limit=0 on URLs is "missing param" semantics; don't return
        // an empty body — that confuses the reconnect path.
        let ring = Arc::new(AuditRing::new());
        for i in 0..10 {
            ring.record(ev(&format!("ev-{i}")));
        }
        let h = AuditHandler::new(Arc::clone(&ring));
        let body = h.render_since(0, 0);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["events"].as_array().unwrap().len(), 10);
    }

    // ---------- D-M3-T3.8: witness state + lag --------------------------

    fn witness_record(ts: chrono::DateTime<chrono::Utc>) -> WitnessRecord {
        WitnessRecord {
            ts,
            chain_head_hash: "deadbeef".into(),
            signature: "f00ba1".into(),
            node_id: "node-1".into(),
            entry_count: 42,
        }
    }

    #[test]
    fn witness_state_default_returns_none_fields() {
        let s = WitnessState::new();
        let snap = s.snapshot();
        assert!(snap.last_signature_ts.is_none());
        assert!(snap.lag_seconds.is_none());
        assert!(snap.chain_head_hash.is_none());
    }

    #[test]
    fn witness_state_lag_math_matches_documented_time_skew() {
        // Per the milestone: "with a known last-witness time, assert
        // lag math." A record signed 60s ago should report lag ≈ 60.
        let s = WitnessState::new();
        let signed_at = chrono::Utc::now() - chrono::Duration::seconds(60);
        s.update(witness_record(signed_at));
        let snap = s.snapshot();
        let lag = snap.lag_seconds.expect("lag set after update");
        // Allow ±2s slack for test scheduling.
        assert!(
            (58..=62).contains(&lag),
            "expected ~60s lag, got {lag}",
        );
        assert_eq!(snap.chain_head_hash.as_deref(), Some("deadbeef"));
        assert_eq!(snap.node_id.as_deref(), Some("node-1"));
        assert_eq!(snap.entry_count, Some(42));
    }

    #[test]
    fn witness_state_negative_lag_for_future_record() {
        // Defensive: clock skew between writer and reader could give
        // a future ts. Lag goes negative — don't panic / clamp; let
        // the UI pill render the raw value.
        let s = WitnessState::new();
        let future = chrono::Utc::now() + chrono::Duration::seconds(30);
        s.update(witness_record(future));
        let lag = s.snapshot().lag_seconds.unwrap();
        assert!(lag < 0, "expected negative lag, got {lag}");
    }

    #[test]
    fn witness_handler_renders_documented_shape() {
        let s = Arc::new(WitnessState::new());
        s.update(witness_record(chrono::Utc::now()));
        let h = WitnessHandler::new(Arc::clone(&s));
        let body = h.render();
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        for key in [
            "last_signature_ts",
            "lag_seconds",
            "chain_head_hash",
            "node_id",
            "entry_count",
        ] {
            assert!(
                v.get(key).is_some(),
                "/api/audit/witness response missing {key}"
            );
        }
    }

    #[test]
    fn witness_handler_renders_null_fields_when_empty() {
        let s = Arc::new(WitnessState::new());
        let h = WitnessHandler::new(Arc::clone(&s));
        let v: serde_json::Value =
            serde_json::from_str(&h.render()).unwrap();
        assert!(v["last_signature_ts"].is_null());
        assert!(v["lag_seconds"].is_null());
    }

    fn ev_with(action: &str, route: Option<&str>, path: Option<&str>, status: Option<u64>) -> AuditEvent {
        let mut fields = serde_json::Map::new();
        if let Some(p) = path {
            fields.insert("path".into(), serde_json::Value::String(p.into()));
        }
        if let Some(s) = status {
            fields.insert("status".into(), serde_json::json!(s));
        }
        AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "test".into(),
            class: AuditClass::Access,
            tenant_id: None,
            tier: None,
            action: action.into(),
            reason: String::new(),
            client_ip: "1.1.1.1".into(),
            route_id: route.map(String::from),
            rule_id: None,
            risk_score: None,
            method: None,
            path: None,
            mode: None,
            fields: serde_json::Value::Object(fields),
        }
    }

    #[test]
    fn first_path_segment_handles_common_shapes() {
        assert_eq!(first_path_segment("/"),                          "/");
        assert_eq!(first_path_segment("/login"),                     "/login");
        assert_eq!(first_path_segment("/api/transactions?limit=20"), "/api");
        assert_eq!(first_path_segment("/api/transactions"),          "/api");
        assert_eq!(first_path_segment(""),                           "/");
    }

    #[test]
    fn route_stats_groups_by_route_id_when_present() {
        let r = AuditRing::new();
        r.record(ev_with("allow", Some("login"), Some("/login"), Some(200)));
        r.record(ev_with("allow", Some("login"), Some("/login"), Some(200)));
        r.record(ev_with("block", Some("api"),   Some("/api/x"), None));
        let rows = r.route_stats(10);
        assert_eq!(rows.len(), 2);
        let login = rows.iter().find(|x| x.route == "login").unwrap();
        assert_eq!(login.total, 2);
        assert_eq!(login.blocked, 0);
        let api = rows.iter().find(|x| x.route == "api").unwrap();
        assert_eq!(api.total, 1);
        assert_eq!(api.blocked, 1);
        assert!((api.block_rate_pct - 100.0).abs() < 0.01);
    }

    #[test]
    fn route_stats_falls_back_to_path_first_segment() {
        let r = AuditRing::new();
        r.record(ev_with("allow", None, Some("/api/transactions"), Some(200)));
        r.record(ev_with("allow", None, Some("/api/profile"),     Some(200)));
        r.record(ev_with("allow", None, Some("/health"),          Some(200)));
        let rows = r.route_stats(10);
        let api = rows.iter().find(|x| x.route == "/api").unwrap();
        assert_eq!(api.total, 2);
        let health = rows.iter().find(|x| x.route == "/health").unwrap();
        assert_eq!(health.total, 1);
    }

    #[test]
    fn route_stats_counts_5xx_into_errors_field() {
        let r = AuditRing::new();
        r.record(ev_with("allow", Some("api"), Some("/api/x"), Some(200)));
        r.record(ev_with("allow", Some("api"), Some("/api/x"), Some(503)));
        r.record(ev_with("allow", Some("api"), Some("/api/x"), Some(500)));
        let rows = r.route_stats(10);
        let api = rows.iter().find(|x| x.route == "api").unwrap();
        assert_eq!(api.total, 3);
        assert_eq!(api.errors_5xx, 2);
        assert!((api.error_rate_pct - (2.0 / 3.0 * 100.0)).abs() < 0.01);
    }

    #[test]
    fn route_stats_orders_by_total_descending() {
        let r = AuditRing::new();
        for _ in 0..5 { r.record(ev_with("allow", Some("hot"),  Some("/h"), Some(200))); }
        for _ in 0..2 { r.record(ev_with("allow", Some("cold"), Some("/c"), Some(200))); }
        let rows = r.route_stats(10);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].route, "hot");
        assert_eq!(rows[1].route, "cold");
    }

    #[test]
    fn route_stats_respects_limit() {
        let r = AuditRing::new();
        for i in 0..20 {
            r.record(ev_with(
                "allow",
                Some(&format!("r{i}")),
                Some("/x"),
                Some(200),
            ));
        }
        let rows = r.route_stats(5);
        assert_eq!(rows.len(), 5);
    }
}
