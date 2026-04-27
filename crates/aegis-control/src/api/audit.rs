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

    /// Current high-water-mark sequence (next seq about to be
    /// assigned, minus one). Useful for tests + monitoring.
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
            cache_ttl,
        }
    }

    /// Render `GET /api/audit/since?cursor=<n>&limit=<m>`. `limit` is
    /// clamped to `[1, MAX_LIMIT]`; missing/malformed values use
    /// `DEFAULT_LIMIT`.
    pub fn render_since(&self, cursor: u64, limit: u32) -> String {
        let now = Instant::now();
        let limit = clamp_limit(limit);
        {
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
        }
        let resp = self.ring.since(cursor, limit);
        let body = serde_json::to_string(&resp).unwrap_or_else(|_| String::from("{}"));
        let mut cache = self.cache.lock().expect("audit cache poisoned");
        *cache = Some((now, cursor, limit, resp));
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
            fields: serde_json::Value::Null,
        }
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
}
