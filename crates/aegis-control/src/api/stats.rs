//! `/api/stats` data layer (D-M2-T2.1).
//!
//! Pure-logic side of the Overview-page stats endpoint. The transport
//! (aegis-proxy admin router) builds a hyper response from
//! [`StatsHandler::render`].
//!
//! Architecture:
//! - [`StatsAggregator`] owns the rolling counters. Updated from the
//!   audit bus subscriber loop (`spawn_stats_task`) the same way the
//!   SSE handler consumes events — no extra hot-path cost on the
//!   data plane.
//! - [`StatsHandler`] wraps the aggregator with a 1 s response
//!   cache (`Mutex<Option<(Instant, StatsResponse)>>`) so a busy
//!   dashboard polling at 1 s doesn't recompute on every request.
//! - The JSON shape is documented in
//!   `docs/control-plane/enterprise/api.md` §"Stats / Overview".

#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aegis_core::audit::AuditEvent;
use serde::Serialize;

/// Rolling window for the request rate KPI on the Overview page.
const REQUEST_WINDOW: Duration = Duration::from_secs(10);
/// "Active threats" is anyone whose risk score crossed the threshold
/// in the last 5 minutes — long enough to surface ongoing actors,
/// short enough that the count drains after they go quiet.
const THREAT_WINDOW: Duration = Duration::from_secs(300);
/// Risk-score threshold above which an IP enters the active-threats
/// set. 70 mirrors the existing risk engine boundary documented in
/// `docs/security/risk-scoring.md`.
const DEFAULT_RISK_THRESHOLD: u32 = 70;
/// Default response cache TTL for [`StatsHandler::render`].
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(1);

/// Retention for per-second timeseries buckets (D-M2-T2.2). Sized
/// to cover the largest documented window (1h) plus a small margin
/// so a query at the boundary doesn't lose points.
const TIMESERIES_RETENTION_SECS: i64 = 3700;

/// Whether an audit `action` represents a terminal request decision that
/// should count toward request volume (Requests/s + the per-second chart).
///
/// 2026-06-21 — this is an **allow-list** of terminal decisions, on purpose.
/// Adjunct "shadow" detection events — `ddos_observed` / `ddos_blocked`,
/// emitted ALONGSIDE a request's terminal decision when the DDoS gate runs in
/// observe-only / log_only mode — must NOT count, or one request inflates the
/// rate ~2× (it emits the shadow event AND its `allow` / `circuit_breaker`
/// decision). A deny-list would let a future shadow action silently re-inflate
/// the metric; an allow-list fails safe (an unknown action just doesn't count).
/// Mirror the contract action strings in
/// [`aegis_control::interop::headers::Action::as_str`] when adding a decision.
fn counts_as_request(action: &str) -> bool {
    matches!(
        action,
        "allow"
            | "block"
            | "challenge"
            | "rate_limit"
            | "timeout"
            | "circuit_breaker"
            | "websocket_frame_block"
    )
}

/// Upstream-pool summary slot embedded in the stats response. The
/// real data source is wired by D-M2-T2.3
/// (`/api/upstreams/summary`); this module emits a placeholder so
/// the JSON shape stays stable across milestones.
#[derive(Clone, Debug, Serialize)]
pub struct UpstreamSummary {
    pub state: String,
    pub healthy_members: u32,
    pub total_members: u32,
}

impl UpstreamSummary {
    /// Placeholder value used until D-M2-T2.3 wires the cluster
    /// pool snapshot.
    pub fn placeholder() -> Self {
        Self {
            state: "Unknown".into(),
            healthy_members: 0,
            total_members: 0,
        }
    }
}

/// JSON shape returned by `GET /api/stats`. Matches
/// `docs/control-plane/enterprise/api.md` verbatim.
#[derive(Clone, Debug, Serialize)]
pub struct StatsResponse {
    pub request_rate: f64,
    pub blocks_total: u64,
    pub block_rate_pct: f64,
    pub active_threats: u32,
    pub upstream: UpstreamSummary,
    pub ts: chrono::DateTime<chrono::Utc>,
    /// Cluster Phase 4 (§2a) — when present, this response is a
    /// **fleet-merged** view and the value is the number of live nodes
    /// it merged. Absent ⇒ this node's local view. Lets the dashboard
    /// label "Fleet view (N nodes)" vs "This node" unambiguously.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fleet_nodes: Option<u32>,
}

/// One bucket of the timeseries response. `ts` is the bucket's start
/// instant (RFC 3339 with `Z` after JSON serialisation), aligned to
/// step boundaries.
#[derive(Clone, Debug, Serialize)]
pub struct TimeseriesPoint {
    pub ts: chrono::DateTime<chrono::Utc>,
    pub total: u32,
    pub blocked: u32,
}

/// JSON shape returned by `GET /api/stats/timeseries`. Matches
/// `docs/control-plane/enterprise/api.md` §"Stats / Overview".
#[derive(Clone, Debug, Serialize)]
pub struct TimeseriesResponse {
    pub window_seconds: u32,
    pub step_seconds: u32,
    pub points: Vec<TimeseriesPoint>,
}

#[derive(Clone, Copy, Default)]
struct SecondBucket {
    total: u32,
    blocked: u32,
}

#[derive(Default)]
struct AggregatorState {
    /// `(seen_at, was_block)` for every audit event in the broader
    /// retention window (max of REQUEST_WINDOW and THREAT_WINDOW).
    requests: VecDeque<(Instant, bool)>,
    /// Lifetime block counter — never decays; matches the `blocks_total`
    /// KPI the screenshot displays as a running total.
    blocks_total: u64,
    /// Last time each client IP was seen above the risk threshold.
    threat_seen: HashMap<String, Instant>,
    /// Per-second bucket totals for the timeseries endpoint.
    /// Key = unix epoch seconds. Sorted by key for cheap front-prune.
    seconds: BTreeMap<i64, SecondBucket>,
}

/// Rolling aggregator over [`AuditEvent`] stream. Cheap to share
/// (`Arc<Mutex<…>>`) across the audit subscriber task and the
/// HTTP handler.
#[derive(Clone)]
pub struct StatsAggregator {
    inner: Arc<Mutex<AggregatorState>>,
    risk_threshold: u32,
}

impl StatsAggregator {
    pub fn new() -> Self {
        Self::with_risk_threshold(DEFAULT_RISK_THRESHOLD)
    }

    pub fn with_risk_threshold(risk_threshold: u32) -> Self {
        Self {
            inner: Arc::new(Mutex::new(AggregatorState::default())),
            risk_threshold,
        }
    }

    /// Ingest one audit event. Cheap: a couple of `VecDeque` /
    /// `HashMap` ops behind a `Mutex`. No I/O.
    pub fn record(&self, ev: &AuditEvent) {
        let now = Instant::now();
        let was_block = ev.action == "block";
        // 2026-06-21 — count ONE event per request. Adjunct "shadow" detection
        // events (`ddos_observed` / `ddos_blocked`) are emitted ALONGSIDE the
        // request's terminal decision in observe/log_only mode; counting them
        // ~doubled Requests/s + the per-second chart. Only terminal decisions
        // contribute to request volume (see `counts_as_request`).
        let is_request = counts_as_request(ev.action.as_str());

        let mut state = self.inner.lock().expect("stats mutex poisoned");

        // Append the event and prune anything outside the broader
        // retention window (max of the request and threat windows).
        if is_request {
            state.requests.push_back((now, was_block));
        }
        let retention = REQUEST_WINDOW.max(THREAT_WINDOW);
        while let Some(&(t, _)) = state.requests.front() {
            if now.duration_since(t) > retention {
                state.requests.pop_front();
            } else {
                break;
            }
        }
        if was_block {
            state.blocks_total = state.blocks_total.saturating_add(1);
        }

        // Threat tracking: only events with a risk score above the
        // threshold and a non-empty client IP feed the active set.
        if let Some(score) = ev.risk_score {
            if score >= self.risk_threshold && !ev.client_ip.is_empty() {
                state.threat_seen.insert(ev.client_ip.clone(), now);
            }
        }

        // Drop threat entries older than the threat window.
        state
            .threat_seen
            .retain(|_, last| now.duration_since(*last) < THREAT_WINDOW);

        // Per-second bucket update for the timeseries endpoint
        // (D-M2-T2.2). Aligned to the event's wall-clock second so the
        // chart plots traffic at its actual time, not at ingest time.
        // Same one-event-per-request rule as the rate above — shadow
        // detection events don't bump the chart.
        let event_sec = ev.ts.timestamp();
        if is_request {
            let bucket = state.seconds.entry(event_sec).or_default();
            bucket.total = bucket.total.saturating_add(1);
            if was_block {
                bucket.blocked = bucket.blocked.saturating_add(1);
            }
        }
        let cutoff = event_sec - TIMESERIES_RETENTION_SECS;
        while let Some((&k, _)) = state.seconds.iter().next() {
            if k < cutoff {
                state.seconds.pop_first();
            } else {
                break;
            }
        }
    }

    /// Compute the current snapshot. Called by [`StatsHandler::render`]
    /// on cache miss.
    pub fn snapshot(&self) -> StatsResponse {
        let state = self.inner.lock().expect("stats mutex poisoned");
        let now = Instant::now();

        let mut total = 0u32;
        let mut blocked = 0u32;
        for &(t, was_block) in state.requests.iter().rev() {
            if now.duration_since(t) > REQUEST_WINDOW {
                break;
            }
            total += 1;
            if was_block {
                blocked += 1;
            }
        }

        let request_rate = f64::from(total) / REQUEST_WINDOW.as_secs_f64();
        let block_rate_pct = if total > 0 {
            f64::from(blocked) * 100.0 / f64::from(total)
        } else {
            0.0
        };

        let active_threats = state
            .threat_seen
            .values()
            .filter(|t| now.duration_since(**t) < THREAT_WINDOW)
            .count() as u32;

        StatsResponse {
            request_rate,
            blocks_total: state.blocks_total,
            block_rate_pct,
            active_threats,
            upstream: UpstreamSummary::placeholder(),
            ts: chrono::Utc::now(),
            fleet_nodes: None,
        }
    }

    /// Build a timeseries response for `GET /api/stats/timeseries`
    /// (D-M2-T2.2). `window_seconds` is the total span; `step_seconds`
    /// is the bucket width. Bucket count = `window / step`.
    ///
    /// Buckets are aligned to step boundaries on the wall clock so
    /// successive polls return overlapping bucket starts (the chart
    /// scrolls smoothly). Step is clamped to `[1, window]` — invalid
    /// callers get a single-bucket result rather than a panic.
    pub fn timeseries(
        &self,
        window_seconds: u32,
        step_seconds: u32,
    ) -> TimeseriesResponse {
        // Clamp step into [1, window]. Invalid input collapses to a
        // single bucket spanning the whole window.
        let window = window_seconds.max(1);
        let step = if step_seconds == 0 || step_seconds > window {
            window
        } else {
            step_seconds
        };
        let step_i64 = i64::from(step);
        let bucket_count = (window / step) as usize;

        // Step-aligned bucket boundaries on the wall clock so polls
        // overlap and the chart scrolls smoothly across refreshes.
        // The last bucket is the one *containing* `now`, so its end
        // is the next step boundary (exclusive).
        let now_sec = chrono::Utc::now().timestamp();
        let current_bucket_start = (now_sec / step_i64) * step_i64;
        let last_end = current_bucket_start + step_i64;
        let first_start = last_end - step_i64 * bucket_count as i64;

        let state = self.inner.lock().expect("stats mutex poisoned");
        let mut points = Vec::with_capacity(bucket_count);
        for i in 0..bucket_count {
            let bucket_start = first_start + step_i64 * i as i64;
            let bucket_end = bucket_start + step_i64;
            let mut total = 0u32;
            let mut blocked = 0u32;
            for (_, b) in state.seconds.range(bucket_start..bucket_end) {
                total = total.saturating_add(b.total);
                blocked = blocked.saturating_add(b.blocked);
            }
            points.push(TimeseriesPoint {
                ts: chrono::DateTime::<chrono::Utc>::from_timestamp(bucket_start, 0)
                    .unwrap_or_default(),
                total,
                blocked,
            });
        }

        TimeseriesResponse {
            window_seconds: window,
            step_seconds: step,
            points,
        }
    }
}

impl Default for StatsAggregator {
    fn default() -> Self {
        Self::new()
    }
}

/// Closure type for injecting upstream-summary data into stats
/// responses. The proxy plugs in a closure that walks the live
/// cluster pool state; tests use a placeholder.
type UpstreamProvider = Box<dyn Fn() -> UpstreamSummary + Send + Sync>;

/// HTTP-side wrapper. Serialises the aggregator snapshot to JSON
/// and caches the bytes for `cache_ttl` so polling clients (1 s
/// per `pages/overview.md`) don't recompute on every request.
///
/// `upstream_provider` is a closure invoked on every cache miss to
/// inject the current upstream summary into the response. The
/// default `new()` constructor wires it to `UpstreamSummary::placeholder()`;
/// the proxy uses [`with_upstream`] to plug in a real reader.
pub struct StatsHandler {
    agg: Arc<StatsAggregator>,
    upstream_provider: UpstreamProvider,
    cache: Mutex<Option<(Instant, StatsResponse)>>,
    cache_ttl: Duration,
}

impl StatsHandler {
    pub fn new(agg: Arc<StatsAggregator>) -> Self {
        Self::with_upstream(agg, UpstreamSummary::placeholder)
    }

    pub fn with_ttl(agg: Arc<StatsAggregator>, cache_ttl: Duration) -> Self {
        Self::with_ttl_and_upstream(agg, cache_ttl, UpstreamSummary::placeholder)
    }

    pub fn with_upstream<F>(agg: Arc<StatsAggregator>, upstream: F) -> Self
    where
        F: Fn() -> UpstreamSummary + Send + Sync + 'static,
    {
        Self::with_ttl_and_upstream(agg, DEFAULT_CACHE_TTL, upstream)
    }

    pub fn with_ttl_and_upstream<F>(
        agg: Arc<StatsAggregator>,
        cache_ttl: Duration,
        upstream: F,
    ) -> Self
    where
        F: Fn() -> UpstreamSummary + Send + Sync + 'static,
    {
        Self {
            agg,
            upstream_provider: Box::new(upstream),
            cache: Mutex::new(None),
            cache_ttl,
        }
    }

    /// Return the JSON body for `GET /api/stats`. Cached for
    /// `cache_ttl` so a polling client doesn't recompute the
    /// snapshot on every request. The upstream summary is
    /// refreshed on each cache miss.
    pub fn render(&self) -> String {
        let now = Instant::now();
        {
            let cache = self.cache.lock().expect("stats cache mutex poisoned");
            if let Some((stamped_at, response)) = cache.as_ref() {
                if now.duration_since(*stamped_at) < self.cache_ttl {
                    return serde_json::to_string(response)
                        .unwrap_or_else(|_| String::from("{}"));
                }
            }
        }

        // Cache miss: take a fresh aggregator snapshot, overlay the
        // current upstream summary, store and return.
        let mut response = self.agg.snapshot();
        response.upstream = (self.upstream_provider)();
        let body = serde_json::to_string(&response).unwrap_or_else(|_| String::from("{}"));
        let mut cache = self.cache.lock().expect("stats cache mutex poisoned");
        *cache = Some((now, response));
        body
    }

    /// Cluster Phase 3 (§2a) — render `GET /api/stats` from the merged
    /// fleet view instead of this node's local aggregator. The upstream
    /// summary stays node-local (pool health is per-node). Not cached:
    /// the fleet view is already refreshed on the publish tick.
    pub fn render_from_fleet(
        &self,
        merged: &crate::metrics::fleet_snapshot::MergedFleet,
    ) -> String {
        let response = StatsResponse {
            request_rate: merged.request_rate,
            blocks_total: merged.blocks_total,
            block_rate_pct: merged.block_rate_pct,
            active_threats: merged.active_threats,
            upstream: (self.upstream_provider)(),
            ts: chrono::Utc::now(),
            fleet_nodes: Some(merged.nodes as u32),
        };
        serde_json::to_string(&response).unwrap_or_else(|_| String::from("{}"))
    }
}

/// Spawn a task that drains the audit bus and feeds events into the
/// aggregator. Returns immediately; the task lives for the program's
/// lifetime (it ends when all `AuditBus` senders drop, which only
/// happens on shutdown).
pub fn spawn_stats_task(
    bus: aegis_core::AuditBus,
    agg: Arc<StatsAggregator>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut rx = bus.subscribe();
        while let Ok(ev) = rx.recv().await {
            agg.record(&ev);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::audit::AuditClass;

    fn ev(class: AuditClass, action: &str, ip: &str, risk: Option<u32>) -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts: chrono::Utc::now(),
            request_id: "test".into(),
            class,
            tenant_id: None,
            tier: None,
            action: action.into(),
            reason: "test".into(),
            client_ip: ip.into(),
            route_id: None,
            rule_id: None,
            risk_score: risk,
            method: None,
            path: None,
            mode: None,
            fields: serde_json::Value::Null,
        }
    }

    fn allow(ip: &str) -> AuditEvent {
        ev(AuditClass::Access, "allow", ip, None)
    }
    fn block(ip: &str) -> AuditEvent {
        ev(AuditClass::Detection, "block", ip, Some(80))
    }
    fn risk_at(ip: &str, score: u32) -> AuditEvent {
        ev(AuditClass::Detection, "challenge", ip, Some(score))
    }

    #[test]
    fn empty_aggregator_returns_zero_rate() {
        let agg = StatsAggregator::new();
        let s = agg.snapshot();
        assert_eq!(s.request_rate, 0.0);
        assert_eq!(s.blocks_total, 0);
        assert_eq!(s.block_rate_pct, 0.0);
        assert_eq!(s.active_threats, 0);
    }

    #[test]
    fn block_rate_pct_is_blocked_over_total() {
        // 7 allow + 3 block → 30% block rate, 3 blocks total.
        let agg = StatsAggregator::new();
        for _ in 0..7 {
            agg.record(&allow("1.1.1.1"));
        }
        for _ in 0..3 {
            agg.record(&block("2.2.2.2"));
        }
        let s = agg.snapshot();
        assert!(
            (s.block_rate_pct - 30.0).abs() < 0.01,
            "expected ~30%, got {}",
            s.block_rate_pct
        );
        assert_eq!(s.blocks_total, 3);
    }

    #[test]
    fn block_rate_pct_handles_zero_total() {
        // No requests → no division by zero, just 0%.
        let agg = StatsAggregator::new();
        let s = agg.snapshot();
        assert_eq!(s.block_rate_pct, 0.0);
    }

    #[test]
    fn request_rate_normalises_by_window_seconds() {
        // 20 events in a fresh aggregator → 20 / 10s = 2/s.
        let agg = StatsAggregator::new();
        for _ in 0..20 {
            agg.record(&allow("1.1.1.1"));
        }
        let s = agg.snapshot();
        assert!(
            (s.request_rate - 2.0).abs() < 0.01,
            "expected 2.0/s, got {}",
            s.request_rate
        );
    }

    // 2026-06-21 — request-rate must count ONE event per request. In DDoS
    // observe/log_only mode an inspected request emits a shadow detection event
    // (`ddos_observed` / `ddos_blocked`) AND its terminal decision (`allow` /
    // `circuit_breaker`). Counting both ~doubled Requests/s. Only terminal
    // actions count toward request volume.
    #[test]
    fn ddos_observed_does_not_count_as_request() {
        let agg = StatsAggregator::new();
        // One logical request in observe mode: shadow event + terminal allow.
        agg.record(&ev(AuditClass::Detection, "ddos_observed", "9.9.9.9", None));
        agg.record(&allow("9.9.9.9"));
        let s = agg.snapshot();
        // 1 request / 10s window = 0.1/s — NOT 0.2 (would be double-count).
        assert!(
            (s.request_rate - 0.1).abs() < 1e-9,
            "ddos_observed must not count as a request; got {}/s",
            s.request_rate,
        );
    }

    #[test]
    fn ddos_blocked_shadow_does_not_count_as_request() {
        let agg = StatsAggregator::new();
        // log_only: shadow `ddos_blocked` + terminal allow.
        agg.record(&ev(AuditClass::Detection, "ddos_blocked", "9.9.9.9", None));
        agg.record(&allow("9.9.9.9"));
        let s = agg.snapshot();
        assert!(
            (s.request_rate - 0.1).abs() < 1e-9,
            "ddos_blocked shadow must not count as a request; got {}/s",
            s.request_rate,
        );
    }

    #[test]
    fn enforced_ddos_block_still_counts_once() {
        // Enforce mode emits a single terminal `block` — it MUST count (and as
        // a block), so excluding the shadow actions can't regress block-rate.
        let agg = StatsAggregator::new();
        agg.record(&block("2.2.2.2"));
        let s = agg.snapshot();
        assert!((s.request_rate - 0.1).abs() < 1e-9, "block counts as 1 request");
        assert_eq!(s.blocks_total, 1);
        assert!((s.block_rate_pct - 100.0).abs() < 0.01);
    }

    #[test]
    fn terminal_actions_all_count_as_requests() {
        // Locks the terminal allow-list: every real decision counts as 1.
        let agg = StatsAggregator::new();
        agg.record(&ev(AuditClass::Access, "allow", "1.1.1.1", None));
        agg.record(&ev(AuditClass::Detection, "block", "1.1.1.1", Some(80)));
        agg.record(&ev(AuditClass::Detection, "challenge", "1.1.1.1", Some(50)));
        agg.record(&ev(AuditClass::Detection, "rate_limit", "1.1.1.1", None));
        agg.record(&ev(AuditClass::Detection, "timeout", "1.1.1.1", None));
        agg.record(&ev(AuditClass::Detection, "circuit_breaker", "1.1.1.1", None));
        let s = agg.snapshot();
        // 6 terminal events / 10s = 0.6/s.
        assert!(
            (s.request_rate - 0.6).abs() < 1e-9,
            "all terminal actions must count; got {}/s",
            s.request_rate,
        );
    }

    #[test]
    fn timeseries_excludes_ddos_observed() {
        let agg = StatsAggregator::new();
        for _ in 0..3 {
            agg.record(&allow("1.1.1.1"));
        }
        for _ in 0..2 {
            agg.record(&ev(AuditClass::Detection, "ddos_observed", "9.9.9.9", None));
        }
        let ts = agg.timeseries(60, 1);
        let total: u32 = ts.points.iter().map(|p| p.total).sum();
        assert_eq!(total, 3, "per-second chart must not count shadow events");
    }

    #[test]
    fn active_threats_counts_distinct_high_risk_ips() {
        let agg = StatsAggregator::new();
        agg.record(&risk_at("1.1.1.1", 80));
        agg.record(&risk_at("2.2.2.2", 90));
        agg.record(&risk_at("3.3.3.3", 70)); // exactly threshold = in
        agg.record(&risk_at("4.4.4.4", 50)); // below threshold = out
        agg.record(&risk_at("1.1.1.1", 85)); // duplicate IP, same actor
        let s = agg.snapshot();
        assert_eq!(s.active_threats, 3);
    }

    #[test]
    fn active_threats_ignores_events_without_risk_score() {
        let agg = StatsAggregator::new();
        agg.record(&allow("1.1.1.1")); // risk = None
        agg.record(&allow("2.2.2.2")); // risk = None
        let s = agg.snapshot();
        assert_eq!(s.active_threats, 0);
    }

    #[test]
    fn active_threats_ignores_empty_client_ip() {
        // System events have empty client_ip; they must not count
        // as a "threat" regardless of risk score.
        let agg = StatsAggregator::new();
        let mut e = risk_at("", 90);
        e.client_ip = String::new();
        agg.record(&e);
        let s = agg.snapshot();
        assert_eq!(s.active_threats, 0);
    }

    #[test]
    fn stats_response_serializes_to_documented_shape() {
        let agg = StatsAggregator::new();
        let s = agg.snapshot();
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        let obj = json.as_object().expect("top-level object");
        for key in [
            "request_rate",
            "blocks_total",
            "block_rate_pct",
            "active_threats",
            "upstream",
            "ts",
        ] {
            assert!(obj.contains_key(key), "stats response missing key {key}");
        }
        let upstream = obj["upstream"].as_object().expect("upstream object");
        for key in ["state", "healthy_members", "total_members"] {
            assert!(
                upstream.contains_key(key),
                "upstream summary missing key {key}"
            );
        }
    }

    #[test]
    fn handler_caches_response_within_ttl() {
        // Two consecutive renders within TTL should return identical
        // bytes — even if the aggregator state changes between them.
        let agg = Arc::new(StatsAggregator::new());
        agg.record(&allow("1.1.1.1"));
        let h = StatsHandler::with_ttl(Arc::clone(&agg), Duration::from_secs(1));
        let first = h.render();
        // Mutate aggregator; cached response must NOT reflect the change.
        agg.record(&block("2.2.2.2"));
        let second = h.render();
        assert_eq!(first, second, "cached response should be identical");
    }

    #[test]
    fn handler_invalidates_after_ttl() {
        let agg = Arc::new(StatsAggregator::new());
        let h = StatsHandler::with_ttl(Arc::clone(&agg), Duration::from_millis(20));
        let first = h.render();
        agg.record(&allow("1.1.1.1"));
        std::thread::sleep(Duration::from_millis(40));
        let second = h.render();
        assert_ne!(first, second, "cache should expire after TTL");
    }

    #[test]
    fn handler_render_emits_valid_json() {
        let agg = Arc::new(StatsAggregator::new());
        let h = StatsHandler::new(agg);
        let json = h.render();
        let _: serde_json::Value =
            serde_json::from_str(&json).expect("render must emit valid JSON");
    }

    #[test]
    fn risk_threshold_is_configurable() {
        // Threshold lowered to 50 → events at 50 register as threats.
        let agg = StatsAggregator::with_risk_threshold(50);
        agg.record(&risk_at("1.1.1.1", 50));
        agg.record(&risk_at("2.2.2.2", 49));
        let s = agg.snapshot();
        assert_eq!(s.active_threats, 1);
    }

    // ---------- D-M2-T2.2: /api/stats/timeseries ------------------------

    #[test]
    fn timeseries_response_carries_window_and_step() {
        let agg = StatsAggregator::new();
        let ts = agg.timeseries(60, 5);
        assert_eq!(ts.window_seconds, 60);
        assert_eq!(ts.step_seconds, 5);
    }

    #[test]
    fn timeseries_points_count_matches_window_div_step() {
        let agg = StatsAggregator::new();
        for &(window, step, expected) in &[
            (60u32, 1u32, 60usize),
            (60, 5, 12),
            (300, 5, 60),
            (900, 5, 180),
            (900, 15, 60),
            (3600, 60, 60),
        ] {
            let ts = agg.timeseries(window, step);
            assert_eq!(
                ts.points.len(),
                expected,
                "window={window} step={step}: expected {expected} points"
            );
        }
    }

    #[test]
    fn timeseries_empty_aggregator_all_zero() {
        let agg = StatsAggregator::new();
        let ts = agg.timeseries(60, 1);
        for p in &ts.points {
            assert_eq!(p.total, 0);
            assert_eq!(p.blocked, 0);
        }
    }

    #[test]
    fn timeseries_records_event_into_buckets() {
        // Record N events; sum of point totals should equal N within
        // the recent window (events are timestamped with chrono::Utc::now,
        // so they all land in the most recent few seconds).
        let agg = StatsAggregator::new();
        for _ in 0..20 {
            agg.record(&allow("1.1.1.1"));
        }
        let ts = agg.timeseries(60, 1);
        let total: u32 = ts.points.iter().map(|p| p.total).sum();
        assert_eq!(total, 20, "sum of point totals should equal recorded events");
    }

    #[test]
    fn timeseries_separates_total_from_blocked() {
        let agg = StatsAggregator::new();
        for _ in 0..7 {
            agg.record(&allow("1.1.1.1"));
        }
        for _ in 0..3 {
            agg.record(&block("2.2.2.2"));
        }
        let ts = agg.timeseries(60, 1);
        let total: u32 = ts.points.iter().map(|p| p.total).sum();
        let blocked: u32 = ts.points.iter().map(|p| p.blocked).sum();
        assert_eq!(total, 10);
        assert_eq!(blocked, 3);
    }

    #[test]
    fn timeseries_points_are_chronologically_ordered() {
        let agg = StatsAggregator::new();
        let ts = agg.timeseries(60, 5);
        let timestamps: Vec<i64> = ts.points.iter().map(|p| p.ts.timestamp()).collect();
        assert!(timestamps.len() >= 2);
        for w in timestamps.windows(2) {
            assert!(w[0] < w[1], "expected strictly ascending ts, got {timestamps:?}");
        }
    }

    #[test]
    fn timeseries_points_are_step_aligned() {
        // Each bucket's ts is a multiple of step_seconds (epoch-aligned).
        let agg = StatsAggregator::new();
        let step = 5i64;
        let ts = agg.timeseries(60, step as u32);
        for p in &ts.points {
            assert_eq!(
                p.ts.timestamp() % step,
                0,
                "bucket ts {p:?} not aligned to step={step}"
            );
        }
    }

    #[test]
    fn timeseries_clamps_step_above_window() {
        // Invalid step (> window) collapses to a single bucket rather
        // than panicking or returning an empty list.
        let agg = StatsAggregator::new();
        let ts = agg.timeseries(60, 120);
        assert_eq!(ts.points.len(), 1);
    }

    #[test]
    fn timeseries_handles_zero_step() {
        // step=0 must not panic / divide-by-zero. Treat as invalid →
        // one bucket spanning the whole window.
        let agg = StatsAggregator::new();
        let ts = agg.timeseries(60, 0);
        assert_eq!(ts.points.len(), 1);
    }

    #[test]
    fn timeseries_response_serializes_to_documented_shape() {
        let agg = StatsAggregator::new();
        agg.record(&allow("1.1.1.1"));
        let ts = agg.timeseries(60, 5);
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&ts).unwrap()).unwrap();
        let obj = json.as_object().expect("top-level object");
        for key in ["window_seconds", "step_seconds", "points"] {
            assert!(obj.contains_key(key), "timeseries response missing {key}");
        }
        let points = obj["points"].as_array().expect("points must be array");
        assert!(!points.is_empty());
        let first = points[0].as_object().expect("point object");
        for key in ["ts", "total", "blocked"] {
            assert!(first.contains_key(key), "point missing key {key}");
        }
    }

    // ---------- D-M2-T2.7: stats handler with upstream provider --------

    #[test]
    fn handler_with_upstream_provider_overrides_placeholder() {
        // The proxy wires StatsHandler with a closure pulling cluster
        // pool state. Verify the closure value lands in the rendered
        // response instead of the default placeholder ("Unknown").
        let agg = Arc::new(StatsAggregator::new());
        let h = StatsHandler::with_upstream(agg, || UpstreamSummary {
            state: "Healthy".into(),
            healthy_members: 4,
            total_members: 4,
        });
        let body = h.render();
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["upstream"]["state"].as_str(), Some("Healthy"));
        assert_eq!(v["upstream"]["healthy_members"].as_u64(), Some(4));
        assert_eq!(v["upstream"]["total_members"].as_u64(), Some(4));
    }

    #[test]
    fn handler_default_upstream_is_placeholder() {
        // Back-compat: the no-provider constructor still emits the
        // placeholder shape so existing callers don't break.
        let agg = Arc::new(StatsAggregator::new());
        let h = StatsHandler::new(agg);
        let body = h.render();
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["upstream"]["state"].as_str(), Some("Unknown"));
    }
}
