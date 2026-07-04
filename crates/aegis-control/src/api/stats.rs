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


use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aegis_core::audit::AuditEvent;
use aegis_core::state::{StateBackend, CONTROL_STATS_COUNTERS_KEY};
use serde::{Deserialize, Serialize};

/// How often the background task persists the lifetime counters. Restart-only
/// knob for now (promoted to the `persistence` config block with H2a). The
/// flush does ZERO Redis I/O per audit event — it snapshots in memory and
/// writes once per interval — so it can never add broadcast `Lagged` drops
/// under a saturated audit bus (redis-interim-durability §9 invariant 5).
const COUNTER_FLUSH_INTERVAL: Duration = Duration::from_secs(5);

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
/// to cover a 1h fine-grained window plus a small margin so a query
/// at the boundary doesn't lose points.
const TIMESERIES_RETENTION_SECS: i64 = 3700;

/// PR-D (2026-07-02) — retention for the per-MINUTE downsampled tier:
/// 24 h plus a 2-minute boundary margin. Every request lands in both
/// stores at record time (~1440 extra `SecondBucket`s — trivial memory);
/// minute-aligned queries (step >= 60 and % 60 == 0 — every dashboard
/// window chip) read this tier, so 6h/24h charts are honestly served.
/// Still in-memory: durable, restart-surviving history stays a non-goal.
const TIMESERIES_MINUTE_RETENTION_SECS: i64 = 86_520;

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
    /// PR-C P5.1 (2026-07-02) — how much history this series can
    /// actually contain. Buckets older than this are structurally
    /// empty (not "no traffic"); the dashboard gates its window chips
    /// + captions on this instead of hardcoded copy. Node-local reads
    /// report the seconds-store retention; fleet-merged reads report
    /// the (smaller) fleet snapshot window.
    pub retention_seconds: u32,
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
    /// PR-D — per-minute downsampled tier (key = minute-start epoch
    /// seconds), retained ~24 h. Written alongside `seconds` on every
    /// request; serves minute-aligned (coarse) queries.
    minutes: BTreeMap<i64, SecondBucket>,
}

/// Rolling aggregator over [`AuditEvent`] stream. Cheap to share
/// (`Arc<Mutex<…>>`) across the audit subscriber task and the
/// HTTP handler.
#[derive(Clone)]
pub struct StatsAggregator {
    inner: Arc<Mutex<AggregatorState>>,
    risk_threshold: u32,
    /// 2026-06-24 — durable-store handle for the interim Redis durability
    /// bridge (`redis-interim-durability` P3): persists the small monotone
    /// lifetime counters (`blocks_total`, …) to `control:waf:stats:counters`
    /// so the Overview top-line survives a restart. `None` on the no-Redis
    /// path. A0 only stores the handle (inert); the separate interval flush
    /// task + boot reload that read it land in A3.
    backend: Option<Arc<dyn StateBackend>>,
}

impl StatsAggregator {
    pub fn new() -> Self {
        Self::with_risk_threshold(DEFAULT_RISK_THRESHOLD)
    }

    pub fn with_risk_threshold(risk_threshold: u32) -> Self {
        Self::build(risk_threshold, None)
    }

    /// Build an aggregator with an optional durable backend. Pass
    /// `Some(..)` (under `#[cfg(feature = "redis")]`) to enable P3 counter
    /// durability; `None` is the in-memory-only path.
    pub fn with_backend(backend: Option<Arc<dyn StateBackend>>) -> Self {
        Self::build(DEFAULT_RISK_THRESHOLD, backend)
    }

    fn build(risk_threshold: u32, backend: Option<Arc<dyn StateBackend>>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(AggregatorState::default())),
            risk_threshold,
            backend,
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
            // PR-D — fold into the minute tier at record time (no
            // background compaction pass needed; both stores are
            // authoritative for their own granularity).
            let minute_start = (event_sec.div_euclid(60)) * 60;
            let mbucket = state.minutes.entry(minute_start).or_default();
            mbucket.total = mbucket.total.saturating_add(1);
            if was_block {
                mbucket.blocked = mbucket.blocked.saturating_add(1);
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
        let minute_cutoff = event_sec - TIMESERIES_MINUTE_RETENTION_SECS;
        while let Some((&k, _)) = state.minutes.iter().next() {
            if k < minute_cutoff {
                state.minutes.pop_first();
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
    /// Sparse per-second traffic buckets within the last `retention_secs`
    /// (only seconds that saw traffic), as `(epoch_sec, total, blocked)`
    /// ascending. Feeds the bounded fleet-timeseries snapshot.
    pub fn recent_seconds(&self, retention_secs: u32) -> Vec<(i64, u32, u32)> {
        let now_sec = chrono::Utc::now().timestamp();
        let cutoff = now_sec - i64::from(retention_secs);
        let state = self.inner.lock().expect("stats mutex poisoned");
        state
            .seconds
            .range(cutoff..)
            .map(|(&sec, b)| (sec, b.total, b.blocked))
            .collect()
    }

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

        // PR-D — store selection. Minute-aligned coarse steps (every
        // dashboard window chip: 60/300/1200) read the ~24h minute
        // tier; fine or unaligned steps keep the ~62min seconds store
        // (a minute bucket would straddle two unaligned step buckets).
        // Step-aligned bucket starts are multiples of `step`, which is
        // a multiple of 60 on the minute path — so every minute key in
        // [start, end) belongs to exactly one bucket.
        let use_minutes = step >= 60 && step % 60 == 0;

        // Step-aligned bucket boundaries on the wall clock so polls
        // overlap and the chart scrolls smoothly across refreshes.
        // The last bucket is the one *containing* `now`, so its end
        // is the next step boundary (exclusive).
        let now_sec = chrono::Utc::now().timestamp();
        let current_bucket_start = (now_sec / step_i64) * step_i64;
        let last_end = current_bucket_start + step_i64;
        let first_start = last_end - step_i64 * bucket_count as i64;

        let state = self.inner.lock().expect("stats mutex poisoned");
        let store = if use_minutes { &state.minutes } else { &state.seconds };
        let mut points = Vec::with_capacity(bucket_count);
        for i in 0..bucket_count {
            let bucket_start = first_start + step_i64 * i as i64;
            let bucket_end = bucket_start + step_i64;
            let mut total = 0u32;
            let mut blocked = 0u32;
            for (_, b) in store.range(bucket_start..bucket_end) {
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
            retention_seconds: if use_minutes {
                TIMESERIES_MINUTE_RETENTION_SECS as u32
            } else {
                TIMESERIES_RETENTION_SECS as u32
            },
            points,
        }
    }

    // --- 2026-06-24 (redis-interim-durability P3) — durable lifetime
    // counters. Stored per-node (field = node id) in the
    // `control:waf:stats:counters` hash as an ABSOLUTE snapshot, NOT a shared
    // INCRBY: the fleet view already SUMS each node's local `blocks_total`
    // (`fleet_snapshot::merge`), so a shared cross-node counter would
    // double-count. Per-node single-writer → an idempotent overwrite is both
    // correct and self-healing (the next tick re-writes the live value, so a
    // reset that races a flush converges within one interval — no fence
    // needed, unlike the append-semantics risk strikes in A2). ---

    /// Snapshot the lifetime counters under the `Mutex`, release, then write
    /// them to this node's field outside the lock (§9 invariant 5: never hold
    /// the lock across Redis I/O). No-op without a backend.
    pub async fn flush_counters(&self, node_id: &str) {
        let Some(backend) = self.backend.as_ref() else {
            return;
        };
        let counters = {
            let state = self.inner.lock().expect("stats mutex poisoned");
            DurableCounters {
                blocks_total: state.blocks_total,
            }
        };
        let json = match serde_json::to_vec(&counters) {
            Ok(j) => j,
            Err(e) => {
                tracing::warn!(error = %e, "stats counter flush: encode failed");
                return;
            }
        };
        if let Err(e) = backend
            .hset_multi(CONTROL_STATS_COUNTERS_KEY, &[(node_id.to_string(), json)])
            .await
        {
            tracing::warn!(error = %e, "stats counter flush: write failed");
        }
    }

    /// Boot reload (P3): seed the lifetime counters from this node's durable
    /// field so the Overview top-line survives a restart. Seeds with `max` of
    /// the durable and current values — it can only ever RAISE the counter,
    /// never lower it, so a re-hydrate or a flush that somehow raced ahead
    /// can't roll the total backward. In the normal post-restart case the
    /// durable total dominates; any blocks that arrived in the brief warm-up
    /// before this runs are absorbed into that (larger) total rather than
    /// added — a small, bounded undercount that is acceptable for a
    /// display-only counter. No-op without a backend; a corrupt field is
    /// ignored.
    pub async fn hydrate(&self, node_id: &str) {
        let Some(backend) = self.backend.as_ref() else {
            return;
        };
        let fields = match backend.hscan(CONTROL_STATS_COUNTERS_KEY).await {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(error = %e, "stats counter hydrate: hscan failed");
                return;
            }
        };
        let Some((_, bytes)) = fields.into_iter().find(|(f, _)| f == node_id) else {
            return; // this node has no persisted counters yet
        };
        let Ok(counters) = serde_json::from_slice::<DurableCounters>(&bytes) else {
            tracing::warn!("stats counter hydrate: decode skipped");
            return;
        };
        let mut state = self.inner.lock().expect("stats mutex poisoned");
        state.blocks_total = state.blocks_total.max(counters.blocks_total);
        if counters.blocks_total > 0 {
            tracing::info!(
                blocks_total = counters.blocks_total,
                "stats counters hydrated from durable store"
            );
        }
    }

    /// Reset hook (sync half) — zero the lifetime counters. Paired with
    /// [`forget_durable`] so `reset_state` gives a clean Overview slate that
    /// doesn't resurrect on the next boot (§4). A flush racing this reset is
    /// self-healing for the LIVE value: the next flush tick snapshots the
    /// now-zero in-memory counter and overwrites any stale durable value
    /// within one `COUNTER_FLUSH_INTERVAL`. The one residual window is a node
    /// restart inside that interval, which would re-hydrate the stale total —
    /// acceptable for a display-only counter, not an enforcement signal.
    ///
    /// [`forget_durable`]: Self::forget_durable
    pub fn reset_counters(&self) {
        let mut state = self.inner.lock().expect("stats mutex poisoned");
        state.blocks_total = 0;
    }

    /// Reset hook (async half) — `HDEL` this node's durable counter field.
    /// No-op without a backend.
    pub async fn forget_durable(&self, node_id: &str) {
        let Some(backend) = self.backend.as_ref() else {
            return;
        };
        if let Err(e) = backend
            .hdel(CONTROL_STATS_COUNTERS_KEY, &[node_id.to_string()])
            .await
        {
            tracing::warn!(error = %e, "stats counter reset: durable hdel failed");
        }
    }

    /// Spawn the background durability task: hydrate this node's counters
    /// once, THEN run the periodic flush loop. Hydrate and flush share one
    /// task (rather than two) so the flush can never run before the hydrate
    /// completes — `tokio::time::interval`'s first tick fires immediately, so
    /// a separate flush task could otherwise snapshot the near-zero warm-up
    /// value and overwrite the durable total before it was ever read back.
    /// No-op (spawns nothing) without a backend. Returns the task handle;
    /// drop to detach (fire-and-forget).
    pub fn spawn_persistence(&self, node_id: String) -> Option<tokio::task::JoinHandle<()>> {
        self.backend.as_ref()?;
        let this = self.clone();
        Some(tokio::spawn(async move {
            this.hydrate(&node_id).await;
            let mut tick = tokio::time::interval(COUNTER_FLUSH_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // Consume the immediate first tick so the first flush is one full
            // interval after hydrate, not back-to-back with it.
            tick.tick().await;
            loop {
                tick.tick().await;
                this.flush_counters(&node_id).await;
            }
        }))
    }
}

/// Durable wire shape for one node's lifetime counters (value of its field in
/// `control:waf:stats:counters`). A struct (not a bare `u64`) so more monotone
/// totals can be added later without a migration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
struct DurableCounters {
    #[serde(default)]
    blocks_total: u64,
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

/// Pure, deterministic bucketiser shared by the fleet timeseries path.
/// Mirrors `StatsAggregator::timeseries` alignment (step-aligned wall-
/// clock boundaries) but takes an explicit `now_sec` and a pre-summed
/// per-second map, so it is testable without a clock.
fn bucketize_seconds(
    by_sec: &BTreeMap<i64, (u32, u32)>,
    now_sec: i64,
    window_seconds: u32,
    step_seconds: u32,
) -> TimeseriesResponse {
    let window = window_seconds.max(1);
    let step = if step_seconds == 0 || step_seconds > window {
        window
    } else {
        step_seconds
    };
    let step_i64 = i64::from(step);
    let bucket_count = (window / step) as usize;
    let current_bucket_start = (now_sec / step_i64) * step_i64;
    let last_end = current_bucket_start + step_i64;
    let first_start = last_end - step_i64 * bucket_count as i64;

    let mut points = Vec::with_capacity(bucket_count);
    for i in 0..bucket_count {
        let bucket_start = first_start + step_i64 * i as i64;
        let bucket_end = bucket_start + step_i64;
        let mut total = 0u32;
        let mut blocked = 0u32;
        for (_, (t, b)) in by_sec.range(bucket_start..bucket_end) {
            total = total.saturating_add(*t);
            blocked = blocked.saturating_add(*b);
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
        // Fleet-merged series only ever contain the bounded snapshot
        // window — report THAT as the retention so the dashboard's
        // truth-gate reflects the fleet path's tighter bound.
        retention_seconds: crate::metrics::fleet_snapshot::FLEET_TIMESERIES_MAX_WINDOW_SECS,
        points,
    }
}

/// Fleet-merged `GET /api/stats/timeseries`. Re-buckets the merged
/// per-second traffic (summed across nodes) into the same wire shape as
/// the node-local `timeseries`. The merged series is bounded to a recent
/// window; callers serve only windows within that bound on the fleet
/// path and fall back node-local beyond it.
pub fn timeseries_from_fleet(
    seconds: &[crate::metrics::fleet_snapshot::SnapSecond],
    window_seconds: u32,
    step_seconds: u32,
) -> TimeseriesResponse {
    let by_sec: BTreeMap<i64, (u32, u32)> = seconds
        .iter()
        .map(|s| (s.sec, (s.total, s.blocked)))
        .collect();
    bucketize_seconds(
        &by_sec,
        chrono::Utc::now().timestamp(),
        window_seconds,
        step_seconds,
    )
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

    /// PR-C P5.1 (2026-07-02) — the response self-describes how much
    /// history the store actually retains, so the dashboard can gate
    /// window chips + captions from truth instead of hardcoded copy
    /// (the 24h-default-vs-62min-retention flat-chart bug).
    #[test]
    fn timeseries_response_reports_retention() {
        let agg = StatsAggregator::new();
        let ts = agg.timeseries(60, 5);
        assert_eq!(ts.retention_seconds, TIMESERIES_RETENTION_SECS as u32);
        let json = serde_json::to_value(&ts).unwrap();
        assert_eq!(
            json["retention_seconds"], TIMESERIES_RETENTION_SECS,
            "retention must be on the wire for the frontend gate"
        );
    }

    // ---- PR-D (2026-07-02) — per-minute downsampled tier ---------------
    //
    // Seconds stay at ~62 min (unchanged); every request ALSO lands in a
    // per-minute bucket retained ~24 h. Queries with a minute-aligned
    // step (>= 60, % 60 == 0 — every dashboard chip) read the minute
    // tier and report its retention, so the 6h/24h chips un-gate;
    // fine-grained steps (Overview's 900/5) keep seconds semantics.

    fn allow_at(ip: &str, ts: chrono::DateTime<chrono::Utc>) -> AuditEvent {
        let mut e = allow(ip);
        e.ts = ts;
        e
    }

    #[test]
    fn minute_tier_serves_a_24h_window() {
        let agg = StatsAggregator::new();
        let now = chrono::Utc::now();
        // Two hours old — far beyond the 3700 s seconds store.
        agg.record(&allow_at("1.1.1.1", now - chrono::Duration::hours(2)));
        agg.record(&block("2.2.2.2")); // now — its cutoff prunes the old SECOND
        let ts = agg.timeseries(86_400, 1200);
        let total: u32 = ts.points.iter().map(|p| p.total).sum();
        let blocked: u32 = ts.points.iter().map(|p| p.blocked).sum();
        assert_eq!(total, 2, "the 2h-old event must survive in the minute tier");
        assert_eq!(blocked, 1);
        assert_eq!(ts.retention_seconds, TIMESERIES_MINUTE_RETENTION_SECS as u32);
    }

    #[test]
    fn minute_and_second_paths_agree_on_recent_traffic() {
        // Cross-tier stitch: the same recent traffic must sum identically
        // whether served from seconds (fine step) or minutes (coarse step).
        let agg = StatsAggregator::new();
        for _ in 0..5 {
            agg.record(&allow("1.1.1.1"));
        }
        agg.record(&block("2.2.2.2"));
        let fine = agg.timeseries(900, 5); // seconds store
        let coarse = agg.timeseries(900, 60); // minute store
        assert_eq!(fine.points.iter().map(|p| p.total).sum::<u32>(), 6);
        assert_eq!(coarse.points.iter().map(|p| p.total).sum::<u32>(), 6);
        assert_eq!(coarse.points.iter().map(|p| p.blocked).sum::<u32>(), 1);
        assert_eq!(coarse.retention_seconds, TIMESERIES_MINUTE_RETENTION_SECS as u32);
    }

    #[test]
    fn sub_minute_and_unaligned_steps_keep_seconds_semantics() {
        let agg = StatsAggregator::new();
        // Fine step — seconds store, seconds retention.
        assert_eq!(
            agg.timeseries(900, 5).retention_seconds,
            TIMESERIES_RETENTION_SECS as u32,
        );
        // Coarse but NOT minute-aligned (90 s) — a minute bucket would
        // straddle two step buckets, so stay on seconds.
        assert_eq!(
            agg.timeseries(3600, 90).retention_seconds,
            TIMESERIES_RETENTION_SECS as u32,
        );
    }

    #[test]
    fn minute_tier_prunes_beyond_its_retention() {
        let agg = StatsAggregator::new();
        let now = chrono::Utc::now();
        agg.record(&allow_at("1.1.1.1", now - chrono::Duration::hours(30)));
        agg.record(&allow("2.2.2.2"));
        let ts = agg.timeseries(86_400, 1200);
        assert_eq!(
            ts.points.iter().map(|p| p.total).sum::<u32>(),
            1,
            "a 30h-old event is outside the minute tier's 24h retention"
        );
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
    fn bucketize_seconds_aligns_and_sums_into_step_buckets() {
        // now=1000, window=10, step=5 → 2 buckets: [995,1000) and
        // [1000,1005). Seconds 996, 1001, 1002 land in those buckets.
        let by_sec: BTreeMap<i64, (u32, u32)> =
            [(996, (3u32, 1u32)), (1001, (4, 2)), (1002, (1, 0))]
                .into_iter()
                .collect();
        let ts = bucketize_seconds(&by_sec, 1000, 10, 5);
        assert_eq!(ts.window_seconds, 10);
        assert_eq!(ts.step_seconds, 5);
        assert_eq!(ts.points.len(), 2);
        assert_eq!(ts.points[0].ts.timestamp(), 995);
        assert_eq!(ts.points[0].total, 3, "996 → first bucket");
        assert_eq!(ts.points[0].blocked, 1);
        assert_eq!(ts.points[1].ts.timestamp(), 1000);
        assert_eq!(ts.points[1].total, 5, "1001 + 1002 summed");
        assert_eq!(ts.points[1].blocked, 2);
    }

    #[test]
    fn timeseries_from_fleet_buckets_merged_seconds() {
        use crate::metrics::fleet_snapshot::SnapSecond;
        // Smoke test the now()-using wrapper: recent seconds land in the
        // newest bucket of a wide window, summing total/blocked.
        let now = chrono::Utc::now().timestamp();
        let seconds = vec![
            SnapSecond { sec: now, total: 6, blocked: 2 },
            SnapSecond { sec: now - 1, total: 4, blocked: 1 },
        ];
        let ts = timeseries_from_fleet(&seconds, 60, 1);
        assert_eq!(ts.window_seconds, 60);
        let total: u32 = ts.points.iter().map(|p| p.total).sum();
        let blocked: u32 = ts.points.iter().map(|p| p.blocked).sum();
        assert_eq!(total, 10);
        assert_eq!(blocked, 3);
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

    // ---------- 2026-06-24 P3 counter durability (A3) ------------------

    /// Stateful in-test backend with real hash storage + a HASH-op call
    /// counter (to prove the per-event path does zero Redis I/O).
    #[derive(Clone, Default)]
    struct MapHashBackend {
        hashes: Arc<Mutex<HashMap<String, HashMap<String, Vec<u8>>>>>,
        hash_ops: Arc<std::sync::atomic::AtomicU64>,
    }
    impl MapHashBackend {
        fn hash_ops(&self) -> u64 {
            self.hash_ops.load(std::sync::atomic::Ordering::Relaxed)
        }
    }
    #[async_trait::async_trait]
    impl StateBackend for MapHashBackend {
        async fn get(&self, _k: &str) -> aegis_core::Result<Option<Vec<u8>>> { Ok(None) }
        async fn set(&self, _k: &str, _v: &[u8], _t: Duration) -> aegis_core::Result<()> { Ok(()) }
        async fn del(&self, _k: &str) -> aegis_core::Result<()> { Ok(()) }
        async fn incr_window(&self, _k: &str, _w: Duration, _l: u64) -> aegis_core::Result<aegis_core::SlidingWindowResult> {
            Ok(aegis_core::SlidingWindowResult { count: 0, allowed: true, retry_after: None })
        }
        async fn token_bucket(&self, _k: &str, _r: u32, _b: u32) -> aegis_core::Result<bool> { Ok(true) }
        async fn get_risk(&self, _k: &aegis_core::risk::RiskKey) -> aegis_core::Result<u32> { Ok(0) }
        async fn add_risk(&self, _k: &aegis_core::risk::RiskKey, _d: i32, _m: u32) -> aegis_core::Result<u32> { Ok(0) }
        async fn auto_block(&self, _ip: std::net::IpAddr, _t: Duration) -> aegis_core::Result<()> { Ok(()) }
        async fn is_auto_blocked(&self, _ip: std::net::IpAddr) -> aegis_core::Result<bool> { Ok(false) }
        async fn put_nonce(&self, _n: &str, _t: Duration) -> aegis_core::Result<bool> { Ok(true) }
        async fn consume_nonce(&self, _n: &str) -> aegis_core::Result<bool> { Ok(true) }
        async fn hset_multi(&self, key: &str, fields: &[(String, Vec<u8>)]) -> aegis_core::Result<()> {
            self.hash_ops.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut g = self.hashes.lock().unwrap();
            let h = g.entry(key.to_string()).or_default();
            for (f, v) in fields { h.insert(f.clone(), v.clone()); }
            Ok(())
        }
        async fn hdel(&self, key: &str, fields: &[String]) -> aegis_core::Result<()> {
            self.hash_ops.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if let Some(h) = self.hashes.lock().unwrap().get_mut(key) {
                for f in fields { h.remove(f); }
            }
            Ok(())
        }
        async fn hscan(&self, key: &str) -> aegis_core::Result<Vec<(String, Vec<u8>)>> {
            self.hash_ops.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(self.hashes.lock().unwrap().get(key)
                .map(|h| h.iter().map(|(f, v)| (f.clone(), v.clone())).collect())
                .unwrap_or_default())
        }
        async fn unlink(&self, key: &str) -> aegis_core::Result<()> {
            self.hashes.lock().unwrap().remove(key);
            Ok(())
        }
    }

    fn be() -> Arc<MapHashBackend> {
        Arc::new(MapHashBackend::default())
    }
    fn agg_with(be: &Arc<MapHashBackend>) -> StatsAggregator {
        StatsAggregator::with_backend(Some(be.clone() as Arc<dyn StateBackend>))
    }

    #[tokio::test]
    async fn blocks_total_flushes_and_survives_restart() {
        let backend = be();
        let agg = agg_with(&backend);
        for _ in 0..5 {
            agg.record(&block("9.9.9.9"));
        }
        assert_eq!(agg.snapshot().blocks_total, 5);
        agg.flush_counters("node-a").await;

        // Fresh aggregator (restart) hydrates this node's field.
        let restarted = agg_with(&backend);
        assert_eq!(restarted.snapshot().blocks_total, 0, "zero before hydrate");
        restarted.hydrate("node-a").await;
        assert_eq!(restarted.snapshot().blocks_total, 5, "counter survived restart");
    }

    #[tokio::test]
    async fn record_does_zero_redis_io_per_event() {
        // §9 invariant 5: the per-event path must never touch Redis (or it
        // could add broadcast Lagged under a saturated audit bus). Only the
        // interval flush/hydrate do hash I/O.
        let backend = be();
        let agg = agg_with(&backend);
        for _ in 0..1000 {
            agg.record(&block("1.2.3.4"));
        }
        assert_eq!(backend.hash_ops(), 0, "record() did no hash I/O");
        agg.flush_counters("n").await;
        assert_eq!(backend.hash_ops(), 1, "exactly one write per flush tick");
    }

    #[tokio::test]
    async fn hydrate_takes_max_and_does_not_lose_live_increments() {
        let backend = be();
        // Persist 3 under node-a.
        let seeder = agg_with(&backend);
        for _ in 0..3 { seeder.record(&block("1.1.1.1")); }
        seeder.flush_counters("node-a").await;

        // A fresh aggregator already counted 10 live blocks before hydrate —
        // the durable 3 must not clobber the larger live value.
        let agg = agg_with(&backend);
        for _ in 0..10 { agg.record(&block("2.2.2.2")); }
        agg.hydrate("node-a").await;
        assert_eq!(agg.snapshot().blocks_total, 10, "live (10) wins over durable (3)");
    }

    #[tokio::test]
    async fn per_node_fields_are_isolated() {
        let backend = be();
        let a = agg_with(&backend);
        let b = agg_with(&backend);
        for _ in 0..2 { a.record(&block("1.1.1.1")); }
        for _ in 0..7 { b.record(&block("2.2.2.2")); }
        a.flush_counters("node-a").await;
        b.flush_counters("node-b").await;

        let a2 = agg_with(&backend);
        a2.hydrate("node-a").await;
        assert_eq!(a2.snapshot().blocks_total, 2, "node-a reads only its own field");
        let b2 = agg_with(&backend);
        b2.hydrate("node-b").await;
        assert_eq!(b2.snapshot().blocks_total, 7, "node-b reads only its own field");
    }

    #[tokio::test]
    async fn reset_zeros_in_memory_and_forgets_durable() {
        let backend = be();
        let agg = agg_with(&backend);
        for _ in 0..4 { agg.record(&block("3.3.3.3")); }
        agg.flush_counters("node-a").await;

        agg.reset_counters();
        agg.forget_durable("node-a").await;
        assert_eq!(agg.snapshot().blocks_total, 0, "in-memory zeroed");
        let restarted = agg_with(&backend);
        restarted.hydrate("node-a").await;
        assert_eq!(restarted.snapshot().blocks_total, 0, "durable field cleared");
    }

    #[tokio::test]
    async fn no_backend_path_is_inert() {
        let agg = StatsAggregator::new(); // no backend
        for _ in 0..3 { agg.record(&block("4.4.4.4")); }
        // Durable hooks no-op without panicking.
        agg.flush_counters("n").await;
        agg.hydrate("n").await;
        agg.forget_durable("n").await;
        assert_eq!(agg.snapshot().blocks_total, 3, "in-memory unchanged");
        agg.reset_counters();
        assert_eq!(agg.snapshot().blocks_total, 0);
    }
}
