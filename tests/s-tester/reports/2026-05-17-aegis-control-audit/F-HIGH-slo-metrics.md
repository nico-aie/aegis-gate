---
id: 2026-05-17-high-slo-metrics-bundle
date: 2026-05-17T00:00Z
severity: HIGH
area: SLO · metrics · tier policy · health
component: crates/aegis-control/src/{slo.rs,api/tiers.rs,health.rs,metrics/*.rs,dashboard_services.rs}
interop_contract: §Performance 20/120 + Round-1 health
status: open
test_mode: source-review
---

# F-HIGH-slo-metrics bundle — 7 issues in SLO + metrics + tier policy + health

---

## SM-01 · `fired_history: Mutex<Vec<SloAlert>>` never trimmed

**Component:** [slo.rs:247](../../../../crates/aegis-control/src/slo.rs#L247)

Long-running process accumulates alerts forever; alerts are never
GC'd. Latent memory leak.

**Fix:** convert to `VecDeque` ring at e.g. 10_000 entries, or
drain to a sink + clear:

```rust
if self.fired_history.lock().len() > MAX_FIRED_HISTORY {
    self.fired_history.lock().drain(..1_000);   // keep last 9k
}
```

---

## SM-02 · `metrics/request_duration::BUCKETS_MS` only 1 bucket ≤1ms

**Component:** [metrics/request_duration.rs:41-44](../../../../crates/aegis-control/src/metrics/request_duration.rs#L41-L44)

Bucket boundaries: `[0.05, 0.1, 0.25, 0.5, 1.0, ...]`. Only 5
sub-1ms buckets, and only 1 between 1 ms and 5 ms (the contract
target). p99 estimation at the 0.5→1 ms boundary is ±25% wide; near
the 5 ms contract boundary it's even wider.

For accurate p99 reporting near the §Performance 5 ms target, add
intermediate buckets:

**Fix:**

```diff
-pub const BUCKETS_MS: &[f64] = &[0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 25.0, 50.0];
+pub const BUCKETS_MS: &[f64] = &[0.05, 0.1, 0.25, 0.5, 0.75, 1.0, 1.5, 2.0, 2.5, 3.0, 4.0, 5.0, 7.5, 10.0, 25.0, 50.0];
```

---

## SM-03 · `/healthz/live` returns 503 on draining → k8s SIGKILLs mid-drain

**Component:** [health.rs:46-52](../../../../crates/aegis-control/src/health.rs#L46-L52)

`/healthz/live` returns `(503, "draining")` when `signal.is_live()`
is false. k8s liveness probes treat 503 as "restart me" — but
draining is graceful-shutdown signal, not "I'm broken". A draining
pod will be SIGKILLed mid-drain.

Per k8s convention:
- `/healthz/live` (200, still alive) — even during drain
- `/healthz/ready` (503 during drain) — stops new traffic

**Fix:**

```diff
 pub fn check_live(...) -> HealthResponse {
-    if !signal.is_live() {
-        return HealthResponse { status: "draining", ..., http_status: 503 };
-    }
+    // Liveness never returns 503 for drain — drain is a readiness signal.
     HealthResponse { status: "ok", ..., http_status: 200 }
 }

 pub fn check_ready(...) -> HealthResponse {
     if signal.is_draining() {
         return HealthResponse { status: "draining", ..., http_status: 503 };
     }
     ...
 }
```

---

## SM-04 · `route_activity` over-counts after idle gaps

**Component:** [metrics/route_activity.rs:104-118](../../../../crates/aegis-control/src/metrics/route_activity.rs#L104-L118)

Lazy bucket reset is incorrect across non-adjacent writes. Walk-through:

- write @ t=141 → bucket[21]=1
- write @ t=200 → `prev_ts=141`, `now.saturating_sub(prev)=59<60`,
  only bucket[20] reset, bucket[21] keeps 1
- snapshot @ t=250 sees `last_bucket_ts=200 ≥ oldest=191` and sums
  every bucket including bucket[21]=1 (109 s old)

Returns `count_60s=2` when real in-window count is 1. Per-route
"req/min" dashboard pill over-counts after idle gaps.

**Fix:** per-bucket `(value, last_touched_ts)` tuple; skip stale on
read. Or sweep more aggressively (mark every bucket older than the
window as zero on each push).

---

## SM-05 · `tiers.rs::pipeline` + `block_threshold` are "descriptive metadata only" — §4 per-tier rate-limit + per-tier detector NOT enforced

**Component:** [api/tiers.rs:30-43, 68-76](../../../../crates/aegis-control/src/api/tiers.rs#L30-L43)

The doc comment is explicit: `Tier::pipeline` and `Tier::block_threshold`
are "descriptive metadata only". The data plane ignores them; the
global `IpRateLimiter` (`data_plane.rs:363`) is shared across tiers.

§4 of official rules mandates per-tier rate-limit + per-tier detector
pipeline + per-tier fail-close. Dashboard surfaces them; flipping
values does nothing.

Cross-ref F-CRITICAL-005 (DDoS no per-tier) + F-CRITICAL-009 (rule
scope no per-tier) from the security audit.

**Fix:** per-tier `IpRateLimiter` keyed off `RequestContext.tier`;
route detector-mask reads through `TierStore::get(tier).pipeline`
instead of the global mask.

---

## SM-06 · SLO dispatch ignores `summary.skipped_feature_off` — receivers built without `--features alerts` go silent

**Component:** [accept.rs:798-816](../../../../crates/aegis-proxy/src/accept.rs#L798-L816)

The SLO dispatch loop iterates `summary.delivered`, `summary.external`,
`summary.failed` but doesn't read `summary.skipped_feature_off`.
Receivers that should land in that bucket (binary built without
`--features alerts`) never get recorded into `dispatch_ring`, so
`/api/alert-receivers` shows phantom "clean" state.

The 2026-05-03 fix in `slo/dispatch.rs:93-110` was supposed to
surface this; the consumer-side wiring is missing.

**Fix:**

```rust
for name in &summary.skipped_feature_off {
    ring.record_skipped(name, now);
}
```

Add `record_skipped` method to `dispatch_ring`. Surface in the API
response.

---

## SM-07 · `DashboardServices` is a 50+ field Arc<struct> — no path to swap whole bundle on reload

**Component:** [dashboard_services.rs:53-268](../../../../crates/aegis-control/src/dashboard_services.rs#L53-L268)

`DashboardServices` is constructed once and shared via `Arc`.
Hot-reload mutates ~10 fields via per-field `ArcSwap`, but the bundle
itself is immutable. Any future field that's not wrapped in `ArcSwap`
silently becomes a boot-time snapshot.

**Fix:** either document the contract explicitly ("every new field
MUST be ArcSwap-wrapped if hot-reloadable") or move the entire
bundle behind one outer ArcSwap:

```rust
pub struct DashboardServicesHandle {
    inner: Arc<ArcSwap<DashboardServices>>,
}
```

Reload swaps the whole inner via `inner.store(Arc::new(new_services))`.
Per-field ArcSwap becomes redundant. Trade-off: every hot-reload
rebuilds the whole bundle (~50 field copies), but fields stay
consistent across the swap.

---

## Severity rationale

HIGH. Each impacts either Performance rubric (SM-02), Round-1 health
view (SM-03), §4 per-tier mandate (SM-05), operational correctness
(SM-04, SM-06), or hot-reload safety (SM-07). SM-01 is a slow leak.
None alone is CRITICAL.
