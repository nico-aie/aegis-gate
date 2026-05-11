# Multi-node metrics aggregation (P4 + P5 counters)

> **Status (2026-05-11): Deferred.** The per-route activity
> counter (P5, `bebca12`) and per-entry access-list hit counter
> (P4, `3c59dcb`) are correct for single-node deployments but
> hold their data in-process only. Multi-node deployments will
> see each node show a partial view of traffic. This document
> captures the design for the hybrid local+flush aggregation
> the next sprint should implement so the story isn't forgotten.

## Why deferred

The QA report didn't flag multi-node aggregation as a finding —
it's a forward-looking concern raised when the operator noticed
the in-process DashMap storage. Acting on it now would:

1. **Force a Redis dependency on the hot path** (or whichever
   `StateBackend` is wired). The hot path currently does one
   atomic `fetch_add` per match (~ns). Writing through to Redis
   on every match adds a ~0.5 ms network RTT — that's the same
   order of magnitude as the WAF's whole legit-request latency
   budget (`prod-balanced` p99 1.03 ms).

2. **Need a perf benchmark under the 5k RPS prod-balanced
   profile** before merging. Without that, we'd risk regressing
   the headline perf numbers.

3. **Require a bucket-retention design** in Redis (TTL on
   `hits:*` keys? Sweeper job? Per-node-id sub-keys?). Each
   choice has trade-offs that need an operator decision.

4. **Open the door to broader telemetry-aggregation work**
   (per-detector hits, per-tier counts, per-IP-risk decays).
   Better to design once than pile on retroactively.

The single-node behaviour the current commits ship is honest +
operator-valuable. Multi-node aggregation can land cleanly in a
dedicated sprint.

## Today's storage (single-node, in-process)

### P5 — `RouteActivityWindow`

`crates/aegis-control/src/metrics/route_activity.rs`

```rust
pub struct RouteActivityWindow {
    rings: Arc<DashMap<String, Arc<RouteRing>>>,
}
struct RouteRing {
    buckets: [AtomicU64; 60],        // 60 × 1-second buckets
    last_bucket_ts: AtomicU64,
    last_seen_ts: AtomicU64,
}
```

- ~480 bytes per route × ~50 routes ≈ 24 KB in steady state.
- Hot path: one `DashMap` shard lookup + two atomic stores.
- Read path: `snapshot_all()` walks every ring; called by
  `GET /api/analytics/route-activity` every ~10 s from the
  dashboard.

### P4 — `AccessListHits`

`crates/aegis-control/src/api/blacklist.rs`

```rust
struct AccessListHits {
    rings: Arc<DashMap<String, Arc<EntryHitRing>>>,
}
struct EntryHitRing {
    buckets: [AtomicU64; 24],        // 24 × 1-hour buckets
    last_bucket_ts: AtomicU64,
}
```

- ~256 bytes per entry × ~10k entries ≈ 2.5 MB at worst.
- Hot path: increment inside `AccessListStore::matches()` so
  callers can't forget.
- Read path: `hit_counts(window_secs)` snapshot, called by
  `GET /api/blacklist/hits` + `GET /api/whitelist/hits` every
  15 s (1h window) + 60 s (24h window).

### Operator-visible consequence on multi-node

| Scenario | What dashboard at `node-A:9443` shows |
|---|---|
| 70/30 LB split A:B | Only node-A's 70% of traffic |
| Entry `198.51.100.50` hot on B, dead on A | "stale · consider removing" on A's dashboard |
| Process restart | All counters reset; "idle" pill on every route |
| SIGUSR2 hot-handover | Counters reset on the child process |

Operators looking at one node can't trust the numbers as a
cluster-wide view. Decisions like "this blacklist entry hasn't
matched in 24h, remove it" are unsafe.

## Design — hybrid local + periodic flush

Same shape both P4 and P5 should adopt; below uses P4 wording
but the structure is identical for P5.

### Hot path stays local

The data plane keeps doing what it does today: one atomic
`fetch_add` on the local ring per match. Zero added latency.
Local rings remain the source of truth between flush cycles.

### Background flush task

```rust
async fn flush_loop(
    hits: AccessListHits,
    state: Arc<dyn StateBackend>,
    node_id: NodeId,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(10));
    let mut last_seen: HashMap<String, [u64; 24]> = HashMap::new();
    loop {
        interval.tick().await;
        for kv in hits.rings.iter() {
            let entry_id = kv.key();
            let current = kv.value().snapshot_buckets();
            let prev = last_seen.entry(entry_id.clone()).or_insert([0; 24]);
            for (bucket_idx, (now, was)) in current.iter().zip(prev.iter()).enumerate() {
                let delta = now.saturating_sub(*was);
                if delta == 0 { continue; }
                let bucket_ts = bucket_idx_to_ts(bucket_idx);
                let key = format!("waf:hits:bl:{entry_id}:{bucket_ts}");
                let _ = state.incrby(&key, delta).await;   // best-effort
                let _ = state.expire(&key, Duration::from_secs(86400 * 2)).await;
            }
            *prev = current;
        }
    }
}
```

- `INCRBY` is atomic + commutative — concurrent flushes from
  multiple nodes converge to the right total.
- TTL on the key is 2 × the window (48h here) so stale buckets
  garbage-collect themselves without a sweeper.
- Flush cadence is the staleness vs. write-amplification
  trade-off. 10 s is a reasonable default; operators tuning for
  high-cardinality lists can push it longer.

### Read path

```rust
pub async fn hit_counts_aggregated(
    state: &Arc<dyn StateBackend>,
    list_kind: &str,         // "bl" or "wl"
    window_secs: u64,
) -> HashMap<String, u64> {
    let now_bucket = current_secs() / HIT_BUCKET_SECS;
    let buckets_back = (window_secs + HIT_BUCKET_SECS - 1) / HIT_BUCKET_SECS;
    // SCAN for `waf:hits:<list_kind>:*` keys whose bucket-ts is
    // within the window. Sum across nodes (Redis INCRBY already
    // aggregated for us).
    // ...
}
```

The endpoint reads from the state backend when wired; falls
back to the local rings on `cfg.state.backend = in_memory` so
single-node deployments don't need Redis just for the dashboard
column.

### Per-node identity (optional refinement)

If operators want to drill into per-node contribution (helpful
for debugging "is the LB sending all traffic to one node?"), the
flush task can write to a `node`-labelled key:

```text
waf:hits:bl:198-51-100-50:1715448000:node-a-1234   → 42
waf:hits:bl:198-51-100-50:1715448000:node-b-5678   → 18
```

`SCAN` + aggregate at read time. Worth doing only if there's
operator demand; the basic shape above already solves the
"trust the numbers" problem.

## Implementation sequence

1. **Shared `WindowFlush` helper** — both `RouteActivityWindow`
   and `AccessListHits` need the same `flush_to_state` shape.
   Extract into `crates/aegis-control/src/metrics/window_flush.rs`
   so the two callers don't duplicate the logic.

2. **State backend trait additions** — confirm `StateBackend`
   has `incrby(key, delta)` and `scan(prefix)` methods, or add
   them. Redis backend already has them via `redis::cmd("INCRBY")`
   and `redis::cmd("SCAN")`; the in-memory backend would need
   stubs returning local-rings data.

3. **Boot wiring** — `aegis_proxy::run` spawns the flush task
   alongside the existing per-pool refresh task pattern
   (`dns_refresh::spawn_pool_refresh`). One task per counter
   class.

4. **Endpoint switch** — wrap the existing local-ring read in
   an `if cfg.state.backend != InMemory` branch that reads from
   state instead. Keep the local-ring path so single-node + dev
   bookings stay zero-infra.

5. **Perf benchmark** — re-run the `prod-balanced` 5k RPS
   profile with the flush task active. Verify no detectable
   regression on the legit p99 latency. Flush task itself
   shouldn't show up on the hot path; if it does, lengthen the
   flush interval.

6. **Audit chain** — emit `flush_failed` audit events on
   sustained Redis errors so operators see the degraded state.
   The local rings keep working in the meantime.

## Effort

- Shared `WindowFlush` helper: ~2 h.
- State backend method additions (if needed): ~1 h.
- Wire P4 + P5 flush tasks + endpoint switch: ~2 h.
- Perf benchmark + sign-off: ~2 h.
- Tests (mock state backend, multi-node convergence assertion):
  ~2 h.

Total: ~9 h, one focused sprint. The single-node behaviour the
current commits ship can stay in place during the rollout —
this plan adds aggregation, doesn't replace the local rings.

## Related design references

- `crates/aegis-security/src/rate_limit/` — already does the
  "local token bucket + Redis writeback" pattern under the
  `redis` feature. Reuse the wiring shape there.
- `crates/aegis-proxy/src/upstream/dns_refresh.rs` — same
  background-task lifecycle pattern (one task per pool, spawned
  at boot, lives for process lifetime).
- `plans/multi-node-deployment/` — if a broader multi-node
  design plan exists, this aggregation slots into it.

## Out of scope for this plan

- **Cross-cluster federation.** Prometheus federation across
  geo regions is a separate problem; this plan stays within one
  WAF cluster.
- **Counter persistence across cluster wipes.** Redis
  persistence is the operator's call (RDB vs AOF); the WAF
  doesn't manage Redis's durability.
- **Per-detector hit aggregation.** Same shape would work for
  detector hits but those already flow through Prometheus
  histograms; this plan covers the in-process counters that
  *don't* have a metrics path today.
