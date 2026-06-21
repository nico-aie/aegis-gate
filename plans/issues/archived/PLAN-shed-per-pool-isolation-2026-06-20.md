# Load-shedder per-pool isolation — one shedder per upstream pool

**Status:** Open — scoped (not yet implemented)
**Filed:** 2026-06-20
**Reporter:** design discussion (blast-radius analysis)
**Severity:** 🟡 Medium-High — fault isolation gap; one slow upstream degrades the whole gate
**Related:**
- [`PLAN-perf-throughput-cliff-2026-06-20.md`](./PLAN-perf-throughput-cliff-2026-06-20.md) (Fix C — verify Gradient2 shedder; placement work)
- [`PLAN-conn-layer-dos-gaps-2026-06-20.md`](./PLAN-conn-layer-dos-gaps-2026-06-20.md) (slot-hold bounding — an upstream response/read deadline is the companion mitigation that caps how long a stalled pool pins its slots)

## TL;DR

The adaptive load shedder is a **single global** `LoadShedder`
([`shed.rs`](../../crates/aegis-proxy/src/shed.rs)) installed once on
`ProxyContext.load_shedder` ([`proxy.rs:163`](../../crates/aegis-proxy/src/proxy.rs#L163),
built at [`run.rs:1005`](../../crates/aegis-proxy/src/run.rs#L1005)). There is **one**
`inflight` counter and **one** `limit` shared across every upstream pool. The `shed.rs:2`
doc comment claims *"Per-pool"* — that is **aspirational; the wiring is global.**

Two channels behave differently when one upstream goes slow:

1. **The adaptive limit (gradient): insulated ✅.** `record_rtt` is fed
   `request_start.elapsed()` measured at the upstream-forward boundary — WAF-inspection
   time only, not the round-trip ([`data_plane.rs:1756-1763`](../../crates/aegis-proxy/src/data_plane.rs#L1756),
   contract in [`shed.rs:44`](../../crates/aegis-proxy/src/shed.rs#L44)). A slow backend
   does **not** shrink the limit.
2. **The in-flight occupancy: NOT insulated ❌.** The RAII `_shed_guard` is acquired
   **before** body buffering / upstream forward ([`data_plane.rs:873-892`](../../crates/aegis-proxy/src/data_plane.rs#L873))
   and held for the **entire request lifetime, including the upstream round-trip**. So:

   ```
   upstream A goes slow
     → requests to A hold their in-flight slots longer
     → the shared global `inflight` climbs toward the shared `limit`
     → once inflight >= limit, should_admit() starts shedding
     → healthy upstream B's Low/Medium traffic gets 503'd
   ```

   One sick backend silently consumes the shared concurrency budget and starves traffic to
   healthy backends. Critical survives (`should_admit(Critical)` short-circuits, [`shed.rs:121`](../../crates/aegis-proxy/src/shed.rs#L121)),
   but everything below Critical on the *healthy* pools pays for the *sick* one.

**Fix:** one `LoadShedder` per upstream pool, keyed by pool name. A slow pool fills *its own*
`inflight` and sheds *its own* non-Critical traffic; healthy pools keep their full budget.

## Why this is tractable (findings from the code)

- **The pool key is already at the gate.** `resolved_route: Option<RouteCtx>` is resolved at
  [`data_plane.rs:425`](../../crates/aegis-proxy/src/data_plane.rs#L425); `RouteCtx.upstream`
  ([`context.rs`](../../crates/aegis-core/src/context.rs)) is the pool name. Both the shed
  gate ([`:868`](../../crates/aegis-proxy/src/data_plane.rs#L868)) and the `record_rtt` call
  ([`:1762`](../../crates/aegis-proxy/src/data_plane.rs#L1762)) already hold it
  (`route_ctx.upstream`).
- **Precedent to mirror:** circuit breakers are *already* per-pool, keyed by name —
  `ctx.pools.breaker(&route_ctx.upstream)` ([`registry.rs:237`](../../crates/aegis-proxy/src/upstream/registry.rs#L237)).
- **`dashmap` is already a workspace dep** of `aegis-proxy` ([`Cargo.toml:84`](../../crates/aegis-proxy/Cargo.toml#L84)).
- **`ShedGuard` already holds `Arc<LoadShedder>`** ([`shed.rs:201`](../../crates/aegis-proxy/src/shed.rs#L201)),
  so `Drop`→`release()` returns the slot to the *correct* pool's counter — **no guard change
  needed.**

## Critical design constraints (the nuances that will bite)

1. **State must outlive pool rebuilds.** Co-locating the shedder *inside* the `Pool` struct
   (like the breaker) is tempting, but pools are rebuilt on every
   `apply_cfg_change_to_upstreams` ([`reload.rs:472`](../../crates/aegis-proxy/src/config_source/reload.rs#L472)).
   That would reset `inflight` to 0 while outstanding `ShedGuard`s still hold slots → their
   `release()` (`fetch_sub`, [`shed.rs:152`](../../crates/aegis-proxy/src/shed.rs#L152))
   **underflows/wraps**. **Decision: store the registry on `ProxyContext`, keyed by pool
   name, persisting across reloads.** This is exactly why `PoolRegistry::from_pools(pools,
   breakers)` takes breakers *separately* — same survival requirement.
2. **`OnceLock` → registry, toggle preserved.** Replace
   `load_shedder: OnceLock<Arc<LoadShedder>>` with `OnceLock<Arc<ShedRegistry>>`. Absent
   (disabled config / test fixtures) still means "always admit" — the `.get()` short-circuit
   at [`data_plane.rs:873`](../../crates/aegis-proxy/src/data_plane.rs#L873) is retained.
3. **Unmatched routes** (`resolved_route == None`) hit the global shedder today, then 404 in
   the forward path. Per-pool, give them a shared sentinel bucket (`"__unrouted__"`) so an
   unrouted flood still meets a shedder — preserves current protection instead of handing
   unmatched traffic a free admit.
4. **No hot-reload path exists for shedder knobs** (there is no
   `apply_cfg_change_to_load_shedder` in `reload.rs`). Lazy per-pool creation reads the
   current global `LoadShedderConfig` at first-touch, so new pools pick up the configured
   knobs without new reload plumbing. Per-pool *override* knobs are deferred to P4.

---

## P1 — `ShedRegistry` type (`shed.rs`), TDD

**Goal:** a name-keyed registry of `LoadShedder`s with lazy creation. `LoadShedder` itself is
unchanged (its per-instance unit tests already pass).

```rust
pub struct ShedRegistry {
    inner: dashmap::DashMap<String, Arc<LoadShedder>>,
    initial_limit: u64,
    min_limit: u64,
}

impl ShedRegistry {
    pub fn new(initial_limit: u64, min_limit: u64) -> Self { /* ... */ }

    /// Get-or-create the shedder for `pool_key`. Lazy: a pool that has
    /// never seen traffic has no shedder. Persists across config reloads
    /// (lives on ProxyContext, NOT inside Pool — see constraint #1).
    pub fn for_pool(&self, pool_key: &str) -> Arc<LoadShedder> { /* entry().or_insert_with(...) */ }
}
```

**Steps (TDD):**
1. **RED** — `for_pool("a")` twice returns the same `Arc` (ptr-eq); `for_pool("a")` and
   `for_pool("b")` are independent instances.
2. **RED — isolation (the headline test):** saturate `for_pool("a")`'s inflight to its limit;
   assert `for_pool("a").should_admit(Low) == false` **and** `for_pool("b").should_admit(Low)
   == true` simultaneously.
3. **GREEN** — implement with `DashMap::entry().or_insert_with`.

## P2 — wire into `ProxyContext` + boot (`proxy.rs`, `run.rs`)

1. `ProxyContext.load_shedder: OnceLock<Arc<ShedRegistry>>` (update the doc comment at
   [`proxy.rs:158`](../../crates/aegis-proxy/src/proxy.rs#L158)).
2. [`run.rs:1005`](../../crates/aegis-proxy/src/run.rs#L1005): build a `ShedRegistry::new(
   cfg.load_shedder.initial_limit, cfg.load_shedder.min_limit)` instead of a bare
   `LoadShedder`; `set()` it on the `OnceLock`. Boot log unchanged in spirit (add a
   `"per-pool"` note).

## P3 — route the data-plane call sites (`data_plane.rs`)

1. **Shed gate** ([`:873`](../../crates/aegis-proxy/src/data_plane.rs#L873)):
   ```rust
   let _shed_guard = if let Some(registry) = upstream_ctx.load_shedder.get() {
       let pool_key = resolved_route
           .as_ref()
           .map(|rc| rc.upstream.as_str())
           .unwrap_or("__unrouted__");           // constraint #3
       let shedder = registry.for_pool(pool_key);
       if !shedder.should_admit(&tier) {
           // ... existing cheap 503 path, unchanged ...
       }
       Some(shedder.admit_guard())
   } else {
       None
   };
   ```
2. **`record_rtt`** ([`:1762`](../../crates/aegis-proxy/src/data_plane.rs#L1762)): route to
   the **same pool's** shedder so the gradient is per-pool —
   `registry.for_pool(&route_ctx.upstream).record_rtt(request_start.elapsed())`. This is the
   half that makes A's latency shrink only A's limit.
3. Fix the now-true **`shed.rs:2`** module doc comment (drop "aspirational"; it really is
   per-pool now).

## P4 — (defer) per-pool override knobs + observability

- `PoolConfig.load_shedder: Option<LoadShedderConfig>` override (global stays the default),
  read by `for_pool` at first-touch.
- Dashboard / API surface per-pool `limit` / `inflight` / `rtt`. **Greenfield:** a grep for
  `current_limit()` / `current_inflight()` consumers found **none** outside `shed.rs` tests —
  there is no shedder telemetry surface today. Scope separately from P1–P3.

---

## Acceptance gates

- [ ] `aegis-proxy` lib green; new `ShedRegistry` unit tests pass, **including the cross-pool
      isolation test** (P1 step 2).
- [ ] Data-plane integration test: slow pool A saturates → A's non-Critical traffic sheds in
      tier order, **B keeps serving** (B's `should_admit` unaffected).
- [ ] **Reload-survival regression:** outstanding `ShedGuard`s from a stalled pool releasing
      *across* an `apply_cfg_change_to_upstreams` reload must not underflow `inflight`
      (registry lives on `ProxyContext`, survives the rebuild).
- [ ] Critical-never-shed + WAF-inspection-only-RTT invariants preserved (existing `shed.rs`
      tests still green).
- [ ] `s-tester`: two-pool setup, throttle one upstream, confirm 503s scoped to the slow
      pool only.

## Risks

| Sev | Risk | Mitigation |
|---|---|---|
| MEDIUM | `inflight` underflow if the registry is rebuilt on reload | Store on `ProxyContext`, **not** in `Pool` (constraint #1); reload-survival gate above |
| LOW | Unbounded registry growth from churny pool names | Bounded by live pool count; optional GC on pool-removal in P4 |
| LOW | Per-pool limits mean aggregate admitted concurrency across N pools can exceed the old single global ceiling | **Correct** behaviour (isolation costs some global ceiling); document — size `initial_limit` per-pool, not fleet-wide |

## Complexity: MEDIUM

P1–P3 are small and surgical (the pool key is already threaded to both call sites). P4 is the
larger, optional surface and is explicitly deferred.
