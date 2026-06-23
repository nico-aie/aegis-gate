# Passive upstream health — derive member health from real traffic (future plan)

> **Status:** Drafted 2026-06-18. Deferred follow-up (option **3.2a**) to the
> shipped *honest upstream badge* fix for the upstream "up" finding
> (commit `9b417e1` on `develop`). That fix added a **display-only** observed
> signal; this plan makes member health reflect the **real request path** and
> feed the load balancer. Not started — it changes LB routing semantics and
> must ship together with a **fail-open** LB change. Related:
> [[project_health_signals_reported_not_gating]].

## Goal

Mark an upstream member **down** when real proxied requests to it fail
(connect refused, timeout, repeated 5xx), and **up** again when they succeed —
so the load balancer stops sending traffic to a dead backend **without**
requiring the operator to configure an active `health:` block, and based on the
*actual* request path (TLS + HTTP), not just a TCP handshake.

This is strictly more accurate than the active probes we ship today, but it
touches LB member selection, so it carries availability risk that the shipped
display-only signal deliberately avoided.

---

## 1. What already ships (and why this is separate)

Verified after `9b417e1`:

- **Active signal only.** `Member.observed` (tri-state up/down/unknown) is fed
  by either the HTTP health checker (`upstream/health.rs::spawn_health_checker`,
  pools with a `health:` block) or a TCP-connect observer
  (`spawn_tcp_observer`, pools without one).
- **Display-only.** `observed` drives the dashboard badge **only**.
  `Member::healthy` — the flag the LB consumes — is left optimistically `true`
  and is **never** touched by the TCP observer. This was intentional:
  > `LbStrategy::pick` (`upstream/lb.rs:32-34`) **returns `None` / fails
  > closed** when zero members are healthy → the pool routes to nothing → hard
  > 503/no-upstream.
  So a probe must never be able to evict the last member.

Passive health changes exactly that flag — which is why it can't land without
the fail-open work below.

## 2. The blocking prerequisite: make the LB fail open

> **✅ Shipped 2026-06-23 (PREREQ-B).** `LbStrategy::pick`
> (`crates/aegis-proxy/src/upstream/lb.rs`) now falls back to the full member
> set when the healthy set is empty, so an all-unhealthy pool attempts a forward
> (real 502) instead of returning `None` (refuse-to-route). `None` is returned
> only for a genuinely empty pool. The rest of this plan (passive marking of
> `Member::healthy`) is now unblocked.

Before any passive marking touches `Member::healthy`, change member selection
so an all-unhealthy pool still routes:

- In `LbStrategy::pick`, when the healthy set is empty, **fall back to the full
  member set** (attempt a known-bad member → a real 502 from the attempt)
  rather than returning `None` (a 503 refusal to route).
- This is a deliberate behavior change affecting **every** pool, including
  today's HTTP-health-checked ones. Today: all members down → 503 "no healthy
  upstream". After: all down → 502 from the actual forward attempt. Decide
  which is the desired contract (502-from-attempt is usually better for an
  edge, but confirm against the benchmark/contract expectations).

## 3. Design

### 3.1 Per-member failure accounting
Hook the existing forward-failure points (near `cb.record_failure()` in
`proxy.rs` ~`:408/465/475` and `data_plane.rs` ~`:2443/2492/2640`):

- Track per-member consecutive failures + successes (`AtomicU32` on `Member`).
- **Mark down** after **N consecutive** failures (hysteresis — never on a
  single error); **mark up** after **M consecutive** successes.
- "Failure" = connect refused / timeout / connection reset. Whether to count
  upstream 5xx is a separate toggle (5xx may be the app, not the member).

### 3.2 Wire to both display and routing
- Set `Member::healthy` (LB) **and** `observed` (display) from the passive
  verdict, so the badge and routing agree.
- Coexist with active checks: if a pool has an HTTP `health:` block, the active
  checker remains authoritative; passive is the fallback for pools without one
  (replacing the TCP observer for those, or augmenting it).

### 3.3 Recovery probing
A member marked down by passive health gets no traffic, so it can't recover
passively. Need a **half-open probe**: periodically send one trial request (or
reuse the TCP observer) to a down member; restore on success. (This mirrors the
circuit-breaker half-open state already in `upstream/circuit.rs`.)

---

## 4. Open decisions / risks

1. **Fail-closed → fail-open (the big one).** Must land first (§2). Changes the
   all-down contract for every pool.
2. **Flapping.** Bad thresholds turn a noisy backend into healthy/unhealthy
   churn that destabilizes routing. Needs tuned N/M + cooldown; make them
   config (`pool.passive_health.{fail_threshold, rise_threshold}`).
3. **Overlap with the circuit breaker.** The per-pool circuit breaker already
   trips on failures (`cb.record_failure()`), but at *pool* granularity and it
   returns 503, not member eviction. Decide the division of labor: CB = pool
   fuse; passive health = per-member rotation. Don't double-penalize.
4. **Cancellation/streaming.** A client-cancelled or long-streaming request
   must not be miscounted as a member failure. Reuse the inflight RAII guard
   semantics already in `Member`.
5. **Single-member pools.** With fail-open in place, marking the only member
   down is safe (still routed, just a real 502) — but confirm the badge then
   reads "down" while traffic still attempts it (honest, but explain in the
   tooltip).

## 5. Phasing
- **P1 — fail-open LB.** `LbStrategy::pick` falls back to all members when none
  healthy. Tests: all-down pool routes (502 from attempt) instead of 503.
  Ship independently; it's a safety improvement on its own.
- **P2 — passive accounting + marking** behind `pool.passive_health.enabled`
  (default off), with hysteresis, wired to `healthy` + `observed`.
- **P3 — half-open recovery probe** for passively-downed members.
- **P4** — default on for pools without an active `health:` block; retire/)fold
  the standalone TCP observer for those pools.

## 6. Tests
- (P1) zero-healthy pool routes via fallback, not `None`.
- (P2) N consecutive connect failures → member down (+ LB skips it while others
  are up); M successes → up; single error never flips.
- (P3) downed member with no traffic recovers via half-open probe.
- LB never returns `None` for a non-empty pool.

## 7. Out of scope
- Active HTTP health-check behavior (unchanged).
- Outlier detection by latency percentile (a possible later refinement).
