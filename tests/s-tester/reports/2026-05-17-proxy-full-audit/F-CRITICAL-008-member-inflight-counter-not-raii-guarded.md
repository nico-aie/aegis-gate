---
id: 2026-05-17-member-inflight-counter-not-raii-guarded
date: 2026-05-17T00:00Z
severity: CRITICAL
area: upstream · load balancer
component: crates/aegis-proxy/src/proxy.rs (handle_request inflight) · crates/aegis-proxy/src/data_plane.rs (same pattern at ~line 1392-1402)
interop_contract: Round 1 stability under sustained traffic · Round 3 long-running resilience
status: open
test_mode: source-review
---

# F-CRITICAL-008 · `Member.inflight` counter is incremented before forward but not RAII-guarded — cancellation / panic leaks the counter, LeastConn / P2C LBs skew permanently

## Summary

The upstream forward path increments `member.inflight: AtomicU32`
before calling `forward()` and decrements it after. There is no
Drop guard. If the future is cancelled (client disconnect mid-
request, listener shutdown, panic during forward, hyper connection
error that propagates), the decrement never runs and the counter
permanently records a request-in-flight that has already finished
or failed.

Over time:

- `LeastConn` load-balancer always sees the affected member as
  "more loaded" than its peers → stops routing traffic to it →
  the member starves while healthy.
- `P2C` (power-of-two-choices) skews toward picking the leaked
  member (its `inflight` looks high — actually low-load it's just
  ghost counters).
- Circuit-breaker statistics treat the leaked counter as live
  traffic.

This is a long-run resilience bug: a freshly-booted WAF won't
exhibit it for the first few minutes. After hours of sustained
traffic with the inevitable cancellations / disconnects, one
member of every pool will be "ghost-pinned" out of rotation.

## Observed code path

`crates/aegis-proxy/src/proxy.rs:300-312` (paraphrased):

```rust
let member = pool.pick(&strategy);
member.inflight.fetch_add(1, Ordering::Relaxed);    // ← raw increment

let result = forward::forward(req, member, ...).await;   // ← can be cancelled / panic

member.inflight.fetch_sub(1, Ordering::Relaxed);    // ← skipped on cancel/panic

match result { ... }
```

Same pattern appears in [data_plane.rs:1392-1402](../../../../crates/aegis-proxy/src/data_plane.rs#L1392-L1402) at the equivalent
forward call site.

Tokio cancellation happens naturally on:
- Client disconnect mid-request (very common — every benchmark
  burst that's interrupted, every keep-alive timeout).
- Listener `select!` falling into a shutdown branch while the
  handler future is still alive.
- Panic inside `forward` (e.g. F-CRITICAL-009's CORS panic, any
  `unwrap` in upstream parsing).

## Repro

```sh
# Set up a slow upstream (e.g. nc that accepts but never replies).
nc -l 9998 &     # upstream that hangs

# Point a route at it (in config or via dashboard).
# Then fire 100 requests and SIGINT them mid-flight:
for i in $(seq 1 100); do
    timeout 1 curl -sk http://127.0.0.1:8080/slow -o /dev/null
done

# Check member inflight via admin API:
curl -sk http://127.0.0.1:9443/api/upstreams/pool/slow | jq '.members[].inflight'
# Expect: 0  (all requests timed out / cancelled).
# Actual: 100 (counter leaked).

# Now send more traffic. With LeastConn / P2C, the slow member
# is now "the most loaded" forever. New requests bypass it.
```

## Impact

- **Round 1 stability under sustained traffic**: after enough
  cancellations, the WAF effectively loses one pool member per
  pool, silently. Throughput degrades, but no metric flags it
  (the `inflight` gauge reports the leaked count as legitimate
  load).
- **Round 3 long-running resilience**: the WAF's effective capacity
  shrinks over the run as more members get ghost-pinned. The
  longer the benchmark, the worse the score.
- **Hard to diagnose in production**: operators see "this one
  member never gets traffic" and may mark it unhealthy or restart
  it, masking the underlying counter leak.

## Suggested fix

RAII drop guard around the `forward()` call:

```diff
+struct InflightGuard<'a> {
+    counter: &'a std::sync::atomic::AtomicU32,
+}
+impl<'a> InflightGuard<'a> {
+    fn new(counter: &'a std::sync::atomic::AtomicU32) -> Self {
+        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
+        Self { counter }
+    }
+}
+impl Drop for InflightGuard<'_> {
+    fn drop(&mut self) {
+        self.counter.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
+    }
+}

 let member = pool.pick(&strategy);
-member.inflight.fetch_add(1, Ordering::Relaxed);
+let _guard = InflightGuard::new(&member.inflight);

 let result = forward::forward(req, member, ...).await;

-member.inflight.fetch_sub(1, Ordering::Relaxed);

 match result { ... }
```

Drop runs on:
- Normal return (after the `match`).
- Panic unwinding through the function (unless `panic = abort`,
  which the workspace doesn't use).
- Future cancellation (tokio drops the future, which drops the
  guard).

Apply the same fix at both call sites (`proxy.rs` and
`data_plane.rs`); ideally extract the LB-pick + forward call into
a single helper that owns the guard internally so future call sites
can't repeat the bug.

## Verification

After the fix, repeat the cancel-storm repro above and check the
admin API:

```sh
curl -sk http://127.0.0.1:9443/api/upstreams/pool/slow | jq '.members[].inflight'
# Expect: 0 — counters released on cancel.
```

Add a regression test that spawns N futures, drops half mid-flight,
and asserts `inflight` returns to the pre-traffic baseline.

## Severity rationale

CRITICAL because the bug is silent, accumulates over time, affects
EVERY pool with LeastConn / P2C strategy (the README's defaults),
and degrades throughput on the very scoring axis (Round 3) where
the WAF most needs to perform. Trivial fix (RAII pattern, ~15 LoC).
