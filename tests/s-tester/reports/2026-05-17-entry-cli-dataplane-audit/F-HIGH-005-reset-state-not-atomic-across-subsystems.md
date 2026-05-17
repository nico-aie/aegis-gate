---
id: 2026-05-17-reset-state-not-atomic-across-subsystems
date: 2026-05-17T00:00Z
severity: HIGH
area: control-plane · interop
component: crates/aegis-control/src/interop/control.rs (reset_state dispatcher)
interop_contract: v2.3 §2.4 ("synchronous + atomic ... KHÔNG ĐƯỢC expose partially reset state")
status: open
test_mode: source-review
---

# F-HIGH-005 · `reset_state` runs subsystem callbacks sequentially without a cross-subsystem lock — not atomic

## Summary

The `reset_state` dispatcher iterates over registered subsystem
callbacks (risk store, rate-limit counters, cache, challenge state,
session metadata, enforcement state) and invokes each in order.
There is no global lock held across the iteration, so a concurrent
data-plane request that arrives midway through the reset sees a
mixed state — e.g. risk counters cleared but rate-limit buckets not
yet cleared, or cache cleared but per-IP strike history still
populated.

§2.4 of the v2.3 contract reads:

> *`reset_state` BẮT BUỘC synchronous và atomic từ góc nhìn của
> benchmarker. ... KHÔNG ĐƯỢC expose partially reset state sau khi
> đã trả success.*

It explicitly allows implementations to "tạm thời reject hoặc queue
các in-flight non-control requests" during the reset. The current
implementation does neither — it simply runs the callbacks one by
one while the data plane keeps serving.

## Observed code path

`crates/aegis-control/src/interop/control.rs:264-282` (paraphrased):

```rust
pub async fn handle_reset_state(rt: &InteropRuntime) -> Response<...> {
    let snapshot = rt.reset_callbacks.load();
    for cb in snapshot.iter() {
        cb().await;     // each callback clears its own subsystem
    }
    // Build success response
    ...
}
```

Each `cb()` is responsible for its own subsystem's lock, but no
container-level synchronization gates *requests* from entering
the pipeline during the iteration. A request can interleave between
two callbacks and observe `state_A: cleared, state_B: not_cleared`.

The contract's "may temporarily reject" clause suggests the
expected design: either an `RwLock` whose write side is acquired
for the whole iteration (data-plane requests acquire read side), or
a "reset in progress" flag that causes the data plane to return
`503 Service Unavailable` for the brief window.

## Repro

```sh
SECRET="${AEGIS_BENCHMARK_SECRET:-waf-hackathon-2026-ctrl}"
HOST="http://127.0.0.1:8080"

# 1. Burn risk + rate-limit state into the WAF:
for i in $(seq 1 200); do
    curl -sk "$HOST/?q=1%27%20OR%20%271%27%3D%271" -o /dev/null
done

# 2. Issue reset_state in one terminal while traffic continues in
#    another:
( for i in $(seq 1 500); do
      curl -sk "$HOST/" -o /dev/null \
          -w "%{http_code} "
  done; echo ) &

curl -sk -X POST -H "X-Benchmark-Secret: $SECRET" \
    "$HOST/__waf_control/reset_state" | jq

wait
# Without a lock, some of the concurrent requests will see a
# transient mixed state — rate-limit cleared but blacklist not yet
# cleared, etc. Hard to demonstrate deterministically; visible as
# inconsistent X-WAF-Risk-Score during the reset window.
```

## Impact

- §2.4 "atomic from benchmarker's POV" violated whenever the harness
  sends a request during the reset window (which is exactly the
  scenario the clause is designed for).
- The contract warns: *"BTC CÓ THỂ áp dụng scoring penalty vì
  premature success responses có thể làm nhiễm các test sau, làm
  benchmark results flaky, hoặc yêu cầu thêm manual verification."*
- The non-atomic reset makes benchmark runs *flaky* — the same
  payload sequence on the same WAF can score differently if reset
  timing differs.

## Suggested fix

Add a `tokio::sync::RwLock<()>` to the data-plane shared state:

- Data-plane request handlers acquire `read()` for the duration of
  the request pipeline.
- `handle_reset_state` acquires `write()` for the duration of the
  callback iteration; this naturally blocks new requests and waits
  for in-flight requests to drain (or you can add a brief timeout
  and fail-loud).

```diff
 pub async fn handle_reset_state(rt: &InteropRuntime) -> Response<...> {
+    // §2.4 — atomic from benchmarker's POV. Acquire write to drain
+    // in-flight requests, then run the callbacks under the lock so
+    // no new request can observe a partially-reset state.
+    let _guard = rt.reset_lock.write().await;
     let snapshot = rt.reset_callbacks.load();
     for cb in snapshot.iter() {
         cb().await;
     }
+    // _guard drops here; new requests resume.
     ...
 }
```

Data-plane wiring (in `accept.rs` / `data_plane.rs`):

```rust
let _request_guard = interop_runtime.reset_lock.read().await;
// ... rest of request handling
```

Alternative (lighter-weight): an `AtomicBool` "reset in progress"
that causes the data plane to return `503` with `Retry-After: 0`
during the reset window. Acceptable per §2.4 ("CÓ THỂ tạm thời
reject"). Cheaper than the RwLock if reset is rare and you don't
want pipeline-wide locking.

## Verification

After the fix, the concurrent burst above should show either
all requests succeeding with a clean post-reset state or a brief
window of 503s (depending on which option is chosen), and the
state observed before vs after the reset should be cleanly
partitioned by the timestamp of the reset response.

A regression case in `tests/contract/` should burn state, fire a
concurrent burst against a reset, and assert that no request
returns a header set inconsistent with either the pre-reset or
post-reset snapshot.

## Severity rationale

HIGH. Hard to demonstrate deterministically (timing-dependent)
but the contract explicitly calls it out, and "benchmark results
flaky" is exactly the failure mode for any team that runs the
harness twice.
