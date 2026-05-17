---
id: 2026-05-17-high-rate-limit-ddos-bundle
date: 2026-05-17T00:00Z
severity: HIGH
area: security · rate-limit · DDoS
component: crates/aegis-security/src/{rate_limit/bucket.rs, rate_limit/ip_limiter.rs, ddos.rs}
interop_contract: official rules §5.2 #02 + #03 · Round-1 stability
status: open
test_mode: source-review
---

# F-HIGH-rate-limit-ddos bundle — 5 issues in rate-limit + DDoS

---

## RD-01 · `bucket.rs` delegates to in-memory backend whose token-bucket is broken (cf. F-CRITICAL-007 from proxy audit)

**Component:** [rate_limit/bucket.rs:9-16](aegis-gate/crates/aegis-security/src/rate_limit/bucket.rs#L9-L16)

The `take` API forwards to `state.token_bucket()`. The proxy-audit
finding F-CRITICAL-007 reports that the in-memory `StateBackend`'s
`decode_bucket` returns `Instant::now()` and the bucket never
refills. Bucket-based rate limit in this module is dead unless
the deployed backend is Redis.

This module's tests use a LOCAL `MockBucket` (lines 30-72) that
re-implements the math correctly, so tests pass green while
production uses a broken impl.

**Fix:** either (a) fix the in-memory backend per the previous
audit, or (b) re-implement the token bucket locally inside `bucket.rs`
using `DashMap` like `ip_limiter.rs` does for sliding-log.

---

## RD-02 · `ip_limiter.rs` sweep capped at one run per 60 s — under DDoS, allows millions of map entries before reclaim

**Component:** [rate_limit/ip_limiter.rs:177-199](aegis-gate/crates/aegis-security/src/rate_limit/ip_limiter.rs#L177-L199)

`IDLE_SWEEP_INTERVAL = 60s`, hardcoded. Under sustained 100k unique-IP
DDoS, 60 s of growth = 6 million entries before reclaim. Each entry
holds a `VecDeque<Instant>`. RAM footprint balloons before any GC
fires.

**Fix:** add a soft cap on `map.len()` that triggers immediate
sweep when crossed:

```rust
if self.map.len() > self.cfg.max_entries_soft_cap {
    self.sweep_expired_now();
}
```

Plus `last_seen` timestamp eviction (drop entries idle > 5 min).

---

## RD-03 · `ip_limiter.rs::consume` holds DashMap write guard across O(N) drain loop

**Component:** [rate_limit/ip_limiter.rs:131](aegis-gate/crates/aegis-security/src/rate_limit/ip_limiter.rs#L131)

`DashMap::entry(ip)` returns a write guard held for the entire body,
including the `while pop_front` loop that drops expired timestamps.
For an attacker's hot IP with thousands of expired timestamps, the
loop is O(N) UNDER the write lock — serializes every other thread
trying to touch the same shard.

**Fix:** bound the per-call work:

```rust
// Drop at most K expired timestamps per call; the next call drops more.
let max_drop_per_call = 64;
let mut dropped = 0;
while entry.front().map_or(false, |t| now - *t > window) && dropped < max_drop_per_call {
    entry.pop_front();
    dropped += 1;
}
```

Or: cap the per-entry VecDeque length to `2 * limit` and let the
cap-trim happen on push.

---

## RD-04 · `ddos.rs::tick_rps` races `check` via `swap(0)`

**Component:** [ddos.rs:256-271](aegis-gate/crates/aegis-security/src/ddos.rs#L256-L271)

```rust
let count = self.counter.swap(0, Ordering::Relaxed);
```

`swap(0)` resets the counter mid-flight. Concurrent `fetch_add(1)`
increments arriving between `load` and `swap` are lost. Under load,
observed `rolling_rps` undercounts → DDoS detection lags.

**Fix:** use a 1-second ring buffer or atomic snapshot — fetch the
current value, store back `count - delta` instead of zeroing.

Or: replace with `tokio::time::interval` driving an explicit
"rotate the window" message; counters are per-second slots, never
zeroed mid-second.

---

## RD-05 · `auto_block` fires in `observe_only` mode

**Component:** [ddos.rs:233-234](aegis-gate/crates/aegis-security/src/ddos.rs#L233-L234)

On breach, `state.auto_block(ip)` is called unconditionally. The
`observe_only` check happens DOWNSTREAM (whether to deny the
response). But the side-effect (IP added to the auto-block list) has
already landed.

Observation mode must be side-effect-free for state tables. Otherwise
operators running "observe before enforce" see different behavior on
the second probe than on the first.

**Fix:**

```diff
 if breach {
+    if !self.cfg.observe_only {
         self.state.auto_block(ip, ttl).ok();
+    }
     ...
 }
```

---

## Severity rationale

HIGH. RD-01 makes burst-control infrastructure dead. RD-02/RD-03
let the very DDoS-protection subsystem be DoS'd. RD-04/RD-05 break
operator semantics around observe-mode and detection accuracy.
Each fix is small and self-contained.
