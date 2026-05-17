---
id: 2026-05-17-sli-ring-buffer-on-of-n
date: 2026-05-17T00:00Z
severity: CRITICAL
area: SLO engine · performance
component: crates/aegis-control/src/slo.rs:216-221 (SliRingBuffer::push) · slo.rs:262 (global Mutex)
interop_contract: §Performance 20/120 (p99 ≤5ms, throughput ≥5000 RPS baseline)
status: open
test_mode: source-review
---

# F-CRITICAL-016 · `SliRingBuffer::push` does `Vec::remove(0)` (O(n) memcpy of up to 10k samples) under global `Mutex` → Performance rubric collapse

## Summary

[slo.rs:216-221](aegis-gate/crates/aegis-control/src/slo.rs#L216-L221):

```rust
fn push(&mut self, sample: SliSample) {
    if self.samples.len() >= self.capacity {
        self.samples.remove(0);    // O(n) memcpy of 10k elements
    }
    self.samples.push(sample);
}
```

`Vec::remove(0)` is `O(n)` — it shifts every subsequent element
forward by one. With `capacity = 10_000`, every push past capacity
shifts ~10k elements.

[slo.rs:262](aegis-gate/crates/aegis-control/src/slo.rs#L262): the
buffer is held inside a `std::sync::Mutex<SliRingBuffer>`. **Every
audit event** (i.e. every request) calls `push` under this lock.

Math: at 5000 req/s = 5000 pushes/s. Once the buffer is at capacity,
that's 5000 × ~10k-element shift per second = **50 million element
moves per second** under a single global lock that ALSO serializes
every other worker thread.

§Performance rubric: "p99 latency overhead ≤5ms | throughput ≥5000
req/s baseline". This single bug torpedoes both.

## Observed code path

[slo.rs:206-221](aegis-gate/crates/aegis-control/src/slo.rs#L206-L221):

```rust
pub struct SliRingBuffer {
    samples: Vec<SliSample>,        // wrong choice; should be VecDeque
    capacity: usize,                // 10_000 by default
}

impl SliRingBuffer {
    fn push(&mut self, sample: SliSample) {
        if self.samples.len() >= self.capacity {
            self.samples.remove(0);   // O(n)!
        }
        self.samples.push(sample);
    }
}
```

[slo.rs:247-262](aegis-gate/crates/aegis-control/src/slo.rs#L247-L262):

```rust
pub struct SloEngine {
    buffers: Mutex<HashMap<SliKind, SliRingBuffer>>,
    fired_history: Mutex<Vec<SloAlert>>,
}
```

Single `Mutex` wrapping the whole map. Every request that emits an
audit event takes this lock.

## Impact

- **Throughput** — 5000 RPS baseline becomes unreachable as soon as
  the buffer hits capacity (within ~2 s on a hot WAF).
- **p99 latency** — every request that contends with another on
  this lock waits its turn. The 50M element-moves/s amplifies the
  hold time massively.
- **CPU usage** — pure waste; could be O(1) with the right data
  structure.

Additionally, [slo.rs:247](aegis-gate/crates/aegis-control/src/slo.rs#L247) — `fired_history: Mutex<Vec<SloAlert>>`
is **never trimmed**. Long-running process accumulates alerts
forever. Latent memory leak (filed as M-? in F-HIGH-slo-metrics
bundle).

## Suggested fix

### 1. Use VecDeque

```diff
 pub struct SliRingBuffer {
-    samples: Vec<SliSample>,
+    samples: std::collections::VecDeque<SliSample>,
     capacity: usize,
 }

 impl SliRingBuffer {
     fn push(&mut self, sample: SliSample) {
         if self.samples.len() >= self.capacity {
-            self.samples.remove(0);
+            self.samples.pop_front();    // O(1)
         }
         self.samples.push_back(sample);  // O(1) amortized
     }
 }
```

`VecDeque::pop_front` is O(1). `push_back` is O(1) amortized.

### 2. Replace global Mutex with per-SLI parking_lot::RwLock or DashMap

```diff
 pub struct SloEngine {
-    buffers: Mutex<HashMap<SliKind, SliRingBuffer>>,
+    buffers: DashMap<SliKind, parking_lot::Mutex<SliRingBuffer>>,
     fired_history: Mutex<Vec<SloAlert>>,
 }
```

`DashMap` shards on the key — different SLIs hit different shards,
no global serialization. `parking_lot::Mutex` is faster than
`std::sync::Mutex`.

For reads (SLO evaluation), use `RwLock` so multiple readers
parallelize.

### 3. Bound `fired_history`

```rust
const MAX_FIRED_HISTORY: usize = 10_000;
// In whatever method appends:
if self.fired_history.lock().len() >= MAX_FIRED_HISTORY {
    self.fired_history.lock().drain(..MAX_FIRED_HISTORY / 4);
}
```

Or convert to a `VecDeque` ring like the SLI buffer.

## Verification

Benchmark before/after:

```sh
cargo bench --bench slo_push    # or similar
# Before: 200 ns/push at low N, 50 µs/push at N=10k
# After:  ~50 ns/push regardless of N
```

End-to-end:

```sh
make mock-load-mix    # 5000 RPS
# Before: p99 spikes above 10ms after 30s of steady load
# After: p99 stays under 2ms steady-state
```

## Severity rationale

CRITICAL on Performance rubric (20/120) grounds. The throughput +
latency claims in the README depend on this not being broken.
~15 LoC fix (VecDeque + DashMap + lock-type swap).
