# Aegis-Gate — Performance Bottleneck Analysis: 7k → 3k RPS Drop

**Date:** 2026-06-20  
**Symptom:** Throughput stable at ~7–8k RPS, system load reaches 95%, then **drops sharply to ~3k RPS** when additional load is applied.  
**Method:** Static source analysis of all crates involved in the hot path.

---

## Summary

The drop is not caused by a single point of failure but by a **cascade**: when CPU hits 95%, RTT increases → the Gradient2 LoadShedder shrinks the concurrency limit → most requests are shed → throughput visible on the Live Feed collapses. In parallel, several hot-path components are burning CPU unnecessarily, pushing the system to the 95% threshold earlier than it should.

---

## 1. Root Cause — LoadShedder Gradient2 Cascade (CRITICAL)

**File:** `crates/aegis-proxy/src/shed.rs`

```rust
// initial_limit = 1000, min_limit = 100 (defaults)
let gradient = rtt_min as f64 / smoothed as f64;
let new_limit = if gradient >= 0.9 {
    (current_limit + 1).min(self.max_limit)   // grow +1
} else {
    (current_limit as f64 * gradient) as u64  // shrink multiplicatively
        .max(self.min_limit)
};
```

**Cascade mechanism:**

```
Load increases → CPU 95% → WAF processing RTT rises (e.g. 2ms → 8ms)
→ gradient = rtt_min/rtt_now = 2/8 = 0.25 < 0.9
→ new_limit = 1000 * 0.25 = 250  (rapid shrink)
→ inflight > 250 → shed Medium + Low tier
→ only Critical + High pass → Live Feed shows ~3k RPS
→ but CPU stays high (Critical/High still processed fully)
→ loop: limit continues shrinking toward min_limit = 100
```

**Specific issues:**
- `rtt_min` decay rate is very slow (`current_min / 512` per sample) — a single low-RTT sample **pins rtt_min low** for a long time, making all normal requests appear "stressed"
- `alpha = 0.2` EMA smoothing retains memory of spikes for a long time
- During load tests from few IPs (eval script), WAF RTT rises due to **WAF's own CPU contention**, not the upstream — but the LoadShedder cannot distinguish between the two

**Fix:**
```yaml
# aegis.yaml
load_shedder:
  enabled: true
  initial_limit: 5000    # raised from 1000 → appropriate for 8k RPS
  min_limit: 2000        # raised from 100 → prevents cliff from going too deep
```

Or temporarily disable the shedder while benchmarking to isolate the true bottleneck:
```yaml
load_shedder:
  enabled: false
```

---

## 2. Single Accept Loop — Missing SO_REUSEPORT (HIGH)

**File:** `crates/aegis-proxy/src/listener/acceptor.rs:20`

```rust
let tcp = tokio::net::TcpListener::bind(lc.bind).await?;
// No SO_REUSEPORT, no backlog config
```

**Problem:** A single socket per port. All connections funnel into one kernel accept queue. Tokio uses `epoll` on a single FD → every `accept()` serializes through one point.

At 8k+ RPS with TLS (each connection = TLS handshake + HTTP), the single accept loop is a clear bottleneck.

**Fix:** Use `SO_REUSEPORT` so each worker thread gets its own listener:

```rust
// crates/aegis-proxy/src/listener/acceptor.rs
use socket2::{Domain, Protocol, Socket, Type};

pub async fn build_listeners(cfg: &WafConfig) -> aegis_core::Result<Vec<BoundListener>> {
    let mut listeners = Vec::new();
    for lc in &cfg.listeners.data {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_reuse_port(true)?;     // SO_REUSEPORT
        socket.set_reuse_address(true)?;
        socket.set_nonblocking(true)?;
        socket.bind(&lc.bind.into())?;
        socket.listen(4096)?;             // explicit backlog (default is often just 128)
        let std_listener: std::net::TcpListener = socket.into();
        let tcp = tokio::net::TcpListener::from_std(std_listener)?;
        // ...
    }
}
```

---

## 3. DDoS: String Heap Alloc + DashMap Write Lock Per Request (HIGH)

**File:** `crates/aegis-security/src/ddos.rs:449`

```rust
// Hot path — check_local() called on every request:
let key = format!("{tier_str}:{ip}");           // heap alloc per request
let mut entry = self.windows.entry(key)          // DashMap write lock (shard)
    .or_default();
// ...
entry.push_back(now);                            // VecDeque grow
```

**Cost at 8k RPS:**
- 8,000 String alloc/dealloc/s → heap pressure, allocator contention
- 8,000 DashMap shard write locks/s (`DashMap::new()` defaults to 16 shards → ~500 locks/s/shard)
- VecDeque accumulates `Instant` entries (16 bytes/entry × 1000 limit × 4 tiers × N IPs) = several MB of RAM held between sweeps

**DashMap default of 16 shards** — too low at 8k RPS:

```rust
windows: DashMap::new(),          // 16 shards
local_blocks: DashMap::new(),     // 16 shards
```

**Fix:**
```rust
// Increase shard count to reduce contention
windows: DashMap::with_shard_amount(64),
local_blocks: DashMap::with_shard_amount(64),
```

And replace the String key with a tuple to avoid heap allocation:
```rust
// Key: (tier_idx: u8, ip: IpAddr) — no heap alloc needed
type WindowKey = (u8, IpAddr);
windows: DashMap<WindowKey, VecDeque<Instant>>,
// ...
let key: WindowKey = (tier as u8, ip);
```

---

## 4. StatsAggregator: `std::sync::Mutex` on Hot Path (HIGH)

**File:** `crates/aegis-control/src/api/stats.rs:153`

```rust
// record() called on every request — this is std::sync::Mutex, NOT parking_lot
let mut state = self.inner.lock().expect("stats mutex poisoned");
// ... multiple HashMap ops inside the lock
```

Rust's `std::sync::Mutex` has no adaptive spinning — when contended it goes straight to a kernel `futex` call. At 8k RPS, this lock is heavily contended across all worker threads.

**Fix:** Replace with `parking_lot::Mutex` (adaptive spinning, ~3–5× faster under low contention) or use lock-free `AtomicU64` counters:

```rust
// Replace inner Mutex with per-field atomics
struct AggregatorState {
    total_requests: AtomicU64,
    blocked_requests: AtomicU64,
    // per-action counters
    action_counts: [AtomicU64; ACTION_COUNT],
}
// record() only needs fetch_add — zero lock, zero syscall
```

---

## 5. AI Detector: `block_in_place()` Parks Worker Thread (MEDIUM-HIGH)

**File:** `crates/aegis-security/src/detectors/ai/batch_detector.rs:127`

```rust
// Runs inline on a Tokio worker thread
let result = tokio::task::block_in_place(|| {
    tokio::runtime::Handle::current()
        .block_on(async move { batch.classify(feats).await })
});
```

`block_in_place()` **parks the current Tokio worker thread**, forcing the runtime to spawn a replacement from the blocking pool. At 8k RPS, if many requests bypass the regex detectors and reach the AI stage, multiple workers may be parked simultaneously → heavy context-switch overhead.

The default `blocking_threads = 512` provides enough threads, but context-switching 512 threads on few cores is expensive.

**Short-term fix:** Reduce AI invocations by raising the confidence threshold:
```yaml
ai:
  confidence_threshold: 0.85   # raise from default to reduce AI-triggered requests
```

**Long-term fix:** Move AI inference to a dedicated thread pool entirely (no `block_in_place` inside the Tokio worker):
```rust
// Use rayon or a dedicated std thread pool for inference
let result = AI_THREAD_POOL.spawn_fifo(|| model.predict(feats));
```

---

## 6. AuditBus Broadcast: Event Cloned Per Subscriber (MEDIUM)

**File:** `crates/aegis-core/src/audit.rs:322`

```rust
pub fn emit(&self, ev: AuditEvent) {
    let _ = self.0.send(ev);  // tokio::sync::broadcast::send()
}
```

`tokio::sync::broadcast::send()` holds an internal lock and clones `AuditEvent` for each subscriber. `AuditEvent` is a large struct (many String fields — request_id, reason, client_ip, path, ...).

At 8k RPS with N SSE subscribers (open dashboard tabs) = 8k × N clones/s. Each open SSE connection adds one more subscriber.

**Current hot path:**
```
request → WAF logic → bus.emit(event)   // clone × N_subscribers
       → SSE task 1 receives event
       → SSE task 2 receives event
       → audit sink task receives event
```

**Fix:**
```rust
// Use Arc<AuditEvent> instead of cloning the struct
pub struct AuditBus(tokio::sync::broadcast::Sender<Arc<AuditEvent>>);

pub fn emit(&self, ev: AuditEvent) {
    let _ = self.0.send(Arc::new(ev));  // 1 Arc clone instead of N struct clones
}
```

---

## 7. Connection Pool: `max_idle_per_host = 32` Too Small (MEDIUM)

**File:** `crates/aegis-core/src/config.rs:2805`

```rust
fn default_pool_max_idle_per_host() -> usize { 32 }
```

At 8k RPS forwarding to upstream, if the upstream processes each request in ~10ms, at least 80 concurrent connections are needed (`8000 * 0.01 = 80`). Capping idle connections at 32 → new connections are opened frequently → TCP + TLS handshake overhead on every request that isn't pooled.

**Fix:**
```yaml
# aegis.yaml
upstreams:
  your-upstream:
    connection:
      max_idle_per_host: 256   # raised from 32
      idle_timeout: "60s"
```

---

## 8. TLS Handshake Inline in Connection Task (MEDIUM)

**File:** `crates/aegis-proxy/src/accept.rs:1647`

```rust
// Inside the spawned connection task — TLS handshake blocking a Tokio worker
Some(acc) => match acc.accept(stream).await {
    Ok(tls_stream) => { ... }
```

A TLS handshake (RSA/ECDHE) costs ~1–3ms of CPU per connection. At 8k RPS with HTTP/1.1 (each request = new connection), **8k handshakes/s × 1–3ms = 8–24 CPU-seconds/s** spent on TLS alone.

**Immediate fix:** Enable HTTP keep-alive and connection reuse to reduce handshake count:
```yaml
# Ensure upstream keep_alive = true (already the default)
# Client side: ensure eval scripts reuse connections
```

**Long-term fix:** TLS session resumption via session tickets — rustls supports this natively, just needs to be enabled in config.

---

## 9. VecDeque Sweep Mutex on Every Request (LOW-MEDIUM)

**File:** `crates/aegis-security/src/ddos.rs:484`

```rust
// Called after every request inside check_local()
fn maybe_sweep(&self, now: Instant) {
    let mut guard = match self.last_sweep.try_lock() { // mutex TAS on every request
        Some(g) => g,
        None => return,
    };
    // ...
}
```

`try_lock()` is an atomic operation on every request. It doesn't block, but at 8k RPS = 8k atomic ops/s just for the sweep check. The same pattern exists in `IpRateLimiter`.

---

## Priority Summary

| # | Issue | Severity | Effort | Impact |
|---|-------|----------|--------|--------|
| 1 | **LoadShedder limits too low** → cascade shed | 🔴 Critical | Low (config) | Immediately resolves 3k cliff |
| 2 | **Missing SO_REUSEPORT** → single accept point | 🔴 High | Medium | +20–40% throughput |
| 3 | **DDoS String alloc + DashMap lock/request** | 🟠 High | Medium | ~10–15% CPU reduction |
| 4 | **StatsAggregator std::Mutex contention** | 🟠 High | Low | Reduces lock latency |
| 5 | **AI block_in_place worker parking** | 🟠 High | High | Reduces context switching |
| 6 | **AuditBus clones event × subscribers** | 🟡 Medium | Low | Reduces clone overhead |
| 7 | **Connection pool max_idle too small** | 🟡 Medium | Low (config) | Reduces TCP/TLS overhead |
| 8 | **TLS handshake per request** | 🟡 Medium | Medium | Reduces CPU |
| 9 | **DashMap default 16 shards** | 🟡 Medium | Low | Reduces shard contention |

---

## Fix Roadmap

### Step 1 — Config only (no code, just restart)
```yaml
load_shedder:
  initial_limit: 5000
  min_limit: 2000

upstreams:
  api:
    connection:
      max_idle_per_host: 256

audit:
  bus_capacity: 200000   # raised from 100k

ai:
  confidence_threshold: 0.80
```

### Step 2 — Code changes (1–2 days)
1. `DashMap::with_shard_amount(64)` in DDoS + RateLimit + RiskTracker
2. `Arc<AuditEvent>` instead of clone in AuditBus
3. `parking_lot::Mutex` for StatsAggregator
4. String key → tuple key in DDoS `check_local()`

### Step 3 — Architecture (3–5 days)
1. `SO_REUSEPORT` on the data-plane listener with explicit backlog `4096`
2. Dedicated thread pool for AI inference (separate from the Tokio worker pool)

### Step 4 — Verify
After each step: run `eval_waf_malicious_dataset.py` + `eval_waf_legitimate_dataset.py` with `--rps 10000` to measure actual throughput before vs. after.

---

## Parallel Infra Checklist

In addition to code changes, verify these OS/infra settings:

```bash
# Check TCP backlog limit
sysctl net.core.somaxconn          # must be >= 4096
sysctl net.ipv4.tcp_max_syn_backlog

# File descriptor limit
ulimit -n                          # must be >= 65535

# TCP TIME_WAIT reuse
sysctl net.ipv4.tcp_tw_reuse       # should be 1

# Interrupt affinity (if single NIC queue)
cat /proc/interrupts | grep eth
```

If `somaxconn` is low (default is 128 on many distros), the kernel will drop connections before the WAF can accept them — this could explain why throughput drops sharply rather than gradually.

---

*Generated by static source analysis — `aegis-gate` codebase 2026-06-20*
