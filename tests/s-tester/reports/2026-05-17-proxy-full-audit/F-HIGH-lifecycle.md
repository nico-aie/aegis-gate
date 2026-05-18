---
id: 2026-05-17-high-lifecycle-bundle
date: 2026-05-17T00:00Z
severity: HIGH
area: process lifecycle · hot-restart · load shedding
component: crates/aegis-proxy/src/{hotbin.rs,shed.rs}
interop_contract: Round 1 stability ("no dropped connections" on hot-restart) · Round 3 graceful degradation
status: open
test_mode: source-review
---

# F-HIGH-lifecycle bundle — 4 issues in hotbin (USR2 hot-restart) + shed (load shedding)

---

## L-01 · `HotReloader::state` field defined but never read or transitioned

**Component:** [hotbin.rs:25, 680](aegis-gate/crates/aegis-proxy/src/hotbin.rs#L25) · [run.rs:1376-1402](aegis-gate/crates/aegis-proxy/src/run.rs#L1376-L1402)

The `ReloadState { Idle, Pending, Draining, RolledBack }` enum is
defined and stored on `HotReloader::state` but no code transitions
it or reads it. The polling task at `run.rs:1384` loops on
`take_signal()` and calls `run_handover` serially — which prevents
double-firing TODAY because the polling task is the only caller.

If a future caller invokes `run_handover` from elsewhere (e.g. an
admin endpoint, a CRON event), nothing prevents two concurrent
forks of the same listener FDs.

Additionally: `signal_received` `AtomicBool` is reset by
`take_signal()` BEFORE the (long) handover begins, so a second
SIGUSR2 mid-handover is silently dropped without queueing.

**Fix:**
1. Actually transition `state` on entry/exit of `run_handover`;
   reject calls when state != `Idle`.
2. Use a `tokio::sync::Notify` instead of `AtomicBool` so multiple
   pending signals coalesce correctly.

---

## L-02 · `ReadinessPipe::new` opens pipe with non-atomic CLOEXEC set → fd leak race

**Component:** [hotbin.rs:319-356](aegis-gate/crates/aegis-proxy/src/hotbin.rs#L319-L356)

`ReadinessPipe::new` calls `unsafe pipe()` then sets
`O_NONBLOCK | FD_CLOEXEC` via separate `fcntl` calls. Between
`pipe()` returning and the `fcntl(F_SETFD, FD_CLOEXEC)` line, a
concurrent `fork+exec` (e.g. the audit JSONL sink spawning a child,
or the SIGUSR2 task firing) inherits the readable fd and keeps it
open for the lifetime of the child.

The comment at line 317 dismisses `pipe2(O_CLOEXEC|O_NONBLOCK)` as
"too Linux-specific", but the deployment target IS Linux per the
audit's `Linux 5.14`.

**Fix:** use `pipe2`:

```rust
let mut fds = [0i32; 2];
let ret = unsafe {
    libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK)
};
if ret != 0 { return Err(...); }
```

---

## L-03 · `std::env::remove_var` race during boot on Rust 2024 = UB

**Component:** [hotbin.rs:419-451](aegis-gate/crates/aegis-proxy/src/hotbin.rs#L419-L451)

`signal_readiness_to_parent` calls `unsafe std::env::remove_var`
during the hot-restart path. The doc comment dismisses the race as
"only runs once at boot" — but actually:

- `run.rs:1408` runs AFTER the SIGUSR2 listener task is spawned
  (`run.rs:1384`).
- `run.rs:1408` runs AFTER the state-rehydrate task is spawned
  (`run.rs:1434`).

Both background tasks may read env vars concurrently. On Rust 2024
edition, mutating env vars while another thread reads them is
undefined behaviour (the standard library moved env mutation behind
`unsafe` precisely because of this).

**Fix:** move `remove_var` to the very top of `main()`, before any
threads exist. Alternatively, drop the `remove_var` entirely — it's
purely cosmetic (avoids re-inheriting the env in a future fork).

---

## L-04 · LoadShedder gradient algorithm is fundamentally broken: limit only decreases

**Component:** [shed.rs:38-76](aegis-gate/crates/aegis-proxy/src/shed.rs#L38-L76)

`record_rtt` computes `gradient = rtt_min / rtt_now` (always ≤ 1
because `rtt_min` is the minimum by construction) and does
`new_limit = current_limit * gradient`. This means:

- `gradient = 1` only when current latency equals the minimum
  observed — i.e. limit stays put.
- `gradient < 1` whenever current latency is above minimum — i.e.
  limit decreases.

The algorithm has NO additive-increase branch. Once latency briefly
spikes, the limit drops to `min_limit` and stays there. Any "AIMD"
(additive-increase / multiplicative-decrease) recovery is missing.

Additionally, the read-modify-write pattern (`load` then `store`)
at lines 66-74 is racy across threads; concurrent `record_rtt`
calls can clobber each other's updates.

Per F-CRITICAL-006, `LoadShedder` has zero callers so the bug is
latent — but if you wire it in (as recommended), this needs to be
fixed FIRST or the WAF will permanently throttle after any latency
event.

**Fix:**

```diff
-let gradient = rtt_min as f64 / rtt_now as f64;
-let new_limit = (current_limit as f64 * gradient).max(min_limit as f64) as u32;
+// Gradient2: AI part (on success path, recover) + MD part (on
+// breach, shrink).
+let gradient = (rtt_min as f64 / rtt_now as f64).clamp(0.5, 1.0);
+let queue_size_estimate = 1.0;     // or based on in-flight count
+let new_limit = ((current_limit as f64 * gradient) + queue_size_estimate)
+    .max(min_limit as f64)
+    .min(max_limit as f64) as u32;
```

Replace the `load` + `store` with `fetch_update` to make it atomic:

```rust
self.limit.fetch_update(Relaxed, Relaxed, |cur| {
    Some(compute_new_limit(cur, rtt_now, rtt_min))
}).ok();
```

---

## Severity rationale

HIGH. L-01 and L-03 are correctness issues that surface only on
specific operational paths (re-entrant hot-restart; concurrent env
mutation). L-02 is a real but rare fd leak. L-04 is a logic bug
in a currently-dead module — promoted from MEDIUM because if anyone
wires shed.rs per the F-CRITICAL-006 recommendation without fixing
this first, the WAF gets worse, not better.
