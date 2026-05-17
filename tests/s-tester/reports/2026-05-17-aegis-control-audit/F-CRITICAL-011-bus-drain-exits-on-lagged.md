---
id: 2026-05-17-bus-drain-exits-on-lagged
date: 2026-05-17T00:00Z
severity: CRITICAL
area: dashboard service · audit bus subscribe
component: crates/aegis-control/src/dashboard_services.rs:428 (drain task)
interop_contract: §5.6 "Live audit ≤5s latency" · Round-1 audit-log filterable
status: open
test_mode: source-review (spot-verified)
---

# F-CRITICAL-011 · Bus drain loop exits PERMANENTLY on `RecvError::Lagged` — under burst, audit ring stops being fed, Live Feed freezes forever

## Summary

The dashboard's central drain task subscribes to the audit bus and
distributes events into the audit ring, stats aggregator, and
attacks aggregator. **Spot-verified** at [dashboard_services.rs:428](aegis-gate/crates/aegis-control/src/dashboard_services.rs#L428):

```rust
while let Ok(ev) = rx.recv().await {
    Self::dispatch_event(&stats_clone, &attacks_clone, ...).await;
}
```

`tokio::sync::broadcast::Receiver::recv` can return three variants:

- `Ok(T)` — event
- `Err(RecvError::Lagged(n))` — subscriber fell behind; `n` events dropped
- `Err(RecvError::Closed)` — sender gone

`while let Ok(...)` treats BOTH errors as terminal — the loop exits
permanently. Under any traffic burst that overruns the broadcast
channel capacity, the subscriber sees `Lagged`, the loop terminates,
and the audit ring stops being fed for the rest of the process's
life. Effects:

- `/api/audit/since` flat-lines (no new events arrive)
- §5.6 "Live audit ≤5s latency" violated; Live Feed UI freezes
- Stats / attack-type charts stop updating
- Round-1 "audit log filterable" silently breaks; the dashboard
  shows "no recent events" while the WAF continues serving traffic

The proxy's own audit persist task (`jsonl.rs:381-388`) uses the
correct pattern:

```rust
match rx.recv().await {
    Ok(ev) => { ... }
    Err(RecvError::Lagged(n)) => { metrics::dropped(n); continue; }
    Err(RecvError::Closed) => break,
}
```

So the bug is purely in the dashboard drain — the pattern is known
elsewhere in the codebase.

## Impact

- **§5.6 violation under load** — the very condition this audit
  subsystem is meant to handle (high-volume audit emit) causes the
  subsystem to silently die.
- **Round-1 Audit Log Viewer + Live Feed Pass/Fail** — both go from
  "works" to "frozen" with no operator-visible warning.
- **Attack Battle scoring** — Red Team DDoS scenario explicitly
  expects the WAF to maintain observability under stress
  ("graceful degradation"). This bug means observability dies first.

## Suggested fix

Mirror the jsonl.rs pattern:

```diff
-while let Ok(ev) = rx.recv().await {
-    Self::dispatch_event(&stats_clone, &attacks_clone, ...).await;
-}
+loop {
+    match rx.recv().await {
+        Ok(ev) => {
+            Self::dispatch_event(&stats_clone, &attacks_clone, ...).await;
+        }
+        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
+            metrics::audit_bus_dropped(n);
+            tracing::warn!(dropped = n, "audit bus subscriber lagged");
+            continue;
+        }
+        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
+    }
+}
```

Also: increase the broadcast channel capacity (currently default
~256 per Agent reading). For a 5k req/s WAF, even a small dashboard
hiccup overruns 256. Recommend 4096+ for the dashboard subscriber.

Cross-fix: F-CRITICAL-012 (sync fs I/O blocks tokio worker) compounds
this — the worker thread stall makes `Lagged` more likely.

## Verification

```sh
# Burst traffic to fill the audit bus faster than the dashboard
# drain can dispatch.
make mock-load-mix    # ~5k RPS per Makefile

# After 30s, dashboard:
curl -sk "$HOST/api/audit/since?limit=10" | jq '.events[0].ts'
# After fix: a recent ts.
# Today (after Lagged fires): the same old ts forever.

# Or measure with metrics:
curl -sk "$HOST/metrics" | grep audit_bus_dropped
# After fix: monotonically increasing counter.
# Today: no such metric exists.
```

Add a regression test that:
1. Subscribes via /dashboard/sse.
2. Generates burst traffic exceeding channel capacity.
3. Waits 5 s + sends 1 more event.
4. Asserts the new event arrives via SSE (today: it doesn't).

## Severity rationale

CRITICAL. 5-LoC fix that touches a single function. The bug is
catastrophic under exactly the load condition the WAF is designed
for. Pattern is already correctly applied elsewhere in the
codebase (jsonl sink) — pure copy-paste fix.
