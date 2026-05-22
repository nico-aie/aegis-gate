---
id: 2026-05-17-interop-audit-sync-fs-io-on-tokio-worker
date: 2026-05-17T00:00Z
severity: CRITICAL
area: interop audit sink · tokio runtime
component: crates/aegis-control/src/interop/audit.rs:86-95 (MinimalJsonlSink::append)
interop_contract: §Performance 20/120 (p99 ≤5ms) · §Round-1 stability under traffic
status: open
test_mode: source-review
---

# F-CRITICAL-012 · `interop/audit.rs::append` does sync `std::fs::write_all` + Mutex on tokio async hot path without `spawn_blocking` → blocks worker threads on every request

## Summary

The v2.3 interop audit sink writes every decision's JSONL line
synchronously while holding a `std::sync::Mutex`. The function is
called from `aegis-proxy/src/admin_dispatch.rs:1086` inside
`stamp_interop_response` — which itself runs on the tokio async path
for EVERY data-plane request.

Per [interop/audit.rs:86-95](../../../../crates/aegis-control/src/interop/audit.rs#L86-L95):

```rust
pub fn append(&self, entry: &MinimalAuditEntry) -> io::Result<()> {
    let mut writer = self.writer.lock().expect("audit writer poisoned");
    writeln!(writer, "{}", serde_json::to_string(entry)?)?;
    writer.flush()?;
    Ok(())
}
```

Three problems compound:

1. **Sync I/O on async thread**: `writeln!` → `BufWriter::write_all` → eventually `std::fs::File::write_all`. The tokio worker thread doing this gets blocked on `write(2)` syscall + page-cache flush + (per F-HIGH M-?) NO fsync but still kernel buffer churn.

2. **Global Mutex serialization**: every request across all worker
   threads contends for `self.writer` lock. Under 5k req/s, the lock
   becomes a single chokepoint.

3. **`expect("audit writer poisoned")` panic on poisoned lock**:
   any prior panic inside another writer (rare but possible — e.g. OOM during `serde_json::to_string`) poisons the mutex, and every subsequent request panics.

The contract requires p99 ≤ 5 ms. The disk write alone can be
0.5–10 ms depending on filesystem; lock contention adds more.

## Suggested fix

### Use `spawn_blocking` or a writer task with mpsc

Option A — `spawn_blocking` per write:

```rust
pub async fn append(&self, entry: &MinimalAuditEntry) -> io::Result<()> {
    let line = serde_json::to_string(entry)?;
    let writer = self.writer.clone();
    tokio::task::spawn_blocking(move || {
        let mut w = writer.lock().unwrap_or_else(|p| p.into_inner());
        writeln!(w, "{}", line)?;
        w.flush()?;
        Ok::<_, io::Error>(())
    })
    .await
    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))??;
    Ok(())
}
```

Option B (preferred for high throughput) — single dedicated writer task:

```rust
pub struct MinimalJsonlSink {
    tx: tokio::sync::mpsc::Sender<MinimalAuditEntry>,
}

impl MinimalJsonlSink {
    pub fn new(path: &Path) -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::channel(4096);
        let writer = BufWriter::new(File::options().append(true).create(true).open(path)?);
        tokio::task::spawn_blocking(move || {
            let mut w = writer;
            while let Some(entry) = rx.blocking_recv() {
                let _ = writeln!(w, "{}", serde_json::to_string(&entry).unwrap_or_default());
                let _ = w.flush();
            }
        });
        Self { tx }
    }

    pub async fn append(&self, entry: MinimalAuditEntry) -> io::Result<()> {
        self.tx.send(entry).await.map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "audit writer closed"))?;
        Ok(())
    }
}
```

Channel-bounded backpressure: when the channel is full (writer can't
keep up), `tx.send().await` waits — propagating natural backpressure
to the request handler instead of blocking the worker thread.

Combine with periodic `fsync` (per F-HIGH-? in audit bundle) for
durability.

### Replace `expect` with soft fallback

```diff
-let mut writer = self.writer.lock().expect("audit writer poisoned");
+let mut writer = self.writer.lock().unwrap_or_else(|p| p.into_inner());
```

## Verification

Use a load test that fills 5k req/s on a single CPU and observes
p99:

```sh
# Before fix: p99 spikes above 5ms during disk fsync stalls.
# After fix: p99 stable, decoupled from disk latency.
make mock-load-mix
curl -sk "$HOST/metrics" | grep aegis_request_duration_seconds_bucket
```

Add tokio-console (or similar) instrumentation to count
worker-thread blocking time. Should drop to near-zero after fix.

## Severity rationale

CRITICAL on Performance 20/120 grounds. The p99 ≤ 5 ms claim cannot
hold while every request stalls on a sync disk write under a global
lock. ~30 LoC fix (Option B refactor).
