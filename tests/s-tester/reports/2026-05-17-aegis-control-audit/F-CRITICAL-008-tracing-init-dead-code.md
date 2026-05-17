---
id: 2026-05-17-tracing-init-dead-code
date: 2026-05-17T00:00Z
severity: CRITICAL
area: tracing · OpenTelemetry
component: crates/aegis-control/src/tracing_init.rs
interop_contract: README claim "OTel feature with Jaeger parent-child"
status: open
test_mode: source-review
---

# F-CRITICAL-008 · `tracing_init.rs` (305 LoC) is dead code; `random_hex()` uses `blake3(timestamp:counter)` — predictable trace IDs if ever wired

## Summary

`crates/aegis-control/src/tracing_init.rs` contains 305 LoC of
tracing setup: `init()`, `random_hex()`, `TraceContext::parse`,
`ensure_trace_context`. The functions exist as a library; the actual
production OTel exporter lives in `aegis-bin/src/otel.rs` (Agent D
verified).

In this module:
- `init()` is a stub that returns `true` unconditionally.
- `random_hex()` derives "random" trace IDs from
  `blake3(now_nanos || counter)` — not crypto-random.
- `TraceContext::parse` has zero non-test callers.

So:
- If `init()` is called somewhere thinking it does setup, it does nothing.
- If `random_hex()` is ever called for trace IDs, those IDs are
  predictable + linkable (an attacker can compute the trace ID for
  any future request given the clock + counter, exactly like
  F-CRITICAL-005 from the proxy audit).
- The real OTel path bypasses this module entirely.

## Observed code path

[tracing_init.rs:??] (file content per Agent D):

```rust
pub fn init() -> bool {
    // stub
    true
}

pub fn random_hex(len: usize) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let cnt = COUNTER.fetch_add(1, Ordering::Relaxed);
    let hash = blake3::hash(format!("trace:{now}:{cnt}").as_bytes());
    hash.to_hex()[..len].to_string()
}
```

Production OTel handling is at `aegis-bin/src/otel.rs` (tonic gRPC
exporter, separately wired). The `tracing_init.rs` module is library
scaffolding never connected.

## Impact

- **README claim** — "OTel feature with Jaeger parent-child traces" is true (lives in aegis-bin) but a reader of this module thinks setup happens here and gets misled.
- **If anyone wires `random_hex`** — predictable trace IDs. Combined with audit-chain Request-ID being predictable too (F-HIGH-004), the entire correlation backbone is forgeable.
- **Maintenance landmine** — 305 LoC of test-passing scaffolding that doesn't do what its name suggests.

## Suggested fix

### Path A — Delete

The real OTel impl is elsewhere. Delete this module and update any
import in `crates/aegis-control/src/lib.rs`.

### Path B — Wire it correctly + fix random_hex

Move the real OTel setup from `aegis-bin/src/otel.rs` into
`tracing_init::init()`. Replace `random_hex` with `OsRng`:

```rust
pub fn random_hex(len: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; (len + 1) / 2];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf.iter().take(len / 2).map(|b| format!("{b:02x}")).collect()
}
```

Recommend **Path A** — the real impl exists; this module is just
confusing scaffolding.

## Verification

After Path A: `grep -rn "tracing_init" crates/` returns zero hits.
Audit-trail clean.

## Severity rationale

CRITICAL on misleading-scaffolding grounds + latent entropy bug if
wired. ~50 LoC fix (delete).
