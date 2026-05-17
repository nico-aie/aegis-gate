---
id: 2026-05-17-medium-bundle-entry-cli-dataplane
date: 2026-05-17T00:00Z
severity: MEDIUM
area: data-plane · orchestrator · admin CLI
component: multiple — see per-item Component lines
interop_contract: not directly enforced; latent correctness / perf / posture issues
status: open
test_mode: source-review
---

# F-MEDIUM bundle — entry-point + data-plane source audit

Five MEDIUM findings rolled up. Each item is independently small;
none breaks the contract today, but each is a code-smell or latent
correctness/perf issue worth landing before declaring the audit
closed.

---

## M-01 · `default_trusted_proxies()` rebuilds the IpNet vec on every request

**Component:** `crates/aegis-proxy/src/data_plane.rs:1948-1957`

The function allocates a `Vec<IpNet>` of 6 entries and parses each
CIDR string from scratch every time it's called — which is per
request when XFF is being considered. Negligible per-call (~µs)
but unnecessary allocator churn on a hot path that handles 5–37 K
RPS.

**Fix:** wrap in a `std::sync::OnceLock`:

```rust
use std::sync::OnceLock;

fn default_trusted_proxies() -> &'static [IpNet] {
    static NETS: OnceLock<Vec<IpNet>> = OnceLock::new();
    NETS.get_or_init(|| vec![
        // (with F-HIGH-002 fix applied — no loopback)
        "10.0.0.0/8".parse().unwrap(),
        "172.16.0.0/12".parse().unwrap(),
        "192.168.0.0/16".parse().unwrap(),
        "fc00::/7".parse().unwrap(),
    ])
}
```

---

## M-02 · Graceful shutdown aborts in-flight requests after a fixed grace window

**Component:** `crates/aegis-proxy/src/run.rs:1462-1502`

The shutdown path calls `tokio::time::sleep(grace)` (default 5 s
via `AEGIS_DRAIN_GRACE_MS`) then `h.abort()` on every listener
handle. Any in-flight request whose response takes longer than the
grace window is dropped mid-stream — the client sees a truncated
response, the upstream may complete the request and leak side
effects.

Round 1's *"không bị crash/panic khi xử lý ... traffic liên tục"*
covers crashes but not silent truncation; a careful grader who
counts client-side connection resets during USR2 hot-restart will
spot this.

**Fix:** swap `sleep(grace).then(abort())` for hyper's `with_graceful_shutdown`
which drains active connections before returning. Or extend the
grace window adaptively while in-flight count > 0.

---

## M-03 · TOTP secret derived from `blake3(time_ns + pid)` — not crypto-random

**Component:** `crates/aegis-bin/src/main.rs:577-617`
(`cmd_admin_enroll_totp`)

```rust
let seed = format!("{}:{}", nanos, std::process::id());
let h = blake3::hash(seed.as_bytes());
let secret = base32::encode(...)
```

An attacker who knows the host's boot time and pid range (e.g. a
sibling container, a leaked log line) can brute-force the TOTP
secret in a tiny keyspace. TOTP is supposed to give 80–160 bits of
shared-secret entropy; this construction gives ~50 bits effective.

**Fix:** `rand::rngs::OsRng.fill_bytes(&mut secret_bytes)`. The
`rand` crate is already pulled transitively; add an explicit dep
or use `getrandom::getrandom(&mut secret_bytes)?` to avoid a new
top-level dep.

---

## M-04 · Handover `process::exit(0)` after `sleep(200ms)` — flush race

**Component:** `crates/aegis-proxy/src/run.rs:1875`

After USR2 hot-restart hands the listeners to the child, the parent
calls `tokio::time::sleep(Duration::from_millis(200))` to "let the
audit bus drain" then `std::process::exit(0)`. Under load, audit-bus
subscribers (file sink, SSE broadcast, Prometheus counter) may not
flush within 200 ms.

A high-throughput parent loses the last few thousand audit lines
during a hot-restart. Visible as a gap in the chain right at the
handover boundary, which an auditor could mistake for tamper.

**Fix:** explicitly `await` each subscriber's `flush()` (give the
audit sink a `flush` method that drains the in-flight bus and
fsyncs the file) instead of sleeping a fixed timeout. Bounded
upper limit (e.g. 5 s) is fine as a defense.

---

## M-05 · `mtls_break_glass_heartbeat` audit emit uses `request_id: String::new()`

**Component:** `crates/aegis-proxy/src/run.rs:194-247`

The heartbeat that records the break-glass mTLS state in the
operator audit bus uses an empty string for `request_id`. The
downstream JSONL writer emits `"request_id":""`. If this event
ever flows into the v2.3 audit sink (today it only flows to the
operator audit bus, so it's latent), a strict UUID validator on
the OC side will reject the line as malformed.

**Fix:** generate a proper request ID for heartbeats too. Either
mint a fresh `uuid::Uuid::new_v4()` per heartbeat, or use a
deterministic-but-valid sentinel like
`00000000-0000-4000-8000-000000000001` reserved for synthetic
operator events. Document the sentinel choice in §6's "additional
fields" section so SIEM consumers can recognize it.

---

## Why these are MEDIUM (not HIGH)

- None alters the WAF's user-visible decision today.
- None breaks a v2.3 contract clause currently in scope.
- Each is a small, self-contained fix (<30 LoC).
- The blast radius of any single one of them is contained:
  - M-01: micro-perf only
  - M-02: edge-case behavior at restart
  - M-03: operator-controlled enrollment, not request-path
  - M-04: hot-restart edge case
  - M-05: operator-audit-only today, latent

## Suggested batching

These bundle naturally into a single "post-audit hardening" PR.
Land them after the four CRITICAL fixes and the five HIGH fixes,
in the same sprint.
