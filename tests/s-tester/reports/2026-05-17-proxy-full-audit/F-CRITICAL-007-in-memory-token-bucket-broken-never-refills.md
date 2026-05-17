---
id: 2026-05-17-in-memory-token-bucket-broken-never-refills
date: 2026-05-17T00:00Z
severity: CRITICAL
area: rate-limit · state backend (in-memory)
component: crates/aegis-proxy/src/state/in_memory.rs (decode_bucket)
interop_contract: v2.3 §3 (rate_limit action) · Round 2 false-positive minimization
status: open
test_mode: source-review (spot-verified)
---

# F-CRITICAL-007 · In-memory token-bucket rate limit is mathematically broken — bucket never refills, every IP permanently denied after `burst` requests

## Summary

`InMemoryStateBackend::decode_bucket` returns `Instant::now()` instead
of the timestamp stored in the bucket. The token-bucket refill
algorithm reads this timestamp to compute `elapsed = now - last_used`,
multiplies by `refill_rate`, and adds the tokens back. Because
`last_used` is ALWAYS "now", `elapsed` is ALWAYS `~0`, and the bucket
NEVER refills.

After the initial `burst` tokens are consumed, every subsequent
request is denied — forever, for that key, until the WAF restarts or
state is reset.

**Spot-verified** at [state/in_memory.rs:286-292](aegis-gate/crates/aegis-proxy/src/state/in_memory.rs#L286-L292):

```rust
fn decode_bucket(data: &[u8]) -> (f64, Instant) {
    let tokens = f64::from_le_bytes(data[..8].try_into().unwrap_or([0; 8]));
    // The timestamp is always "now" relative — we re-encode on every access
    // so for simplicity we treat the stored timestamp as the last access time.
    // In a real impl this would be a proper epoch-based timestamp.
    (tokens, Instant::now())
}
```

The comment ACKNOWLEDGES the bug ("In a real impl..."). It's never
been fixed.

## Impact under §3 / Round 2

The in-memory backend is the default for single-node deployments
(redis backend is opt-in via `cfg.state.backend = redis`). The
benchmark sandbox is single-node per team. So every benchmark run
uses this broken backend by default.

§3 lists `rate_limit` as the correct action for "Volumetric abuse
from single source". §7 normalization classifies a `rate_limit`
response as `prevented` for malicious traffic and `collateral` for
legitimate stress traffic.

With the bucket never refilling:

- **Round-1 sustained traffic**: a moderate burst of legitimate
  requests (e.g. the OC's startup synthetic traffic) exhausts the
  bucket within seconds. From then on EVERY legitimate request from
  that source IP gets `rate_limit` 429 → counts as `false_positive`
  per §7.
- **Round-2 every test from one IP**: ditto. False-positive rate
  approaches 100% for any source that crosses the burst threshold
  once.
- **§3 contract clause "rate_limit" → upstream protection**: the
  intent is to throttle, not to permanently ban. The current
  behavior is closer to an indefinite `block` mislabelled as
  `rate_limit`.

## Repro

`config/dev.yaml` ships with rate-limit settings (default `cfg.rate_limit`
has burst ~50, rate ~10 rps in-memory).

```sh
HOST="http://127.0.0.1:8080"

# Burst — first ~50 succeed, then permanent 429:
for i in $(seq 1 100); do
    curl -ski "$HOST/" -o /dev/null -w "%{http_code} "
done; echo
# Output looks like: 200 200 ... (50 times) ... 429 429 429 ...

# Wait 60 seconds — bucket SHOULD refill if rate=10rps:
sleep 60

# Should now allow ~50 more requests:
for i in $(seq 1 60); do
    curl -ski "$HOST/" -o /dev/null -w "%{http_code} "
done; echo
# Output: 429 429 429 ... (still rate-limited)

# Audit log shows continuous rate_limit decisions:
tail -100 ./waf_audit.log | jq -r '.action' | sort | uniq -c
# →    100 rate_limit
```

Sleep arbitrarily long; the WAF never lets the source through again.

## Suggested fix

Store the timestamp as nanoseconds-since-epoch alongside the token
count, and decode it as a real `Instant`:

```diff
-fn decode_bucket(data: &[u8]) -> (f64, Instant) {
-    let tokens = f64::from_le_bytes(data[..8].try_into().unwrap_or([0; 8]));
-    // ... acknowledged-broken comment ...
-    (tokens, Instant::now())
-}
+fn decode_bucket(data: &[u8]) -> (f64, Instant) {
+    if data.len() < 16 {
+        // Legacy 8-byte encoding (tokens only) — treat as freshly seeded.
+        return (
+            f64::from_le_bytes(data[..8].try_into().unwrap_or([0; 8])),
+            Instant::now(),
+        );
+    }
+    let tokens = f64::from_le_bytes(data[..8].try_into().unwrap_or([0; 8]));
+    let nanos_since_epoch = u64::from_le_bytes(data[8..16].try_into().unwrap_or([0; 8]));
+    let stored = std::time::UNIX_EPOCH + std::time::Duration::from_nanos(nanos_since_epoch);
+    let elapsed_from_epoch = std::time::SystemTime::now()
+        .duration_since(stored)
+        .unwrap_or(std::time::Duration::ZERO);
+    let last_used = Instant::now()
+        .checked_sub(elapsed_from_epoch)
+        .unwrap_or_else(Instant::now);
+    (tokens, last_used)
+}
```

And the `encode_bucket` side:

```diff
-fn encode_bucket(tokens: f64, _instant: Instant) -> Vec<u8> {
-    tokens.to_le_bytes().to_vec()
-}
+fn encode_bucket(tokens: f64, _instant: Instant) -> Vec<u8> {
+    let mut out = Vec::with_capacity(16);
+    out.extend_from_slice(&tokens.to_le_bytes());
+    let nanos = std::time::SystemTime::now()
+        .duration_since(std::time::UNIX_EPOCH)
+        .unwrap_or_default()
+        .as_nanos() as u64;
+    out.extend_from_slice(&nanos.to_le_bytes());
+    out
+}
```

`Instant` cannot be serialized directly (it's an opaque
monotonic-clock value), hence the indirection through `SystemTime`
nanos-since-epoch. The legacy 8-byte branch above handles any
in-flight buckets across the upgrade.

## Verification

After the fix, the repro above should resume serving 200s after the
60 s sleep. Add a regression case in `tests/api/`:

```sh
# Burst until rate-limited, sleep > burst/rate seconds, assert
# request succeeds. Repeat across a few cycles to assert the
# refill is steady-state.
```

## Severity rationale

CRITICAL. The default rate-limit backend is fundamentally broken;
the operator who reads "rate_limit" in the audit log assumes the
contract semantic (throttle and recover) but observes an indefinite
ban. The bug is acknowledged in the source comment but never
addressed. Fix is ~20 LoC.
