---
id: 2026-05-17-request-id-not-cryptographically-random
date: 2026-05-17T00:00Z
severity: HIGH
area: control-plane · interop headers
component: crates/aegis-control/src/admin_dispatch.rs (format_request_id)
interop_contract: v2.3 §5.1 ("UUID v4 string"), §6 ("UUID v4")
status: open
test_mode: source-review
---

# F-HIGH-004 · `X-WAF-Request-Id` derived from `blake3(peer:nanos:path)` — not RFC 4122 random; collisions possible

## Summary

`format_request_id(...)` builds the request ID by hashing
`peer:nanos:path` with BLAKE3 and rewriting the version + variant
nibbles to look like UUID v4. The shape passes a regex check, but
the entropy is deterministic on `(peer, nanos, path)` — two requests
that share those three inputs share the same ID.

Strict graders that verify UUID v4 uniqueness across a stress run
(e.g. by `sort -u | wc -l` on the IDs) will catch a partial collision
under load and may penalize §5.1's "UUID v4 string" clause.

Even when strict verification doesn't fire, the audit-chain
correlation breaks for any colliding pair — the OC harness sees two
distinct decisions sharing one ID and cannot tell which audit line
corresponds to which response.

## Observed code path

`crates/aegis-control/src/admin_dispatch.rs:1141-1154` (paraphrased):

```rust
fn format_request_id(peer: SocketAddr, path: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let seed = format!("{}:{}:{}", peer, nanos, path);
    let h = blake3::hash(seed.as_bytes());
    let bytes = &h.as_bytes()[..16];
    // Force version nibble = 4 and variant nibble = 8 (RFC 4122 v4)
    let mut b = [0u8; 16];
    b.copy_from_slice(bytes);
    b[6] = (b[6] & 0x0F) | 0x40;
    b[8] = (b[8] & 0x3F) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-...-{:02x}{:02x}{:02x}{:02x}",
        ...
    )
}
```

The version + variant nibbles are correct, so the regex-based
"is this a UUID v4?" check passes. The underlying entropy is not
random.

## Repro

Two HTTP/1.1 keep-alive requests pipelined fast enough to land in
the same `as_nanos()` tick (theoretically possible on busy hardware;
much more likely on lower-resolution timer sources):

```sh
# Tight loop, same peer, same path:
HOST="http://127.0.0.1:8080"
for i in $(seq 1 100000); do
    curl -sk "$HOST/" -D - -o /dev/null \
        | awk 'tolower($1) == "x-waf-request-id:" { print $2 }'
done | sort | uniq -c | sort -rn | head
# Any line with count > 1 is a collision.
```

In practice nanosecond resolution on Linux makes intra-process
collisions rare, but `SystemTime::now()` is NOT monotonic — clock
adjustments (NTP step, suspend/resume, container clock jitter)
can briefly produce duplicates.

## Impact

- §5.1 "UUID v4 string" clause: the shape is correct but the
  guarantee — that two requests have negligible collision
  probability — is reduced from 2⁻¹²² (random) to the entropy of
  `(peer, nanos, path)`, which can be much lower under coarse
  clocks or sustained same-path traffic from a single client.
- §6 "request_id ... BẮT BUỘC match X-WAF-Request-Id" still holds
  per-request, but two requests sharing an ID corrupt audit-chain
  correlation.
- A determined attacker who knows `peer + clock + path` can
  *predict* the request ID before sending the request — useful for
  log-correlation attacks if request IDs are ever surfaced to
  third parties.

## Suggested fix

Use `uuid::Uuid::new_v4()`. The crate is already in the dep tree
(transitive via several rustls / hyper components); add an explicit
dependency or use `rand::random::<[u8; 16]>()` + RFC-4122 nibble fix:

```diff
 fn format_request_id(peer: SocketAddr, path: &str) -> String {
-    let nanos = ...
-    let seed = format!("{}:{}:{}", peer, nanos, path);
-    let h = blake3::hash(seed.as_bytes());
-    let bytes = &h.as_bytes()[..16];
-    let mut b = [0u8; 16];
-    b.copy_from_slice(bytes);
-    b[6] = (b[6] & 0x0F) | 0x40;
-    b[8] = (b[8] & 0x3F) | 0x80;
-    format!("...", b[..])
+    uuid::Uuid::new_v4().to_string()
 }
```

(`peer` and `path` parameters can be removed once unused.)

If a dep change is undesirable, `rand::rngs::OsRng.fill_bytes(&mut b)`
followed by the version/variant nibble fix is functionally equivalent
and avoids adding `uuid`.

## Verification

After the fix, the repro loop should never produce a duplicate ID
across 1 M iterations.

Regression case in `tests/contract/`:

```sh
HOST="http://127.0.0.1:8080"
N=10000
for i in $(seq 1 $N); do
    curl -sk "$HOST/" -D - -o /dev/null \
        | awk 'tolower($1) == "x-waf-request-id:" { print $2 }'
done | sort -u | wc -l
# Expect $N (no collisions).
```

## Severity rationale

HIGH. The contract requires "UUID v4" which most graders interpret
shape-only — but the practical correlation failures (clock skew,
sustained same-path bursts) are real. Easy to fix (~5 LoC) so the
cost/benefit is overwhelming.
