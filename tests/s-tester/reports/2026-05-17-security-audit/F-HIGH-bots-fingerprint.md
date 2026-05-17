---
id: 2026-05-17-high-bots-fingerprint-bundle
date: 2026-05-17T00:00Z
severity: HIGH
area: security · bot management · TLS fingerprinting · IP reputation
component: crates/aegis-security/src/{bots.rs, fingerprint/*.rs, ip_rep/asn.rs}
interop_contract: official rules §5.2 #05 + #08
status: open
test_mode: source-review
---

# F-HIGH-bots-fingerprint bundle — 4 issues in bot management + fingerprint stability + IoC compatibility

---

## BF-01 · rDNS classification is NOT forward-confirmed despite "FCrDNS" claim in docstring

**Component:** [bots.rs:84-91](aegis-gate/crates/aegis-security/src/bots.rs#L84-L91)

The module's header comment claims forward-confirmed reverse DNS
(FCrDNS) — the correct way to identify legitimate bots. Implementation
only does a suffix match on the rDNS string.

An attacker who controls the reverse DNS for their own IP (e.g.
`*.googlebot.com.attacker.tld` via a rogue PTR record on their own
ASN) gets classified as `GoodBot`. `GoodBot` likely bypasses
downstream gates (rate-limit, detector chain).

**Fix:** FCrDNS = (a) reverse-DNS lookup IP → hostname, (b) forward
DNS hostname → IP set, (c) verify the original IP is in the
returned set:

```rust
async fn is_verified_googlebot(ip: IpAddr) -> bool {
    let rdns = reverse_lookup(ip).await.ok()?;
    if !rdns.ends_with("googlebot.com.") { return false; }
    let forward = forward_lookup(&rdns).await.ok()?;
    forward.contains(&ip)
}
```

Cache the (ip → verified-or-not) result with TTL. The current rDNS
cache becomes part of this layer.

---

## BF-02 · rDNS cache eviction uses `clear()` on overflow

**Component:** [bots.rs:118-126](aegis-gate/crates/aegis-security/src/bots.rs#L118-L126)

When the cache hits `max_cache` capacity, the implementation calls
`HashMap::clear()` — wiping every entry. Under DDoS with fresh IPs,
this thrashes constantly:

- 1000 unique IPs in 1 second → cache fills → `clear()` → next
  request re-resolves → repeat.
- Re-resolution under load is expensive (synchronous DNS or async
  cache miss).

**Fix:** use `lru::LruCache` for proper LRU eviction (drops only the
least-recently-used entry), or random-sample eviction (drop 10% of
random entries on overflow).

---

## BF-03 · JA3/JA4 hashed with BLAKE3 instead of MD5/SHA-256 → incompatible with every external IoC feed

**Component:** [fingerprint/ja3.rs:29-31](aegis-gate/crates/aegis-security/src/fingerprint/ja3.rs#L29-L31), [fingerprint/ja4.rs:96](aegis-gate/crates/aegis-security/src/fingerprint/ja4.rs#L96)

The JA3 spec defines the fingerprint as `md5(comma-separated-fields)`.
The JA4 spec defines it as `sha256(...)` truncated to 12 hex chars.
Aegis uses BLAKE3 for both, with a comment "We use blake3 instead of
MD5 for security".

Security argument is sound in isolation — but the JA3/JA4 identifier
IS the hash output, and commercial IoC feeds publish hashes in the
spec format. Aegis-computed hashes never match any published
indicator → `IndicatorType::JA3` / `JA4` lookups against
`threat_intel/` always miss.

**Fix:** use MD5 for JA3, SHA-256-trunc-12 for JA4 — interoperability
trumps the choice of underlying hash (MD5 weakness doesn't apply to
fingerprint identifiers; it's the data structure that matters).

Combine with F-CRITICAL-011 fix (strip GREASE, preserve order) for
correct JA4.

---

## BF-04 · `header_order` in device-ID hash breaks stability under HTTP/2 HPACK

**Component:** [fingerprint/mod.rs:10-31](aegis-gate/crates/aegis-security/src/fingerprint/mod.rs#L10-L31)

`device_id` includes the request's header order in its hash:

```rust
let combined = format!("{ja3}|{ja4}|{h2}|{ua}|{enc}|{header_order:?}", ...);
```

HTTP/2 HPACK indexes-and-reuses headers; the wire order can differ
across requests from the same client even when the client emits
headers in the same logical order. Two consecutive requests from
the same Chrome instance can produce DIFFERENT device IDs purely
because of HPACK reordering.

§5.2 #08 requires "device ID bền vững" (stable). Combined with
F-CRITICAL-011 (JA4 instability via GREASE) and F-CRITICAL-010
(no same-device-different-IP detection), every layer of device
identification is wobbling.

**Fix:** sort the header SET before hashing (lose order, gain
stability). Document that order-sensitive analysis is a separate
signal (used as an anti-evasion hint, not as identity).

```diff
-let header_order_str = header_order.join(",");
+let mut header_set: Vec<_> = header_order.iter().map(|h| h.to_ascii_lowercase()).collect();
+header_set.sort_unstable();
+header_set.dedup();
+let header_set_str = header_set.join(",");
```

---

## Severity rationale

HIGH. BF-01 lets attackers bypass the good-bot allow-list. BF-02
amplifies DDoS by thrashing the rDNS cache. BF-03 makes the entire
TLS-fingerprint IoC chain non-functional. BF-04 makes device ID
non-stable on HTTP/2 (the dominant browser protocol).

Compounding with F-CRITICAL-011 (JA4 GREASE) and F-CRITICAL-010
(no rotation detector), the cumulative fingerprinting subsystem
delivers no scoring value.
