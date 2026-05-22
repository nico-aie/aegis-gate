---
id: 2026-05-17-ja4-sorts-and-no-grease-strip
date: 2026-05-17T00:00Z
severity: CRITICAL
area: security · TLS fingerprinting
component: crates/aegis-security/src/fingerprint/ja4.rs
interop_contract: official rules §5.2 #08 (device ID bền vững / stable)
status: open
test_mode: source-review (spot-verified)
---

# F-CRITICAL-011 · JA4 implementation sorts ciphers + extensions AND doesn't strip GREASE → Chrome's per-connection GREASE rotation breaks "stable device ID"

## Summary

The JA4 specification (FoxIO 2023, the de-facto industry standard
for TLS-client fingerprinting) is precise about two things:

1. **GREASE values MUST be stripped** before hashing. GREASE
   (RFC 8701) entries follow the pattern `0x?A?A` (`0x0A0A`, `0x1A1A`,
   `0x2A2A`, ..., `0xFAFA` — 16 reserved values). Chrome (and others)
   rotate GREASE values per-connection specifically to prevent
   fingerprinting that doesn't strip them. NOT stripping GREASE makes
   the same Chrome instance produce different JA4 hashes per
   connection — the OPPOSITE of "stable device ID".

2. **JA4 preserves observed order** of ciphers/extensions (the
   `JA4` form). Sorted variants exist (`JA4_S`, `JA4_R`) for
   server-side fingerprints / round-trip resilience but are DISTINCT
   variants with distinct identifier prefixes. Sorting the standard
   JA4 destroys discriminative power: two clients sending the same
   cipher SET in different orders collapse to one hash.

Shipped `fingerprint/ja4.rs`:

- Sorts ciphers + extensions unconditionally
  ([ja4.rs:57-60](../../../../crates/aegis-security/src/fingerprint/ja4.rs#L57-L60)).
- Has ZERO mention of GREASE / `0x?A?A` / `0x_A_A` anywhere in the
  file. **Spot-verified** with `grep -n 'grease\|GREASE\|0x[0-9a-f]*[Aa]'`.
- Uses BLAKE3 instead of SHA-256 (the JA4 spec uses SHA-256
  truncated to 12 chars) — see F-HIGH-bots-fingerprint for that
  separate IoC-compatibility issue.

Spot-verified at [ja4.rs:10-11](../../../../crates/aegis-security/src/fingerprint/ja4.rs#L10-L11)
(docstring): *"cipher_hash: truncated blake3 of sorted cipher list /
ext_hash: truncated blake3 of sorted extension list"*. The author
KNEW they were sorting; the comment is honest about deviating from
spec.

## Observed code path

[ja4.rs:55-71](../../../../crates/aegis-security/src/fingerprint/ja4.rs#L55-L71):

```rust
let mut sorted_ciphers: Vec<u16> = cipher_suites.to_vec();
sorted_ciphers.sort_unstable();
let mut sorted_exts: Vec<u16> = extensions.to_vec();
sorted_exts.sort_unstable();

let cipher_str = sorted_ciphers
    .iter()
    .map(|c| format!("{c:04x}"))
    .collect::<Vec<_>>()
    .join(",");
// ... GREASE values 0x0A0A, 0x1A1A, ..., 0xFAFA are still in the list ...
```

No filter like `cipher_suites.iter().filter(|c| (*c & 0x0F0F) != 0x0A0A)`
before sorting.

## Impact

- **§5.2 #08 violation** — the spec's first word about device ID is
  "bền vững" (durable / stable). GREASE rotation makes each Chrome
  connection produce a different JA4 hash; the WAF treats every
  connection as a different device.
- **Cascading effect on F-CRITICAL-001** — even when the risk
  tracker is fixed to key on device_fp (CRITICAL-001 fix), the
  device_fp itself is unstable, so risk still doesn't accumulate
  across requests from the same browser.
- **Cascading effect on F-CRITICAL-010** — the "same device,
  different IP" detector cannot identify "same device" because the
  device ID changes per connection.
- **External IoC feeds** — JA4 IoC databases (commercial threat-intel)
  publish standardized JA4 hashes. Hash-as-blake3 + sort + GREASE
  makes EVERY published indicator never match in this WAF
  (compounding F-HIGH-bots-fingerprint M-3).

## Suggested fix

Two-part fix.

### 1. Strip GREASE

```diff
+/// Per RFC 8701, the 16 reserved GREASE values follow the pattern
+/// `0x?A?A` — i.e., (value & 0x0F0F) == 0x0A0A. Strip them before
+/// hashing so per-connection GREASE rotation doesn't perturb the
+/// fingerprint.
+fn is_grease(v: u16) -> bool {
+    (v & 0x0F0F) == 0x0A0A
+}
+
-let mut sorted_ciphers: Vec<u16> = cipher_suites.to_vec();
-sorted_ciphers.sort_unstable();
+let ciphers: Vec<u16> = cipher_suites
+    .iter()
+    .copied()
+    .filter(|c| !is_grease(*c))
+    .collect();
+
-let mut sorted_exts: Vec<u16> = extensions.to_vec();
-sorted_exts.sort_unstable();
+let exts: Vec<u16> = extensions
+    .iter()
+    .copied()
+    .filter(|e| !is_grease(*e))
+    .collect();
```

### 2. Stop sorting (use observed order)

```diff
-let cipher_str = sorted_ciphers
+let cipher_str = ciphers
     .iter()
     .map(|c| format!("{c:04x}"))
     .collect::<Vec<_>>()
     .join(",");
```

Same for extensions.

If sorted-variant support is genuinely wanted (for IoC-database
compatibility OR for handling clients that legitimately reorder),
add it as a DISTINCT `compute_ja4_s()` function and label the
output's prefix accordingly (`q13d0309h2_...` for JA4 vs
`q13d0309h2_s_...` for JA4_S). Don't conflate the two.

### 3. (separate finding) Switch BLAKE3 → SHA-256 trunc-12

For IoC compatibility per F-HIGH-bots-fingerprint M-3.

## Verification

After the fix, two Chrome connections from the same browser
instance must produce the SAME JA4 hash. Test with a real curl
client (`curl --tls-max 1.3 --no-alpn -v https://...`) — its TLS
ClientHello is deterministic, so the hash should be stable across
runs.

Unit test:

```rust
#[test]
fn ja4_strips_grease_before_hashing() {
    let with_grease    = compute_ja4(&[0x0A0A, 0x1301, 0x1302], &[0x1A1A, 0x000B], "h2");
    let without_grease = compute_ja4(&[0x1301, 0x1302],          &[0x000B],          "h2");
    assert_eq!(with_grease, without_grease, "GREASE not stripped");
}

#[test]
fn ja4_preserves_observed_order() {
    let a = compute_ja4(&[0x1301, 0x1302], &[], "h2");
    let b = compute_ja4(&[0x1302, 0x1301], &[], "h2");
    assert_ne!(a, b, "ordered ja4 collapses different orders to same hash");
}
```

## Severity rationale

CRITICAL. The fingerprinting subsystem is named explicitly in §5.2
#08; the rules emphasize "bền vững" (stability). Today's JA4 is
unstable on Chrome (the dominant browser) due to GREASE rotation,
which means F-CRITICAL-001 / F-CRITICAL-010 fixes only partially
realize their value. Fix is ~15 LoC + a docstring update.
