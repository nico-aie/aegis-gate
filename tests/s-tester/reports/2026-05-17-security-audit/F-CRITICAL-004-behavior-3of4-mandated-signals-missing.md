---
id: 2026-05-17-behavior-3of4-mandated-signals-missing
date: 2026-05-17T00:00Z
severity: CRITICAL
area: security · behavioral anomaly
component: crates/aegis-security/src/behavior.rs
interop_contract: official rules §5.2 #09 (Behavioral Anomaly Detection) · Attack Battle scenario 05
status: open
test_mode: source-review
---

# F-CRITICAL-004 · `behavior.rs` implements only 1 of 4 mandated §5.2 behavioral signals

## Summary

Official rules §5.2 #09 enumerate FOUR behavioral signals as required:

> *Phát hiện: request timing quá đều (bot), zero-depth session (thẳng
> vào CRITICAL route không qua homepage), thiếu Referer trên sensitive
> routes, inter-request interval < 50ms*

Shipped `behavior.rs` implements **timing variance only** (and even
that one is via coefficient-of-variation, NOT the absolute <50 ms
inter-request check the rules name).

| Required signal | Status | Evidence |
|---|---|---|
| Request timing quá đều (bot) | ⚠️ Partial — CoV only, no absolute <50ms | `behavior.rs:122-132` |
| Zero-depth session (direct to CRITICAL) | ❌ Missing | `behavior.rs` collects `paths` but never checks "first-request-is-sensitive" |
| Missing Referer on sensitive routes | ❌ Missing | `observe()` signature has no `referer` field |
| Inter-request interval < 50 ms (absolute) | ❌ Missing | only CoV computed, no min-interval check |

The Attack Battle (§7) scenarios that exercise these signals:

- **05 Behavioral Bypass** — "Zero-depth session attack (thẳng vào
  /deposit), perfectly-timed bot request, giả mạo Referer header"

All three components of scenario 05 are uncovered.

## Observed code path

[behavior.rs:49-144](aegis-gate/crates/aegis-security/src/behavior.rs#L49-L144) — main analysis loop. Key issues:

1. **`observe()` signature** has no `referer` parameter:

   ```rust
   pub fn observe(&self, ip: IpAddr, path: &str, status: u16, now: Instant) -> Vec<Anomaly>
   ```

2. **`paths` field** is populated:

   ```rust
   struct Session {
       paths: Vec<String>,
       ...
   }
   ```

   but never queried for "is this the first request and is it
   sensitive?". No tier/sensitivity classification on the path.

3. **Timing variance** uses coefficient of variation (low CoV →
   bot-like). A steady 10 ms / 10 ms / 10 ms attack passes the CoV
   check (CoV = 0 is suspicious, but lots of legit traffic also has
   low CoV). The spec's "<50 ms" is an ABSOLUTE inter-request gap,
   not a variance signal.

4. **Bonus bugs in scope**:
   - `paths: Vec<String>` is unbounded per session (grows forever
     until LRU evicts the whole session).
   - "Oldest" eviction at [behavior.rs:60-65](aegis-gate/crates/aegis-security/src/behavior.rs#L60-L65)
     uses `map.keys().next()` (random HashMap iteration order, not
     LRU) — can evict the active attacker's session.
   - [behavior.rs:71](aegis-gate/crates/aegis-security/src/behavior.rs#L71)
     `now - Duration::from_secs(self.window_s)` panics if `Instant::now()`
     hasn't advanced `window_s` since process start (cold boot).
   - Global `Mutex<HashMap>` on the request hot path — serializes
     every detector call.

## Impact

- **Attack Battle scenario 05** — undetectable; the three concrete
  vectors (zero-depth, perfectly-timed, missing-Referer) all pass.
- **Intelligence rubric (20/120)** — "Behavioral anomaly detection"
  is explicitly enumerated as a scored sub-item.
- **Security Effectiveness (40/120)** — §5.2 #09 is under "Chức năng
  cốt lõi (BẮT BUỘC)".

## Suggested fix

Three additive changes:

### Add `referer` + `tier` to `observe()`

```diff
 pub fn observe(
     &self,
     ip: IpAddr,
     path: &str,
+    referer: Option<&str>,
+    tier: aegis_core::tier::Tier,
     status: u16,
     now: Instant,
 ) -> Vec<Anomaly> {
     ...
+    // Signal: missing Referer on sensitive tier.
+    if matches!(tier, Tier::Critical | Tier::High) && referer.is_none() {
+        out.push(Anomaly::MissingReferer { path: path.into() });
+    }
+
+    // Signal: zero-depth session (first event is to a sensitive tier).
+    if session.paths.is_empty() && matches!(tier, Tier::Critical) {
+        out.push(Anomaly::ZeroDepthSession { path: path.into() });
+    }
+
+    // Signal: <50ms inter-request (absolute).
+    if let Some(last) = session.last_event {
+        let gap = now.duration_since(last);
+        if gap < Duration::from_millis(50) {
+            out.push(Anomaly::TooFastInterRequest { gap_ms: gap.as_millis() as u32 });
+        }
+    }
+    session.last_event = Some(now);
     ...
 }
```

Wire `tier` plumbing: the route table already classifies routes per
the §4 tier table; pass the tier to `observe()` from the data plane.

### Bound `paths` length

```rust
session.paths.push(path.into());
if session.paths.len() > 256 {
    session.paths.remove(0);
}
```

Or use a `VecDeque` + push_back/pop_front for O(1).

### Replace `Mutex<HashMap>` with `DashMap`

Trivial. Removes the hot-path lock.

### Use real LRU

Replace `map.keys().next()` eviction with `lru::LruCache` keyed on
`SessionId`.

## Verification

```sh
HOST="http://127.0.0.1:8080"

# Zero-depth session: first request is /deposit (CRITICAL tier).
curl -ski "$HOST/deposit" -d "amount=1000"
# Expect: 429 challenge or 403 block; audit shows
# rule_id: behavior.zero_depth.

# Missing Referer on sensitive route.
curl -ski "$HOST/login" -d "user=alice"
# No Referer header. Expect: anomaly recorded.

# <50ms inter-request.
curl -ski "$HOST/api/x" & curl -ski "$HOST/api/x" &
# Expect: second request anomaly flagged.
```

Regression cases in `tests/security/`:

- `behavior_zero_depth.sh` — first request to `/deposit` blocks.
- `behavior_missing_referer.sh` — `/login` without Referer triggers.
- `behavior_fast_interval.sh` — two requests <50 ms apart triggers.

## Severity rationale

CRITICAL. Three concrete signals from a four-signal mandatory list
are unimplemented; the fourth is implemented as a variance metric
rather than the absolute interval the spec names. Attack Battle
scenario 05 is undefended. ~50 LoC + tier plumbing.
