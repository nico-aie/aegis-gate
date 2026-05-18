# Behaviour signals detector (§5.2)

Per-request behaviour signals that the §5.2 audit specifically
mandated. Distinct from the richer `BehavioralAnalyzer` in
`crates/aegis-security/src/behavior.rs`, which exists for deeper
session-window analytics (path diversity, error ratio, jitter,
cookie absence over many requests) — this detector ships the four
narrow signals the v2.3 spec calls for and is wired into the
default detector chain.

- **Source:** `crates/aegis-security/src/detectors/behavior_signals.rs`
- **Tags:** `behavior_burst`, `behavior_no_ua`,
  `behavior_missing_referer`, `behavior_zero_depth`
- **Surface:** request method, peer IP, `User-Agent` header,
  `Referer` header, `Cookie` header — no body inspection
- **State:** per-peer-IP last-seen timestamp, bounded at 100 000
  entries by default
- **Added:** 2026-05-18 — Phase F of the
  [2026-05-17 security audit](../../../tests/s-tester/reports/2026-05-17-security-audit/)
  (F-CRITICAL-004)

## Signals

| Tag | Score | Trigger |
|---|---|---|
| `behavior_burst` | 25 | Same peer IP made another request <50 ms ago — automated client signature. Tunable via `BehaviorSignalsDetector::with_tuning`. |
| `behavior_no_ua` | 15 | Request has no `User-Agent` header, or it's empty / whitespace-only. |
| `behavior_missing_referer` | 20 | Mutation method (POST / PUT / PATCH / DELETE) without a `Referer` header — CSRF-shaped traffic. |
| `behavior_zero_depth` | 15 | First request from a peer with NO `Cookie` AND NO `Referer` — fresh stateless touch typical of crawlers / scanners. Fires only on FIRST request from each IP. |

## Why these signals + scoring

The v2.3 risk thresholds default to `challenge_at: 30`, `block_at: 70`.
Each signal individually is sub-threshold (15-25 points) — none is
a single-hit-block on its own, because the underlying patterns
have legitimate false-positives:

- A real browser may load a page so fast (instrumented page +
  prefetch hint) that two GETs from the same IP land within 50 ms.
- Some legitimate API clients omit `User-Agent`.
- Mobile webviews sometimes drop `Referer` for privacy.
- Privacy-strict browsers (Brave, Safari ITP) sometimes strip
  `Cookie` and `Referer` together.

The signals are designed to **stack** instead. A typical bot
profile:

```
POST /login from 203.0.113.5   →   missing_referer (20) + no_ua (15) + zero_depth (15) = 50
+ rapid retry <50 ms later     →   add burst (25) = 75
```

…clears `block_at: 70` on the second request, with no OWASP
signal needed. A legitimate browser hits at most one of these
signals (typically zero) and never accumulates above
`challenge_at`.

## State management

`behavior_burst` and `behavior_zero_depth` need per-IP memory.
Stored in a single `Mutex<HashMap<IpAddr, LastSeen>>` (the same
shape `RiskTracker` uses). When the map grows past `max_tracked`
(default 100 000), a random-ish eviction drops one entry to make
room. Random eviction is intentional — attackers can't pin a slot
to mask burst detection.

State is cleared by `BehaviorSignalsDetector::clear()`, wired
into the v2.3 `POST /__waf_control/reset_state` callback so
benchmark phases start clean.

## Why outside `DetectorClass`

`DetectorClass` is a closed-set bitfield with stable bit positions,
paired 1-to-1 with `DetectorsConfig` fields. The behaviour-signals
detector is stateful + always-on; treating it as a regular
`Detector` with `id = "behavior_signals"` keeps the mask
machinery unchanged. The mask's "unknown id runs unconditionally"
path covers it — same as the canary detector.

## Boot-time wiring

`default_detectors_with_canary(&detectors_cfg, &canary_paths)` in
`crates/aegis-security/src/detectors/mod.rs` appends the
`BehaviorSignalsDetector` after the OWASP detectors and (when
configured) the canary detector. The proxy boot path in
`crates/aegis-proxy/src/run.rs` uses this constructor.

## Tuning

The default 50 ms burst threshold catches most automated retry
loops without false-positiving on browser prefetch hints. To
tighten or loosen:

```rust
use std::time::Duration;
let detector = BehaviorSignalsDetector::with_tuning(
    Duration::from_millis(30),  // burst threshold
    250_000,                    // max tracked peer IPs
);
```

Both knobs are construction-time today. If operators need runtime
tuning, the future `PUT /api/behavior` endpoint can expose them —
schema parity with the `PUT /api/detectors` mask hot-reload path.

## Tests

`crates/aegis-security/src/detectors/behavior_signals.rs` ships
14 unit tests covering:

- No signals for clean browser request (UA + Cookie + Referer)
- Burst fires on rapid repeat from same IP
- Missing / empty `User-Agent` both fire
- Missing `Referer` on POST/PUT/PATCH/DELETE fires
- Missing `Referer` on GET does NOT fire
- `Referer` present on POST does NOT fire missing_referer
- Zero-depth fires on FIRST touch with no Cookie + no Referer
- Zero-depth does NOT fire after warming (subsequent requests)
- Zero-depth does NOT fire when Cookie present
- All 4 signals stack on a fresh-IP POST with no UA / Cookie /
  Referer (sums to 50, just under block_at)
- Stable detector id `"behavior_signals"`
- `clear()` drops state
- `max_tracked` cap evicts entries (test sets cap to 3, inserts
  10, asserts ≤3 tracked)
