# Behaviour signals detector (§5.2)

Per-request behaviour signals that the §5.2 audit specifically
mandated. Distinct from the richer `BehavioralAnalyzer` in
`crates/aegis-security/src/behavior.rs`, which exists for deeper
session-window analytics (path diversity, error ratio, jitter,
cookie absence over many requests) — this detector ships the
narrow signals the v2.3 spec calls for and is wired into the
default detector chain.

- **Source:** `crates/aegis-security/src/detectors/behavior_signals.rs`
- **Tags:** `behavior_no_ua`, `behavior_missing_referer`,
  `behavior_zero_depth`
- **Surface:** request method, peer IP, `User-Agent` header,
  `Referer` header, `Cookie` header — no body inspection
- **State:** per-peer-IP "warmed" flag, bounded at 100 000
  entries by default
- **Added:** 2026-05-18 — Phase F of the
  [2026-05-17 security audit](../../../tests/s-tester/reports/2026-05-17-security-audit/)
  (F-CRITICAL-004)
- **Updated:** 2026-05-19 — promoted to first-class togglable
  `DetectorClass::BehaviorSignals` (bit 12); `behavior_burst`
  signal retired (see below).

## Signals

| Tag | Score | Trigger |
|---|---|---|
| `behavior_no_ua` | 15 | Request has no `User-Agent` header, or it's empty / whitespace-only. |
| `behavior_missing_referer` | 20 | Mutation method (POST / PUT / PATCH / DELETE) without a `Referer` header — CSRF-shaped traffic. |
| `behavior_zero_depth` | 15 | First request from a peer with NO `Cookie` AND NO `Referer` — fresh stateless touch typical of crawlers / scanners. Fires only on FIRST request from each IP. |

### `behavior_burst` retired (2026-05-19)

The detector previously also emitted `behavior_burst` (score 25)
when two requests from the same `peer.ip()` landed within 50 ms.
Single-IP benchmark / dashboard demo flows tripped it on every
repeat — judges driving the dashboard's "test attack" buttons saw
their own clicks tagged as automation. Removed. If a per-session
burst gate makes sense later it should key on the composite
`RiskKey { ip, device_fp, session }` (Phase E future work) so two
distinct sessions on the same NAT'd IP don't share one timer.

## Why these signals + scoring

The v2.3 risk thresholds default to `challenge_at: 30`, `block_at: 70`.
Each signal individually is sub-threshold (15-20 points) — none is
a single-hit-block on its own, because the underlying patterns
have legitimate false-positives:

- Some legitimate API clients omit `User-Agent`.
- Mobile webviews sometimes drop `Referer` for privacy.
- Privacy-strict browsers (Brave, Safari ITP) sometimes strip
  `Cookie` and `Referer` together.

The signals are designed to **stack** instead. A typical bot
profile:

```
POST /login from 203.0.113.5   →   missing_referer (20) + no_ua (15) + zero_depth (15) = 50
```

…sits at 50 — comfortably below `block_at: 70` on its own, but
one corroborating OWASP detector hit (or any score-bearing
detector class) pushes a bot-shaped request over the threshold
while leaving a legit browser at zero.

## State management

`behavior_zero_depth` needs per-IP memory (the "is this the first
touch" flag). Stored in a single `Mutex<HashMap<IpAddr, LastSeen>>`
where `LastSeen` is just a `pub_warmed: bool`. When the map grows
past `max_tracked` (default 100 000), a random-ish eviction drops
one entry to make room. Random eviction is intentional — attackers
can't pin a slot.

State is cleared by `BehaviorSignalsDetector::clear()`, wired
into the v2.3 `POST /__waf_control/reset_state` callback so
benchmark phases start clean.

## Config + toggling

As of 2026-05-19 the detector is a first-class togglable class:

```yaml
detectors:
  behavior_signals: { enabled: false }   # default OFF
  per_tier:
    critical: { behavior_signals: true }  # opt-in per tier
```

Hot-flippable via `PUT /api/detectors { mask: { behavior_signals: true } }`
or the chip in the Detector Mask card on the Detectors page. The
old "always-on, no toggle" registration was replaced with a gated
push in `default_detectors_with_canary`; disabled → not registered
→ zero per-request cost.

## Boot-time wiring

`default_detectors_with_canary(&detectors_cfg, &canary_paths)` in
`crates/aegis-security/src/detectors/mod.rs` conditionally appends
the `BehaviorSignalsDetector` when `cfg.detectors.behavior_signals.enabled`
is `true`. The proxy boot path in `crates/aegis-proxy/src/run.rs`
uses this constructor.

## Tuning

`max_tracked` is the only knob today:

```rust
let detector = BehaviorSignalsDetector::with_tuning(250_000);
```

Construction-time only. If operators need runtime tuning, a future
`PUT /api/behavior` endpoint can expose it — schema parity with the
`PUT /api/detectors` mask hot-reload path.

## Tests

`crates/aegis-security/src/detectors/behavior_signals.rs` ships
14 unit tests covering:

- No signals for clean browser request (UA + Cookie + Referer)
- `behavior_burst` is retired (back-to-back same-IP requests
  produce zero signals — pinning test)
- Missing / empty `User-Agent` both fire
- Missing `Referer` on POST/PUT/PATCH/DELETE fires
- Missing `Referer` on GET does NOT fire
- `Referer` present on POST does NOT fire missing_referer
- Zero-depth fires on FIRST touch with no Cookie + no Referer
- Zero-depth does NOT fire after warming (subsequent requests)
- Zero-depth does NOT fire when Cookie present
- All 3 signals stack on a fresh-IP POST with no UA / Cookie /
  Referer (sums to 50, just under block_at)
- Stable detector id `"behavior_signals"`
- `clear()` drops state
- `max_tracked` cap evicts entries (test sets cap to 3, inserts
  10, asserts ≤3 tracked)
