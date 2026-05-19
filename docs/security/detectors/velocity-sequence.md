# Velocity sequence engine

Cross-endpoint sequence detector. Catches **shape attacks** — two
distinct endpoints hit in fast succession by the same peer IP that
don't individually trip a rate cap but together reveal a
credential-stuffer / account-takeover pattern.

Distinct from `crates/aegis-security/src/velocity.rs`, which is a
per-action rate cap ("max N withdrawals in 10 minutes"). The
sequence engine sees the *transitions*, not the counts.

- **Source:** `crates/aegis-security/src/detectors/velocity_sequence.rs`
- **Tags:** `velocity_login_to_deposit`,
  `velocity_login_to_withdrawal`, `velocity_otp_to_deposit`,
  `velocity_otp_to_withdrawal`
- **Surface:** request path + peer IP
- **State:** per-peer-IP ring buffer of `(endpoint_tag, timestamp)`
  tuples, max 8 entries each, bounded at 100 000 IPs by default
- **Added:** 2026-05-18 — Phase F of the
  [2026-05-17 security audit](../../../tests/s-tester/reports/2026-05-17-security-audit/)
  (F-CRITICAL-003)

## Rules

| Sequence | Window | Score | Why suspicious |
|---|---|---|---|
| `login → deposit` | 5 s | 60 | Credential-stuffer monetising a successful login |
| `login → withdrawal` | 5 s | 70 | ATO cashout — fastest + highest-value shape |
| `otp → deposit` | 5 s | 50 | Same shape after the 2FA step |
| `otp → withdrawal` | 5 s | 60 | Cashout after 2FA |

A real user takes much longer than 5 s between login and a money
move — they browse, check balance, pick an amount, confirm. An
ATO script hits the endpoints back-to-back.

Scores 50-70 are picked so:

- A single sequence match is challengeable (`challenge_at: 30`)
  but not single-shot-blockable (`block_at: 70`) for the lower
  rules.
- `login → withdrawal` at 70 is exactly on the block threshold
  in v2.3 defaults — one match = block. This is the riskiest
  shape (cashout, irreversible).
- Stacking with any other detector hit (e.g. `behavior_no_ua` +20
  on a UA-less bot, an OWASP class score, a recon path probe)
  pushes a single sequence match deterministically over the
  block line. The previous `behavior_burst` (25) co-signal was
  retired 2026-05-19 — see
  [behavior-signals.md](./behavior-signals.md#behavior_burst-retired-2026-05-19).

## Endpoint tagging

Each request path is mapped to an `EndpointTag` via lower-cased
substring matching. The heuristic is intentionally generous —
false-positive on an English word in a non-financial route is
fine because the **sequence** is what's load-bearing.

| Path contains (lower-cased) | Tag |
|---|---|
| `login`, `/auth/`, `signin` | `Login` |
| `otp`, `2fa`, `verify` | `Otp` |
| `deposit`, `topup`, `recharge` | `Deposit` |
| `withdraw`, `cashout`, `payout`, `transfer`, `send-money` | `Withdrawal` |
| (anything else) | None — not stored, no signal |

Only "interesting" tags are stored in the ring buffer, so chatty
browse flows (GET `/api/profile`, GET `/static/...`) don't pollute
state. Intermediate untagged hits don't break a real sequence
either — `login → GET /api/profile → deposit` still fires
`velocity_login_to_deposit` because `/api/profile` doesn't get
inserted into the history.

## Per-IP state

A ring buffer of `(tag, instant)` tuples, max 8 entries per IP.
The buffer is newest-first so the sequence walk is short.

The state map is bounded at `max_tracked` IPs (default 100 000) —
random-ish eviction when full. `clear()` drops everything; wired
into the v2.3 `POST /__waf_control/reset_state` callback.

## Why outside `DetectorClass`

Same rationale as canary + behavior_signals: the velocity-sequence
detector is stateful and data-driven (operator path patterns +
rule list), not a closed-set pattern class. It ships as a regular
`Detector` with `id = "velocity_sequence"`. The mask treats unknown
ids as always-on.

## Boot-time wiring

`default_detectors_with_canary(&detectors_cfg, &canary_paths)`
appends `VelocitySequenceDetector` after the OWASP detectors and
the `BehaviorSignalsDetector`. The proxy boot path in
`crates/aegis-proxy/src/run.rs` uses this constructor.

## v1 scope + future work

The rule list and window are **hardcoded** for v1. Operators can't
configure custom sequences yet. The hardcoded list covers the
audit's explicit example (`Login → Deposit < 5 s`) and the three
most common ATO shapes.

Operator-tunable config is a planned enhancement:

```yaml
# Future, NOT yet wired:
velocity_sequence:
  rules:
    - id: custom-flow
      prev: login
      next: deposit
      window: "10s"
      score: 50
```

When the schema design lands in `aegis_core::config`, the detector
will take a `Vec<SequenceRule>` constructor arg instead of the
const list.

Custom endpoint tagging is similarly hardcoded today; a future
`tags: { login: ["/myco/auth/start"], deposit: ["/wallet/add"] }`
config would let operators map their own URL shapes.

## Tests

12 unit tests cover:

- Tag classification for all four endpoint kinds + the `None` case
- `login → deposit` within 5 s fires at score 60
- `login → withdrawal` within 5 s fires at score 70
- `otp → deposit` fires
- Deposit alone (no prior login/otp) does NOT fire
- Login → deposit AFTER the 5 s window does NOT fire
- Different IPs do NOT chain (login from IP A, deposit from IP B)
- Unrelated paths (e.g. `/health`) don't touch state
- Intermediate untagged hits don't break the sequence
  (`login → /api/profile → deposit` still fires)
- Stable detector id `"velocity_sequence"`
- `clear()` drops state
- `max_tracked` cap evicts entries
