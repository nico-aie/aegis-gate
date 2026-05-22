---
id: 2026-05-17-velocity-no-cross-endpoint-sequence
date: 2026-05-17T00:00Z
severity: CRITICAL
area: security · transaction velocity
component: crates/aegis-security/src/velocity.rs
interop_contract: official rules §5.2 #10 (Transaction Velocity & Sequence) · §7 Attack Battle scenario 06
status: open
test_mode: source-review (spot-verified — zero matches for Login/OTP/Deposit/sequence/withdraw)
---

# F-CRITICAL-003 · `velocity.rs` has NO cross-endpoint sequence engine — Login→OTP→Deposit, withdrawal-after-deposit, rapid-limit-change all unimplemented

## Summary

Official rules §5.2 #10 lists THREE concrete velocity scenarios as
required:

| # | Scenario | Status |
|---|---|---|
| 1 | "Login→OTP→Deposit trong N giây" | ❌ Not implemented |
| 2 | "Withdrawal velocity check sau deposit" | ❌ Not implemented |
| 3 | "Rapid limit-change pattern detection" | ❌ Not implemented |

Attack Battle scenario 06 explicitly calls this out as a test vector
("Login→Deposit nhanh (<5s), withdrawal ngay sau deposit, rapid
limit-change + withdrawal pattern").

The shipped `velocity.rs` (196 lines) implements only a **generic
per-rule sliding-window counter** keyed on a caller-supplied
`discriminator` string. There is zero code for:

- Cross-action correlation (the rule says "across endpoints").
- Per-user state machine (the rule says "Per-user cross-endpoint tracking").
- Inter-action time delta (the rule says "trong N giây").

**Spot-verified** with `grep -n "Login\|OTP\|Deposit\|sequence\|withdraw" velocity.rs`: **zero matches**. The module contains no code referencing any of the three scenarios.

## Observed code path

[velocity.rs](../../../../crates/aegis-security/src/velocity.rs) entire file: just a generic counter.
Representative signature:

```rust
pub fn check(
    &self,
    rule_id: &str,
    discriminator: &str,    // typically "{user_id}" or "{ip}:{action}"
    now: Instant,
) -> Decision { ... }
```

What's needed:

```rust
pub fn record_event(&self, user_id: &str, action: Action, now: Instant);

pub enum SequenceVerdict {
    Ok,
    SuspectFastSequence(Vec<(Action, Duration)>),
    SuspectWithdrawAfterDeposit { gap: Duration },
    SuspectRapidLimitChange { count: usize, window: Duration },
}

pub fn evaluate(&self, user_id: &str, now: Instant) -> SequenceVerdict;
```

## Impact

- **Attack Battle scenario 06** (Transaction Fraud Pattern) — entirely undetectable.
- **Intelligence & Adaptiveness rubric (20 / 120)** — "Transaction velocity & sequence detection" is explicitly enumerated as a scored sub-item.
- **Security Effectiveness (40 / 120)** — partial. The §5.2 requirements list this under "Chức năng cốt lõi (BẮT BUỘC)" — required, not optional.
- **Forbidden-shape risk**: the shipped module's `discriminator` is caller-supplied with no validation. If a proxy mistakenly passes an empty string, all users collapse into one bucket and the velocity module degrades to "global per-second counter". This is functionally indistinguishable from "feature not implemented" but harder to debug.

## Suggested fix

Net-new module `velocity_sequence.rs` (~300 LoC). Sketch:

```rust
pub enum Action {
    Login, Otp, Deposit, Withdraw, LimitChange, ...,
}

pub struct SequenceTracker {
    // Per-user event log; bounded to last N events / last M minutes.
    events: DashMap<String, VecDeque<(Action, Instant)>>,
    cfg: SequenceConfig,
}

pub struct SequenceConfig {
    pub max_events_per_user: usize,        // e.g. 64
    pub event_ttl: Duration,               // e.g. 1 hour
    pub login_to_deposit_window: Duration, // e.g. 5 seconds
    pub withdraw_after_deposit_window: Duration,  // e.g. 30 seconds
    pub rapid_limit_change_count: usize,   // e.g. 3
    pub rapid_limit_change_window: Duration, // e.g. 1 minute
}

impl SequenceTracker {
    pub fn record(&self, user: &str, action: Action, now: Instant) {
        let mut log = self.events.entry(user.to_string()).or_default();
        log.push_back((action, now));
        // Bound length + TTL
        while log.len() > self.cfg.max_events_per_user
            || log.front().map_or(false, |(_, t)| now.duration_since(*t) > self.cfg.event_ttl) {
            log.pop_front();
        }
    }

    pub fn evaluate(&self, user: &str, now: Instant) -> SequenceVerdict {
        let log = match self.events.get(user) { Some(l) => l, None => return SequenceVerdict::Ok };
        // Pattern 1: Login → OTP → Deposit within window.
        if has_subsequence(&*log, &[Action::Login, Action::Otp, Action::Deposit], self.cfg.login_to_deposit_window) {
            return SequenceVerdict::SuspectFastSequence(extract_timings(&*log));
        }
        // Pattern 2: Withdraw right after Deposit.
        if let Some(gap) = withdraw_after_deposit_gap(&*log) {
            if gap < self.cfg.withdraw_after_deposit_window {
                return SequenceVerdict::SuspectWithdrawAfterDeposit { gap };
            }
        }
        // Pattern 3: Rapid limit-change.
        if count_recent(&*log, Action::LimitChange, self.cfg.rapid_limit_change_window) >= self.cfg.rapid_limit_change_count {
            return SequenceVerdict::SuspectRapidLimitChange { ... };
        }
        SequenceVerdict::Ok
    }
}
```

Wire-in points:

- The route table classifies endpoints by Action (login → Action::Login, etc.). Annotation in YAML:
  ```yaml
  routes:
    - path: "/login"
      action_class: login
    - path: "/otp"
      action_class: otp
    - path: "/deposit"
      action_class: deposit
  ```
- Data plane calls `tracker.record(user_id, action, now)` on successful auth completion (or per-request for unauth velocity).
- Pipeline reads `tracker.evaluate(user_id, now)` and feeds the verdict into the risk-score delta.

`user_id` plumbing requires session/JWT extraction (cf. F-HIGH-challenge-auth — JWT verification is currently broken; fix first).

## Verification

```sh
HOST="http://127.0.0.1:8080"
USER=alice

# Simulate the Attack Battle pattern: Login → OTP → Deposit in <5s.
curl -ski "$HOST/login"   -H "Cookie: u=$USER" -d "user=alice&pass=...."
curl -ski "$HOST/otp"     -H "Cookie: u=$USER" -d "code=123456"
curl -ski "$HOST/deposit" -H "Cookie: u=$USER" -d "amount=10000"

# Third request should be challenged or blocked.
# Audit log should mention rule_id: velocity.login_otp_deposit_fast.
tail -1 ./waf_audit.log | jq '{action, rule_id}'
```

## Severity rationale

CRITICAL. Three of three §5.2 #10 scenarios unimplemented; explicit
Attack Battle vector untested. Implementation is ~300-400 LoC of
self-contained code — the work is doable in a day. The current
`velocity.rs` is generic-counter scaffolding that does NOT count
against the missing-feature claim; keep it, but add the sequence
engine on top.
