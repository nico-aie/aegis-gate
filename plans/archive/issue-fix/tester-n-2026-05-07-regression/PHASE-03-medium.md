# Phase 3 — MEDIUM fixes (rerun)

> **Branch:** all changes target `develop`.

---

## NEW-4 · `X-WAF-Risk-Score` always reports 0 in blocked responses

**Source:** Run-2 §2 NEW-4.

### Verified state (2026-05-08, on `develop`)

The QA's described symptom is correct, but the root cause as stated ("`DecisionTag` carries `risk_score: None`") is slightly off. Cross-check:

- `crates/aegis-control/src/interop/headers.rs:93-104` — `DecisionTag` struct has fields `action`, `rule_id`, `tier`. **No `risk_score` field.**
- `crates/aegis-proxy/src/admin_dispatch.rs:787-794` — `stamp_interop_response` takes `risk_score: u32` as a separate argument.
- `crates/aegis-proxy/src/accept.rs:1114-1117` — that `risk_score` is bound by `risk.snapshot(peer.ip()).map(|s| s.score).unwrap_or(0)`.
- `crates/aegis-proxy/src/data_plane.rs:192-199` — the data plane's risk tracker is keyed under `peer_ip`, which is the **XFF-resolved client IP**, not the raw TCP `peer.ip()`.

So the actual bug is a **key mismatch**:

| Layer | IP key used |
|---|---|
| Risk accumulation (data plane) | `peer_ip` = XFF-resolved client IP (line 192 onwards) |
| Risk lookup (response stamper, accept.rs:1115) | `peer.ip()` = raw TCP peer (the proxy in front, if any) |

When the WAF runs behind a proxy or behind a synthetic client that injects `X-Forwarded-For`, the score accumulates under the resolved IP but the stamper queries under the TCP peer — which has no score recorded. `unwrap_or(0)` → header is always 0. Direct (no XFF) requests *should* work since both keys collapse to the same IP, but the QA observation suggests their test client emitted XFF.

### Plan

Two clean ways to fix:

| Option | Where | Trade-off |
|---|---|---|
| **A. Recompute peer_ip in accept.rs** before snapshot | `accept.rs:1114` area | Duplicates the XFF resolution logic; needs the `default_trusted_proxies` constant in scope |
| **B. Hand the score from the data plane to the stamper via DecisionTag** | extend `DecisionTag` with `risk_score: Option<u32>` | Cleanest — the data plane already knows the score at decision time |

**Recommend Option B.** The data plane is the authoritative source for the score-at-decision-time; pushing it through DecisionTag eliminates the lookup-after-the-fact race entirely (between the data plane's `record_malicious` and the stamper's `snapshot`, another request from the same IP could land and shift the score).

### Plan steps

**Step 1 — extend `DecisionTag`.**

```rust
// crates/aegis-control/src/interop/headers.rs:93
pub struct DecisionTag {
    pub action: Action,
    pub rule_id: Option<String>,
    pub tier: Option<aegis_core::tier::Tier>,
+   /// Score at decision time. The data plane knows this when it
+   /// records malicious / clean events; persisting it through to
+   /// the stamper avoids a lookup-after-the-fact race when the
+   /// stamper would otherwise re-query the tracker (which keys
+   /// on the XFF-resolved IP, while the stamper sees the TCP peer
+   /// — see NEW-4 from QA Run-2).
+   pub risk_score: Option<u32>,
}

impl DecisionTag {
    pub fn allow() -> Self {
        Self { action: Action::Allow, rule_id: None, tier: None, risk_score: None }
    }
    pub fn block(rule_id: impl Into<String>) -> Self {
        Self { action: Action::Block, rule_id: Some(rule_id.into()), tier: None, risk_score: None }
    }
    // ... same for rate_limit, challenge, timeout, circuit_breaker

+   pub fn with_risk_score(mut self, score: u32) -> Self {
+       self.risk_score = Some(score);
+       self
+   }
}
```

**Step 2 — populate at every block site in `data_plane.rs`.**

```rust
// crates/aegis-proxy/src/data_plane.rs
// Detector hit (line 536 area):
let block_tag = DecisionTag::block(detector_rule)
    .with_tier(tier)
    .with_risk_score(post_state.score);

// Risk-score block (line 599):
(resp, DecisionTag::block("risk-score").with_tier(tier).with_risk_score(post_state.score))

// Challenge (line 621):
(resp, DecisionTag::challenge("risk-challenge").with_tier(tier).with_risk_score(post_state.score))

// Strike block (line 252):
return (resp, DecisionTag::block("risk-strikes").with_risk_score(post_state.score));

// Blacklist hit (line 227): no risk score (didn't run risk gate)
return (resp, DecisionTag::block("blacklist"));
```

**Step 3 — read in `accept.rs` stamping path.**

```rust
// crates/aegis-proxy/src/accept.rs:1114 area
- let risk_score = risk
-     .snapshot(peer.ip())
-     .map(|s| s.score)
-     .unwrap_or(0);
+ // Prefer the score the data plane stamped at decision time
+ // (XFF-resolved key, matches accumulation). Fall back to a
+ // peer.ip() snapshot for code paths that don't carry the score
+ // (allow path with no risk gate run).
+ let risk_score = decision.risk_score
+     .or_else(|| risk.snapshot(peer.ip()).map(|s| s.score))
+     .unwrap_or(0);
```

**Step 4 — RED test.**

```rust
// crates/aegis-control/src/interop/headers.rs tests
#[test]
fn decision_tag_with_risk_score_round_trip() {
    let t = DecisionTag::block("ai").with_tier(Tier::High).with_risk_score(42);
    assert_eq!(t.risk_score, Some(42));
    assert_eq!(t.rule_id.as_deref(), Some("ai"));
}
```

Plus an integration-style test in `data_plane.rs` (mirroring existing detector-block tests) that asserts a malicious request produces a `DecisionTag` with a non-zero `risk_score`.

**Step 5 — manual verification.**

```sh
make bench-dev    # in another terminal
# Send 5 SQLi attacks from a synthetic IP
for i in 1 2 3 4 5; do
  curl -ks -i "http://127.0.0.1:8080/login?u=1' OR '1'='1" -H "X-Forwarded-For: 203.0.113.42" \
    | grep -i 'x-waf-risk-score'
done
# Expect: each response shows a non-zero, monotonically-increasing score
# Pre-fix: every response showed 0
```

### Acceptance

- [ ] `DecisionTag` carries `risk_score: Option<u32>`
- [ ] Every detector-block / risk-block / strike-block / challenge site populates the score
- [ ] `stamp_interop_response` prefers the DecisionTag-carried score; falls back to peer.ip() snapshot
- [ ] Blocked response from an XFF-via-proxy client shows the actual accumulated score, not 0
- [ ] Allow path (no risk-event) still gets `0` if the snapshot returns None — no behavior change there
- [ ] All existing data-plane and stamper tests pass
- [ ] New `decision_tag_with_risk_score_round_trip` test passes

**Effort:** ~1 h. Surgical, but touches every block exit in data_plane.rs.

---

## M009 closure verification

**Source:** Run-2 §2 M009 (downstream of C002).

The Run-1 closure of M009 was already correct — the SLO widget reads `/api/slo` faithfully; the value was depressed because the AI detector was over-firing. With Phase-1's C002 follow-up landing (`ai.enabled: false` by default), the SLO should recover.

### Plan

1. After Phase 1's C002 follow-up deploys, wait for the burn window to roll (24 h–72 h depending on SLO objective length).
2. Verify `/api/slo` shows `data_plane_availability` ≥ 99.9 % during the post-fix window.
3. Operator action: ack the firing `DataPlaneAvailability-1h / -6h / -72h` alerts in the dashboard's Health & SLOs page.
4. **If VipTalk channel still returns 401** (Run-1 §M005 secondary observation), rotate the channel token in `cfg.alerts.viptalk.token`.

No code changes needed. Track as an ops follow-up.

### Acceptance

- [ ] After C002 default-tightening lands + 24 h, `data_plane_availability` ≥ 99.9 %
- [ ] All firing DataPlaneAvailability alerts ack'd
- [ ] VipTalk channel returns 200 to alert deliveries (or the channel is replaced / disabled)

**Effort:** ~30 min operator action.

---

## Sequencing

NEW-4 ships in its own PR. M009 is operator-only post-deploy. One PR for the round:

`fix(interop): X-WAF-Risk-Score reflects decision-time score (NEW-4)`
