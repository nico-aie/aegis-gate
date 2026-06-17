---
id: 2026-06-17-section-03-decision-classes
contract_section: "§3 — WAF Decision Classes + §3.1 threat→action map"
checklist_ids: C-3-* C-3.1-*
verdict: PASS
test_mode: source-review
---

# §3 — Decision Classes & §3.1 Threat→Action Map

Primary code: `crates/aegis-control/src/interop/headers.rs:39 Action`,
emission sites in `crates/aegis-proxy/src/data_plane.rs`.

## §3 — 6 decision classes — ✅ PASS

- `Action` enum has exactly the 6 classes; `as_str()` emits the exact
  lowercase strings `allow|block|challenge|rate_limit|timeout|circuit_breaker`
  (`headers.rs:50`). Test `action_strings_match_spec` pins them (C-3-02).
- Each request resolves to exactly one `DecisionTag` carried to the stamper
  (C-3-01). Constructors: `allow/block/rate_limit/challenge/timeout/circuit_breaker`
  (`headers.rs:162-179`).

## §3.1 — Threat→action semantic map — ✅ PASS (by design)

The contract table is a *semantic compatibility map*, not a per-test
PASS spec. The WAF satisfies it by emitting an action in the acceptable
set for each category. Spot mapping against the live detectors:

| Category (C-3.1-*) | Acceptable actions | Aegis emits | OK? |
|---|---|---|---|
| Auth abuse | block/challenge/rate_limit | risk gate → challenge/block; ip_limiter → rate_limit | ✅ |
| Relay/proxy spoofing | block/challenge OR allow + risk>0 | xff/ip_rep raise risk; allow-with-score path exists (`with_rule_id` on allow) | ✅ |
| Behavioral anomaly / bot | block/challenge/rate_limit | bots.rs / behavior.rs detectors | ✅ |
| Behavioral signal (header on auth route) | …or allow + risk delta>0 | detector adds risk delta, allow carries score | ✅ |
| Bot discipline (token brute / IDOR) | block/challenge/rate_limit | velocity.rs + risk strikes | ✅ |
| Transaction fraud | block/challenge/rate_limit | velocity.rs (velocity/geo/value) | ✅ |
| Recon/enumeration | block/challenge/rate_limit | recon detector | ✅ |
| Canary / known-bad IP | block | canary policy + blacklist → block | ✅ |
| Negative control / legit | allow (risk<10) | clean path → `DecisionTag::allow`, risk 0 | ✅ |

Notes confirmed:
- C-3.1-11: `rate_limit` and `challenge` both return HTTP 429
  (`data_plane.rs:706` rate-limit 429, `data_plane.rs:1388` challenge 429).
- C-3.1-12: allow-with-risk supported — `DecisionTag::allow().with_rule_id(..)`
  + `with_risk_score(..)` lets an under-threshold detection forward as
  `allow` while still elevating `X-WAF-Risk-Score` and labelling the detector
  (`headers.rs:344` test).

## Net
Decision-class machinery is exact and complete. No findings. Per-test PASS
weighting is organizer-owned and not assessable from source.
