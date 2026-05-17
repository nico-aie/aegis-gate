---
id: 2026-05-17-log-only-bypassed-by-non-detector-block-paths
date: 2026-05-17T00:00Z
severity: CRITICAL
area: data-plane · security pipeline
component: crates/aegis-proxy/src/data_plane.rs (rate-limit, strike, blacklist, risk-score branches)
interop_contract: v2.3 §3 (Threat → Action), §5.3 (Header consistency), §2.5 (set_profile)
status: open
test_mode: source-review
---

# F-CRITICAL-002 · `log_only` mode is honored only by detector blocks — 4 other block paths still enforce

## Summary

`mode_for_rule(...) == LogOnly` is consulted in **exactly one place**
on the data-plane hot path
(`crates/aegis-proxy/src/data_plane.rs:644-660`, inside the detector
branch). Every other branch that can short-circuit a request with a
block response ignores the `interop_modes` snapshot entirely:

| Block branch | File:line | `interop_modes` consulted? |
|---|---|---|
| Detector hit | `data_plane.rs:644-660` | ✅ |
| Blacklist hit | `data_plane.rs:215-231` | ❌ |
| Strike-block hit | `data_plane.rs:245-264` | ❌ |
| Rate-limit per-IP | `data_plane.rs:363-428` | ❌ |
| Risk-score threshold | `data_plane.rs:740-758` | ❌ |

The v2.3 contract is explicit (§3 / §5.3):

> *Khi `X-WAF-Mode: log_only`, các decisions `block`, `challenge`,
> `rate_limit`, `timeout`, và `circuit_breaker` BẮT BUỘC report qua
> `X-WAF-Action` như intended decisions only; enforcement effect
> KHÔNG ĐƯỢC áp dụng.*

The OC harness uses this exact mechanism to verify detector behavior
without losing the request: it sets `set_profile mode:"log_only"`,
sends a known-bad payload, and expects the request to reach upstream
while still reporting `X-WAF-Action: block / rate_limit` + `X-WAF-Mode:
log_only`. Today only detector rules behave this way; everything else
returns 403/429 regardless of mode.

## Observed code path

`crates/aegis-proxy/src/data_plane.rs:533` snapshots `interop_modes`
once per request:

```rust
let interop_modes = upstream_ctx.interop_modes.get();
```

It is then read only at line 644 (detector branch):

```rust
let detector_mode = interop_modes
    .as_ref()
    .map(|m| aegis_control::interop::rule_map::mode_for_rule(
        m, Some(detector_rule.as_str())
    ))
    .unwrap_or_default();
if detector_mode == aegis_control::interop::headers::Mode::LogOnly {
    // fall through to upstream
}
```

`grep -n 'interop_modes\|mode_for_rule\|LogOnly' data_plane.rs`
returns only those three lines — no other branch in the file even
references the snapshot.

By contrast, the blacklist branch around line 215 returns a fixed
`DecisionTag::block("blacklist")` + 403 builder result, then exits;
the rate-limit branch around 363 returns 429; the strike branch
around 245 returns 403; the risk-score branch around 740 returns 403.

## Repro (post-build)

```sh
SECRET="${AEGIS_BENCHMARK_SECRET:-waf-hackathon-2026-ctrl}"
HOST="http://127.0.0.1:8080"

# 1. Flip rate_limit to log_only:
curl -sk -X POST -H "X-Benchmark-Secret: $SECRET" \
    -H 'content-type: application/json' \
    -d '{"scope":"features","mode":"log_only","features":["rate_limit"]}' \
    "$HOST/__waf_control/set_profile" | jq

# 2. Burst more than per-IP threshold (default ~50/s in dev.yaml):
for i in $(seq 1 200); do
    curl -ski "$HOST/" -o /dev/null -w "%{http_code} "
done; echo

# Expected (per §3 log_only):
#   200 200 200 ... (all reach upstream)
#   each response carries: X-WAF-Action: rate_limit · X-WAF-Mode: log_only
#
# Actual (today):
#   200 200 ... 429 429 429 ... (WAF still enforces)
```

Same pattern works for `set_profile features:["risk_engine"]`,
`features:["access_control"]` (blacklist), etc.

## Impact

- Any OC verification probe that toggles a non-detector feature to
  `log_only` will observe the request being blocked → §3 violation
  recorded against the WAF on every such probe.
- The contract's primary mechanism for detector validation
  (set log_only → send payload → verify intended action without
  service interruption) is unusable for 4 of the 5 enforcement
  surfaces.
- False positives during log_only verification phases will count
  as `false_positive` in the §7 normalization matrix even though
  the operator intentionally asked for log-only mode.

## Suggested fix

At each of the four block branches, consult `mode_for_rule` against
the rule-id used for that branch and fall through to upstream when
`LogOnly`. The header pipeline already records `X-WAF-Mode: log_only`
via the stamper once the decision tag is set with the correct mode.

Concretely (sketch for rate-limit; mirror for the other three):

```rust
// data_plane.rs ~ line 380
if rate_limit_exceeded {
    let rl_mode = interop_modes
        .as_ref()
        .map(|m| mode_for_rule(m, Some("rate_limit.per_ip")))
        .unwrap_or_default();
    if rl_mode == Mode::LogOnly {
        // Record the intended action; do not enforce.
        observed_intended_action = Some(IntendedAction::RateLimit);
        // fall through into the proxy path below
    } else {
        let resp = build_429(...);
        return (resp, DecisionTag::block("rate_limit.per_ip"));
    }
}
```

The `IntendedAction` carrier is what `stamp_interop_response` already
reads for the detector branch — extending it to the other branches is
a few-line refactor each.

Rule-id naming (so `set_profile policies:[...]` can target each
branch individually) should follow the capabilities response:

| Branch | Suggested rule-id / policy key |
|---|---|
| Blacklist | `access_control.blacklist` |
| Strike-block | `access_control.strike_block` |
| Rate-limit | `rate_limit.per_ip` |
| Risk-score | `risk_engine.score` |

(These keys already need to appear in `GET /__waf_control/capabilities`
for §2.3 — verify they do.)

## Verification

After the fix, the repro burst should print 200s only, and each
response should carry `X-WAF-Action: rate_limit · X-WAF-Mode:
log_only`. A regression case belongs in `tests/contract/` for each
of the four block branches.

## Severity rationale

CRITICAL. Contract §3 is one of the v2.3 deltas
(see §12 *"Updated observability and audit-log consistency rules
for `log_only` mode"*) — the harness is built around this exact
behavior. Any failure here is detected on every probe of every
non-detector enforcement surface.
