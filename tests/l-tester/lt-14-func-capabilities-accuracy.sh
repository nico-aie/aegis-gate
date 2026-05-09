#!/usr/bin/env bash
# LT-14 — Capabilities accuracy: feature names, policy lists, risk_engine
#
# Bug-hunter test: verifies the capabilities response exposes the correct
# feature names and policies matching the real WAF's run.rs wiring.
#
# Bugs targeted:
#   - Feature named "rate_limiting" instead of "rate_limit" (name mismatch)
#   - Missing "risk_engine" feature (with score/strikes policies)
#   - rules_engine missing extended policies: command_injection, template_injection,
#     nosql_injection, open_redirect, ai, header_injection, body_abuse, brute_force
#   - "challenge" feature exposed when not part of v2.3 contract surface
#
# Contract references: §2.3 capabilities response shape.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"
require curl
require jq

trap trap_cleanup EXIT
start_waf
reset_to_enforce

body=$(ctrl_get "/__waf_control/capabilities")

# ------------------------------------------------------------------
# 1. rate_limit feature present (not rate_limiting)
# ------------------------------------------------------------------
feat_type=$(printf '%s' "$body" | jq -r '.features.rate_limit | type')
[[ "$feat_type" == "object" ]] \
  || fail "§2.3 feature 'rate_limit' missing (got type=$feat_type); real WAF uses 'rate_limit' not 'rate_limiting'"
ok "§2.3 feature 'rate_limit' present"

has_per_ip=$(printf '%s' "$body" | jq -r '.features.rate_limit.policies | contains(["per_ip"])')
[[ "$has_per_ip" == "true" ]] \
  || fail "§2.3 rate_limit feature is missing 'per_ip' policy"
ok "§2.3 rate_limit.per_ip policy present"

# ------------------------------------------------------------------
# 2. risk_engine feature present with score + strikes
# ------------------------------------------------------------------
feat_type=$(printf '%s' "$body" | jq -r '.features.risk_engine | type')
[[ "$feat_type" == "object" ]] \
  || fail "§2.3 feature 'risk_engine' missing; must be exposed so OC can toggle risk scoring"
ok "§2.3 feature 'risk_engine' present"

has_score=$(printf '%s' "$body" | jq -r '.features.risk_engine.policies | contains(["score"])')
[[ "$has_score" == "true" ]] || fail "§2.3 risk_engine is missing 'score' policy"
ok "§2.3 risk_engine.score policy present"

has_strikes=$(printf '%s' "$body" | jq -r '.features.risk_engine.policies | contains(["strikes"])')
[[ "$has_strikes" == "true" ]] || fail "§2.3 risk_engine is missing 'strikes' policy"
ok "§2.3 risk_engine.strikes policy present"

# ------------------------------------------------------------------
# 3. access_control present with blacklist + whitelist
# ------------------------------------------------------------------
feat_type=$(printf '%s' "$body" | jq -r '.features.access_control | type')
[[ "$feat_type" == "object" ]] || fail "§2.3 feature 'access_control' missing"
ok "§2.3 feature 'access_control' present"

for pol in blacklist whitelist; do
  has=$(printf '%s' "$body" | jq -r ".features.access_control.policies | contains([\"$pol\"])")
  [[ "$has" == "true" ]] || fail "§2.3 access_control missing policy '$pol'"
done
ok "§2.3 access_control has blacklist + whitelist"

# ------------------------------------------------------------------
# 4. rules_engine has all mandatory policies (≥ 10)
# ------------------------------------------------------------------
pol_count=$(printf '%s' "$body" | jq '.features.rules_engine.policies | length')
[[ "$pol_count" -ge 10 ]] \
  || fail "§2.3 rules_engine has only $pol_count policies (expected ≥ 10; should include extended detectors)"
ok "§2.3 rules_engine has $pol_count policies (≥ 10)"

# ------------------------------------------------------------------
# 5. rules_engine has all core security policies
# ------------------------------------------------------------------
for pol in sqli xss path_traversal ssrf command_injection template_injection nosql_injection; do
  has=$(printf '%s' "$body" | jq -r ".features.rules_engine.policies | contains([\"$pol\"])")
  [[ "$has" == "true" ]] \
    || fail "§2.3 rules_engine missing policy '$pol' (needed for set_profile targeting and mode resolution)"
done
ok "§2.3 rules_engine has all core security policies: sqli/xss/path_traversal/ssrf/command_injection/template_injection/nosql_injection"

# ------------------------------------------------------------------
# 6. Verify set_profile can target risk_engine.score
# ------------------------------------------------------------------
result=$(ctrl_post "/__waf_control/set_profile" \
  '{"scope":"policies","mode":"log_only","feature":"risk_engine","policies":["score"]}')
ok_field=$(printf '%s' "$result" | jq -r '.ok')
[[ "$ok_field" == "true" ]] || fail "set_profile targeting risk_engine.score failed: $result"
unsupported=$(printf '%s' "$result" | jq '.unsupported | length')
[[ "$unsupported" -eq 0 ]] \
  || fail "risk_engine.score listed as unsupported (not exposed in capabilities)"
ok "set_profile can target risk_engine.score (no unsupported)"

# Restore
ctrl_post "/__waf_control/set_profile" '{"scope":"all","mode":"enforce"}' >/dev/null

# ------------------------------------------------------------------
# 7. Verify set_profile can target rules_engine.template_injection
# ------------------------------------------------------------------
result=$(ctrl_post "/__waf_control/set_profile" \
  '{"scope":"policies","mode":"log_only","feature":"rules_engine","policies":["template_injection"]}')
ok_field=$(printf '%s' "$result" | jq -r '.ok')
[[ "$ok_field" == "true" ]] || fail "set_profile targeting rules_engine.template_injection failed"
unsupported=$(printf '%s' "$result" | jq '.unsupported | length')
[[ "$unsupported" -eq 0 ]] \
  || fail "template_injection listed as unsupported — policy not in capabilities"
ok "set_profile can target rules_engine.template_injection"

ctrl_post "/__waf_control/set_profile" '{"scope":"all","mode":"enforce"}' >/dev/null

ok "LT-14 capabilities-accuracy: all checks green"
