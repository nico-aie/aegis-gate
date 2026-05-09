#!/usr/bin/env bash
# LT-18 — reset_state runtime state isolation
#
# Bug-hunter test: verifies that reset_state correctly resets TRANSIENT
# runtime state (risk scores, rate-limit counters) while preserving
# operator-set config (mode overrides).
#
# Bugs targeted:
#   - reset_state not resetting risk scores → risk accumulation leaks across runs
#   - reset_state not resetting rate-limit counters → rate-limit bleeds across tests
#   - reset_state incorrectly also clearing mode overrides (covered in LT-16)
#
# Contract reference: §2.4 reset_state semantics.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"
require curl
require jq

trap trap_cleanup EXIT
start_waf
reset_to_enforce

# ------------------------------------------------------------------
# 1. Accumulate risk score by firing injection attacks
# ------------------------------------------------------------------
echo "==> §2.4 risk score isolation: firing 6 SQLi attacks to accumulate risk"
for i in $(seq 1 6); do
  curl -sI --max-time 3 "$DATA/?id=1%27%20OR%20%271%27%3D%271-lt18-risk-$i" \
    >/dev/null 2>&1 || true
done
sleep 0.3

# After multiple attacks, risk score should be > 0
raw=$(curl -sI --max-time 3 "$DATA/lt18-risk-check" 2>/dev/null || true)
risk_before=$(header_value "$raw" "X-WAF-Risk-Score")
# Validate risk_before is numeric
[[ "$risk_before" =~ ^[0-9]+$ ]] \
  || fail "X-WAF-Risk-Score is not numeric: '$risk_before'"
[[ "$risk_before" -gt 0 ]] \
  || fail "§2.4 risk score should be > 0 after 6 attacks (got $risk_before)"
ok "§2.4 risk score elevated to $risk_before after attacks"

# ------------------------------------------------------------------
# 2. reset_state should clear risk scores
# ------------------------------------------------------------------
ctrl_post "/__waf_control/reset_state" >/dev/null
sleep 0.2

raw=$(curl -sI --max-time 3 "$DATA/lt18-risk-check-after" 2>/dev/null || true)
risk_after=$(header_value "$raw" "X-WAF-Risk-Score")
[[ "$risk_after" =~ ^[0-9]+$ ]] || fail "X-WAF-Risk-Score not numeric after reset: '$risk_after'"
[[ "$risk_after" -eq 0 ]] \
  || fail "§2.4 BUG: risk score still $risk_after after reset_state (should be 0); reset_state must clear risk counters"
ok "§2.4 risk score reset to 0 after reset_state"

# ------------------------------------------------------------------
# 3. Accumulate rate-limit breach (burst > threshold)
# ------------------------------------------------------------------
ctrl_post "/__waf_control/reset_state" >/dev/null
ctrl_post "/__waf_control/set_profile" '{"scope":"all","mode":"enforce"}' >/dev/null

echo "==> §2.4 rate-limit isolation: sending 210 rapid requests to breach limit"
rate_tripped=0
for i in $(seq 1 210); do
  a=$(curl -sI --max-time 1 "$DATA/lt18-burst-$i" 2>/dev/null \
      | awk 'BEGIN{IGNORECASE=1} tolower($1)=="x-waf-action:"{print $2; exit}' \
      | tr -d '\r')
  case "$a" in
    rate_limit|block)
      rate_tripped=1
      break
      ;;
  esac
done

[[ "$rate_tripped" -eq 1 ]] \
  || fail "§2.4 rate limit never tripped after 210 requests (threshold should be ~200 per 10s)"
ok "§2.4 rate limit triggered after burst"

# ------------------------------------------------------------------
# 4. reset_state should clear rate-limit counters
# ------------------------------------------------------------------
ctrl_post "/__waf_control/reset_state" >/dev/null
sleep 0.3

# First few requests after reset should be allowed (counters cleared)
allowed_after=0
for i in $(seq 1 3); do
  raw=$(curl -sI --max-time 3 "$DATA/lt18-clean-$i" 2>/dev/null || true)
  action=$(header_value "$raw" "X-WAF-Action")
  if [[ "$action" == "allow" ]]; then
    allowed_after=1
    break
  fi
done

[[ "$allowed_after" -eq 1 ]] \
  || fail "§2.4 BUG: requests still rate-limited after reset_state (counters not cleared)"
ok "§2.4 rate-limit counters cleared after reset_state (first request allowed)"

# ------------------------------------------------------------------
# 5. Verify mode override was NOT cleared by reset_state
# ------------------------------------------------------------------
# Set a feature to log_only, reset, verify it's still log_only
ctrl_post "/__waf_control/set_profile" \
  '{"scope":"features","mode":"log_only","features":["access_control"]}' >/dev/null
ctrl_post "/__waf_control/reset_state" >/dev/null

caps=$(ctrl_get "/__waf_control/capabilities")
access_mode=$(printf '%s' "$caps" | jq -r '.active.overrides.access_control // empty')
[[ "$access_mode" == "log_only" ]] \
  || fail "§2.4 BUG: access_control override cleared by reset_state (expected log_only, got '$access_mode')"
ok "§2.4 mode override (access_control=log_only) NOT cleared by reset_state"

ctrl_post "/__waf_control/set_profile" '{"scope":"all","mode":"enforce"}' >/dev/null

ok "LT-18 reset-state-isolation: all checks green"
