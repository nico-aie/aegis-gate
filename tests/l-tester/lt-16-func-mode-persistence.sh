#!/usr/bin/env bash
# LT-16 — Mode persistence across reset_state
#
# Bug-hunter test: verifies that set_profile overrides SURVIVE reset_state.
#
# Per §2.4 of the contract:
#   "reset_state MUST clear temporary runtime WAF state
#    (risk scores, rate-limit counters, etc.) but MUST NOT clear
#    operator-configured state (rules, mode overrides, long-term config)."
#
# Many implementations erroneously clear the ModeStore on reset_state,
# treating log_only overrides as "runtime state" rather than "operator
# config".  After a correct reset_state the WAF must still enforce the
# mode profile that was set via set_profile.
#
# Bugs targeted:
#   - reset_state clearing mode overrides set by set_profile
#   - reset_state setting default_mode back to "enforce"
#
# Test flow:
#   1. Set rules_engine to log_only via scope=features
#   2. Confirm attack passes through (HTTP 200) under log_only
#   3. Call reset_state
#   4. Read capabilities — override must still be present
#   5. Confirm attack still passes through (mode NOT reset)
#   6. Restore with scope=all enforce, confirm block resumes

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"
require curl
require jq

trap trap_cleanup EXIT
start_waf
reset_to_enforce

# ------------------------------------------------------------------
# 1. Set rules_engine to log_only
# ------------------------------------------------------------------
body=$(ctrl_post "/__waf_control/set_profile" \
  '{"scope":"features","mode":"log_only","features":["rules_engine"]}')
ok_val=$(printf '%s' "$body" | jq -r '.ok')
[[ "$ok_val" == "true" ]] || fail "set_profile scope=features log_only failed: $body"
override=$(printf '%s' "$body" | jq -r '.active.overrides.rules_engine // empty')
[[ "$override" == "log_only" ]] \
  || fail "rules_engine override not set in response (got: $override)"
ok "§2.5 rules_engine set to log_only"

# ------------------------------------------------------------------
# 2. Confirm SQLi attack passes through in log_only (HTTP 200 or 502)
# ------------------------------------------------------------------
raw=$(curl -si --max-time 5 \
  "$DATA/?id=1%27%20OR%20%271%27%3D%271-lt16-before-reset" 2>/dev/null || true)
http_status=$(printf '%s' "$raw" | grep -oP 'HTTP/\S+\s+\K\d+' | head -1 || echo 0)
action=$(header_value "$raw" "X-WAF-Action")
mode_hdr=$(header_value "$raw" "X-WAF-Mode")

[[ "$http_status" == "200" || "$http_status" == "502" ]] \
  || fail "log_only attack should not be denied (got HTTP $http_status)"
[[ "$action" == "block" || "$action" == "challenge" ]] \
  || fail "X-WAF-Action should be intended action (block/challenge) in log_only; got '$action'"
[[ "$mode_hdr" == "log_only" ]] \
  || fail "X-WAF-Mode should be 'log_only' (got '$mode_hdr')"
ok "§2.7 attack passes through in log_only (HTTP $http_status, action=$action, mode=$mode_hdr)"

# ------------------------------------------------------------------
# 3. Call reset_state
# ------------------------------------------------------------------
r=$(ctrl_post "/__waf_control/reset_state")
ok_val=$(printf '%s' "$r" | jq -r '.ok')
[[ "$ok_val" == "true" ]] || fail "reset_state failed"
ok "§2.4 reset_state called"

# ------------------------------------------------------------------
# 4. Capabilities must still show log_only override
# ------------------------------------------------------------------
caps=$(ctrl_get "/__waf_control/capabilities")
override_after=$(printf '%s' "$caps" | jq -r '.active.overrides.rules_engine // empty')
[[ "$override_after" == "log_only" ]] \
  || fail "§2.4 BUG: rules_engine override was '$override_after' after reset_state (expected log_only); reset_state must NOT clear operator-set mode overrides"
default_after=$(printf '%s' "$caps" | jq -r '.active.default_mode')
[[ "$default_after" == "enforce" ]] \
  || fail "§2.4 default_mode changed to '$default_after' after reset_state (should stay enforce)"
ok "§2.4 mode override survives reset_state (rules_engine=log_only, default=enforce)"

# ------------------------------------------------------------------
# 5. Attack still passes through after reset_state (mode not reset)
# ------------------------------------------------------------------
raw=$(curl -si --max-time 5 \
  "$DATA/?id=1%27%20OR%20%271%27%3D%271-lt16-after-reset" 2>/dev/null || true)
http_status=$(printf '%s' "$raw" | grep -oP 'HTTP/\S+\s+\K\d+' | head -1 || echo 0)
action=$(header_value "$raw" "X-WAF-Action")
mode_hdr=$(header_value "$raw" "X-WAF-Mode")

[[ "$http_status" == "200" || "$http_status" == "502" ]] \
  || fail "§2.4 BUG: after reset_state, attack was denied (HTTP $http_status) — mode was incorrectly reset to enforce"
[[ "$mode_hdr" == "log_only" ]] \
  || fail "§2.4 BUG: X-WAF-Mode='$mode_hdr' after reset_state (expected log_only — mode must persist)"
ok "§2.4 attack still passes through after reset_state (mode persisted)"

# ------------------------------------------------------------------
# 6. Restore enforce via scope=all, confirm attack is blocked again
# ------------------------------------------------------------------
ctrl_post "/__waf_control/set_profile" '{"scope":"all","mode":"enforce"}' >/dev/null
sleep 0.2

raw=$(curl -si --max-time 5 \
  "$DATA/?id=1%27%20OR%20%271%27%3D%271-lt16-restored" 2>/dev/null || true)
http_status=$(printf '%s' "$raw" | grep -oP 'HTTP/\S+\s+\K\d+' | head -1 || echo 0)
[[ "$http_status" == "403" || "$http_status" == "429" ]] \
  || fail "after restoring enforce, attack should be blocked (got HTTP $http_status)"
ok "§2.5 attack blocked after mode restored to enforce"

ok "LT-16 mode-persistence: all checks green"
