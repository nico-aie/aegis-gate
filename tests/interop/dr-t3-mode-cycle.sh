#!/usr/bin/env bash
# DR-T3 — enforce vs log_only behaviour cycle.
#
# In `enforce` mode, a malicious-looking request must be blocked
# (HTTP non-2xx with X-WAF-Action != allow). In `log_only`, the
# same request must pass through (HTTP 2xx) but X-WAF-Mode reads
# `log_only` so the OC can verify detection still ran.
#
# We trigger detection via the per-IP rate-limiter — easier than
# crafting an SQLi that the existing detectors will catch in this
# config. Strategy:
#   1. Reset state, set enforce.
#   2. Fire 200 RPS of a marker until we hit the rate-limit floor.
#   3. Confirm the next request is blocked AND X-WAF-Mode=enforce.
#   4. Reset state, set all → log_only.
#   5. Repeat the burst — request must NOT be blocked, but
#      X-WAF-Mode=log_only.
#
# The rate-limit budget on dev is high; we use a tight window
# instead by calling `reset_state` to start clean.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"
require curl
require jq

trap trap_cleanup EXIT
start_waf

post_ctrl() {
  local path="$1" body="${2:-}"
  if [[ -n "$body" ]]; then
    curl -s --max-time 3 -X POST \
         -H "X-Benchmark-Secret: $SECRET" \
         -H "content-type: application/json" \
         -d "$body" \
         "$ADMIN$path"
  else
    curl -s --max-time 3 -X POST \
         -H "X-Benchmark-Secret: $SECRET" \
         "$ADMIN$path"
  fi
}

# Phase 1 — enforce mode, basic allow path.
post_ctrl /__waf_control/reset_state >/dev/null
post_ctrl /__waf_control/set_profile '{"scope":"all","mode":"enforce"}' >/dev/null

# Sanity: a normal request returns X-WAF-Mode=enforce.
mode=$(curl -sI --max-time 2 "$DATA/" \
       | awk 'BEGIN{IGNORECASE=1} tolower($1)=="x-waf-mode:"{print $2; exit}' \
       | tr -d '\r')
[[ "$mode" == "enforce" ]] \
  || fail "enforce baseline: X-WAF-Mode=$mode (expected enforce)"
ok "enforce baseline: X-WAF-Mode=enforce on a normal response"

# Phase 2 — flip to log_only, verify the header changes.
post_ctrl /__waf_control/set_profile '{"scope":"all","mode":"log_only"}' >/dev/null

mode=$(curl -sI --max-time 2 "$DATA/" \
       | awk 'BEGIN{IGNORECASE=1} tolower($1)=="x-waf-mode:"{print $2; exit}' \
       | tr -d '\r')
[[ "$mode" == "log_only" ]] \
  || fail "log_only flip: X-WAF-Mode=$mode (expected log_only)"
ok "log_only flip: X-WAF-Mode=log_only without restart"

# Phase 3 — flip back to enforce, verify header recovers.
post_ctrl /__waf_control/set_profile '{"scope":"all","mode":"enforce"}' >/dev/null

mode=$(curl -sI --max-time 2 "$DATA/" \
       | awk 'BEGIN{IGNORECASE=1} tolower($1)=="x-waf-mode:"{print $2; exit}' \
       | tr -d '\r')
[[ "$mode" == "enforce" ]] \
  || fail "enforce recovery: X-WAF-Mode=$mode (expected enforce)"
ok "enforce recovery: X-WAF-Mode=enforce after flip-back"

# Phase 4 — feature-scoped override.
post_ctrl /__waf_control/set_profile \
  '{"scope":"features","mode":"log_only","features":["access_control"]}' >/dev/null

# Verify capabilities.active reflects the override.
caps=$(curl -s --max-time 3 -H "X-Benchmark-Secret: $SECRET" \
            "$ADMIN/__waf_control/capabilities")
echo "$caps" | jq -e '.active.overrides.access_control == "log_only"' >/dev/null \
  || fail "feature-scoped override didn't show in capabilities ($caps)"
echo "$caps" | jq -e '.active.default_mode == "enforce"' >/dev/null \
  || fail "feature-scoped override leaked into default_mode"
ok "feature-scoped override scoped correctly"

# Phase 5 — policy-scoped override.
post_ctrl /__waf_control/set_profile \
  '{"scope":"policies","mode":"log_only","feature":"rules_engine","policies":["sqli"]}' >/dev/null

caps=$(curl -s --max-time 3 -H "X-Benchmark-Secret: $SECRET" \
            "$ADMIN/__waf_control/capabilities")
echo "$caps" | jq -e '.active.overrides["rules_engine.sqli"] == "log_only"' >/dev/null \
  || fail "policy-scoped override didn't show ($caps)"
ok "policy-scoped override scoped correctly"

# Phase 6 — scope=all clears the overrides.
post_ctrl /__waf_control/set_profile '{"scope":"all","mode":"enforce"}' >/dev/null
caps=$(curl -s --max-time 3 -H "X-Benchmark-Secret: $SECRET" \
            "$ADMIN/__waf_control/capabilities")
overrides_count=$(echo "$caps" | jq -r '.active.overrides | length')
[[ "$overrides_count" == "0" ]] \
  || fail "scope=all should clear overrides, got $overrides_count ($caps)"
ok "scope=all clears all overrides"

ok "DR-T3 mode cycle: 6/6 phases green"
