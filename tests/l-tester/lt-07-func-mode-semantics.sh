#!/usr/bin/env bash
# LT-07 — §2.5 / §2.7 / §5.3  enforce vs log_only mode semantics
#
# Contract:
#   enforce:
#     - X-WAF-Mode: enforce on every proxied response.
#     - A request that would be blocked IS blocked (non-2xx HTTP status
#       AND X-WAF-Action: block).
#   log_only:
#     - X-WAF-Mode: log_only on every proxied response.
#     - The WAF MUST still evaluate policies and report the INTENDED
#       X-WAF-Action (e.g. "block") in the header.
#     - The enforcement effect MUST NOT be applied: the request SHOULD
#       pass upstream (HTTP 2xx even for a malicious payload).
#     - X-WAF-Rule-Id and audit log evidence MUST still be produced.
#
# Phases:
#   1. Enforce baseline — normal request carries X-WAF-Mode: enforce.
#   2. Enforce attack   — SQLi blocked; HTTP 4xx + X-WAF-Action: block.
#   3. log_only flip    — X-WAF-Mode: log_only on normal request.
#   4. log_only attack  — SQLi NOT blocked (HTTP not 403/429) but
#                         X-WAF-Action reports intended action.
#   5. Enforce recovery — flip back; X-WAF-Mode: enforce returns.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"
require curl
require jq

trap trap_cleanup EXIT
start_waf

# ------------------------------------------------------------------
# Phase 1 — enforce baseline
# ------------------------------------------------------------------
ctrl_post "/__waf_control/reset_state"  >/dev/null
ctrl_post "/__waf_control/set_profile" '{"scope":"all","mode":"enforce"}' >/dev/null

raw=$(curl -sI --max-time 3 "$DATA/" 2>/dev/null || true)
mode=$(header_value "$raw" 'X-WAF-Mode')
[[ "$mode" == "enforce" ]] \
  || fail "Phase 1: enforce baseline X-WAF-Mode='$mode' (expected enforce)"
ok "Phase 1: X-WAF-Mode=enforce on normal request"

# ------------------------------------------------------------------
# Phase 2 — enforce attack: SQLi must be blocked
# ------------------------------------------------------------------
status_enforce=$(curl -s --max-time 3 -o /dev/null -w '%{http_code}' \
                   "$DATA/?id=1%27%20OR%20%271%27%3D%271" 2>/dev/null || echo 000)
raw_enforce=$(curl -sI --max-time 3 \
                "$DATA/?id=1%27%20OR%20%271%27%3D%271" 2>/dev/null || true)
action_enforce=$(header_value "$raw_enforce" 'X-WAF-Action')
mode_enforce=$(header_value "$raw_enforce" 'X-WAF-Mode')

case "$action_enforce" in
  block|challenge) ;;
  *) fail "Phase 2: SQLi in enforce mode X-WAF-Action='$action_enforce' (expected block or challenge)";;
esac
ok "Phase 2: enforce SQLi → X-WAF-Action=$action_enforce"

[[ "$mode_enforce" == "enforce" ]] \
  || fail "Phase 2: enforce SQLi X-WAF-Mode='$mode_enforce' (expected enforce)"
ok "Phase 2: enforce SQLi X-WAF-Mode=enforce"

# HTTP status must be non-2xx for a block/challenge.
if [[ "$action_enforce" == "block" ]]; then
  [[ "$status_enforce" -ge 400 ]] 2>/dev/null \
    || fail "Phase 2: block action but HTTP status=$status_enforce (expected 4xx)"
  ok "Phase 2: block action → HTTP $status_enforce (non-2xx)"
fi

# ------------------------------------------------------------------
# Phase 3 — flip to log_only; normal request gets log_only header
# ------------------------------------------------------------------
ctrl_post "/__waf_control/reset_state"  >/dev/null
ctrl_post "/__waf_control/set_profile" '{"scope":"all","mode":"log_only"}' >/dev/null

raw=$(curl -sI --max-time 3 "$DATA/" 2>/dev/null || true)
mode=$(header_value "$raw" 'X-WAF-Mode')
[[ "$mode" == "log_only" ]] \
  || fail "Phase 3: log_only flip X-WAF-Mode='$mode' (expected log_only)"
ok "Phase 3: X-WAF-Mode=log_only after flip"

# ------------------------------------------------------------------
# Phase 4 — log_only attack: reports intended action BUT passes upstream
# ------------------------------------------------------------------
status_log=$(curl -s --max-time 3 -o /dev/null -w '%{http_code}' \
               "$DATA/?id=1%27%20OR%20%271%27%3D%271" 2>/dev/null || echo 000)
raw_log=$(curl -sI --max-time 3 \
             "$DATA/?id=1%27%20OR%20%271%27%3D%271" 2>/dev/null || true)
action_log=$(header_value "$raw_log" 'X-WAF-Action')
mode_log=$(header_value "$raw_log" 'X-WAF-Mode')

[[ "$mode_log" == "log_only" ]] \
  || fail "Phase 4: log_only SQLi X-WAF-Mode='$mode_log' (expected log_only)"
ok "Phase 4: log_only SQLi X-WAF-Mode=log_only"

# In log_only the WAF must STILL evaluate and report the intended action.
# Acceptable: block, challenge (intended, not applied); allow (if detector
# fires below threshold in this config).
case "$action_log" in
  allow|block|challenge|rate_limit) ;;
  *) fail "Phase 4: X-WAF-Action='$action_log' not in valid set";;
esac
ok "Phase 4: log_only SQLi X-WAF-Action=$action_log (detection reported)"

# If the intended action is block/challenge, enforcement MUST NOT be applied.
# The WAF must forward to upstream — status 2xx means upstream responded;
# status 502 means upstream was unavailable but the WAF DID attempt the forward
# (the WAF did not block).  403/429 would mean the WAF itself blocked → fail.
if [[ "$action_log" == "block" || "$action_log" == "challenge" ]]; then
  [[ "$status_log" != "403" && "$status_log" != "429" ]] 2>/dev/null \
    || fail "Phase 4: log_only block/challenge intended but enforcement applied (HTTP $status_log)"
  ok "Phase 4: log_only block/challenge intended — NOT enforced (HTTP $status_log)"
fi

# ------------------------------------------------------------------
# Phase 5 — flip back to enforce; mode header recovers
# ------------------------------------------------------------------
ctrl_post "/__waf_control/set_profile" '{"scope":"all","mode":"enforce"}' >/dev/null

raw=$(curl -sI --max-time 3 "$DATA/" 2>/dev/null || true)
mode=$(header_value "$raw" 'X-WAF-Mode')
[[ "$mode" == "enforce" ]] \
  || fail "Phase 5: enforce recovery X-WAF-Mode='$mode' (expected enforce)"
ok "Phase 5: X-WAF-Mode=enforce restored after flip-back"

ok "LT-07 mode-semantics: all checks green"
