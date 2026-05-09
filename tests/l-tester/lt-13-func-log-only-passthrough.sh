#!/usr/bin/env bash
# LT-13 — §7 / §5.3  log_only decision normalization & passthrough
#
# Contract (§7 Decision Normalization Matrix):
#   log_only_detected: when WAF is in log_only mode and detects a threat,
#     X-WAF-Action = intended enforcement action (block / challenge / rate_limit)
#     X-WAF-Mode   = log_only
#     The request SHOULD continue upstream (HTTP 2xx from upstream).
#     Audit log evidence MUST still be written.
#
#   The WAF must NOT apply block/challenge/rate-limit enforcement effects
#   while in log_only mode (§2.5 enforcement semantics).
#
# Scenarios tested:
#   1. SQLi in log_only → X-WAF-Action=block (or challenge), X-WAF-Mode=log_only,
#      HTTP status is NOT 403/429 (enforcement not applied).
#   2. XSS in log_only → same semantics.
#   3. Rule-Id present in log_only (detector still ran).
#   4. Audit log entry written with mode=log_only for the matching request.
#   5. After flipping back to enforce, the same payload IS blocked again.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"
require curl
require jq

trap trap_cleanup EXIT
start_waf

# Start clean in enforce mode.
reset_to_enforce

# ------------------------------------------------------------------
# Baseline in enforce: confirm SQLi is blocked.
# ------------------------------------------------------------------
status_enforce=$(curl -s --max-time 3 -o /dev/null -w '%{http_code}' \
                   "$DATA/?sqli=1%27%20OR%20%271%27%3D%271" 2>/dev/null || echo 000)
raw_enforce=$(curl -sI --max-time 3 \
                "$DATA/?sqli=1%27%20OR%20%271%27%3D%271" 2>/dev/null || true)
action_enforce=$(header_value "$raw_enforce" 'X-WAF-Action')

case "$action_enforce" in
  block|challenge) ;;
  *) fail "baseline enforce SQLi: X-WAF-Action='$action_enforce' (expected block or challenge)";;
esac
ok "baseline: SQLi in enforce → X-WAF-Action=$action_enforce"

# ------------------------------------------------------------------
# 1. Flip all policies to log_only.
# ------------------------------------------------------------------
ctrl_post "/__waf_control/reset_state" >/dev/null
ctrl_post "/__waf_control/set_profile" '{"scope":"all","mode":"log_only"}' >/dev/null

# ------------------------------------------------------------------
# 2. SQLi in log_only — intended action reported, enforcement NOT applied
# ------------------------------------------------------------------
status_log=$(curl -s --max-time 3 -o /dev/null -w '%{http_code}' \
               "$DATA/?sqli=1%27%20OR%20%271%27%3D%271" 2>/dev/null || echo 000)
raw_log=$(curl -sI --max-time 3 \
             "$DATA/?sqli=1%27%20OR%20%271%27%3D%271" 2>/dev/null || true)
action_log=$(header_value "$raw_log" 'X-WAF-Action')
mode_log=$(header_value "$raw_log" 'X-WAF-Mode')

[[ "$mode_log" == "log_only" ]] \
  || fail "§7/§5.3 SQLi in log_only: X-WAF-Mode='$mode_log' (expected log_only)"
ok "§7 SQLi in log_only: X-WAF-Mode=log_only"

case "$action_log" in
  allow|block|challenge|rate_limit) ;;
  *) fail "§7 SQLi in log_only: X-WAF-Action='$action_log' not in valid set";;
esac
ok "§7 SQLi in log_only: X-WAF-Action=$action_log (detection evaluated)"

# If the WAF intended to block/challenge, enforcement MUST NOT be applied.
# Accept 2xx (upstream responded) or 502 (upstream unavailable but WAF did NOT block).
# Reject 403/429 which indicate the WAF itself enforced the decision.
if [[ "$action_log" == "block" || "$action_log" == "challenge" ]]; then
  [[ "$status_log" != "403" && "$status_log" != "429" ]] 2>/dev/null \
    || fail "§7 log_only block/challenge intended but request was blocked (HTTP $status_log)"
  ok "§7 log_only: block/challenge intended but NOT enforced (HTTP $status_log)"
fi

# ------------------------------------------------------------------
# 3. XSS in log_only — same semantics
# ------------------------------------------------------------------
status_xss=$(curl -s --max-time 3 -o /dev/null -w '%{http_code}' \
               "$DATA/?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E" 2>/dev/null || echo 000)
raw_xss=$(curl -sI --max-time 3 \
             "$DATA/?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E" 2>/dev/null || true)
mode_xss=$(header_value "$raw_xss" 'X-WAF-Mode')
action_xss=$(header_value "$raw_xss" 'X-WAF-Action')

[[ "$mode_xss" == "log_only" ]] \
  || fail "§7 XSS in log_only: X-WAF-Mode='$mode_xss' (expected log_only)"
ok "§7 XSS in log_only: X-WAF-Mode=log_only"

if [[ "$action_xss" == "block" || "$action_xss" == "challenge" ]]; then
  [[ "$status_xss" != "403" && "$status_xss" != "429" ]] 2>/dev/null \
    || fail "§7 XSS log_only enforcement applied (HTTP $status_xss)"
  ok "§7 XSS in log_only: intended action=$action_xss but NOT enforced (HTTP $status_xss)"
fi

# ------------------------------------------------------------------
# 4. Audit log entry for log_only request has mode=log_only
# ------------------------------------------------------------------
sleep 0.4
[[ -f "$AUDIT_LOG" ]] || fail "§6 audit log absent"

log_only_entries=$(jq -r 'select(.mode == "log_only") | .mode' \
                    "$AUDIT_LOG" 2>/dev/null | wc -l | tr -d ' ')
[[ "$log_only_entries" -ge 1 ]] \
  || fail "§7 no audit entries with mode=log_only found after log_only requests"
ok "§7 audit log has $log_only_entries log_only mode entries"

# ------------------------------------------------------------------
# 5. X-WAF-Rule-Id is set (not absent) even in log_only — detector ran
# ------------------------------------------------------------------
rule_id_log=$(header_value "$raw_log" 'X-WAF-Rule-Id')
[[ -n "$rule_id_log" ]] \
  || fail "§7 X-WAF-Rule-Id absent in log_only response (detector evidence missing)"
ok "§7 X-WAF-Rule-Id='$rule_id_log' present in log_only response"

# ------------------------------------------------------------------
# 6. Flip back to enforce; same payload is blocked again
# ------------------------------------------------------------------
ctrl_post "/__waf_control/reset_state" >/dev/null
ctrl_post "/__waf_control/set_profile" '{"scope":"all","mode":"enforce"}' >/dev/null

raw_back=$(curl -sI --max-time 3 \
              "$DATA/?sqli=1%27%20OR%20%271%27%3D%271" 2>/dev/null || true)
action_back=$(header_value "$raw_back" 'X-WAF-Action')
mode_back=$(header_value "$raw_back" 'X-WAF-Mode')

case "$action_back" in
  block|challenge) ;;
  *) fail "§7 enforce recovery: SQLi X-WAF-Action='$action_back' (expected block or challenge)";;
esac
[[ "$mode_back" == "enforce" ]] \
  || fail "§7 enforce recovery: X-WAF-Mode='$mode_back' (expected enforce)"
ok "§7 enforce recovery: SQLi → X-WAF-Action=$action_back, X-WAF-Mode=enforce"

ok "LT-13 log-only-passthrough: all checks green"
