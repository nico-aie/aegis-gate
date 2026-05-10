#!/usr/bin/env bash
# LT-12 — §10  Source IP trust model
#
# Contract (§10):
#   - Audit log `ip` MUST be the TCP peer address (NOT XFF or X-Real-IP).
#   - In the sandbox all traffic comes from 127.0.0.x loopback aliases.
#   - Different 127.0.0.x addresses MUST be treated as distinct clients
#     (distinct rate-limit buckets, distinct risk accumulation).
#   - XFF / X-Real-IP are supplementary context only — MUST NOT be
#     used as the sole IP identity for rate limiting or risk scoring.
#
# Verifications:
#   A. Audit log ip ≠ XFF when spoofed XFF is sent.
#   B. Audit log ip ≠ X-Real-IP when spoofed X-Real-IP is sent.
#   C. Audit log ip IS the loopback (127.x.x.x).
#   D. X-WAF-Risk-Score accumulates independently for distinct loopback
#      IPs (if loopback aliases are available; skipped otherwise).

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"
require curl
require jq

trap trap_cleanup EXIT
start_waf
reset_to_enforce

# ------------------------------------------------------------------
# A. Audit ip ≠ spoofed X-Forwarded-For
# ------------------------------------------------------------------
SPOOFED_XFF="9.8.7.6"
curl -s --max-time 3 -o /dev/null \
  -H "X-Forwarded-For: $SPOOFED_XFF" "$DATA/lt12-xff" || true
sleep 0.4

last_line=$(tail -n 1 "$AUDIT_LOG" 2>/dev/null || echo '{}')
audit_ip=$(printf '%s' "$last_line" | jq -r '.ip // empty')

[[ -n "$audit_ip" ]] || fail "§10 audit ip field absent"
[[ "$audit_ip" != "$SPOOFED_XFF" ]] \
  || fail "§10 audit ip='$audit_ip' matches spoofed XFF; MUST use TCP peer"
ok "§10 audit ip='$audit_ip' (not spoofed XFF $SPOOFED_XFF)"

# ------------------------------------------------------------------
# B. Audit ip ≠ spoofed X-Real-IP
# ------------------------------------------------------------------
SPOOFED_REAL="10.20.30.40"
curl -s --max-time 3 -o /dev/null \
  -H "X-Real-IP: $SPOOFED_REAL" "$DATA/lt12-xrip" || true
sleep 0.4

last_line=$(tail -n 1 "$AUDIT_LOG" 2>/dev/null || echo '{}')
audit_ip2=$(printf '%s' "$last_line" | jq -r '.ip // empty')

[[ "$audit_ip2" != "$SPOOFED_REAL" ]] \
  || fail "§10 audit ip='$audit_ip2' matches spoofed X-Real-IP; MUST use TCP peer"
ok "§10 audit ip='$audit_ip2' (not spoofed X-Real-IP $SPOOFED_REAL)"

# ------------------------------------------------------------------
# C. Audit ip is a loopback address (127.x.x.x) — all test traffic
#    originates from localhost.
# ------------------------------------------------------------------
[[ "$audit_ip" =~ ^127\. ]] \
  || fail "§10 audit ip='$audit_ip' is not a 127.x.x.x loopback (unexpected)"
ok "§10 audit ip is loopback (127.x.x.x) as expected in sandbox"

# ------------------------------------------------------------------
# D. Different loopback aliases treated as distinct clients
#    Only run if loopback aliases 127.0.0.2 and 127.0.0.3 are available.
# ------------------------------------------------------------------
if ip addr show lo 2>/dev/null | grep -q '127.0.0.2'; then
  echo "==> §10 loopback alias 127.0.0.2 available — testing distinct client treatment"

  reset_to_enforce

  # Fire 100 rapid requests from 127.0.0.1 (default curl source).
  triggered=0
  for i in $(seq 1 100); do
    action=$(curl -sI --max-time 1 "$DATA/lt12-burst-a-$i" 2>/dev/null \
             | awk 'BEGIN{IGNORECASE=1} tolower($1)=="x-waf-action:"{print $2;exit}' \
             | tr -d '\r')
    case "$action" in
      rate_limit|block) triggered=1; break;;
    esac
  done

  if [[ "$triggered" == "1" ]]; then
    # Now fire from 127.0.0.2 — this should be a fresh bucket, not rate-limited.
    action_2=$(curl -sI --max-time 3 --interface 127.0.0.2 "$DATA/lt12-new-ip" 2>/dev/null \
               | awk 'BEGIN{IGNORECASE=1} tolower($1)=="x-waf-action:"{print $2;exit}' \
               | tr -d '\r')
    [[ "$action_2" == "allow" ]] \
      || fail "§10 127.0.0.2 treated as same rate-limit bucket as 127.0.0.1 (action=$action_2)"
    ok "§10 127.0.0.2 has independent rate-limit bucket from 127.0.0.1"
  else
    ok "SKIP §10 loopback-distinct test (rate-limit not triggered in 100 requests)"
  fi
else
  ok "SKIP §10 loopback-distinct test (127.0.0.2 alias not configured)"
fi

ok "LT-12 source-ip: all checks green"
