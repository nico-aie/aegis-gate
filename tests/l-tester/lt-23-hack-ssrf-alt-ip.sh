#!/usr/bin/env bash
# LT-23 — Hacker: SSRF via alternate IP representations
#
# Attacker perspective: WAF SSRF detectors typically match dotted-decimal
# notation (127.0.0.1, 10.x.x.x, etc.).  Many implementations miss
# non-standard but equally valid representations of the same addresses:
#
#   Decimal integer:  127.0.0.1  == 2130706433
#   Hex:              127.0.0.1  == 0x7f000001
#   Octal:            127.0.0.1  == 0177.0.0.1
#   IPv6 loopback:    127.0.0.1  == ::1  or  ::ffff:127.0.0.1
#   All-zeros:        0.0.0.0     (binds to all interfaces on Linux)
#   Cloud metadata decimal: 169.254.169.254 == 2852039166
#
# Each check uses a parameter name ("ssrf_fetch") that does NOT appear
# in the open_redirect pattern, so we validate the SSRF detector fires
# (not the open_redirect detector).  We also reset WAF state before each
# check to prevent risk-score accumulation from masking true bypasses.
#
# Bugs targeted:
#   - Decimal integer notation not detected by SSRF detector
#   - Hex notation not detected
#   - Octal notation not detected
#   - IPv6 loopback not detected
#   - 0.0.0.0 not detected
#   - ::ffff:127.0.0.1 (IPv4-mapped IPv6) not detected
#
# Contract reference: §3.1 — SSRF threats must be detected regardless
# of the IP representation used in the payload.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"
require curl

trap trap_cleanup EXIT
start_waf
reset_to_enforce

# check_ssrf: reset state, fire request, verify rule_id=ssrf (not open_redirect)
check_ssrf_blocked() {
  local desc="$1" url="$2"

  # Reset risk scores between checks to avoid false-positive "challenge" actions
  ctrl_post "/__waf_control/reset_state" >/dev/null
  ctrl_post "/__waf_control/set_profile" '{"scope":"all","mode":"enforce"}' >/dev/null

  raw=$(curl -sI --max-time 5 "$url" 2>/dev/null || true)
  action=$(header_value "$raw" "X-WAF-Action")
  rule_id=$(header_value "$raw" "X-WAF-Rule-Id")

  if [[ "$action" == "allow" || -z "$action" ]]; then
    fail "$desc → BYPASS: SSRF not detected (action='$action', rule_id='$rule_id')"
  fi
  # Verify the ssrf detector fired (not open_redirect or generic block)
  if [[ "$rule_id" != "ssrf" ]]; then
    fail "$desc → MISCLASSIFIED: action=$action but rule_id='$rule_id' (expected 'ssrf')"
  fi
  ok "$desc → action=$action rule_id=$rule_id ✓"
}

# ------------------------------------------------------------------
# 1. Baseline: standard 127.0.0.1 SSRF (sanity check)
#    Uses "ssrf_fetch" param (not "url") to avoid open_redirect detector
# ------------------------------------------------------------------
check_ssrf_blocked \
  "Baseline SSRF: http://127.0.0.1/internal" \
  "$DATA/?ssrf_fetch=http%3A%2F%2F127.0.0.1%2Finternal"

# ------------------------------------------------------------------
# 2. Decimal integer representation: 2130706433 == 127.0.0.1
# ------------------------------------------------------------------
check_ssrf_blocked \
  "SSRF decimal IP: http://2130706433/" \
  "$DATA/?ssrf_fetch=http%3A%2F%2F2130706433%2Finternal-lt23"

# ------------------------------------------------------------------
# 3. Hex representation: 0x7f000001 == 127.0.0.1
# ------------------------------------------------------------------
check_ssrf_blocked \
  "SSRF hex IP: http://0x7f000001/" \
  "$DATA/?ssrf_fetch=http%3A%2F%2F0x7f000001%2Finternal-lt23"

# ------------------------------------------------------------------
# 4. Octal representation: 0177.0.0.1 == 127.0.0.1
# ------------------------------------------------------------------
check_ssrf_blocked \
  "SSRF octal IP: http://0177.0.0.1/" \
  "$DATA/?ssrf_fetch=http%3A%2F%2F0177.0.0.1%2Finternal-lt23"

# ------------------------------------------------------------------
# 5. IPv6 loopback: http://[::1]/
# ------------------------------------------------------------------
check_ssrf_blocked \
  "SSRF IPv6 loopback: http://[::1]/" \
  "$DATA/?ssrf_fetch=http%3A%2F%2F%5B%3A%3A1%5D%2Finternal-lt23"

# ------------------------------------------------------------------
# 6. 0.0.0.0 — binds to all interfaces, routes to loopback
# ------------------------------------------------------------------
check_ssrf_blocked \
  "SSRF 0.0.0.0: http://0.0.0.0/" \
  "$DATA/?ssrf_fetch=http%3A%2F%2F0.0.0.0%2Finternal-lt23"

# ------------------------------------------------------------------
# 7. IPv4-mapped IPv6: ::ffff:127.0.0.1
# ------------------------------------------------------------------
check_ssrf_blocked \
  "SSRF IPv4-mapped IPv6: http://[::ffff:127.0.0.1]/" \
  "$DATA/?ssrf_fetch=http%3A%2F%2F%5B%3A%3Affff%3A127.0.0.1%5D%2F-lt23"

# ------------------------------------------------------------------
# 8. Short decimal without trailing slash
# ------------------------------------------------------------------
check_ssrf_blocked \
  "SSRF decimal IP no trailing slash" \
  "$DATA/?ssrf_fetch=http%3A%2F%2F2130706433"

# ------------------------------------------------------------------
# 9. Cloud metadata endpoint via decimal: 2852039166 == 169.254.169.254
# ------------------------------------------------------------------
check_ssrf_blocked \
  "SSRF cloud metadata decimal: http://2852039166/" \
  "$DATA/?ssrf_fetch=http%3A%2F%2F2852039166%2Flatest%2Fmeta-data-lt23"

# ------------------------------------------------------------------
# 10. Open-redirect parameter with standard IP — verify rule_id=ssrf
#     The SSRF detector should fire BEFORE the open_redirect detector
#     since SSRF is checked first in the detection pipeline.
# ------------------------------------------------------------------
ctrl_post "/__waf_control/reset_state" >/dev/null
ctrl_post "/__waf_control/set_profile" '{"scope":"all","mode":"enforce"}' >/dev/null
raw=$(curl -sI --max-time 5 "$DATA/?url=http%3A%2F%2F127.0.0.1%2Finternal-lt23-order" 2>/dev/null || true)
action=$(header_value "$raw" "X-WAF-Action")
rule_id=$(header_value "$raw" "X-WAF-Rule-Id")
[[ "$action" != "allow" && -n "$action" ]] \
  || fail "Detector-order check: 127.0.0.1 via ?url= not detected at all"
[[ "$rule_id" == "ssrf" ]] \
  || fail "Detector-order: ?url=http://127.0.0.1 → rule_id='$rule_id' (expected 'ssrf' — SSRF must be checked before open_redirect)"
ok "Detector-order: ?url=http://127.0.0.1 → action=$action rule_id=ssrf ✓"

ok "LT-23 hack-ssrf-alt-ip: all checks complete"
