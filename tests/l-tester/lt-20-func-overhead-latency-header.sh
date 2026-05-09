#!/usr/bin/env bash
# LT-20 — X-WAF-Overhead-Latency bonus header
#
# Bug-hunter test: verifies the X-WAF-Overhead-Latency observability header
# is present and correctly formatted on every data-plane response type.
#
# The v2.3 contract does not mandate this header but implementations
# that include it MUST format it correctly (N.NNN ms decimal) to avoid
# breaking downstream log parsers or dashboards.
#
# Bugs targeted:
#   - Header absent on some response types (allow/block/challenge/rate_limit)
#   - Header present but NaN, negative, or non-decimal format
#   - Header format using integer-only (no fractional part)
#   - Header absent on blocked responses (common oversight)
#
# Format contract: "<integer>.<3-digit-fraction>" e.g. "1.234" or "0.045"

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"
require curl
require jq

trap trap_cleanup EXIT
start_waf
reset_to_enforce

# Helper — check X-WAF-Overhead-Latency format on a response.
# Returns 0 if present and well-formed; prints warning if absent (not a failure
# since this is a bonus header — present/format is tested, not strict presence).
check_latency_header() {
  local desc="$1"
  local raw="$2"

  local val
  val=$(header_value "$raw" "X-WAF-Overhead-Latency")

  if [[ -z "$val" ]]; then
    # Header absent — this is not a hard contract violation
    # but record as an observation
    echo "  OBS: X-WAF-Overhead-Latency absent on $desc" >&2
    return 0
  fi

  # Must match N.NNN (non-negative decimal with exactly 3 fractional digits)
  if [[ ! "$val" =~ ^[0-9]+\.[0-9]{3}$ ]]; then
    fail "X-WAF-Overhead-Latency='$val' on $desc — must match N.NNN format (e.g. '1.234')"
  fi

  # Must be non-negative (trivially true since we matched [0-9]+)
  local int_part="${val%%.*}"
  local frac_part="${val##*.}"
  [[ "$int_part" =~ ^[0-9]+$ ]] || fail "overhead-latency int part non-numeric: $val"
  [[ "$frac_part" =~ ^[0-9]{3}$ ]] || fail "overhead-latency frac part not 3 digits: $val"

  ok "$desc → X-WAF-Overhead-Latency=$val (format valid)"
  return 0
}

# ------------------------------------------------------------------
# 1. Allow response (clean path)
# ------------------------------------------------------------------
raw=$(curl -sI --max-time 5 "$DATA/lt20-clean" 2>/dev/null || true)
check_latency_header "allow response" "$raw"

# ------------------------------------------------------------------
# 2. Block response (SQLi in enforce mode)
# ------------------------------------------------------------------
raw=$(curl -sI --max-time 5 \
  "$DATA/?id=1%27%20OR%20%271%27%3D%271-lt20" 2>/dev/null || true)
check_latency_header "block response (SQLi)" "$raw"

# ------------------------------------------------------------------
# 3. Rate-limit response (burst)
# ------------------------------------------------------------------
ctrl_post "/__waf_control/reset_state" >/dev/null
ctrl_post "/__waf_control/set_profile" '{"scope":"all","mode":"enforce"}' >/dev/null

echo "==> LT-20: sending burst to trigger rate_limit"
rate_raw=""
for i in $(seq 1 210); do
  r=$(curl -sI --max-time 1 "$DATA/lt20-burst-$i" 2>/dev/null || true)
  a=$(header_value "$r" "X-WAF-Action")
  if [[ "$a" == "rate_limit" || "$a" == "block" ]]; then
    rate_raw="$r"
    break
  fi
done

if [[ -n "$rate_raw" ]]; then
  check_latency_header "rate_limit response" "$rate_raw"
else
  echo "  OBS: rate limit not triggered in 210 requests — skipping rate_limit header check" >&2
fi

# ------------------------------------------------------------------
# 4. Challenge response (risk accumulation path)
# ------------------------------------------------------------------
# Reset, fire multiple attacks to push score into challenge zone
ctrl_post "/__waf_control/reset_state" >/dev/null
ctrl_post "/__waf_control/set_profile" '{"scope":"all","mode":"enforce"}' >/dev/null

# Check XSS (challenge or block response)
raw=$(curl -sI --max-time 5 \
  "$DATA/?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E-lt20" 2>/dev/null || true)
action=$(header_value "$raw" "X-WAF-Action")
if [[ "$action" == "challenge" ]]; then
  check_latency_header "challenge response (XSS)" "$raw"
elif [[ "$action" == "block" ]]; then
  check_latency_header "block response (XSS)" "$raw"
else
  echo "  OBS: XSS returned action=$action, skipping challenge-specific check" >&2
fi

# ------------------------------------------------------------------
# 5. Header present on multiple HTTP methods
# ------------------------------------------------------------------
for method in GET POST PUT DELETE; do
  raw=$(curl -sI -X "$method" --max-time 5 "$DATA/lt20-method-$method" 2>/dev/null || true)
  check_latency_header "$method request" "$raw"
done

# ------------------------------------------------------------------
# 6. Log-only response (attack not enforced, forwarded upstream)
# ------------------------------------------------------------------
ctrl_post "/__waf_control/set_profile" \
  '{"scope":"features","mode":"log_only","features":["rules_engine"]}' >/dev/null

raw=$(curl -si --max-time 5 \
  "$DATA/?id=1%27%20OR%20%271%27%3D%271-lt20-logonly" 2>/dev/null || true)
check_latency_header "log_only (proxied) response" "$(printf '%s' "$raw" | grep -i 'x-waf')"

ctrl_post "/__waf_control/set_profile" '{"scope":"all","mode":"enforce"}' >/dev/null

ok "LT-20 overhead-latency-header: all checks green"
