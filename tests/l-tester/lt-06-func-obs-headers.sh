#!/usr/bin/env bash
# LT-06 — §5.1 / §5.3  Mandatory observability headers on every response
#
# Contract (§5.1):
#   Every HTTP response through the WAF MUST carry all six headers:
#     X-WAF-Request-Id  — UUID v4
#     X-WAF-Risk-Score  — integer 0–100, no whitespace
#     X-WAF-Action      — allow|block|challenge|rate_limit|timeout|circuit_breaker
#     X-WAF-Rule-Id     — alphanumeric+hyphens or "none"
#     X-WAF-Cache       — HIT|MISS|BYPASS (uppercase)
#     X-WAF-Mode        — enforce|log_only (lowercase)
#
# The requirement applies to ALL decision types, not just allowed responses.
# We test:
#   A. 50 normal (expected-allow) requests — headers + value sets
#   B. A blocked (SQLi) request — headers present on block response too
#   C. Header precision: X-WAF-Rule-Id must be "none" or a valid identifier
#   D. §5.3 consistency: X-WAF-Cache MUST be BYPASS on the /login path

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"
require curl

trap trap_cleanup EXIT
start_waf
reset_to_enforce

# ------------------------------------------------------------------
# A. 50 normal requests — all six headers, correct value sets
# ------------------------------------------------------------------
echo "==> §5.1 sampling 50 normal responses"
fails=0

for i in $(seq 1 50); do
  raw=$(curl -sI --max-time 3 "$DATA/lt06-sample-$i" 2>/dev/null || true)

  # Presence check
  for h in X-WAF-Request-Id X-WAF-Risk-Score X-WAF-Action \
           X-WAF-Rule-Id X-WAF-Cache X-WAF-Mode; do
    if ! assert_header_present "$raw" "$h"; then
      printf '  FAIL: response %d missing %s\n' "$i" "$h" >&2
      fails=$((fails + 1))
    fi
  done

  # X-WAF-Action value set
  action=$(header_value "$raw" 'X-WAF-Action')
  case "$action" in
    allow|block|challenge|rate_limit|timeout|circuit_breaker) ;;
    *) printf '  FAIL: response %d X-WAF-Action="%s" not in spec set\n' "$i" "$action" >&2
       fails=$((fails + 1));;
  esac

  # X-WAF-Cache uppercase exact set
  cache=$(header_value "$raw" 'X-WAF-Cache')
  case "$cache" in
    HIT|MISS|BYPASS) ;;
    *) printf '  FAIL: response %d X-WAF-Cache="%s" must be HIT|MISS|BYPASS\n' "$i" "$cache" >&2
       fails=$((fails + 1));;
  esac

  # X-WAF-Mode lowercase exact set
  mode=$(header_value "$raw" 'X-WAF-Mode')
  case "$mode" in
    enforce|log_only) ;;
    *) printf '  FAIL: response %d X-WAF-Mode="%s" must be enforce|log_only\n' "$i" "$mode" >&2
       fails=$((fails + 1));;
  esac

  # X-WAF-Risk-Score: plain integer 0–100
  score=$(header_value "$raw" 'X-WAF-Risk-Score')
  if ! [[ "$score" =~ ^[0-9]+$ ]] || (( score < 0 || score > 100 )); then
    printf '  FAIL: response %d X-WAF-Risk-Score="%s" not integer 0..100\n' "$i" "$score" >&2
    fails=$((fails + 1))
  fi

  # X-WAF-Request-Id: UUID v4 shape
  rid=$(header_value "$raw" 'X-WAF-Request-Id')
  if ! uuid_valid "$rid"; then
    printf '  FAIL: response %d X-WAF-Request-Id="%s" not UUID v4\n' "$i" "$rid" >&2
    fails=$((fails + 1))
  fi

  # X-WAF-Rule-Id: alphanumeric + hyphens, or "none"
  rule_id=$(header_value "$raw" 'X-WAF-Rule-Id')
  if ! [[ "$rule_id" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    printf '  FAIL: response %d X-WAF-Rule-Id="%s" invalid chars\n' "$i" "$rule_id" >&2
    fails=$((fails + 1))
  fi
done

[[ "$fails" -eq 0 ]] \
  || fail "$fails header violation(s) across 50 normal responses"
ok "§5.1 all 6 headers valid across 50 normal responses"

# ------------------------------------------------------------------
# B. Headers present on a BLOCKED response (§5.3)
# ------------------------------------------------------------------
# SQLi payload (percent-encoded to avoid shell quoting issues)
raw_block=$(curl -sI --max-time 3 \
              "$DATA/?id=1%27%20OR%20%271%27%3D%271" 2>/dev/null || true)
block_fails=0
for h in X-WAF-Request-Id X-WAF-Risk-Score X-WAF-Action \
         X-WAF-Rule-Id X-WAF-Cache X-WAF-Mode; do
  if ! assert_header_present "$raw_block" "$h"; then
    echo "  FAIL: block response missing $h" >&2
    block_fails=$((block_fails + 1))
  fi
done
[[ "$block_fails" -eq 0 ]] \
  || fail "$block_fails headers missing from blocked response"
ok "§5.3 all 6 headers present on a blocked response"

# X-WAF-Action on the block response must be block or challenge (not allow)
block_action=$(header_value "$raw_block" 'X-WAF-Action')
case "$block_action" in
  block|challenge) ;;
  *) fail "§5.3 X-WAF-Action on SQLi request='$block_action'; expected block or challenge";;
esac
ok "§5.3 blocked response X-WAF-Action='$block_action' (correct)"

block_mode=$(header_value "$raw_block" 'X-WAF-Mode')
[[ "$block_mode" == "enforce" ]] \
  || fail "§5.3 blocked response X-WAF-Mode='$block_mode'; expected enforce"
ok "§5.3 blocked response X-WAF-Mode=enforce"

# ------------------------------------------------------------------
# C. X-WAF-Rule-Id must be "none" on a clean allow (no rule fired)
#    OR a valid identifier if a catch-all rule fires.
# ------------------------------------------------------------------
raw_clean=$(curl -sI --max-time 3 "$DATA/healthcheck" 2>/dev/null || true)
rule_id=$(header_value "$raw_clean" 'X-WAF-Rule-Id')
[[ -n "$rule_id" ]] \
  || fail "§5.1 X-WAF-Rule-Id absent on clean allow response"
if ! [[ "$rule_id" =~ ^[a-zA-Z0-9_-]+$ ]]; then
  fail "§5.1 X-WAF-Rule-Id='$rule_id' contains invalid characters"
fi
ok "§5.1 X-WAF-Rule-Id='$rule_id' on clean allow (valid format)"

# ------------------------------------------------------------------
# D. §5.3 / §9 — X-WAF-Cache MUST be BYPASS on the /login path
#    (authenticated / dynamic / sensitive route)
# ------------------------------------------------------------------
raw_login=$(curl -sI --max-time 3 "$DATA/login" 2>/dev/null || true)
cache_login=$(header_value "$raw_login" 'X-WAF-Cache')
[[ "$cache_login" == "BYPASS" ]] \
  || fail "§5.3/§9 /login X-WAF-Cache='$cache_login'; MUST be BYPASS (sensitive route)"
ok "§5.3/§9 /login X-WAF-Cache=BYPASS (sensitive route not cached)"

ok "LT-06 observability-headers: all checks green"
