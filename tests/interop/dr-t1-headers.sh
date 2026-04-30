#!/usr/bin/env bash
# DR-T1 — every WAF response carries the six required X-WAF-*
# headers with values from the contract's exact value sets.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"
require curl

trap trap_cleanup EXIT
start_waf

# 1. Send 50 sample requests (mix of paths) and inspect headers.
echo "==> sampling 50 responses"
fails=0
for i in $(seq 1 50); do
  raw=$(curl -sI --max-time 3 "$DATA/path-$i" 2>/dev/null \
        || true)

  for h in x-waf-request-id x-waf-risk-score x-waf-action \
           x-waf-rule-id x-waf-cache x-waf-mode; do
    if ! printf '%s' "$raw" | awk 'BEGIN{IGNORECASE=1} tolower($1)==hh":" { found=1 } END{exit !found}' hh="$h"; then
      printf 'FAIL: response %d missing header %s\n' "$i" "$h"
      fails=$((fails + 1))
      break
    fi
  done

  # Validate value sets.
  action=$(printf '%s' "$raw" | awk 'BEGIN{IGNORECASE=1} tolower($1)=="x-waf-action:"{print $2; exit}' | tr -d '\r')
  case "$action" in
    allow|block|challenge|rate_limit|timeout|circuit_breaker) ;;
    *) printf 'FAIL: response %d X-WAF-Action=%s not in spec set\n' "$i" "$action"; fails=$((fails + 1));;
  esac

  cache=$(printf '%s' "$raw" | awk 'BEGIN{IGNORECASE=1} tolower($1)=="x-waf-cache:"{print $2; exit}' | tr -d '\r')
  case "$cache" in
    HIT|MISS|BYPASS) ;;
    *) printf 'FAIL: response %d X-WAF-Cache=%s not in spec set (must be uppercase)\n' "$i" "$cache"; fails=$((fails + 1));;
  esac

  mode=$(printf '%s' "$raw" | awk 'BEGIN{IGNORECASE=1} tolower($1)=="x-waf-mode:"{print $2; exit}' | tr -d '\r')
  case "$mode" in
    enforce|log_only) ;;
    *) printf 'FAIL: response %d X-WAF-Mode=%s not in spec set\n' "$i" "$mode"; fails=$((fails + 1));;
  esac

  score=$(printf '%s' "$raw" | awk 'BEGIN{IGNORECASE=1} tolower($1)=="x-waf-risk-score:"{print $2; exit}' | tr -d '\r')
  if ! [[ "$score" =~ ^[0-9]+$ ]] || (( score < 0 || score > 100 )); then
    printf 'FAIL: response %d X-WAF-Risk-Score=%s not in 0..100\n' "$i" "$score"
    fails=$((fails + 1))
  fi

  rid=$(printf '%s' "$raw" | awk 'BEGIN{IGNORECASE=1} tolower($1)=="x-waf-request-id:"{print $2; exit}' | tr -d '\r')
  if ! [[ "$rid" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
    printf 'FAIL: response %d X-WAF-Request-Id=%s not UUID-shaped\n' "$i" "$rid"
    fails=$((fails + 1))
  fi
done

if (( fails > 0 )); then
  echo "FAIL: $fails header violations across 50 responses"
  exit 1
fi
ok "all 6 X-WAF-* headers present and well-formed across 50 responses"
