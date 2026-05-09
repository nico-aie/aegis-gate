#!/usr/bin/env bash
# LT-11 — §9  Caching observability
#
# Contract (§9):
#   X-WAF-Cache MUST be present on every response (HIT / MISS / BYPASS).
#   Sensitive / authenticated / dynamic / high-risk routes SHOULD return BYPASS.
#   Static / cacheable routes MAY return MISS on first hit, HIT on repeat.
#   POST /__waf_control/flush_cache MUST clear cache before returning success.
#
# Paths tested as sensitive (must BYPASS):
#   /login            — authentication endpoint
#   /admin            — admin panel
#   /account/profile  — user-specific dynamic
#   /checkout         — payment / sensitive
#   /api/token        — token endpoint
#   A request that carries Authorization header (by convention, sensitive).
#
# Paths tested as potentially cacheable (static-like):
#   /static/logo.png, /favicon.ico, /robots.txt
#   (these may be proxied or handled internally; if the WAF sees them
#    and decides to cache, HIT must follow MISS after a repeat call)

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"
require curl

trap trap_cleanup EXIT
start_waf
reset_to_enforce

check_cache() {
  local desc="$1" url="$2" expected="$3"
  raw=$(curl -sI --max-time 3 "$url" 2>/dev/null || true)
  cache=$(header_value "$raw" 'X-WAF-Cache')
  # For BYPASS expectation: must be BYPASS (not HIT, not MISS)
  if [[ "$expected" == "BYPASS" ]]; then
    [[ "$cache" == "BYPASS" ]] \
      || fail "§9 $desc X-WAF-Cache='$cache' (expected BYPASS)"
    ok "§9 $desc → X-WAF-Cache=BYPASS (sensitive route not cached)"
  elif [[ "$expected" == "MISS_OR_HIT" ]]; then
    case "$cache" in
      HIT|MISS|BYPASS) ok "§9 $desc → X-WAF-Cache=$cache (cacheable route)";;
      *) fail "§9 $desc X-WAF-Cache='$cache' not in {HIT,MISS,BYPASS}";;
    esac
  fi
}

# ------------------------------------------------------------------
# A. Sensitive routes — MUST return BYPASS
# ------------------------------------------------------------------
for path in /login /admin /account/profile /checkout /api/token /api/user/me; do
  check_cache "$path (sensitive)" "$DATA$path" "BYPASS"
done

# Requests carrying Authorization header must be BYPASS.
raw_auth=$(curl -sI --max-time 3 \
             -H 'Authorization: Bearer test-token' \
             "$DATA/protected" 2>/dev/null || true)
cache_auth=$(header_value "$raw_auth" 'X-WAF-Cache')
[[ "$cache_auth" == "BYPASS" ]] \
  || fail "§9 /protected with Authorization: Bearer → X-WAF-Cache='$cache_auth' (expected BYPASS)"
ok "§9 /protected with Authorization header → X-WAF-Cache=BYPASS"

# High-risk: a request that triggered a WAF action should be BYPASS.
raw_risk=$(curl -sI --max-time 3 \
             "$DATA/?id=1%27%20OR%20%271%27%3D%271" 2>/dev/null || true)
cache_risk=$(header_value "$raw_risk" 'X-WAF-Cache')
[[ "$cache_risk" == "BYPASS" ]] \
  || fail "§9 high-risk blocked request → X-WAF-Cache='$cache_risk' (expected BYPASS)"
ok "§9 high-risk (blocked) request → X-WAF-Cache=BYPASS"

# ------------------------------------------------------------------
# B. X-WAF-Cache must always be one of the three allowed values
#    (tested across 20 diverse routes)
# ------------------------------------------------------------------
cache_fail=0
for i in $(seq 1 20); do
  raw=$(curl -sI --max-time 3 "$DATA/lt11-route-$i" 2>/dev/null || true)
  cache=$(header_value "$raw" 'X-WAF-Cache')
  case "$cache" in
    HIT|MISS|BYPASS) ;;
    *) echo "  FAIL: route $i X-WAF-Cache='$cache' not in {HIT,MISS,BYPASS}" >&2
       cache_fail=$((cache_fail + 1));;
  esac
done
[[ "$cache_fail" -eq 0 ]] \
  || fail "§9 $cache_fail X-WAF-Cache value violation(s) across 20 routes"
ok "§9 X-WAF-Cache in {HIT,MISS,BYPASS} across 20 diverse routes"

# ------------------------------------------------------------------
# C. Static route: MISS → HIT lifecycle (if caching implemented)
# ------------------------------------------------------------------
# Prime the cache.
curl -s --max-time 3 -o /dev/null "$DATA/static/logo.png" || true
raw1=$(curl -sI --max-time 3 "$DATA/static/logo.png" 2>/dev/null || true)
cache1=$(header_value "$raw1" 'X-WAF-Cache')

raw2=$(curl -sI --max-time 3 "$DATA/static/logo.png" 2>/dev/null || true)
cache2=$(header_value "$raw2" 'X-WAF-Cache')

if [[ "$cache1" == "MISS" && "$cache2" == "HIT" ]]; then
  ok "§9 static route: MISS → HIT (cache implemented correctly)"
elif [[ "$cache1" == "BYPASS" && "$cache2" == "BYPASS" ]]; then
  ok "§9 static route: BYPASS (no caching for static, compliant)"
else
  ok "§9 static route: first=$cache1 second=$cache2 (observing behavior)"
fi

# ------------------------------------------------------------------
# D. flush_cache produces MISS on a previously HIT route
# ------------------------------------------------------------------
if [[ "$cache2" == "HIT" ]]; then
  # We have a HIT; flush and re-check.
  curl -s --max-time 5 -X POST \
       -H "X-Benchmark-Secret: $SECRET" \
       -o /dev/null "$ADMIN/__waf_control/flush_cache" || true

  raw3=$(curl -sI --max-time 3 "$DATA/static/logo.png" 2>/dev/null || true)
  cache3=$(header_value "$raw3" 'X-WAF-Cache')
  [[ "$cache3" == "MISS" ]] \
    || fail "§9 after flush_cache, static route returned $cache3 (expected MISS)"
  ok "§9 flush_cache: HIT → MISS after flush"
else
  ok "§9 SKIP post-flush MISS check (route was not HIT before flush)"
fi

ok "LT-11 caching: all checks green"
