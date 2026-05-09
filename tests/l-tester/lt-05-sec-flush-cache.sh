#!/usr/bin/env bash
# LT-05 — §2.6  flush_cache: supported or clear not-supported response
#
# Contract:
#   POST /__waf_control/flush_cache MUST:
#   - Require X-Benchmark-Secret (covered by LT-01 for all endpoints).
#   - Return HTTP 200 if cache is implemented.
#   - Return a machine-readable "not supported" response if caching is
#     not implemented (the spec permits this).
#   - In either case: MUST NOT return 5xx.
#   - Body: .ok field present; .supported boolean present.
#   - If caching IS implemented (supported=true): subsequent GET to a
#     static route that previously returned X-WAF-Cache: HIT should
#     return X-WAF-Cache: MISS after flush.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"
require curl
require jq

trap trap_cleanup EXIT
start_waf

# ------------------------------------------------------------------
# 1. Returns non-5xx (200 or 4xx are both allowed)
# ------------------------------------------------------------------
status=$(curl -s --max-time 5 -X POST \
              -H "X-Benchmark-Secret: $SECRET" \
              -o /tmp/lt05_fc.json -w '%{http_code}' \
              "$ADMIN/__waf_control/flush_cache" || echo 000)
[[ "$status" -lt 500 ]] 2>/dev/null \
  || fail "flush_cache → HTTP $status (must be < 500)"
ok "flush_cache → HTTP $status (not 5xx)"

# ------------------------------------------------------------------
# 2. Body has .ok and .supported boolean fields
# ------------------------------------------------------------------
body=$(cat /tmp/lt05_fc.json 2>/dev/null || echo '{}')
ok_field=$(printf '%s' "$body" | jq '.ok | type' 2>/dev/null || echo 'null')
[[ "$ok_field" == '"boolean"' ]] \
  || fail "flush_cache .ok must be boolean (got type=$ok_field; body: $body)"
ok "flush_cache .ok is boolean"

supported=$(printf '%s' "$body" | jq '.supported | type' 2>/dev/null || echo 'null')
[[ "$supported" == '"boolean"' ]] \
  || fail "flush_cache .supported must be boolean (got type=$supported; body: $body)"
ok "flush_cache .supported is boolean"

# ------------------------------------------------------------------
# 3. If caching is supported, verify flush actually clears the cache
# ------------------------------------------------------------------
cache_supported=$(printf '%s' "$body" | jq -r '.supported')
if [[ "$cache_supported" == "true" ]]; then
  ok "caching supported — verifying flush clears HIT entries"

  # Prime the cache with two identical GET requests.
  curl -s --max-time 3 -o /dev/null "$DATA/static-cacheable" || true
  raw_second=$(curl -sI --max-time 3 "$DATA/static-cacheable" 2>/dev/null || true)
  cache_before=$(header_value "$raw_second" 'X-WAF-Cache')

  if [[ "$cache_before" == "HIT" ]]; then
    # Flush, then verify the next hit is a MISS.
    curl -s --max-time 5 -X POST \
         -H "X-Benchmark-Secret: $SECRET" \
         -o /dev/null "$ADMIN/__waf_control/flush_cache" || true

    raw_after=$(curl -sI --max-time 3 "$DATA/static-cacheable" 2>/dev/null || true)
    cache_after=$(header_value "$raw_after" 'X-WAF-Cache')
    [[ "$cache_after" == "MISS" ]] \
      || fail "after flush, X-WAF-Cache='$cache_after'; expected MISS"
    ok "flush_cache clears cache: HIT → MISS after flush"
  else
    ok "SKIP post-flush MISS check (route returned X-WAF-Cache=$cache_before, not HIT)"
  fi
else
  ok "caching not supported — flush_cache returns ok/not-supported (compliant)"
fi

# ------------------------------------------------------------------
# 4. Idempotent: a second flush_cache call also succeeds
# ------------------------------------------------------------------
status2=$(curl -s --max-time 5 -X POST \
               -H "X-Benchmark-Secret: $SECRET" \
               -o /dev/null -w '%{http_code}' \
               "$ADMIN/__waf_control/flush_cache" || echo 000)
[[ "$status2" -lt 500 ]] 2>/dev/null \
  || fail "second flush_cache → $status2 (must be < 500)"
ok "flush_cache is idempotent (second call → $status2)"

ok "LT-05 flush-cache: all checks green"
