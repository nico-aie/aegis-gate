#!/usr/bin/env bash
# LT-01 — §2.2  Control-plane authentication
#
# Contract: every /__waf_control/* endpoint MUST reject requests with
# a missing or incorrect X-Benchmark-Secret with HTTP 403.
# A correct secret MUST be accepted (2xx).
#
# Negative cases (must 403):
#   1. No X-Benchmark-Secret header
#   2. Empty X-Benchmark-Secret header
#   3. Wrong X-Benchmark-Secret value
#   4. Secret in query-string instead of header (wrong placement)
#   5. Correct secret sent to POST endpoints (reset_state, set_profile)
#      with wrong secret → 403
#
# Positive case:
#   6. Correct secret → capabilities returns 200

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"
require curl
require jq

trap trap_cleanup EXIT
start_waf

# ------------------------------------------------------------------
# §2.2 — Missing secret header → 403 on all four control endpoints
# ------------------------------------------------------------------
for path in \
  "GET /__waf_control/capabilities" \
  "POST /__waf_control/reset_state" \
  "POST /__waf_control/set_profile" \
  "POST /__waf_control/flush_cache"
do
  method="${path%% *}"
  ep="${path##* }"

  status=$(curl -s --max-time 5 \
                -X "$method" \
                -o /dev/null -w '%{http_code}' \
                "$ADMIN$ep" || echo 000)
  [[ "$status" == "403" ]] \
    || fail "missing secret on $method $ep → $status (expected 403)"
  ok "missing secret: $method $ep → 403"
done

# ------------------------------------------------------------------
# §2.2 — Empty secret header → 403
# ------------------------------------------------------------------
status=$(curl -s --max-time 5 \
              -H "X-Benchmark-Secret: " \
              -o /dev/null -w '%{http_code}' \
              "$ADMIN/__waf_control/capabilities" || echo 000)
[[ "$status" == "403" ]] \
  || fail "empty secret → $status (expected 403)"
ok "empty X-Benchmark-Secret → 403"

# ------------------------------------------------------------------
# §2.2 — Wrong secret → 403
# ------------------------------------------------------------------
status=$(curl -s --max-time 5 \
              -H "X-Benchmark-Secret: WRONG-SECRET-XYZ" \
              -o /dev/null -w '%{http_code}' \
              "$ADMIN/__waf_control/capabilities" || echo 000)
[[ "$status" == "403" ]] \
  || fail "wrong secret → $status (expected 403)"
ok "wrong X-Benchmark-Secret → 403"

# ------------------------------------------------------------------
# §2.2 — Secret in query-string (not a header) → 403
# ------------------------------------------------------------------
status=$(curl -s --max-time 5 \
              -o /dev/null -w '%{http_code}' \
              "$ADMIN/__waf_control/capabilities?X-Benchmark-Secret=$SECRET" || echo 000)
[[ "$status" == "403" ]] \
  || fail "secret in query-string → $status (expected 403)"
ok "secret in query-string (not header) → 403"

# ------------------------------------------------------------------
# §2.2 — Wrong secret on POST reset_state → 403
# ------------------------------------------------------------------
status=$(curl -s --max-time 5 -X POST \
              -H "X-Benchmark-Secret: BAD" \
              -o /dev/null -w '%{http_code}' \
              "$ADMIN/__waf_control/reset_state" || echo 000)
[[ "$status" == "403" ]] \
  || fail "wrong secret on reset_state → $status (expected 403)"
ok "wrong secret on POST reset_state → 403"

# ------------------------------------------------------------------
# §2.2 — Wrong secret on POST set_profile → 403
# ------------------------------------------------------------------
status=$(curl -s --max-time 5 -X POST \
              -H "X-Benchmark-Secret: BAD" \
              -H "content-type: application/json" \
              -d '{"scope":"all","mode":"enforce"}' \
              -o /dev/null -w '%{http_code}' \
              "$ADMIN/__waf_control/set_profile" || echo 000)
[[ "$status" == "403" ]] \
  || fail "wrong secret on set_profile → $status (expected 403)"
ok "wrong secret on POST set_profile → 403"

# ------------------------------------------------------------------
# §2.2 (positive) — Correct secret → 200 on capabilities
# ------------------------------------------------------------------
status=$(ctrl_get_status "/__waf_control/capabilities")
[[ "$status" == "200" ]] \
  || fail "correct secret on capabilities → $status (expected 200)"
ok "correct X-Benchmark-Secret → 200 on capabilities"

ok "LT-01 control-auth: all checks green"
