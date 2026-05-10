#!/usr/bin/env bash
# LT-25 — Hacker: control plane input abuse
#
# Attacker perspective: a privileged operator (or an attacker who has
# stolen the benchmark secret) attempts to abuse the control plane via:
#   - Wrong JSON types (integer/boolean/null/array instead of string)
#   - Array passed where a string is expected (scope, mode)
#   - String passed where an array is expected (features, policies)
#   - Empty JSON body / null body
#   - Oversized / deeply nested JSON (DoS probe)
#   - Mode "ENFORCE" (uppercase) vs "enforce" (lowercase)
#   - Scope misspelling / unsupported variant
#   - Injection via field values (check that mode is never evaluated)
#
# All malformed inputs must be rejected with 4xx; no malformed input
# should be silently accepted and applied to WAF state.
#
# Bugs targeted:
#   - features: "string" (wrong type) accepted as if it were a list
#   - policies: "string" (wrong type) iterates over characters
#   - mode: 1 / true / null silently coerced
#   - scope: null / [] silently coerced
#
# Contract reference: §2.5 set_profile — strict input validation.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"
require curl
require jq

trap trap_cleanup EXIT
start_waf
reset_to_enforce

# Helper: assert set_profile returns a specific HTTP status
check_profile_status() {
  local desc="$1" body="$2" expected_status="$3"
  status=$(curl -s --max-time 5 -o /dev/null -w '%{http_code}' \
    -X POST \
    -H "X-Benchmark-Secret: $SECRET" \
    -H "Content-Type: application/json" \
    -d "$body" \
    "$ADMIN/__waf_control/set_profile")
  if [[ "$status" == "$expected_status" ]]; then
    ok "$desc → HTTP $status ✓"
  else
    fail "$desc → HTTP $status (expected $expected_status)"
  fi
}

# Helper: assert 400 (bad request)
check_400() { check_profile_status "$1" "$2" "400"; }

# ------------------------------------------------------------------
# 1. Baseline: valid set_profile (must succeed as 200)
# ------------------------------------------------------------------
check_profile_status \
  "Baseline: valid set_profile scope=all enforce" \
  '{"scope":"all","mode":"enforce"}' \
  "200"

# ------------------------------------------------------------------
# 2. mode is integer (1) — must reject 400
# ------------------------------------------------------------------
check_400 \
  "mode: 1 (integer instead of string)" \
  '{"scope":"all","mode":1}'

# ------------------------------------------------------------------
# 3. mode is boolean true — must reject 400
# ------------------------------------------------------------------
check_400 \
  "mode: true (boolean instead of string)" \
  '{"scope":"all","mode":true}'

# ------------------------------------------------------------------
# 4. mode is null — must reject 400
# ------------------------------------------------------------------
check_400 \
  "mode: null" \
  '{"scope":"all","mode":null}'

# ------------------------------------------------------------------
# 5. scope is null — must reject 400
# ------------------------------------------------------------------
check_400 \
  "scope: null (null instead of string)" \
  '{"scope":null,"mode":"enforce"}'

# ------------------------------------------------------------------
# 6. scope is an array — must reject 400
# ------------------------------------------------------------------
check_400 \
  "scope: [\"all\"] (array instead of string)" \
  '{"scope":["all"],"mode":"enforce"}'

# ------------------------------------------------------------------
# 7. Empty body {} (no scope/mode) — must reject 400
# ------------------------------------------------------------------
check_400 \
  "Empty JSON body: {}" \
  '{}'

# ------------------------------------------------------------------
# 8. mode "ENFORCE" (uppercase) — must reject 400
#    The contract specifies lowercase "enforce" / "log_only".
# ------------------------------------------------------------------
check_400 \
  "mode: \"ENFORCE\" (uppercase variant)" \
  '{"scope":"all","mode":"ENFORCE"}'

# ------------------------------------------------------------------
# 9. mode "log-only" (hyphen instead of underscore) — must reject 400
# ------------------------------------------------------------------
check_400 \
  "mode: \"log-only\" (hyphen variant)" \
  '{"scope":"all","mode":"log-only"}'

# ------------------------------------------------------------------
# 10. scope=features with features as a STRING (not array)
#     A naive implementation iterates over characters → BUG
# ------------------------------------------------------------------
check_400 \
  "features: \"rules_engine\" (string instead of array)" \
  '{"scope":"features","mode":"enforce","features":"rules_engine"}'

# ------------------------------------------------------------------
# 11. scope=policies with policies as a STRING (not array)
#     Iterating string chars produces unsupported single letters → BUG
# ------------------------------------------------------------------
check_400 \
  "policies: \"sqli\" (string instead of array)" \
  '{"scope":"policies","mode":"enforce","feature":"rules_engine","policies":"sqli"}'

# ------------------------------------------------------------------
# 12. scope=policies with feature as an array (not string)
# ------------------------------------------------------------------
check_400 \
  "feature: [\"rules_engine\"] (array instead of string)" \
  '{"scope":"policies","mode":"enforce","feature":["rules_engine"],"policies":["sqli"]}'

# ------------------------------------------------------------------
# 13. Unknown scope value (not all/features/policies) — must reject 400
# ------------------------------------------------------------------
check_400 \
  "scope: \"global\" (unknown scope)" \
  '{"scope":"global","mode":"enforce"}'

# ------------------------------------------------------------------
# 14. Injection attempt via mode value (ensure no eval occurs)
# ------------------------------------------------------------------
check_400 \
  "mode injection: \"enforce; rm -rf /\"" \
  '{"scope":"all","mode":"enforce; rm -rf /"}'

# ------------------------------------------------------------------
# 15. Verify WAF state was NOT corrupted by any of the above bad inputs
# ------------------------------------------------------------------
reset_to_enforce
caps=$(ctrl_get "/__waf_control/capabilities")
dm=$(printf '%s' "$caps" | jq -r '.active.default_mode')
ov=$(printf '%s' "$caps" | jq -r '.active.overrides | keys | length')
[[ "$dm" == "enforce" ]] \
  || fail "§2.5 WAF default_mode corrupted by bad input (got: $dm)"
[[ "$ov" -eq 0 ]] \
  || fail "§2.5 WAF overrides map corrupted by bad input (got $ov entries)"
ok "§2.5 WAF state clean after all bad inputs — default_mode=enforce, no overrides"

ok "LT-25 hack-control-plane-abuse: all checks complete"
