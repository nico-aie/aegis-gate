#!/usr/bin/env bash
# LT-02 — §2.3  Capabilities response shape & feature contract
#
# Contract:
#   GET /__waf_control/capabilities (with correct secret) MUST return:
#   - HTTP 200
#   - JSON body with:
#       .ok == true
#       .features  — object with at least one entry
#       .features.<name>.supported — boolean
#       .features.<name>.toggleable — boolean
#       .features.<name>.policies  — array (may be empty)
#       .active.default_mode — "enforce" | "log_only"
#       .active.overrides    — object
#
#   Feature and policy names MUST be stable: two consecutive calls
#   MUST return the same feature keys.
#
#   The WAF MUST expose at least one toggleable feature (otherwise
#   set_profile has nothing to toggle).

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"
require curl
require jq

trap trap_cleanup EXIT
start_waf

# ------------------------------------------------------------------
# 1. HTTP 200 with the correct secret
# ------------------------------------------------------------------
status=$(ctrl_get_status "/__waf_control/capabilities")
[[ "$status" == "200" ]] \
  || fail "capabilities → $status (expected 200)"
ok "capabilities returns HTTP 200"

# ------------------------------------------------------------------
# 2. Response body: top-level required keys
# ------------------------------------------------------------------
body=$(ctrl_get "/__waf_control/capabilities")

assert_json_eq      "$body" '.ok'                      'true'  \
  || fail "capabilities .ok must be true"
ok "capabilities .ok == true"

assert_json_present "$body" '.features' \
  || fail "capabilities .features must be present"
ok "capabilities .features present"

assert_json_present "$body" '.active.default_mode' \
  || fail "capabilities .active.default_mode must be present"
ok "capabilities .active.default_mode present"

assert_json_present "$body" '.active.overrides' \
  || fail "capabilities .active.overrides must be present"
ok "capabilities .active.overrides present"

# ------------------------------------------------------------------
# 3. .features must be a non-empty object
# ------------------------------------------------------------------
features_len=$(printf '%s' "$body" | jq '.features | length')
[[ "$features_len" -gt 0 ]] \
  || fail "capabilities .features must have at least one entry (got 0)"
ok "capabilities .features has $features_len feature(s)"

# ------------------------------------------------------------------
# 4. Each feature must carry supported, toggleable, policies
# ------------------------------------------------------------------
feature_check_fail=0
while IFS= read -r feat_name; do
  sup=$(printf '%s' "$body" | jq -r ".features[\"$feat_name\"].supported | type")
  tog=$(printf '%s' "$body" | jq -r ".features[\"$feat_name\"].toggleable | type")
  pol=$(printf '%s' "$body" | jq -r ".features[\"$feat_name\"].policies | type")

  if [[ "$sup" != "boolean" ]]; then
    echo "  feature '$feat_name'.supported type=$sup (expected boolean)" >&2
    feature_check_fail=$((feature_check_fail + 1))
  fi
  if [[ "$tog" != "boolean" ]]; then
    echo "  feature '$feat_name'.toggleable type=$tog (expected boolean)" >&2
    feature_check_fail=$((feature_check_fail + 1))
  fi
  if [[ "$pol" != "array" ]]; then
    echo "  feature '$feat_name'.policies type=$pol (expected array)" >&2
    feature_check_fail=$((feature_check_fail + 1))
  fi
done < <(printf '%s' "$body" | jq -r '.features | keys[]')

[[ "$feature_check_fail" -eq 0 ]] \
  || fail "$feature_check_fail feature schema violation(s)"
ok "all features have valid supported/toggleable/policies schema"

# ------------------------------------------------------------------
# 5. active.default_mode must be "enforce" or "log_only"
# ------------------------------------------------------------------
default_mode=$(printf '%s' "$body" | jq -r '.active.default_mode')
case "$default_mode" in
  enforce|log_only) ;;
  *) fail "active.default_mode='$default_mode'; expected enforce|log_only";;
esac
ok "active.default_mode='$default_mode' (valid)"

# ------------------------------------------------------------------
# 6. active.overrides must be an object (not null / array)
# ------------------------------------------------------------------
overrides_type=$(printf '%s' "$body" | jq '.active.overrides | type')
[[ "$overrides_type" == '"object"' ]] \
  || fail "active.overrides type=$overrides_type (expected object)"
ok "active.overrides is an object"

# ------------------------------------------------------------------
# 7. At least one toggleable feature must exist
# ------------------------------------------------------------------
toggleable_count=$(printf '%s' "$body" | jq '[.features[] | select(.toggleable == true)] | length')
[[ "$toggleable_count" -gt 0 ]] \
  || fail "no toggleable features; set_profile has nothing to control"
ok "$toggleable_count toggleable feature(s) exposed"

# ------------------------------------------------------------------
# 8. Stability: two consecutive calls return the same feature keys
# ------------------------------------------------------------------
keys1=$(ctrl_get "/__waf_control/capabilities" | jq -r '.features | keys | sort | @json')
keys2=$(ctrl_get "/__waf_control/capabilities" | jq -r '.features | keys | sort | @json')
[[ "$keys1" == "$keys2" ]] \
  || fail "feature key set is unstable across two calls ($keys1 vs $keys2)"
ok "feature key set stable across two calls"

ok "LT-02 capabilities: all checks green"
