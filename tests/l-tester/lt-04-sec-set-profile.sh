#!/usr/bin/env bash
# LT-04 — §2.5  set_profile: all three scopes, isolation, unsupported handling
#
# Contract:
#   POST /__waf_control/set_profile MUST:
#   1. scope=all     → change default_mode for ALL features/policies;
#                      clear previous overrides.
#   2. scope=features→ change only listed features; others UNCHANGED.
#   3. scope=policies→ change only listed policy under one feature;
#                      other policies and features UNCHANGED.
#   4. Respond with .ok, .action, .applied, .active, .unsupported, .ts_ms.
#   5. Unsupported feature/policy name → populated .unsupported (NOT silent ignore).
#   6. Invalid body (missing required fields) → 400.
#   7. scope=all enforce after log_only overrides → overrides cleared.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"
require curl
require jq

trap trap_cleanup EXIT
start_waf

# Discover the first feature name for scoped tests.
caps=$(ctrl_get "/__waf_control/capabilities")
first_feature=$(printf '%s' "$caps" | jq -r '.features | keys[0]')
[[ -n "$first_feature" ]] || fail "no features found in capabilities"
ok "using feature '$first_feature' for scoped tests"

# Discover first policy under first_feature (may be empty array → use "dummy").
first_policy=$(printf '%s' "$caps" | jq -r ".features[\"$first_feature\"].policies[0] // empty")

# ------------------------------------------------------------------
# 1. scope=all → mode=log_only
# ------------------------------------------------------------------
body=$(ctrl_post "/__waf_control/set_profile" '{"scope":"all","mode":"log_only"}')

assert_json_eq      "$body" '.ok'           'true'       || fail "set_profile scope=all .ok != true"
assert_json_eq      "$body" '.action'       'set_profile'|| fail "set_profile .action wrong"
assert_json_eq      "$body" '.applied.scope' 'all'       || fail "set_profile .applied.scope != all"
assert_json_eq      "$body" '.applied.mode'  'log_only'  || fail "set_profile .applied.mode != log_only"
assert_json_present "$body" '.active'                    || fail "set_profile .active missing"
assert_json_present "$body" '.unsupported'               || fail "set_profile .unsupported missing"
ts=$(printf '%s' "$body" | jq -r '.ts_ms')
[[ "$ts" =~ ^[0-9]+$ ]] || fail "set_profile .ts_ms not numeric (got: $ts)"
ok "set_profile scope=all → shape valid"

# Verify capabilities reflect the new default_mode.
caps=$(ctrl_get "/__waf_control/capabilities")
default_mode=$(printf '%s' "$caps" | jq -r '.active.default_mode')
[[ "$default_mode" == "log_only" ]] \
  || fail "capabilities.active.default_mode='$default_mode' after scope=all log_only (expected log_only)"
ok "capabilities.active.default_mode updated to log_only after scope=all"

# ------------------------------------------------------------------
# 2. scope=all → mode=enforce  clears overrides
# ------------------------------------------------------------------
body=$(ctrl_post "/__waf_control/set_profile" '{"scope":"all","mode":"enforce"}')
assert_json_eq "$body" '.applied.mode' 'enforce' || fail "scope=all enforce .applied.mode wrong"

caps=$(ctrl_get "/__waf_control/capabilities")
overrides_count=$(printf '%s' "$caps" | jq '.active.overrides | length')
default_mode=$(printf '%s' "$caps" | jq -r '.active.default_mode')
[[ "$default_mode" == "enforce" ]] \
  || fail "default_mode not restored to enforce after scope=all enforce"
[[ "$overrides_count" == "0" ]] \
  || fail "scope=all enforce should clear overrides, got $overrides_count ($(printf '%s' "$caps" | jq '.active.overrides'))"
ok "scope=all enforce restores default_mode and clears overrides"

# ------------------------------------------------------------------
# 3. scope=features → only the listed feature changes
# ------------------------------------------------------------------
body=$(ctrl_post "/__waf_control/set_profile" \
  "{\"scope\":\"features\",\"mode\":\"log_only\",\"features\":[\"$first_feature\"]}")

assert_json_eq "$body" '.applied.scope' 'features'  || fail "scope=features .applied.scope wrong"
# The override must appear in active.overrides.
override_val=$(printf '%s' "$body" | jq -r ".active.overrides[\"$first_feature\"] // empty")
[[ "$override_val" == "log_only" ]] \
  || fail "feature-scoped override not recorded for $first_feature (got: $override_val)"
ok "scope=features override recorded for $first_feature"

# default_mode MUST remain enforce.
default_mode=$(printf '%s' "$body" | jq -r '.active.default_mode')
[[ "$default_mode" == "enforce" ]] \
  || fail "scope=features override leaked into default_mode (got $default_mode)"
ok "scope=features: default_mode stays enforce"

# Verify capabilities reflects the feature override.
caps=$(ctrl_get "/__waf_control/capabilities")
caps_override=$(printf '%s' "$caps" | jq -r ".active.overrides[\"$first_feature\"] // empty")
[[ "$caps_override" == "log_only" ]] \
  || fail "capabilities didn't reflect feature override for $first_feature (got: $caps_override)"
ok "capabilities reflects feature-level override"

# ------------------------------------------------------------------
# 4. scope=all enforce → feature override cleared
# ------------------------------------------------------------------
ctrl_post "/__waf_control/set_profile" '{"scope":"all","mode":"enforce"}' >/dev/null

caps=$(ctrl_get "/__waf_control/capabilities")
ov=$(printf '%s' "$caps" | jq -r ".active.overrides[\"$first_feature\"] // empty")
[[ -z "$ov" ]] \
  || fail "scope=all enforce should clear feature override; still got '$ov'"
ok "scope=all enforce clears feature override"

# ------------------------------------------------------------------
# 5. scope=policies → only the listed policy changes (if policies exist)
# ------------------------------------------------------------------
if [[ -n "$first_policy" ]]; then
  body=$(ctrl_post "/__waf_control/set_profile" \
    "{\"scope\":\"policies\",\"mode\":\"log_only\",\"feature\":\"$first_feature\",\"policies\":[\"$first_policy\"]}")

  assert_json_eq "$body" '.applied.scope'   'policies'      || fail "scope=policies .applied.scope wrong"
  assert_json_eq "$body" '.applied.feature' "$first_feature"|| fail "scope=policies .applied.feature wrong"
  pol_arr=$(printf '%s' "$body" | jq -r ".applied.policies | @json")
  [[ "$pol_arr" == "[\"$first_policy\"]" ]] \
    || fail "scope=policies .applied.policies wrong (got $pol_arr)"

  pol_key="$first_feature.$first_policy"
  pol_override=$(printf '%s' "$body" | jq -r ".active.overrides[\"$pol_key\"] // empty")
  [[ "$pol_override" == "log_only" ]] \
    || fail "policy override key '$pol_key' not found in overrides (got: $pol_override)"
  ok "scope=policies override recorded for $pol_key"

  # default_mode must stay enforce.
  dmode=$(printf '%s' "$body" | jq -r '.active.default_mode')
  [[ "$dmode" == "enforce" ]] || fail "scope=policies leaked into default_mode"
  ok "scope=policies: default_mode stays enforce"

  ctrl_post "/__waf_control/set_profile" '{"scope":"all","mode":"enforce"}' >/dev/null
else
  ok "SKIP scope=policies (no policies defined for $first_feature)"
fi

# ------------------------------------------------------------------
# 6. Invalid body (missing required fields) → 400
# ------------------------------------------------------------------
status=$(curl -s --max-time 5 -X POST \
              -H "X-Benchmark-Secret: $SECRET" \
              -H "content-type: application/json" \
              -d '{"bogus":"shape"}' \
              -o /dev/null -w '%{http_code}' \
              "$ADMIN/__waf_control/set_profile" || echo 000)
[[ "$status" == "400" || "$status" == "422" ]] \
  || fail "invalid body → $status (expected 400 or 422)"
ok "invalid body → $status (correctly rejected)"

# ------------------------------------------------------------------
# 7. Unsupported feature name → .unsupported populated (NOT silently ignored)
# ------------------------------------------------------------------
body=$(curl -s --max-time 5 -X POST \
            -H "X-Benchmark-Secret: $SECRET" \
            -H "content-type: application/json" \
            -d '{"scope":"features","mode":"log_only","features":["__l_tester_nonexistent__"]}' \
            "$ADMIN/__waf_control/set_profile" || echo '{}')
unsupported_len=$(printf '%s' "$body" | jq '.unsupported | length' 2>/dev/null || echo 0)
[[ "$unsupported_len" -ge 1 ]] \
  || fail "unsupported feature should appear in .unsupported (got: $body)"
ok "unsupported feature populates .unsupported list"

ok "LT-04 set-profile: all checks green"
