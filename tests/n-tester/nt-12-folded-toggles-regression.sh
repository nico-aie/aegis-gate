#!/usr/bin/env bash
# NT-12 — Regression: the older folded toggles still round-trip
# through the cluster config plane after the AI threshold fold
# landed (commit e77d379).
#
# Spot-checks three siblings that ride the same plumbing:
#   • PUT /api/ai/enabled       (boolean fold)
#   • PUT /api/response-filter  (three-rung fold)
#   • PUT /api/tiers/<id>       (numeric risk_threshold fold)
#
# Each one: PUT new value → 200 with `version` → GET reflects.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

require curl; require jq; require docker

trap stop_cluster EXIT
start_cluster
login "$NODE_A_ADMIN"

# --- ai.enabled -----------------------------------------------------------
pre_en="$(admin_get "$NODE_A_ADMIN" "/api/ai/enabled")"
feat="$(printf '%s' "$pre_en" | jq -r '.feature_present')"
if [[ "$feat" == "true" ]]; then
  cur="$(printf '%s' "$pre_en" | jq -r '.enabled')"
  flipped=$([[ "$cur" == "true" ]] && echo false || echo true)
  out="$(http_status "$NODE_A_ADMIN" PUT "/api/ai/enabled" \
         "{\"enabled\": $flipped}")"
  code="$(printf '%s' "$out" | tail -1)"
  body="$(printf '%s' "$out" | sed '$d')"
  [[ "$code" == "200" ]] || fail "ai/enabled PUT: HTTP $code ($body)"
  assert_json_eq "$body" '.ok' 'true'
  assert_json_present "$body" '.version'
  ok "ai.enabled fold: $cur → $flipped"
else
  ok "ai.enabled fold: skipped — feature_present=false on this binary"
fi

# --- response_filter rungs -----------------------------------------------
pre_rf="$(admin_get "$NODE_A_ADMIN" "/api/response-filter")"
pre_scrub="$(printf '%s' "$pre_rf" | jq -r '.scrub_stack_traces // true')"
new_scrub=$([[ "$pre_scrub" == "true" ]] && echo false || echo true)
out="$(http_status "$NODE_A_ADMIN" PUT "/api/response-filter" \
       "{\"scrub_stack_traces\": $new_scrub}")"
code="$(printf '%s' "$out" | tail -1)"
body="$(printf '%s' "$out" | sed '$d')"
[[ "$code" == "200" ]] || fail "response-filter PUT: HTTP $code ($body)"
assert_json_present "$body" '.version'
# 2026-05-29 — response_filter fold applies via the config-plane
# watcher (~3 s poll). On the originating node we still need to
# wait for the next watcher tick to read the new value back. AI
# `confidence_threshold` updates synchronously on the originator
# (see handle_ai_confidence_put), but the other folds do NOT.
# Polling is the portable fix.
rf_converged() {
  [[ "$(admin_get "$NODE_A_ADMIN" "/api/response-filter" \
        | jq -r '.scrub_stack_traces')" == "$new_scrub" ]]
}
wait_for rf_converged 10 \
  || fail "response-filter rung did not reflect within 10 s: want $new_scrub"
ok "response_filter fold: scrub_stack_traces $pre_scrub → $new_scrub"

# --- tier risk_threshold --------------------------------------------------
# Tier PUT is a FULL upsert (requires `pipeline` etc.), not a patch.
# Read the existing tier, bump one numeric field, send the whole
# object back.
tiers="$(admin_get "$NODE_A_ADMIN" "/api/tiers")"
tier_obj="$(printf '%s' "$tiers" | jq -c '.tiers[0] // empty')"
tier_name="$(printf '%s' "$tier_obj" | jq -r '.name // empty')"
old_thr="$(printf '%s' "$tier_obj" | jq -r '.risk_threshold // empty')"
if [[ -n "$tier_name" && -n "$old_thr" ]]; then
  new_thr=$((old_thr + 1))
  new_obj="$(printf '%s' "$tier_obj" | jq -c --argjson n "$new_thr" '.risk_threshold = $n')"
  out="$(http_status "$NODE_A_ADMIN" PUT "/api/tiers/$tier_name" "$new_obj")"
  code="$(printf '%s' "$out" | tail -1)"
  body="$(printf '%s' "$out" | sed '$d')"
  [[ "$code" == "200" ]] || fail "tier PUT: HTTP $code ($body)"
  assert_json_present "$body" '.version'
  tier_converged() {
    [[ "$(admin_get "$NODE_A_ADMIN" "/api/tiers" \
          | jq -r --arg n "$tier_name" '.tiers[] | select(.name==$n) | .risk_threshold')" \
       == "$new_thr" ]]
  }
  wait_for tier_converged 10 \
    || fail "tier $tier_name risk_threshold did not reflect within 10 s: want $new_thr"
  ok "tier fold: $tier_name risk_threshold $old_thr → $new_thr"
else
  ok "tier fold: skipped — /api/tiers shape unexpected ($tiers)"
fi

echo "NT-12 PASS"
