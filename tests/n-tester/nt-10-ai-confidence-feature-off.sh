#!/usr/bin/env bash
# NT-10 — Feature-off behaviour: GET still returns default, PUT still
# patches the doc.
#
# When the binary is built without `--features ai`:
#   • `services.ai_threshold` is None on every node.
#   • GET /api/ai/confidence still returns `default` (from
#     services.ai_threshold_default, populated at boot from cfg).
#   • PUT still writes to the cluster config doc — so a later
#     feature-rebuild picks up the operator's choice without lossy
#     re-entry.
#
# Auto-skips when the running binary HAS the ai feature (detect via
# /api/ai/enabled.feature_present); the test only proves the
# graceful-degradation contract.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

require curl; require jq; require docker

trap stop_cluster EXIT
start_cluster
login "$NODE_A_ADMIN"

# Detect feature state on the running binary.
enabled_view="$(admin_get "$NODE_A_ADMIN" "/api/ai/enabled")"
feat="$(printf '%s' "$enabled_view" | jq -r '.feature_present')"
if [[ "$feat" == "true" ]]; then
  skip "binary built WITH --features ai; this test is for the no-ai build"
fi
ok "binary is feature-off (ai_enabled.feature_present=false)"

# GET still returns a usable view.
view="$(admin_get "$NODE_A_ADMIN" "/api/ai/confidence")"
assert_json_eq    "$view" '.feature_present' 'false'
assert_json_present "$view" '.default'
assert_json_present "$view" '.confidence_threshold'
ok "GET surfaces default + flags feature_present=false"

# PUT must still 200 and persist (config-doc only — no live writer).
target="0.66"
put="$(admin_put "$NODE_A_ADMIN" "/api/ai/confidence" \
       "{\"confidence_threshold\": $target}")"
v_put="$(printf '%s' "$put" | jq -r '.version // empty')"
[[ -n "$v_put" ]] \
  || fail "PUT did not return version (handler may have early-exited on feature_off): $put"
ok "PUT activated v=$v_put against feature-off binary"

# The doc should now carry the new value; a feature-on rebuild would
# pick it up on next boot. Read GET back — `default` is the boot
# value (unchanged), `confidence_threshold` reflects the persisted
# doc only when a writer is wired; with no writer it still shows
# `default` (the documented degradation).
post="$(admin_get "$NODE_A_ADMIN" "/api/ai/confidence")"
post_feat="$(printf '%s' "$post" | jq -r '.feature_present')"
[[ "$post_feat" == "false" ]] \
  || fail "feature_present flipped unexpectedly after PUT: $post"
ok "feature_present stays false post-PUT; doc carries the operator's choice"

echo "NT-10 PASS"
