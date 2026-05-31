#!/usr/bin/env bash
# NT-04 — Cluster config plane: rollback
#
# Publish v1 → v2 → v3 (each changing a different rung of the
# response-filter so the diffs are visible), then
# POST /api/config/versions/2/rollback. Both nodes should converge
# to a NEW version (v4) whose blob matches v2 exactly.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

require curl; require jq; require docker

trap stop_cluster EXIT
start_cluster
login "$NODE_A_ADMIN"

# v1, v2, v3 — three distinct response-filter states.
v1_resp="$(admin_put "$NODE_A_ADMIN" "/api/response-filter" \
           '{"scrub_stack_traces": true,  "mask_internal_ips": true,  "redact_dlp": true }')"
v1="$(printf '%s' "$v1_resp" | jq -r '.version')"
v2_resp="$(admin_put "$NODE_A_ADMIN" "/api/response-filter" \
           '{"scrub_stack_traces": false, "mask_internal_ips": true,  "redact_dlp": true }')"
v2="$(printf '%s' "$v2_resp" | jq -r '.version')"
v3_resp="$(admin_put "$NODE_A_ADMIN" "/api/response-filter" \
           '{"scrub_stack_traces": false, "mask_internal_ips": false, "redact_dlp": false}')"
v3="$(printf '%s' "$v3_resp" | jq -r '.version')"
echo "versions: v1=$v1 v2=$v2 v3=$v3"
[[ -n "$v1" && -n "$v2" && -n "$v3" ]] \
  || fail "missing version returns: $v1_resp / $v2_resp / $v3_resp"

# Rollback to v2. 2026-05-30 (QC R2-004): the
# `/api/config/versions/<seq>/rollback` endpoint replays an audit
# event via the audit-ring whitelist (ROLLBACKABLE_ACTIONS), which
# does NOT include the folded toggles — `response_filter_put` etc.
# Use the config-plane endpoint `/api/config/rollback` instead. It
# re-activates the stored YAML snapshot via ConfigStore::rollback
# with no per-action gating, which is what an operator wants when
# they say "undo my last save".
rb="$(admin_post "$NODE_A_ADMIN" "/api/config/rollback" \
      "{\"target_version\": $v2}")"
echo "rollback resp: $rb"
v4="$(printf '%s' "$rb" | jq -r '.version // empty')"
[[ -n "$v4" ]] || fail "rollback did not return a new version: $rb"
(( v4 > v3 )) \
  || fail "rollback version $v4 should be > $v3"
ok "rollback produced new version $v4"

# Live response-filter rungs on A should match v2's (scrub: false,
# mask: true, redact: true). 2026-05-30: rollback activates a new
# doc, but the local watcher still polls every ~3 s to re-derive
# the in-process state via `apply_cfg_change_to_response_filter`.
# wait_for the convergence instead of reading immediately.
a_at_v2() {
  local s
  s="$(admin_get "$NODE_A_ADMIN" "/api/response-filter")"
  [[ "$(printf '%s' "$s" | jq -r '.scrub_stack_traces')" == "false" ]] \
    && [[ "$(printf '%s' "$s" | jq -r '.mask_internal_ips')"  == "true"  ]] \
    && [[ "$(printf '%s' "$s" | jq -r '.redact_dlp')"         == "true"  ]]
}
wait_for a_at_v2 10 \
  || fail "node-A did not converge to v2's rungs after rollback within 10 s"
ok "node-A reflects v2's rungs after rollback"

# Same on B — convergence within the watcher window.
login "$NODE_B_ADMIN"
b_converged() {
  local s
  s="$(admin_get "$NODE_B_ADMIN" "/api/response-filter")"
  [[ "$(printf '%s' "$s" | jq -r '.scrub_stack_traces')" == "false" ]] \
    && [[ "$(printf '%s' "$s" | jq -r '.mask_internal_ips')"  == "true" ]] \
    && [[ "$(printf '%s' "$s" | jq -r '.redact_dlp')"         == "true" ]]
}
wait_for b_converged 10 \
  || fail "node-B did not converge to rolled-back state within 10 s"
ok "node-B converged to v2's rungs"

echo "NT-04 PASS"
