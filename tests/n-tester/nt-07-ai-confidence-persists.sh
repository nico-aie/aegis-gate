#!/usr/bin/env bash
# NT-07 — AI confidence_threshold persists across restart
#
# PUT a non-default value, restart node-A, GET still returns the same
# value — proves the change rode through the config plane (Redis
# config:waf:doc) and wasn't ephemeral.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

require curl; require jq; require docker

trap stop_cluster EXIT
start_cluster
login "$NODE_A_ADMIN"

# Pick a value that's NOT the cfg default 0.85 so the test is meaningful.
target="0.42"
put="$(admin_put "$NODE_A_ADMIN" "/api/ai/confidence" \
       "{\"confidence_threshold\": $target}")"
v_put="$(printf '%s' "$put" | jq -r '.version // empty')"
[[ -n "$v_put" ]] || fail "PUT did not return version: $put"
ok "PUT activated v=$v_put"

# Live read before restart. 2026-05-30 (QC R2-007): use float-
# tolerant comparison — 0.42 round-trips through f32 → JSON as
# 0.41999998688697815, breaking strict awk equality.
pre="$(admin_get "$NODE_A_ADMIN" "/api/ai/confidence")"
echo "pre-restart: $pre"
pre_val="$(printf '%s' "$pre" | jq -r '.confidence_threshold')"
floats_eq "$pre_val" "$target" \
  || fail "pre-restart value mismatch: $pre_val vs $target"

# Restart node-A.
stop_node "$NODE_A_PID"
NODE_A_PID=""
sleep 1
start_node A
NODE_A_PID="$LAST_NODE_PID"
wait_ready "$NODE_A_ADMIN"

# After restart, the value must come from the cluster doc, not the
# YAML default (0.85). 2026-05-30 (QC R2-006): wait_for here — the
# node responds to /healthz/ready as soon as state hydration
# completes, but the config-plane watcher runs separately and may
# not have polled yet. Same float-tolerant compare as above.
login "$NODE_A_ADMIN"
a_at_target() {
  local v
  v="$(admin_get "$NODE_A_ADMIN" "/api/ai/confidence" \
       | jq -r '.confidence_threshold // empty')"
  floats_eq "$v" "$target"
}
wait_for a_at_target 10 \
  || fail "post-restart value never converged to $target (regressed to YAML default?)"
post="$(admin_get "$NODE_A_ADMIN" "/api/ai/confidence")"
echo "post-restart: $post"
ok "post-restart value persists: $(printf '%s' "$post" | jq -r '.confidence_threshold')"

echo "NT-07 PASS"
