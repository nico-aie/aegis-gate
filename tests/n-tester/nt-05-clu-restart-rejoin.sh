#!/usr/bin/env bash
# NT-05 — Restart-rejoin: cluster doc wins over local waf.yaml
#
# Answers the design question "when a node joins, how does it know its
# waf.yaml is older/newer than cluster?" by proving the rule in code:
#   • Cluster doc is the source of truth.
#   • A restarted node converges to the active cluster doc, regardless
#     of what its local file says.
#
# Scenario:
#   1. Cluster boots — config defaults from cluster-{a,b}.yaml.
#   2. Operator publishes v=N via PUT /api/response-filter on node-A,
#      flipping `scrub_stack_traces` AWAY from cluster-b.yaml's default.
#   3. Kill node-B (without touching its waf.yaml).
#   4. Restart node-B from the SAME (stale) cluster-b.yaml.
#   5. After convergence, node-B serves the v=N value, NOT what its
#      local YAML says.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

require curl; require jq; require docker

trap stop_cluster EXIT
start_cluster

# Read cluster-b.yaml's seed value so we know what "stale local"
# looks like. 2026-05-30 (QC R2-005): cluster-b.yaml doesn't set
# `scrub_stack_traces` explicitly, so `grep` finds nothing and
# pipefail aborts the script silently before the fallback assignment
# can fire. `|| true` neutralises the pipeline failure so the
# fallback runs.
yaml_seed_b="$(grep -E '^\s*scrub_stack_traces:' "$CONFIG_B" 2>/dev/null \
               | head -1 | awk '{print $2}' || true)"
yaml_seed_b="${yaml_seed_b:-true}"  # default in `default_response_filter` is true

# Pick the opposite to make the test meaningful.
target=$([[ "$yaml_seed_b" == "true" ]] && echo false || echo true)

login "$NODE_A_ADMIN"
put="$(admin_put "$NODE_A_ADMIN" "/api/response-filter" \
       "{\"scrub_stack_traces\": $target}")"
v_n="$(printf '%s' "$put" | jq -r '.version')"
ok "published v=$v_n with scrub_stack_traces=$target (cluster-b.yaml says $yaml_seed_b)"

# Wait for B to converge first so we're sure the activation propagated.
login "$NODE_B_ADMIN"
b_at_v_n() {
  [[ "$(admin_get "$NODE_B_ADMIN" "/api/config" | jq -r '.version')" == "$v_n" ]]
}
wait_for b_at_v_n 10 || fail "node-B did not converge to v=$v_n before restart"

# Stop B (clean), confirm it's gone, restart from the same config.
stop_node "$NODE_B_PID"
NODE_B_PID=""
sleep 1   # give the port time to release
start_node B
NODE_B_PID="$LAST_NODE_PID"
wait_ready "$NODE_B_ADMIN"

# After rejoin, B's live response-filter should reflect the CLUSTER doc
# (the value `$target`), not its local YAML (`$yaml_seed_b`).
login "$NODE_B_ADMIN"
b_reflects_cluster() {
  [[ "$(admin_get "$NODE_B_ADMIN" "/api/response-filter" \
        | jq -r '.scrub_stack_traces')" == "$target" ]]
}
wait_for b_reflects_cluster 10 \
  || fail "restarted node-B did not converge to cluster doc (still reflecting stale waf.yaml?)"
ok "restarted node-B converged to cluster doc value ($target), not local YAML ($yaml_seed_b)"

echo "NT-05 PASS"
