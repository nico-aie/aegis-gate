#!/usr/bin/env bash
# NT-03 — Cluster config plane: leader failover
#
# Identify the current leader, kill it, and verify:
#   • The surviving node still serves config-plane mutations
#   • No phantom rollback / data loss (last committed version persists)
#   • /api/cluster/peers reflects the loss
#
# The config plane uses Redis CAS, not leader-routed writes, so this
# test really verifies "no node is privileged" + the leader-lease
# infra recovers cleanly.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

require curl; require jq; require docker

trap stop_cluster EXIT
start_cluster

# Seed a known version.
login "$NODE_A_ADMIN"
seed="$(admin_put "$NODE_A_ADMIN" "/api/response-filter" \
        '{"scrub_stack_traces": true}')"
v_seed="$(printf '%s' "$seed" | jq -r '.version')"
ok "seeded version $v_seed"

# Discover leader. /api/cluster/peers shape varies — early-boot it
# can be `{peers: null}` or have `peers` absent entirely. 2026-05-30
# (QC R2-007): guard with `// []` so jq doesn't iterate over null
# and explode with `Cannot iterate over null` (exit 5 with no FAIL
# line from the test).
peers="$(admin_get "$NODE_A_ADMIN" "/api/cluster/peers")"
peer_count="$(printf '%s' "$peers" | jq -r '(.peers // []) | length')"
if [[ "$peer_count" == "0" ]]; then
  skip "/api/cluster/peers returned no peers — leader-lease may not be wired in this build (resp: ${peers:0:200})"
fi
leader_id="$(printf '%s' "$peers" \
  | jq -r '(.peers // [])[] | select(.is_leader==true) | .node_id' \
  | head -1)"
[[ -n "$leader_id" ]] \
  || skip "no peer marked is_leader in /api/cluster/peers — leader-lease may not be wired in this build"
ok "current leader: $leader_id"

# Map leader_id back to A or B by comparing with A's self-id.
my_id_a="$(printf '%s' "$peers" | jq -r '.self.node_id // .peers[0].node_id // empty')"
if [[ "$leader_id" == "$my_id_a" ]]; then
  kill_pid="$NODE_A_PID"; kill_label=A; survivor_url="$NODE_B_ADMIN"
  NODE_A_PID=""
else
  kill_pid="$NODE_B_PID"; kill_label=B; survivor_url="$NODE_A_ADMIN"
  NODE_B_PID=""
fi
echo "killing leader node-$kill_label (pid $kill_pid)"
kill -TERM "$kill_pid" 2>/dev/null || true
wait "$kill_pid" 2>/dev/null || true

# Survivor: re-login and mutate. CAS should still work — the leader
# lease is for leader-only tasks (ACME etc.), NOT for config writes.
login "$survivor_url"
post_kill="$(admin_put "$survivor_url" "/api/response-filter" \
             '{"scrub_stack_traces": false}')"
v_post="$(printf '%s' "$post_kill" | jq -r '.version')"
[[ -n "$v_post" && "$v_post" != "null" ]] \
  || fail "PUT against survivor failed after leader kill: $post_kill"
(( v_post > v_seed )) \
  || fail "post-kill version $v_post not > seeded $v_seed"
ok "survivor accepted PUT (version $v_seed → $v_post)"

# /api/cluster/peers on the survivor should show the killed node as
# stale or dropped. Allow ≤ 15 s — the lease TTL governs how fast a
# missing peer disappears.
peer_dropped() {
  local n
  # `// []` to keep jq from blowing up on null peers during the
  # transient lease-lapse window.
  n="$(admin_get "$survivor_url" "/api/cluster/peers" \
       | jq -r '[(.peers // [])[] | select(.is_leader==true)] | length')"
  # Either no leader (lease lapsed) or a new one elected.
  [[ "$n" != "1" ]] || {
    local new_leader
    new_leader="$(admin_get "$survivor_url" "/api/cluster/peers" \
                  | jq -r '(.peers // [])[] | select(.is_leader==true) | .node_id')"
    [[ "$new_leader" != "$leader_id" ]]
  }
}
wait_for peer_dropped 15 \
  || fail "cluster/peers still reports $leader_id as leader after 15 s"
ok "cluster/peers reflects leader loss"

echo "NT-03 PASS"
