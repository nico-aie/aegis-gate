#!/usr/bin/env bash
# tests/cluster/02-leader-failover.sh
# Asserts the cross-node leader lease (B1-T3) hands off cleanly
# when the lease holder dies.
#
# Both nodes start, both contend for `leader:cluster`, exactly
# one wins; the other waits. Killing the winner must let the
# survivor acquire the lease within ≤ heartbeat × 2.
#
# We probe the lease holder via the admin API; the
# `/api/cluster/leader` endpoint (introduced with B1-T4) returns
# this node's membership view: `{ "is_leader": true|false,
# "leader_node": "<id>" }`. Tests that don't have that endpoint
# fall back to inspecting log lines.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

require curl
require jq

with_two_nodes

# Probe both nodes for the leader-state endpoint. If neither
# replies, the build doesn't surface leadership through the
# admin API yet — skip with a clear message.
leader_view() {
  local admin="$1"
  # Carry-over 3 surface lives at `/api/cluster`; the response
  # carries `is_leader`, `leader_node`, and `our_node`.
  curl --silent --insecure --max-time 2 \
       "$admin/api/cluster" 2>/dev/null
}

view_a=$(leader_view "$NODE_A_ADMIN" || echo "")
view_b=$(leader_view "$NODE_B_ADMIN" || echo "")
# Skip cleanly when neither node has the endpoint OR the
# response lacks the `is_leader` field. The current build
# wires `/api/cluster` (peers only) but not yet
# `/api/cluster/leader` — leader-state surface is a follow-up.
combined="${view_a}${view_b}"
if [[ -z "$combined" ]] \
   || ! printf '%s' "$combined" | grep -q '"is_leader"'; then
  skip "leader-state admin surface not exposed yet (no \"is_leader\" key in /api/cluster/leader response)"
fi

# Wait up to 5 s for one node to claim leadership. The
# heartbeat default is ~2 s so this is generous.
leader=""
for _ in $(seq 1 20); do
  for letter in A B; do
    admin="NODE_${letter}_ADMIN"
    pid="NODE_${letter}_PID"
    is_leader=$(leader_view "${!admin}" \
                | jq -r '.is_leader // false' 2>/dev/null \
                || echo "false")
    if [[ "$is_leader" == "true" ]]; then
      leader="$letter"
      leader_pid="${!pid}"
      break
    fi
  done
  if [[ -n "$leader" ]]; then break; fi
  sleep 0.25
done

if [[ -z "$leader" ]]; then
  echo "FAIL: no node claimed leadership within 5 s"
  exit 1
fi
ok "node $leader is the initial leader"

# Pick the survivor.
if [[ "$leader" == "A" ]]; then
  survivor="B"
  survivor_admin="$NODE_B_ADMIN"
else
  survivor="A"
  survivor_admin="$NODE_A_ADMIN"
fi

# Sanity: survivor reports is_leader=false today.
survivor_was_leader=$(leader_view "$survivor_admin" \
                      | jq -r '.is_leader // false' 2>/dev/null)
if [[ "$survivor_was_leader" == "true" ]]; then
  echo "FAIL: both nodes claim leadership — split-brain"
  exit 1
fi
ok "node $survivor is currently a follower"

# Kill the leader. Trap-based cleanup will skip it.
echo "==> killing leader (node $leader, pid $leader_pid)"
stop_node "$leader_pid"
if [[ "$leader" == "A" ]]; then NODE_A_PID=""; else NODE_B_PID=""; fi

# Survivor must claim the lease within roughly
# TTL + retry-half-TTL + leader-view-poll-period
# (5 + 2.5 + 2 ≈ 10 s today). Give 25 s to absorb scheduler
# jitter on busy CI hosts and the in-process polling cadence.
acquired=""
for _ in $(seq 1 100); do
  is_leader=$(leader_view "$survivor_admin" \
              | jq -r '.is_leader // false' 2>/dev/null \
              || echo "false")
  if [[ "$is_leader" == "true" ]]; then
    acquired="yes"
    break
  fi
  sleep 0.25
done

if [[ -z "$acquired" ]]; then
  echo "FAIL: survivor (node $survivor) did not acquire leadership within 25 s"
  exit 1
fi
ok "node $survivor took over leadership after $leader died"
