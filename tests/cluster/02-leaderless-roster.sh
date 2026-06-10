#!/usr/bin/env bash
# tests/cluster/02-leaderless-roster.sh
# Asserts the LEADERLESS roster (cluster plan Phase 1).
#
# The cluster has no leader: `/api/cluster` returns a flat peer list +
# `our_node`, with NO `is_leader` / `leader_node` fields. Each node's
# membership heartbeat (`members:<id>`) means both nodes should see
# each other in the roster within a couple of poll cycles.
#
# Asserts:
#   - each node reports its own `our_node` (waf-a)
#   - neither response carries `is_leader` or `leader_node`
#   - the roster converges to BOTH nodes as peers

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

require curl
require jq

with_two_nodes

# /api/cluster is admin-auth gated — log in to each node (no shared
# session state across nodes).
login "$NODE_A_ADMIN" || skip "node A admin login failed (fixture creds?)"
view_a="$(authed_get "$NODE_A_ADMIN" /api/cluster)"

# our_node correctness.
on_a="$(printf '%s' "$view_a" | jq -r '.our_node // ""')"
[[ "$on_a" == "waf-a" ]] || { echo "FAIL: node A our_node='$on_a' (want waf-a); resp: $view_a"; exit 1; }
ok "node A reports our_node=waf-a"

# Leaderless: the removed fields must be ABSENT (not just false).
if printf '%s' "$view_a" | jq -e 'has("is_leader") or has("leader_node")' >/dev/null 2>&1; then
  echo "FAIL: /api/cluster still carries is_leader/leader_node — not leaderless"; exit 1
fi
ok "no is_leader / leader_node fields (leaderless)"

# Roster convergence: node B should list both waf-a and waf-b within
# a few membership-poll cycles (heartbeat 15s TTL, poll ~5s).
login "$NODE_B_ADMIN" || skip "node B admin login failed (fixture creds?)"
converged=""
peers=""
for _ in $(seq 1 24); do
  peers="$(authed_get "$NODE_B_ADMIN" /api/cluster | jq -r '.peers[].id' 2>/dev/null | sort | tr '\n' ',')"
  if [[ "$peers" == *"waf-a"* && "$peers" == *"waf-b"* ]]; then
    converged="$peers"
    break
  fi
  sleep 1
done
[[ -n "$converged" ]] || { echo "FAIL: roster did not converge to {waf-a,waf-b} within 24s (saw: ${peers:-none})"; exit 1; }
ok "roster converged to both nodes as peers ($converged)"

echo "PASS: 02-leaderless-roster"
