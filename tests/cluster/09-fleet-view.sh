#!/usr/bin/env bash
# tests/cluster/09-fleet-view.sh
# Asserts the merged fleet METRICS view (cluster plan Phase 3, §2a):
# with `cluster.fleet_view` on, `/api/stats` on any node returns the
# fleet-merged traffic view, self-declared via `fleet_nodes` (the
# count of live nodes merged) instead of just this node's 1/N slice.
#
# Flow:
#   1. Drive traffic at BOTH node A and node B's data planes.
#   2. Log in to node B and read /api/stats.
#   3. Assert `fleet_nodes` is present and ≥ 2 (the merge saw both
#      nodes' TTL'd snapshots) and request_rate > 0.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

require curl
require jq

with_two_nodes

# 1. Traffic on both nodes so both publish non-empty snapshots.
echo "==> driving traffic at node A and node B"
for _ in $(seq 1 15); do
  curl --silent --max-time 1 -o /dev/null "$NODE_A_DATA/" -H "x-aegis-test: fleet-view" || true
  curl --silent --max-time 1 -o /dev/null "$NODE_B_DATA/" -H "x-aegis-test: fleet-view" || true
done

# 2. Let the snapshot publish/merge tick run (publish_interval 1s in
#    the fixture; give a few cycles for both keys to land + merge).
sleep 4

login "$NODE_B_ADMIN" || skip "node B admin login failed (fixture creds?)"
stats="$(authed_get "$NODE_B_ADMIN" /api/stats)"
echo "node B /api/stats: $stats"

fleet_nodes="$(printf '%s' "$stats" | jq -r '.fleet_nodes // -1' 2>/dev/null)"
if [[ "$fleet_nodes" == "-1" ]]; then
  echo "FAIL: /api/stats has no fleet_nodes — merged fleet view not active" >&2
  echo "      (cluster.fleet_view disabled, or snapshot task not publishing)" >&2
  exit 1
fi
if (( fleet_nodes < 2 )); then
  echo "FAIL: fleet_nodes=$fleet_nodes (want ≥2 — both nodes' snapshots merged)" >&2
  exit 1
fi
ok "node B /api/stats is fleet-merged across $fleet_nodes nodes"

rate="$(printf '%s' "$stats" | jq -r '.request_rate // 0' 2>/dev/null)"
# request_rate is a float; compare via awk to avoid bash integer-only.
if awk "BEGIN{exit !($rate > 0)}"; then
  ok "merged request_rate > 0 ($rate rps) — reflects fleet traffic"
else
  echo "FAIL: merged request_rate=$rate (want > 0)" >&2
  exit 1
fi

echo "PASS: 09-fleet-view"
