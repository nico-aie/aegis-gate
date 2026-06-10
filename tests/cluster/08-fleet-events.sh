#!/usr/bin/env bash
# tests/cluster/08-fleet-events.sh
# Asserts cross-node fleet EVENT fanout (cluster plan Phase 2, §2b —
# the ≤ 5 s logs/events SLA): a security event decided on node A shows
# up on node B's dashboard SSE feed, tagged with the originating node.
#
# Mechanism under test: node A publishes its AuditEvents to the shared
# Redis `fleet:events` channel; node B's subscriber re-emits them onto
# its fleet-event bus, which the dashboard SSE merges in. Remote events
# carry `fields.origin_node` (here "waf-a"); node B's own events don't.
#
# `/dashboard/sse` is an open (no-auth) endpoint, so we can stream it
# directly. Flow:
#   1. Start streaming node B's /dashboard/sse to a temp file.
#   2. Fire an SQLi probe at node A's data plane (→ detection event).
#   3. Within the SLA window, node B's stream must contain a frame
#      with origin_node=waf-a.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

require curl

with_two_nodes

SSE_OUT="$(mktemp -t aegis-sse.XXXXXX)"
cleanup_sse() { [[ -n "${SSE_PID:-}" ]] && kill "$SSE_PID" 2>/dev/null || true; rm -f "$SSE_OUT"; }
trap 'cleanup_sse; stop_node "$NODE_A_PID"; stop_node "$NODE_B_PID"' EXIT

# 1. Stream node B's SSE in the background (≤ 8 s, well past the 5 s SLA).
curl --silent --no-buffer --max-time 8 \
     "$NODE_B_ADMIN/dashboard/sse" > "$SSE_OUT" 2>/dev/null &
SSE_PID=$!
sleep 1   # let the subscription establish before generating the event

# 2. Generate a detection event on node A (SQLi probe).
for _ in $(seq 1 3); do
  curl --silent --max-time 2 -o /dev/null \
       -H "x-aegis-test: fleet-event-fanout" \
       "$NODE_A_DATA/?q=1%27%20OR%20%271%27%3D%271" 2>/dev/null || true
  sleep 0.3
done

# 3. Poll node B's stream for an origin-tagged remote event (≤ 5 s).
found=""
for _ in $(seq 1 10); do
  if grep -q 'origin_node' "$SSE_OUT" 2>/dev/null \
     && grep -q 'waf-a' "$SSE_OUT" 2>/dev/null; then
    found="yes"
    break
  fi
  sleep 0.5
done

if [[ -z "$found" ]]; then
  echo "FAIL: node A's event did not reach node B's SSE within ~5s" >&2
  echo "      (cross-node fleet_events fanout not observed)" >&2
  echo "      node B SSE capture (first 20 lines):" >&2
  head -20 "$SSE_OUT" >&2 || true
  exit 1
fi
ok "node A's event reached node B's SSE feed, tagged origin_node=waf-a (≤5s)"

echo "PASS: 08-fleet-events"
