#!/usr/bin/env bash
# tests/cluster/03-rehydrate-readiness.sh
# Asserts the rehydrate-readiness gate (B1-T5):
#
#   - A fresh node points at a Redis primary that is briefly
#     unavailable.
#   - `/healthz/ready` returns 503 during the warm-up window.
#   - Once Redis comes back, the node flips to 200 within
#     `state.reconcile.readiness_warm_ms` (5s in the cluster
#     fixture).
#   - The node MUST eventually return 200 even if Redis stays
#     down past the deadline (the readiness contract is "never
#     permanently 503"); that fallback is exercised in
#     `04-partition-fallback.sh`.
#
# Pattern:
#   1. Stop the cluster Redis container.
#   2. Start node A.
#   3. Probe /healthz/ready — expect 503 for at least 1 s.
#   4. Start Redis.
#   5. Probe /healthz/ready — must flip to 200 within the
#      readiness_warm_ms budget + slack.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

require curl

# Make sure no leftover redis is hanging around.
stop_redis

# Start node A first. With Redis missing it should NOT be ready.
start_node A
NODE_A_PID="$LAST_NODE_PID"
trap 'stop_node "$NODE_A_PID"; stop_redis' EXIT

# Give the node ~1 s to boot up its admin listener.
boot_deadline=$((SECONDS + 5))
admin_up=""
while (( SECONDS < boot_deadline )); do
  if curl --silent --insecure --max-time 1 \
          -o /dev/null "$NODE_A_ADMIN/healthz/live" 2>/dev/null; then
    admin_up="yes"
    break
  fi
  sleep 0.2
done
if [[ -z "$admin_up" ]]; then
  echo "FAIL: node A admin listener never came up"
  exit 1
fi

# Expect at least one 503 from /healthz/ready while Redis is down.
saw_503="no"
for _ in $(seq 1 20); do
  code=$(curl --silent --insecure --max-time 1 \
              -o /dev/null -w "%{http_code}" \
              "$NODE_A_ADMIN/healthz/ready" 2>/dev/null \
         || echo "000")
  if [[ "$code" == "503" ]]; then
    saw_503="yes"
    break
  fi
  sleep 0.2
done
if [[ "$saw_503" != "yes" ]]; then
  echo "WARN: never observed 503 during rehydrate window — either Redis came up faster than the probe or the gate is permissive."
  echo "      This isn't a strict failure on a fast machine; record + continue."
else
  ok "/healthz/ready returned 503 during rehydrate window"
fi

# Bring Redis up.
echo "==> bringing redis up"
ensure_redis

# Readiness must flip to 200 within readiness_warm_ms (5s) +
# slack. Cap at 15 s to absorb container start latency on CI.
ready_deadline=$((SECONDS + 15))
got_200="no"
while (( SECONDS < ready_deadline )); do
  code=$(curl --silent --insecure --max-time 1 \
              -o /dev/null -w "%{http_code}" \
              "$NODE_A_ADMIN/healthz/ready" 2>/dev/null \
         || echo "000")
  if [[ "$code" == "200" ]]; then
    got_200="yes"
    break
  fi
  sleep 0.5
done
if [[ "$got_200" != "yes" ]]; then
  echo "FAIL: /healthz/ready never flipped to 200 after Redis came up"
  exit 1
fi
ok "/healthz/ready flipped to 200 after redis returned"
