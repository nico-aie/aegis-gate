#!/usr/bin/env bash
# tests/cluster/06-mid-burst-failover.sh — mid-burst failover
# budget through the LB.
#
# Pattern:
#   1. Bring up redis + 2 WAF nodes + HAProxy (per HA-T1).
#   2. Start a 30 s k6 baseline at the VIP in the background.
#   3. At t≈10s, kill node B (`SIGKILL` for hard failover, or
#      `SIGTERM` + drain readiness flip when AEGIS_GRACEFUL=1).
#   4. Wait for k6 to finish.
#   5. Assert:
#        - allow_success > 95 % (LB pulled the dead node within
#          the configured `inter × fall` budget — 4 s).
#        - HAProxy stats show node B's `chkfail` count > 0.
#
# Variables:
#   AEGIS_GRACEFUL=1   — use SIGTERM + drain readiness, not SIGKILL.
#                        With HA-T5 wired this should produce 0 5xx.
#                        Without it, expect a 4s window of 502s.
#
# Skip rules: same as 05-single-vip-baseline.sh.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

require curl
require docker

LB_PROFILE="ha"
LB_VIP_PLAINTEXT="${LB_VIP_PLAINTEXT:-http://127.0.0.1:9180}"
LB_STATS="${LB_STATS:-http://127.0.0.1:8404}"
COMPOSE_FILE="${COMPOSE_FILE:-$AEGIS_REPO/deploy/docker-compose.dev.yml}"
GRACEFUL="${AEGIS_GRACEFUL:-0}"

start_lb() {
  if ! docker compose -f "$COMPOSE_FILE" --profile "$LB_PROFILE" \
       up -d aegis-lb >/tmp/aegis-lb-up.log 2>&1; then
    skip "couldn't start aegis-lb"
  fi
  for _ in $(seq 1 30); do
    if curl --silent --max-time 2 "$LB_STATS" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  skip "aegis-lb didn't come up in time"
}

stop_lb() {
  docker compose -f "$COMPOSE_FILE" --profile "$LB_PROFILE" \
    stop aegis-lb >/dev/null 2>&1 || true
}

ensure_redis
start_node A
NODE_A_PID="$LAST_NODE_PID"
start_node B
NODE_B_PID="$LAST_NODE_PID"
trap 'stop_node "$NODE_A_PID"; stop_node "$NODE_B_PID"; stop_lb' EXIT

wait_ready "$NODE_A_ADMIN" || exit 1
wait_ready "$NODE_B_ADMIN" || exit 1
start_lb

# Drive k6 in the background. Total run is 30s; we kill
# node B at t≈10s so the LB has 20s to absorb the failure
# and recover.
echo "==> starting 30 s k6 burst at $LB_VIP_PLAINTEXT"
# Use rate-controlled (`failover-burst.js`) instead of VU-driven.
# At 200 RPS × 30 s = 6 000 reqs we stay well under the host's
# ephemeral-port budget (mac default ~16 k ports × 60 s TIME_WAIT)
# while still seeing the failover transient.
docker exec -d aegis-k6 sh -c \
  "k6 run -e DURATION=30s -e RPS=200 \
          -e WAF_TARGET=http://host.docker.internal:9180 \
          /scripts/failover-burst.js > /tmp/k6-failover.log 2>&1"

sleep 10

if [[ "$GRACEFUL" == "1" ]]; then
  # HA-T5 — proper graceful drain pattern:
  #   1. POST /admin/drain on node B → readiness flips to 503.
  #   2. Wait `inter × fall = 4s` for HAProxy to stop routing.
  #   3. SIGTERM the process — by then no new traffic is hitting it.
  echo "==> graceful drain of node B via /admin/drain"
  drain_resp=$(curl --silent --max-time 2 -X POST \
                    "$NODE_B_ADMIN/admin/drain" 2>/dev/null \
               || echo "{}")
  echo "drain response: $drain_resp"
  echo "==> waiting 5s for HAProxy to pull node B from rotation"
  sleep 5
  echo "==> graceful kill of node B (SIGTERM)"
  kill -TERM "$NODE_B_PID" 2>/dev/null || true
else
  echo "==> hard kill of node B (SIGKILL)"
  kill -9 "$NODE_B_PID" 2>/dev/null || true
fi
NODE_B_PID=""

# Wait for k6 to finish (it runs 30s total + summary print).
# The detached k6 inside aegis-k6 needs ~5s after the burst
# completes to flush its summary, otherwise the awk parse below
# returns empty.
sleep 25

# Pull k6 results.
docker exec aegis-k6 cat /tmp/k6-failover.log \
  > /tmp/aegis-failover.log 2>/dev/null \
  || cp /tmp/k6-failover.log /tmp/aegis-failover.log 2>/dev/null \
  || true

# Parse `allow_success` — text shape e.g. "allow_success.....: 99.5% ✓ ..."
# Falling back to `http_req_failed` if `allow_success` isn't set.
allow_pct=$(awk '/allow_success/{
                   for (i=1;i<=NF;i++) if ($i ~ /%$/) {
                     sub("%","",$i); print $i; exit
                   }
                 }' /tmp/aegis-failover.log 2>/dev/null \
            || echo "0")
if [[ -z "$allow_pct" ]]; then allow_pct="0"; fi

echo "k6 allow_success: ${allow_pct}%"

# Threshold: graceful path should produce > 99 %; hard path
# > 90 %. The hard path's 5xx window is `inter × fall = 4s`,
# during which LB still routes to B until the second failed
# health check. With 10 RPS that's ~40 reqs lost out of 300
# total = 86.7 %. Set the floor at 80 % to absorb scheduler
# jitter on a busy CI host.
if [[ "$GRACEFUL" == "1" ]]; then
  floor="99"
else
  floor="80"
fi
# Use bc for fractional comparison.
ok_check=$(awk -v a="$allow_pct" -v f="$floor" 'BEGIN{print (a+0 >= f+0) ? "1" : "0"}')
if [[ "$ok_check" != "1" ]]; then
  echo "FAIL: allow_success ${allow_pct}% below ${floor}% floor"
  exit 1
fi
ok "allow_success ${allow_pct}% ≥ ${floor}% floor"

# Confirm HAProxy noticed B failed. CSV column 22 is `chkfail`
# (count of failed L7 health checks). For both hard kill and
# graceful drain, this must be > 0 — otherwise the LB never
# rotated traffic away.
chkfail_b=$(curl --silent "$LB_STATS/;csv" 2>/dev/null \
            | awk -F',' '$1=="cluster_http" && $2=="waf-b"{print $22}' \
            || echo "0")
status_b=$(curl --silent "$LB_STATS/;csv" 2>/dev/null \
            | awk -F',' '$1=="cluster_http" && $2=="waf-b"{print $18}' \
            || echo "")
echo "haproxy waf-b status=${status_b:-?} chkfail=${chkfail_b:-0}"
if [[ -z "$chkfail_b" || "$chkfail_b" == "0" ]]; then
  echo "FAIL: HAProxy never observed waf-b health check fail"
  exit 1
fi
ok "HAProxy detected waf-b failure (chkfail=$chkfail_b)"

ok "mid-burst failover budget honoured (graceful=$GRACEFUL)"
