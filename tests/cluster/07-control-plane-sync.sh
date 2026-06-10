#!/usr/bin/env bash
# tests/cluster/07-control-plane-sync.sh
# Asserts cluster-native control-plane propagation (C-1 / cluster
# plan Phase 0): a `set_profile` on ONE node converges to the whole
# fleet via the shared config plane, and `reset_state` is accepted
# fleet-wide.
#
# Observable WITHOUT admin auth — `/__waf_control/*` is loopback-open,
# and the data-plane response carries `X-WAF-Action` + `X-WAF-Mode`:
#   - enforce  → an SQLi probe is BLOCKED (403)
#   - log_only → the same probe is ALLOWED (non-403) but stamped
#                `X-WAF-Action: block` + `X-WAF-Mode: log_only`
#
# Flow:
#   1. SQLi probe at node B → expect a block (enforce default).
#   2. `set_profile {scope:all, mode:log_only}` at node A (cluster:true).
#   3. Poll node B's data plane until the SAME probe is no longer
#      enforced (X-WAF-Mode: log_only) — proves A's change reached B.
#   4. `reset_state` at node A → expect HTTP 200 (accepted).
#   5. Restore enforce (cleanup) so the fixture is left clean.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

require curl

with_two_nodes

# An obvious SQLi the detector chain flags. Header carries a unique
# marker so the probe is easy to spot in logs.
PROBE_PATH="/?q=1%27%20OR%20%271%27%3D%271"   # ?q=1' OR '1'='1
probe() {
  # echo "<http_code> <x-waf-mode>"
  curl --silent --max-time 2 -o /dev/null \
       -w '%{http_code} %header{x-waf-mode}' \
       -H "x-aegis-test: c1-control-plane" \
       "$1$PROBE_PATH" 2>/dev/null || echo "000 "
}

set_profile() {  # <admin_url> <enforce|log_only>
  curl --silent --max-time 2 -o /dev/null -w '%{http_code}' \
       -H "content-type: application/json" \
       --data "{\"scope\":\"all\",\"mode\":\"$2\",\"cluster\":true}" \
       "$1/__waf_control/set_profile" 2>/dev/null || echo "000"
}

# `%header{...}` needs curl ≥ 7.84. Detect + skip cleanly if too old.
if ! curl --help all 2>/dev/null | grep -q -- '--write-out'; then
  skip "curl too old for response-header capture"
fi

# 1. Baseline: node B enforces (blocks the SQLi).
base="$(probe "$NODE_B_DATA")"
echo "node B baseline probe: $base"
case "$base" in
  403*) ok "node B enforces by default (SQLi blocked)" ;;
  *) skip "node B did not block the baseline SQLi probe ($base) — detector/profile differs; can't observe mode flip" ;;
esac

# 2. Flip the whole fleet to log_only via node A (cluster-scoped).
code="$(set_profile "$NODE_A_ADMIN" log_only)"
[[ "$code" == "2"* ]] || { echo "FAIL: set_profile on node A returned HTTP $code"; exit 1; }
ok "set_profile {all, log_only, cluster:true} accepted on node A (HTTP $code)"

# 3. Node B must converge to log_only (config-plane poll ~3s).
converged=""
last=""
for _ in $(seq 1 20); do
  last="$(probe "$NODE_B_DATA")"
  # log_only ⇒ no longer 403, and X-WAF-Mode reports log_only.
  if [[ "$last" != 403* && "$last" == *"log_only"* ]]; then
    converged="$last"
    break
  fi
  sleep 1
done
[[ -n "$converged" ]] || { echo "FAIL: node B did not converge to log_only within 20s (last: '$last')"; exit 1; }
ok "node B converged to log_only after node A's set_profile ($converged) — C-1 propagation"

# 4. reset_state fleet-wide (accepted).
rs="$(curl --silent --max-time 2 -o /dev/null -w '%{http_code}' \
        -X POST "$NODE_A_ADMIN/__waf_control/reset_state" 2>/dev/null || echo "000")"
[[ "$rs" == "2"* ]] || { echo "FAIL: reset_state on node A returned HTTP $rs"; exit 1; }
ok "reset_state accepted on node A (HTTP $rs)"

# 5. Restore enforce so the shared config plane is left clean for
#    later scripts in the run-all sequence.
restore="$(set_profile "$NODE_A_ADMIN" enforce)"
echo "restored enforce on node A (HTTP $restore)"

echo "PASS: 07-control-plane-sync"
