#!/usr/bin/env bash
# NT-01 — Cluster config plane: convergence
#
# Mutate the shared config doc on node-A; assert node-B converges
# within the watcher's poll window (~3 s, capped at 10 s) AND that
# both nodes write their per-node ACK key.
#
# Verifies:
#   • PUT /api/config{,/<field>} on A → store update
#   • B's redis_source watcher picks it up
#   • config:waf:applied:<node_id> ACK keys exist for both nodes
#   • GET /api/config on both nodes returns the same version

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

require curl; require jq; require docker

trap stop_cluster EXIT
start_cluster
login "$NODE_A_ADMIN"

# Mutate via a well-folded toggle (response_filter.scrub_stack_traces).
# We pick this one so the convergence assertion doesn't depend on AI
# being built in.
read_pre_a="$(admin_get "$NODE_A_ADMIN" "/api/response-filter")"
pre_scrub="$(printf '%s' "$read_pre_a" | jq -r '.scrub_stack_traces // true')"
target=$([[ "$pre_scrub" == "true" ]] && echo false || echo true)

put_resp="$(admin_put "$NODE_A_ADMIN" "/api/response-filter" \
  "{\"scrub_stack_traces\": $target}")"
new_version="$(printf '%s' "$put_resp" | jq -r '.version // empty')"
[[ -n "$new_version" ]] \
  || fail "PUT did not return a version: $put_resp"
ok "PUT on A activated version $new_version"

# Re-login on B so we have a B-side session for the GET.
A_COOKIE="$COOKIE"; A_CSRF="$CSRF"
login "$NODE_B_ADMIN"

# Convergence poll on B.
converged_on_b() {
  local v
  v="$(admin_get "$NODE_B_ADMIN" "/api/config" \
       | jq -r '.version // empty')"
  [[ "$v" == "$new_version" ]]
}
wait_for converged_on_b 10 \
  || fail "node-B did not converge to version $new_version within 10 s"
ok "node-B converged to version $new_version"

# ACK keys: both nodes should have written config:waf:applied:<node_id>.
# 2026-05-30 (QC R2-002): /api/config reads the doc straight from Redis,
# so `converged_on_b` returns in milliseconds — long before each node's
# watcher loop has had its ~3 s tick to call `record_applied`. Wait
# for the watcher to land its first post-PUT poll rather than scanning
# instantly.
acks_present() {
  local n
  n="$(docker exec "$AEGIS_REDIS_NAME" redis-cli --no-raw \
       --scan --pattern 'config:waf:applied:*' \
       | wc -l | tr -d ' ' || true)"
  (( n >= 2 ))
}
wait_for acks_present 10 \
  || fail "expected ≥ 2 ACK keys within 10 s of PUT — watcher may not be polling"
ok "ACK keys present (≥ 2)"

# Both nodes' GETs agree on the live value too (not just the version).
COOKIE="$A_CSRF"; CSRF="$A_CSRF"
login "$NODE_A_ADMIN"
live_a="$(admin_get "$NODE_A_ADMIN" "/api/response-filter" \
         | jq -r '.scrub_stack_traces')"
login "$NODE_B_ADMIN"
live_b="$(admin_get "$NODE_B_ADMIN" "/api/response-filter" \
         | jq -r '.scrub_stack_traces')"
[[ "$live_a" == "$target" && "$live_b" == "$target" ]] \
  || fail "live value disagrees: A=$live_a B=$live_b (target=$target)"
ok "live value coheres across nodes ($target)"

echo "NT-01 PASS"
