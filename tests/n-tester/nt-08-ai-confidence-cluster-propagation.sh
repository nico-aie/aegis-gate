#!/usr/bin/env bash
# NT-08 — AI confidence_threshold propagates to other nodes
#
# PUT on node-A; the persisted config doc must reflect on node-B's
# GET /api/config.ai.confidence_threshold (the SOURCE OF TRUTH) and
# node-B's `default` (loaded at boot) plus the ACK key prove the
# new doc activated cluster-wide.
#
# KNOWN GAP (named explicitly): the LIVE atomic on node-B is NOT
# updated by the watcher today — `apply_cfg_change_to_ai` does not
# carry the threshold yet (it's a separate follow-up to the e77d379
# commit). So this test asserts the persisted doc + ACK, NOT a live
# read from node-B's `/api/ai/confidence`. Once the apply extension
# ships, replace this assertion with the live-read shape (see the
# `# TODO(live-propagate)` block below).

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

require curl; require jq; require docker

trap stop_cluster EXIT
start_cluster
login "$NODE_A_ADMIN"

target="0.31"
put="$(admin_put "$NODE_A_ADMIN" "/api/ai/confidence" \
       "{\"confidence_threshold\": $target}")"
v_put="$(printf '%s' "$put" | jq -r '.version')"
ok "PUT activated v=$v_put on node-A"

# Node-B: the config-plane GET must reflect the new version + the
# patched ai.confidence_threshold in the doc.
login "$NODE_B_ADMIN"
b_doc_caught_up() {
  local resp v ai_conf
  resp="$(admin_get "$NODE_B_ADMIN" "/api/config")"
  v="$(printf '%s' "$resp" | jq -r '.version // empty')"
  [[ "$v" == "$v_put" ]] || return 1
  # Drift overlay exposes the live ai_confidence_threshold (it's
  # mirrored alongside ai_enabled — verify it tracks the patched value).
  ai_conf="$(printf '%s' "$resp" | jq -r '.overlay.ai_confidence_threshold // empty')"
  if [[ -n "$ai_conf" ]]; then
    # 2026-05-30: float-tolerant — f32 round-trip widens 0.31 etc.
    floats_eq "$ai_conf" "$target"
    return $?
  fi
  # Older overlay shape: just confirm version.
  return 0
}
wait_for b_doc_caught_up 10 \
  || fail "node-B's /api/config did not catch up to v=$v_put"
ok "node-B's config doc shows v=$v_put"

# ACK keys: both nodes must record their applied version. 2026-05-30
# (QC R2-002): wait_for to give the watcher its first poll.
acks_present() {
  local n
  n="$(docker exec "$AEGIS_REDIS_NAME" sh -c \
       'redis-cli --scan --pattern "config:waf:applied:*"' \
       | wc -l | tr -d ' ' || true)"
  (( n >= 2 ))
}
wait_for acks_present 10 \
  || fail "expected ≥ 2 ACK keys within 10 s of PUT — watcher may not be polling"
ok "ACK keys present (≥ 2)"

# 2026-05-30 — apply_cfg_change_to_ai now carries the threshold, so
# node-B's LIVE atomic flips on its next watcher poll. Assert it.
b_live_at_target() {
  local v
  v="$(admin_get "$NODE_B_ADMIN" "/api/ai/confidence" \
       | jq -r '.confidence_threshold // empty')"
  floats_eq "$v" "$target"
}
wait_for b_live_at_target 10 \
  || fail "node-B live threshold did not converge to $target within 10 s"
ok "node-B live threshold converged: $target"

echo "NT-08 PASS"
