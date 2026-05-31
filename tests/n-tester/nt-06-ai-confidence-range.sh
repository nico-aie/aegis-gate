#!/usr/bin/env bash
# NT-06 — PUT /api/ai/confidence range validation
#
# The handler enforces: finite f32 in [0.0, 1.0]. Anything outside →
# 400 with Validation reason. Valid boundaries (0.0, 0.5, 1.0) accept.
#
# This test verifies the validator without needing the AI feature to
# be built — the handler validates BEFORE checking the writer.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

require curl; require jq; require docker

trap stop_cluster EXIT
start_cluster
login "$NODE_A_ADMIN"

# --- Invalid: must 400 ----------------------------------------------------
INVALIDS=(
  '{"confidence_threshold": -0.1}'
  '{"confidence_threshold": 1.1}'
  '{"confidence_threshold": 2}'
  '{"confidence_threshold": "abc"}'
  '{"confidence_threshold": null}'
  '{}'
)
for body in "${INVALIDS[@]}"; do
  out="$(http_status "$NODE_A_ADMIN" PUT "/api/ai/confidence" "$body")"
  code="$(printf '%s' "$out" | tail -1)"
  payload="$(printf '%s' "$out" | sed '$d')"
  case "$code" in
    400|422)
      ok "rejected: $body → $code"
      ;;
    *)
      fail "expected 400/422 for $body, got $code: $payload"
      ;;
  esac
done

# --- Valid boundaries: must 200 ------------------------------------------
for v in 0.0 0.5 1.0; do
  out="$(http_status "$NODE_A_ADMIN" PUT "/api/ai/confidence" \
         "{\"confidence_threshold\": $v}")"
  code="$(printf '%s' "$out" | tail -1)"
  body="$(printf '%s' "$out" | sed '$d')"
  [[ "$code" == "200" ]] \
    || fail "expected 200 for $v, got $code: $body"
  echoed="$(printf '%s' "$body" | jq -r '.confidence_threshold')"
  # 2026-05-30: float-tolerant — the PUT response is the operator's
  # number, no f32 round-trip happens here, but use the same helper
  # across the suite for consistency.
  floats_eq "$echoed" "$v" \
    || fail "echo mismatch for $v: got $echoed"
  ok "accepted: $v → 200 (echo=$echoed)"
done

echo "NT-06 PASS"
