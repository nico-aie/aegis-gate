#!/usr/bin/env bash
# NT-11 — AI confidence_threshold: live verdict effect (hot-swap)
#
# The whole point of the runtime atomic: changing the threshold
# without rebuilding the detector must flip a borderline verdict
# from allow → block (and back). We drive a payload that the model
# rates "borderline malicious" (prob_attack ≈ 0.55-0.65), set the
# gate ABOVE → allowed, then PUT a lower gate → blocked.
#
# Gated by AEGIS_AI_E2E=1 because it needs:
#   • `--features ai` build
#   • an ONNX model linked (`make ai-link MODEL=<path>`)
#   • cfg.ai.enabled true OR the dashboard's PUT /api/ai/enabled true
#
# When env-gated off, the test exits 0 (skip) — run-all.sh records
# that as a skip in the report.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

if [[ "${AEGIS_AI_E2E:-0}" != "1" ]]; then
  skip "AEGIS_AI_E2E=1 not set; the live-effect test needs a real ONNX model"
fi

require curl; require jq; require docker

trap stop_cluster EXIT
start_cluster
login "$NODE_A_ADMIN"

# Confirm AI is actually in the chain on this build/config.
en="$(admin_get "$NODE_A_ADMIN" "/api/ai/enabled")"
[[ "$(printf '%s' "$en" | jq -r '.feature_present')" == "true" ]] \
  || skip "ai feature not present in this binary"
if [[ "$(printf '%s' "$en" | jq -r '.enabled')" != "true" ]]; then
  admin_put "$NODE_A_ADMIN" "/api/ai/enabled" '{"enabled": true}' >/dev/null
  sleep 0.5
fi
ok "AI detector enabled"

# A borderline payload — a mildly suspicious request the model is
# expected to rate around 0.55-0.65. Tune via env if the local model
# rates this differently:
#   AEGIS_AI_BORDERLINE_PATH=/api/items?id=1%27%20OR%201=1
BORDERLINE_PATH="${AEGIS_AI_BORDERLINE_PATH:-/api/items?id=1%27%20OR%201=1}"

# Phase 1 — High gate (0.95). Even a borderline attack should NOT
# emit the ai signal; the request flows through unless other
# detectors fire (we pick a payload the regex SQLi detector also
# catches as a safety check OR we use a non-regex borderline).
# To make the test deterministic, we DISABLE the sqli regex for the
# duration so only AI can affect the verdict.
admin_put "$NODE_A_ADMIN" "/api/detectors" \
  '{"base": {"sqli": false}}' >/dev/null
sleep 0.5

admin_put "$NODE_A_ADMIN" "/api/ai/confidence" \
  '{"confidence_threshold": 0.95}' >/dev/null
sleep 1  # let the atomic write settle (it's relaxed)

code_high="$(curl --silent --insecure --max-time 5 -o /dev/null \
              -w '%{http_code}' "$NODE_A_DATA$BORDERLINE_PATH")"
echo "high-gate (0.95) response: $code_high"

# Phase 2 — Low gate (0.30). Same request should now be blocked.
admin_put "$NODE_A_ADMIN" "/api/ai/confidence" \
  '{"confidence_threshold": 0.30}' >/dev/null
sleep 1

code_low="$(curl --silent --insecure --max-time 5 -o /dev/null \
             -w '%{http_code}' "$NODE_A_DATA$BORDERLINE_PATH")"
echo "low-gate (0.30) response: $code_low"

# Restore sqli regex so the post-test cluster is back to normal.
admin_put "$NODE_A_ADMIN" "/api/detectors" \
  '{"base": {"sqli": true}}' >/dev/null || true

# Expected: high-gate → upstream-shape (200/502/etc., NOT 403);
# low-gate → 403 from the AI signal pushing risk over the strike.
if [[ "$code_high" == "403" ]]; then
  fail "high-gate ALSO blocked — payload may not be borderline for this model; override AEGIS_AI_BORDERLINE_PATH"
fi
if [[ "$code_low" != "403" ]]; then
  fail "low-gate did NOT block — atomic hot-swap may have regressed (got HTTP $code_low)"
fi
ok "threshold hot-swap flipped verdict: high=$code_high → low=$code_low"

echo "NT-11 PASS"
