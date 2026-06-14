#!/usr/bin/env bash
# 05-websocket-block.sh — PROVE WebSocket text-frame inspection blocks
# attacks inside the tunnel (not just the handshake).
#
# This is the demo companion to 04-websocket.sh (which only proves the
# handshake passes through). Here we open a real WS tunnel through the
# WAF to the echo upstream, send a benign frame then an attack frame,
# and print FOUR independent receipts that the WAF read inside the
# WebSocket and blocked the attack:
#
#   1. CLIENT      — the attack frame's socket is closed with WS 1008
#   2. AUDIT       — a `websocket_frame_block` row (action/rule_id/score/mode)
#   3. METRIC      — aegis_websocket_frame_block_total{route,tag} increments
#   4. LIFECYCLE   — websocket_open … websocket_close bracket the tunnel
#
# Requires: `make run-dev` running (WAF data :8080 + admin :9443 + the
# WS-capable mock upstream on :9999), and `node`.

HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

require node
require curl
ensure_admin_ready

WS_URL="${WS_URL:-ws://127.0.0.1:8080/ws}"
AUDIT_LOG="${AEGIS_AUDIT_LOG:-/tmp/aegis-dev-audit.jsonl}"
METRICS_URL="$AEGIS_ADMIN/metrics"
CLIENT="$HERE/ws-attack-client.mjs"

BENIGN='{"msg":"hello chat"}'
# Default attack payload: a classic SQLi probe inside the WS text frame.
# Built as its own var so the JSON `{ }` don't collide with bash's
# `${VAR:-default}` brace parsing.
ATTACK_DEFAULT='{"msg":"1'\'' OR 1=1-- UNION SELECT"}'
ATTACK="${ATTACK_PAYLOAD:-$ATTACK_DEFAULT}"

echo "==> WebSocket FRAME-BLOCK proof on $WS_URL"
echo "    audit log: $AUDIT_LOG"
echo

# --- snapshot the metric + audit-log offset BEFORE we send anything ---
metric_before=$(curl --silent --max-time 3 "$METRICS_URL" \
  | awk '/^aegis_websocket_frame_block_total/ {s+=$NF} END {print s+0}')
audit_lines_before=0
[ -f "$AUDIT_LOG" ] && audit_lines_before=$(wc -l < "$AUDIT_LOG" | tr -d ' ')

# ---------------------------------------------------------------------
# Beat 1 — benign frame. Expect the backend echo (frame ALLOWED).
# ---------------------------------------------------------------------
echo "--- [1/2] benign frame: $BENIGN"
benign_out=$(node "$CLIENT" "$WS_URL" "$BENIGN")
echo "$benign_out"
benign_outcome=$(echo "$benign_out" | sed -n 's/.*OUTCOME=\([a-z_]*\).*/\1/p' | head -1)
echo

# ---------------------------------------------------------------------
# Beat 2 — attack frame. Expect a WS 1008 close (frame BLOCKED).
# ---------------------------------------------------------------------
echo "--- [2/2] attack frame: $ATTACK"
attack_out=$(node "$CLIENT" "$WS_URL" "$ATTACK")
echo "$attack_out"
attack_outcome=$(echo "$attack_out" | sed -n 's/.*OUTCOME=\([a-z_]*\).*/\1/p' | head -1)
attack_close=$(echo "$attack_out" | sed -n 's/.*CLOSE_CODE=\([0-9-]*\).*/\1/p' | head -1)
echo

# Give the async audit/metric emission a moment to flush.
sleep 1

# ---------------------------------------------------------------------
# Receipts
# ---------------------------------------------------------------------
echo "================ EVIDENCE ================"

# Receipt 1 — client outcome.
echo
echo "[1] CLIENT"
if [ "$benign_outcome" = "echo" ]; then
  echo "    benign  → echoed (ALLOWED)         ✓"
else
  echo "    benign  → $benign_outcome (expected echo) ✗"
fi
if [ "$attack_outcome" = "closed" ] && [ "$attack_close" = "1008" ]; then
  echo "    attack  → closed with WS 1008 (BLOCKED) ✓"
else
  echo "    attack  → $attack_outcome / code $attack_close (expected closed/1008) ✗"
fi

# Receipt 2 — audit row(s) for websocket_frame_block.
echo
echo "[2] AUDIT  (new websocket_frame_block rows in $AUDIT_LOG)"
if [ -f "$AUDIT_LOG" ]; then
  tail -n +"$((audit_lines_before + 1))" "$AUDIT_LOG" \
    | grep '"websocket_frame_block"' \
    | tail -3 \
    | sed 's/^/    /' \
    || echo "    (none found)"
else
  echo "    audit log not found — is the jsonl sink configured? (dev.yaml → $AUDIT_LOG)"
fi

# Receipt 3 — metric delta.
echo
echo "[3] METRIC aegis_websocket_frame_block_total"
metric_after=$(curl --silent --max-time 3 "$METRICS_URL" \
  | awk '/^aegis_websocket_frame_block_total/ {s+=$NF} END {print s+0}')
echo "    before=$metric_before  after=$metric_after  delta=$((metric_after - metric_before))"
curl --silent --max-time 3 "$METRICS_URL" \
  | grep '^aegis_websocket_frame_block_total' | sed 's/^/    /' || true

# Receipt 4 — open/close lifecycle.
echo
echo "[4] LIFECYCLE (websocket_open / websocket_close this run)"
if [ -f "$AUDIT_LOG" ]; then
  tail -n +"$((audit_lines_before + 1))" "$AUDIT_LOG" \
    | grep -oE '"websocket_(open|close|frame_block)"' \
    | sort | uniq -c | sed 's/^/    /' || true
fi

echo
echo "=========================================="

# Overall verdict.
if [ "$benign_outcome" = "echo" ] && [ "$attack_outcome" = "closed" ] \
   && [ "$attack_close" = "1008" ] && [ "$((metric_after - metric_before))" -ge 1 ]; then
  ok "WS frame inspection blocked the in-tunnel attack on all surfaces"
else
  fail "expected benign=echo, attack=closed/1008, and metric delta ≥ 1 — see above"
fi
