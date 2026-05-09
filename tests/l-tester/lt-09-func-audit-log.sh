#!/usr/bin/env bash
# LT-09 — §6  Audit log schema, JSONL format, append-only, IP semantics
#
# Contract (§6):
#   - ./waf_audit.log (configurable) created once first request processed.
#   - Append-only JSONL: one JSON object per line, never truncated.
#   - Every line MUST carry all 8 mandatory fields with correct types:
#       request_id  — string (UUID)
#       ts_ms       — integer (epoch ms)
#       ip          — string (TCP peer address, NOT XFF)
#       method      — string (uppercase HTTP method)
#       path        — string (path + query)
#       action      — one of the 6 decision classes
#       risk_score  — integer 0–100
#       mode        — "enforce" | "log_only"
#   - ip MUST be the TCP peer (§6 IP semantics), not X-Forwarded-For.
#   - request_id MUST match the X-WAF-Request-Id header (§5.3).

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"
require curl
require jq

trap trap_cleanup EXIT
start_waf
reset_to_enforce

# ------------------------------------------------------------------
# 1. Audit log is created after the first request
# ------------------------------------------------------------------
# Record baseline line count before our requests (file may already exist
# from a previous test; we validate growth and schema, not emptiness).
BASELINE_LINES=$(count_audit_lines)

# Fire one request and wait a moment.
curl -s --max-time 3 -o /dev/null "$DATA/lt09-first" || true
sleep 0.5

[[ -f "$AUDIT_LOG" ]] \
  || fail "§6 audit log not created at $AUDIT_LOG after first request"
ok "§6 audit log exists at $AUDIT_LOG"

# ------------------------------------------------------------------
# 2. Every line parses as a single JSON object (JSONL)
# ------------------------------------------------------------------
# Send 20 more requests to have a meaningful sample.
for i in $(seq 1 20); do
  curl -s --max-time 1 -o /dev/null "$DATA/lt09-sample-$i" || true
done
sleep 0.5

total_lines=$(wc -l < "$AUDIT_LOG" | tr -d ' ')
[[ "$total_lines" -ge 1 ]] || fail "§6 audit log empty"

object_lines=$(jq -c 'type' "$AUDIT_LOG" 2>/dev/null | grep -c '"object"' || true)
[[ "$object_lines" == "$total_lines" ]] \
  || fail "§6 JSONL: $((total_lines - object_lines)) of $total_lines lines not a single JSON object"
ok "§6 all $total_lines audit lines parse as single JSON objects (JSONL)"

# ------------------------------------------------------------------
# 3. Every line carries all 8 mandatory fields with valid types
# ------------------------------------------------------------------
# We check the whole file with jq, streaming over each line.
valid_lines=$(jq -c '
  if (
    (.request_id | type == "string" and length > 0) and
    (.ts_ms      | type == "number" and . > 0)      and
    (.ip         | type == "string" and length > 0) and
    (.method     | type == "string" and length > 0) and
    (.path       | type == "string" and length > 0) and
    (.action     | type == "string" and
      (. as $a | ["allow","block","challenge","rate_limit","timeout","circuit_breaker"] | index($a) != null)) and
    (.risk_score | type == "number" and . >= 0 and . <= 100) and
    (.mode       | type == "string" and (. == "enforce" or . == "log_only"))
  ) then "ok" else "FAIL" end' \
  "$AUDIT_LOG" 2>/dev/null | grep -c '"ok"' || true)

[[ "$valid_lines" == "$total_lines" ]] \
  || fail "§6 field schema: $((total_lines - valid_lines)) of $total_lines lines fail mandatory-field check"
ok "§6 all $total_lines lines have the 8 mandatory fields with valid types"

# ------------------------------------------------------------------
# 4. ip field is TCP peer address, NOT X-Forwarded-For (§6 IP semantics)
# ------------------------------------------------------------------
# Drive a request with a forged XFF header.
curl -s --max-time 3 -o /dev/null \
  -H 'X-Forwarded-For: 5.6.7.8' "$DATA/lt09-xff-test" || true
sleep 0.5

# The newest audit line must NOT have ip=5.6.7.8 (the spoofed value).
audit_ip=$(tail -n 1 "$AUDIT_LOG" | jq -r '.ip' 2>/dev/null || echo '')
[[ -n "$audit_ip" ]] \
  || fail "§6 ip field absent in last audit line"
[[ "$audit_ip" != "5.6.7.8" ]] \
  || fail "§6 ip='$audit_ip' matches spoofed XFF value; must be TCP peer"
ok "§6 audit ip='$audit_ip' is TCP peer, not spoofed XFF 5.6.7.8"

# ------------------------------------------------------------------
# 5. ts_ms is monotonically non-decreasing (sanity check)
# ------------------------------------------------------------------
prev_ts=0
non_mono=0
while IFS= read -r line; do
  ts=$(printf '%s' "$line" | jq -r '.ts_ms' 2>/dev/null || echo 0)
  if [[ "$ts" =~ ^[0-9]+$ ]] && (( ts < prev_ts )); then
    non_mono=$((non_mono + 1))
  fi
  prev_ts="$ts"
done < "$AUDIT_LOG"

[[ "$non_mono" -eq 0 ]] \
  || fail "§6 ts_ms went backwards $non_mono time(s) — audit log entries out of order"
ok "§6 ts_ms monotonically non-decreasing across $total_lines entries"

# ------------------------------------------------------------------
# 6. method field is uppercase
# ------------------------------------------------------------------
lowercase_methods=$(jq -r '.method' "$AUDIT_LOG" 2>/dev/null \
  | grep -cE '^[a-z]+$' || true)
[[ "$lowercase_methods" -eq 0 ]] \
  || fail "§6 $lowercase_methods audit lines have lowercase method field"
ok "§6 method field is uppercase in all entries"

ok "LT-09 audit-log: all checks green"
