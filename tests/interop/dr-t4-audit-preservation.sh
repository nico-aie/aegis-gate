#!/usr/bin/env bash
# DR-T4 — `./waf_audit.log` must be append-only across
# `reset_state`. Per §2.4 the contract penalises premature
# success; per §6 the file is the OC's correlation truth.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"
require curl

trap trap_cleanup EXIT
start_waf

# Round 1 — fire 25 requests, count audit lines.
for i in $(seq 1 25); do
  curl -s --max-time 1 -o /dev/null "$DATA/r1-$i" || true
done
sleep 0.5
before=$(count_audit_lines)
[[ "$before" -ge 25 ]] \
  || fail "expected ≥ 25 audit lines after warm-up, got $before"
ok "round 1: $before audit lines after 25 requests"

# Reset state.
curl -s --max-time 3 -X POST \
     -H "X-Benchmark-Secret: $SECRET" \
     "$ADMIN/__waf_control/reset_state" >/dev/null

after_reset=$(count_audit_lines)
[[ "$after_reset" -ge "$before" ]] \
  || fail "reset_state truncated audit log: was $before, now $after_reset"
ok "reset_state preserved log: $after_reset ≥ $before"

# Round 2 — fire 25 more, confirm the count grows monotonically.
for i in $(seq 1 25); do
  curl -s --max-time 1 -o /dev/null "$DATA/r2-$i" || true
done
sleep 0.5
final=$(count_audit_lines)
[[ "$final" -gt "$after_reset" ]] \
  || fail "round 2 didn't grow log: was $after_reset, now $final"
ok "round 2: $final lines (grew by $((final - after_reset)))"

# Verify every line is a single-line JSON object (jsonl format).
require jq
total_lines=$(wc -l < "$AUDIT_LOG" | tr -d ' ')
object_lines=$(jq -c 'type' "$AUDIT_LOG" 2>/dev/null | { grep -c '"object"' || true; })
[[ "$object_lines" == "$total_lines" ]] \
  || fail "$((total_lines - object_lines)) of $total_lines audit lines aren't single JSON objects"
ok "every line in $AUDIT_LOG parses as a single JSON object"

# Verify every line has the 8 required fields.
ok_lines=$(jq -c \
  '[has("request_id"), has("ts_ms"), has("ip"), has("method"), has("path"), has("action"), has("risk_score"), has("mode")] | all' \
  "$AUDIT_LOG" 2>/dev/null | { grep -c '^true$' || true; })
[[ "$ok_lines" == "$total_lines" ]] \
  || fail "$((total_lines - ok_lines)) audit lines are missing required fields"
ok "all $final audit lines have the 8 required fields"

ok "DR-T4 audit preservation: 4/4 phases green"
