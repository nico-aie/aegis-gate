#!/usr/bin/env bash
# LT-03 — §2.4  reset_state: atomicity, response shape, audit preservation
#
# Contract:
#   POST /__waf_control/reset_state (with correct secret) MUST:
#   - Return HTTP 200
#   - Body: .ok==true, .action=="reset_state", .audit_log_preserved==true,
#           .ts_ms (integer ≥ 0)
#   - NOT truncate, rewrite, or delete the audit log (append-only)
#   - Be synchronous: a 200 response means state is fully cleared
#
# Side-channel we can observe:
#   - Rate-limit state cleared: after reset, a burst of requests that
#     previously hit rate-limit now flows cleanly again.
#   - Risk counters cleared: X-WAF-Risk-Score on a fresh IP drops
#     after reset compared to a post-attack score.
#
# Audit-log preservation is the definitive check (§2.4 paragraph 3).

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"
require curl
require jq

trap trap_cleanup EXIT
start_waf

# ------------------------------------------------------------------
# Warm up: fire a request so the audit log is non-empty before reset.
# ------------------------------------------------------------------
curl -s --max-time 2 -o /dev/null "$DATA/?warmup=1" || true
# Trigger at least one suspicious request so a score builds up.
curl -s --max-time 2 -o /dev/null "$DATA/?id=1%27%20OR%20%271%27%3D%271" || true
sleep 0.5

audit_before=$(count_audit_lines)
[[ "$audit_before" -ge 1 ]] \
  || fail "audit log must be non-empty before reset (got $audit_before lines)"
ok "pre-reset audit log has $audit_before line(s)"

# ------------------------------------------------------------------
# 1. HTTP 200
# ------------------------------------------------------------------
status=$(curl -s --max-time 5 -X POST \
              -H "X-Benchmark-Secret: $SECRET" \
              -o /tmp/lt03_reset.json -w '%{http_code}' \
              "$ADMIN/__waf_control/reset_state" || echo 000)
[[ "$status" == "200" ]] \
  || fail "reset_state → $status (expected 200)"
ok "reset_state returns HTTP 200"

# ------------------------------------------------------------------
# 2. Response body shape
# ------------------------------------------------------------------
body=$(cat /tmp/lt03_reset.json)

assert_json_eq      "$body" '.ok'                  'true'       \
  || fail "reset_state .ok must be true (got: $body)"
ok "reset_state .ok == true"

assert_json_eq      "$body" '.action'              'reset_state' \
  || fail "reset_state .action must be 'reset_state' (got: $body)"
ok "reset_state .action == 'reset_state'"

assert_json_eq      "$body" '.audit_log_preserved' 'true'       \
  || fail "reset_state .audit_log_preserved must be true (got: $body)"
ok "reset_state .audit_log_preserved == true"

ts=$(printf '%s' "$body" | jq -r '.ts_ms')
[[ "$ts" =~ ^[0-9]+$ ]] && [[ "$ts" -gt 0 ]] \
  || fail "reset_state .ts_ms must be a positive integer (got: $ts)"
ok "reset_state .ts_ms is a positive integer ($ts)"

# ------------------------------------------------------------------
# 3. Audit log must NOT be truncated after reset
# ------------------------------------------------------------------
audit_after=$(count_audit_lines)
[[ "$audit_after" -ge "$audit_before" ]] \
  || fail "reset_state truncated audit log: was $audit_before lines, now $audit_after"
ok "audit log preserved: $audit_after >= $audit_before lines"

# ------------------------------------------------------------------
# 4. Audit log grows after reset (append-only confirmation round 2)
# ------------------------------------------------------------------
for i in $(seq 1 10); do
  curl -s --max-time 1 -o /dev/null "$DATA/post-reset-$i" || true
done
sleep 0.4
audit_final=$(count_audit_lines)
[[ "$audit_final" -gt "$audit_after" ]] \
  || fail "audit log didn't grow after reset: stuck at $audit_after"
ok "audit log grew after reset: $audit_final > $audit_after (append-only confirmed)"

# ------------------------------------------------------------------
# 5. Idempotent: a second reset_state also returns 200 with the same shape
# ------------------------------------------------------------------
status2=$(curl -s --max-time 5 -X POST \
               -H "X-Benchmark-Secret: $SECRET" \
               -o /tmp/lt03_reset2.json -w '%{http_code}' \
               "$ADMIN/__waf_control/reset_state" || echo 000)
[[ "$status2" == "200" ]] \
  || fail "second reset_state → $status2 (expected 200)"

body2=$(cat /tmp/lt03_reset2.json)
assert_json_eq "$body2" '.ok'     'true'        || fail "second reset .ok != true"
assert_json_eq "$body2" '.action' 'reset_state' || fail "second reset .action wrong"
ok "reset_state is idempotent (second call also returns 200)"

ok "LT-03 reset-state: all checks green"
