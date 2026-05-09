#!/usr/bin/env bash
# LT-10 — §5.3 / §4  X-WAF-Request-Id ↔ audit log correlation
#
# Contract:
#   - X-WAF-Request-Id MUST be present on every response.
#   - The value MUST be a UUID v4.
#   - Every value MUST be unique across requests (no ID reuse).
#   - X-WAF-Request-Id MUST match the `request_id` field of the
#     corresponding audit-log entry (§5.3, §6).
#   - If X-WAF-Request-Id is missing or mismatched the benchmarker
#     records an observability contract failure.
#
# Method:
#   Fire 50 requests and capture each X-WAF-Request-Id.
#   After a brief pause, scan the audit log for each ID.
#   Report any mismatches or missing entries.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"
require curl
require jq

trap trap_cleanup EXIT
start_waf
reset_to_enforce

SAMPLE="$(mktemp -t lt10-ids.XXXXXX)"
trap 'rm -f "$SAMPLE"' EXIT

# ------------------------------------------------------------------
# 1. Collect 50 unique X-WAF-Request-Id values
# ------------------------------------------------------------------
echo "==> capturing X-WAF-Request-Id from 50 requests"
fail_count=0
for i in $(seq 1 50); do
  rid=$(curl -sI --max-time 3 "$DATA/lt10-correlate-$i" 2>/dev/null \
        | awk 'BEGIN{IGNORECASE=1} tolower($1)=="x-waf-request-id:"{print $2; exit}' \
        | tr -d '\r')

  if [[ -z "$rid" ]]; then
    echo "  FAIL: response $i missing X-WAF-Request-Id" >&2
    fail_count=$((fail_count + 1))
    continue
  fi

  if ! uuid_valid "$rid"; then
    echo "  FAIL: response $i X-WAF-Request-Id='$rid' not UUID v4" >&2
    fail_count=$((fail_count + 1))
    continue
  fi

  printf '%s\n' "$rid" >> "$SAMPLE"
done

[[ "$fail_count" -eq 0 ]] \
  || fail "$fail_count X-WAF-Request-Id violations in 50 responses"
ok "all 50 responses carry a valid UUID v4 X-WAF-Request-Id"

# ------------------------------------------------------------------
# 2. All 50 IDs must be distinct (no reuse)
# ------------------------------------------------------------------
total=$(wc -l < "$SAMPLE" | tr -d ' ')
unique=$(sort -u "$SAMPLE" | wc -l | tr -d ' ')
[[ "$unique" == "$total" ]] \
  || fail "§5.3 request ID reuse: $total responses but only $unique distinct IDs"
ok "all $unique X-WAF-Request-Id values are distinct"

# ------------------------------------------------------------------
# 3. Each ID must appear as request_id in the audit log
# ------------------------------------------------------------------
sleep 0.4   # let the WAF flush buffered log writes

[[ -f "$AUDIT_LOG" ]] || fail "§6 audit log not found at $AUDIT_LOG"

hits=0
miss=0
missing_ids=""
while IFS= read -r rid; do
  count=$(jq -r --arg rid "$rid" 'select(.request_id == $rid) | .request_id' \
            "$AUDIT_LOG" 2>/dev/null | wc -l | tr -d ' ')
  if [[ "$count" -ge 1 ]]; then
    hits=$((hits + 1))
  else
    miss=$((miss + 1))
    missing_ids="$missing_ids $rid"
  fi
done < "$SAMPLE"

if (( miss > 0 )); then
  echo "  FAIL: $miss of $total IDs not found in audit log" >&2
  # Print up to 5 examples.
  printf '%s\n' "$missing_ids" | tr ' ' '\n' | head -5 | while read -r id; do
    echo "    missing: $id" >&2
  done
  fail "§5.3/§6 $miss X-WAF-Request-Id values absent from audit log"
fi
ok "all $hits X-WAF-Request-Id values correlated to audit-log request_id entries"

# ------------------------------------------------------------------
# 4. Spot-check: X-WAF-Request-Id in header matches audit .request_id
#    for the same path (using a distinctive path marker)
# ------------------------------------------------------------------
MARKER="lt10-spot-$(date +%s)"
raw_spot=$(curl -sI --max-time 3 "$DATA/$MARKER" 2>/dev/null || true)
hdr_rid=$(header_value "$raw_spot" 'X-WAF-Request-Id')
sleep 0.3

log_rid=$(jq -r --arg path "/$MARKER" 'select(.path | startswith($path)) | .request_id' \
           "$AUDIT_LOG" 2>/dev/null | tail -n 1 || echo '')

[[ -n "$hdr_rid" ]] || fail "§5.3 spot-check: header X-WAF-Request-Id absent"
[[ -n "$log_rid" ]] || fail "§5.3 spot-check: no audit entry found for path /$MARKER"
[[ "$hdr_rid" == "$log_rid" ]] \
  || fail "§5.3 spot-check: header rid='$hdr_rid' ≠ audit rid='$log_rid'"
ok "§5.3 spot-check: header X-WAF-Request-Id='$hdr_rid' matches audit log"

ok "LT-10 correlation: all checks green"
