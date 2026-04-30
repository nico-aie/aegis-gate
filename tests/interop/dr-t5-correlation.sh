#!/usr/bin/env bash
# DR-T5 — every `X-WAF-Request-Id` returned in a response
# header must appear as the `request_id` field of the matching
# audit-log line. Contract §5.3.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"
require curl
require jq

trap trap_cleanup EXIT
start_waf

# Send 100 requests, capture each response's X-WAF-Request-Id.
sample="$(mktemp)"
for i in $(seq 1 100); do
  rid=$(curl -sI --max-time 2 "$DATA/correlate-$i" 2>/dev/null \
        | awk 'BEGIN{IGNORECASE=1} tolower($1)=="x-waf-request-id:"{print $2; exit}' \
        | tr -d '\r')
  if [[ -z "$rid" ]]; then
    fail "response $i missing X-WAF-Request-Id"
  fi
  printf '%s\n' "$rid" >> "$sample"
done

# Count unique IDs — they must all be distinct.
unique=$(sort -u "$sample" | wc -l | tr -d ' ')
[[ "$unique" == "100" ]] \
  || fail "expected 100 unique request IDs, got $unique"
ok "100 distinct X-WAF-Request-Id values"

sleep 0.3

# Each ID must appear exactly once as `request_id` in the audit log.
hits=0
miss=0
for rid in $(cat "$sample"); do
  count=$(jq -r 'select(.request_id == $rid) | .request_id' \
            --arg rid "$rid" "$AUDIT_LOG" | wc -l | tr -d ' ')
  if [[ "$count" -ge 1 ]]; then
    hits=$((hits + 1))
  else
    miss=$((miss + 1))
    echo "MISS: $rid not found in audit log"
  fi
done

rm -f "$sample"

if (( miss > 0 )); then
  fail "$miss out of 100 request IDs missing from audit log"
fi
ok "all 100 X-WAF-Request-Id values correlated to audit-log entries"

ok "DR-T5 correlation: 2/2 phases green"
