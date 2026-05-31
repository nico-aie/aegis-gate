#!/usr/bin/env bash
# NT-02 — Cluster config plane: version conflict (CAS)
#
# Two concurrent PUTs against the SAME expected_version must produce
# exactly one 200 and one 409 `version_conflict` carrying the
# post-conflict `current` version.
#
# Verifies:
#   • The ConfigStore CAS write (StateBackend::cas_set)
#   • The dashboard's 409 retry contract (uses `current` to refresh)

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

require curl; require jq; require docker

trap stop_cluster EXIT
start_cluster

# Seed v1 via a clean PUT so both racers start from the same expected.
login "$NODE_A_ADMIN"
seed="$(admin_put "$NODE_A_ADMIN" "/api/response-filter" \
        '{"scrub_stack_traces": true}')"
v1="$(printf '%s' "$seed" | jq -r '.version')"
[[ -n "$v1" && "$v1" != "null" ]] || fail "seed PUT failed: $seed"

# Race two PUTs against v1. Both target the same field with different
# values; whichever wins CAS goes through, the loser must 409.
#
# 2026-05-30 (QC R2-003): pre-login BOTH nodes BEFORE forking. The
# old shape did a full `login "$NODE_B_ADMIN"` (request + response +
# cookie parse, ~200 ms) inside the B-side subshell — long enough
# for A's PUT to complete + activate v=2 before B's PUT even reads
# the doc. CAS conflict never fired; the test always reported
# `ok=2 conflict=0` and passed-by-accident. Login first; race PUTs.
A_COOKIE="$COOKIE"; A_CSRF="$CSRF"
login "$NODE_B_ADMIN"
B_COOKIE="$COOKIE"; B_CSRF="$CSRF"

race_log_a="$(mktemp)"
race_log_b="$(mktemp)"
(
  COOKIE="$A_COOKIE"; CSRF="$A_CSRF"
  http_status "$NODE_A_ADMIN" PUT "/api/response-filter" \
    '{"scrub_stack_traces": false}' >"$race_log_a" 2>&1
) &
pid_a=$!
(
  COOKIE="$B_COOKIE"; CSRF="$B_CSRF"
  http_status "$NODE_B_ADMIN" PUT "/api/response-filter" \
    '{"scrub_stack_traces": true, "mask_internal_ips": false}' >"$race_log_b" 2>&1
) &
pid_b=$!
wait "$pid_a" "$pid_b"

# Each output is "<body>\n<code>" (per http_status). Pull codes.
code_a="$(tail -1 "$race_log_a")"
code_b="$(tail -1 "$race_log_b")"
body_a="$(sed '$d' "$race_log_a")"
body_b="$(sed '$d' "$race_log_b")"
rm -f "$race_log_a" "$race_log_b"

echo "A: $code_a / $body_a"
echo "B: $code_b / $body_b"

ok_count=0; conflict_count=0
for pair in "$code_a:$body_a" "$code_b:$body_b"; do
  code="${pair%%:*}"
  body="${pair#*:}"
  case "$code" in
    200)
      ok_count=$((ok_count + 1))
      ;;
    409)
      reason="$(printf '%s' "$body" | jq -r '.error // empty')"
      current="$(printf '%s' "$body" | jq -r '.current // empty')"
      [[ "$reason" == "version_conflict" ]] \
        || fail "409 without 'version_conflict' error tag: $body"
      [[ -n "$current" && "$current" != "null" ]] \
        || fail "409 missing 'current' version field: $body"
      conflict_count=$((conflict_count + 1))
      ;;
    *)
      fail "race returned unexpected HTTP $code: $body"
      ;;
  esac
done

[[ $ok_count -eq 1 && $conflict_count -eq 1 ]] \
  || fail "expected exactly one 200 + one 409, got ok=$ok_count conflict=$conflict_count"

ok "CAS produced exactly one winner + one 409 version_conflict"
echo "NT-02 PASS"
