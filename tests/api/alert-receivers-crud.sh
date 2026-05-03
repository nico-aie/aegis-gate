#!/usr/bin/env bash
# tests/api/alert-receivers-crud.sh — CC-T2.1.b
#
# Walks the alert-receiver CRUD round-trip end-to-end and asserts
# every contract from CC-T2.1 (read-side) + CC-T2.1.b (writes +
# hot-swap of the shared ArcSwap'd list) holds:
#
#   1.  GET  /api/alert-receivers returns the documented shape
#       (`{ receivers: [...] }`).
#   2.  PUT  whole-list without CSRF → 403 csrf_missing_*.
#   3.  PUT  with CSRF inserts a test receiver → 200 ok=true; GET
#       reflects it.
#   4.  PUT  with a duplicate name fails validation → 400.
#   5.  DELETE on the test receiver → 200 ok=true; GET no longer
#       lists it.
#   6.  DELETE on an unknown name → 400 validation (audit-chain
#       invariant: every chain entry is an applied state change).
#   7.  Audit chain advances by ≥ 2 entries across the run
#       (verified via /api/config/version delta).
#
# Run order: this script may run after other api/*.sh tests.
# It uses receiver names prefixed with `cc_t2_audit_` so re-runs
# don't collide with seeded fixtures.
#
# ENV NOTE — same macOS curl caveat as `upstreams-crud.sh`. Run
# in CI / on Linux, or `brew install curl` and prepend
# `/opt/homebrew/opt/curl/bin` to PATH.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

aegis_login

TEST_NAME="cc_t2_audit_test"

cleanup() {
  # Best-effort restore. If the test left the receiver behind,
  # delete it so re-runs start clean. Errors swallowed.
  curl "${AEGIS_CURL_OPTS[@]}" -X DELETE \
    -H "x-csrf-token: $AEGIS_CSRF" \
    -o /dev/null "$AEGIS_ADMIN/api/alert-receivers/$TEST_NAME" 2>/dev/null || true
}
trap cleanup EXIT

# Pre-state.
version_before=$(aegis_get /api/config/version | jq -r '.version')

# ---------------------------------------------------------------
# 1. GET shape
# ---------------------------------------------------------------
list=$(aegis_get /api/alert-receivers)
echo "$list" | jq -e '.receivers' >/dev/null \
  || { echo "FAIL: GET /api/alert-receivers missing .receivers" >&2; exit 1; }
ok "GET /api/alert-receivers shape"

# Snapshot the existing receivers so we can preserve them across
# the whole-list PUT. The handler's contract is "replace the
# entire list" — we're not adding incrementally.
existing=$(echo "$list" | jq '.receivers')

# ---------------------------------------------------------------
# 2. PUT whole-list without CSRF → 403
# ---------------------------------------------------------------
new_receiver=$(jq -nc --arg name "$TEST_NAME" '{
  name: $name,
  kind: { AlertmanagerWebhook: { url: "http://127.0.0.1:65530/test-webhook" } }
}')
put_body=$(jq -nc --argjson existing "$existing" --argjson new "$new_receiver" '{
  receivers: ($existing + [$new])
}')
status=$(aegis_put_status "/api/alert-receivers" "$put_body" "")
assert_eq "$status" "403" "PUT alert-receivers without CSRF must reject"
ok "PUT /api/alert-receivers without CSRF → 403"

# ---------------------------------------------------------------
# 3. PUT with CSRF → 200, GET reflects it
# ---------------------------------------------------------------
resp=$(aegis_put "/api/alert-receivers" "$put_body")
echo "$resp" | jq -e '.ok == true' >/dev/null \
  || { echo "FAIL: PUT alert-receivers did not return ok=true; got: $resp" >&2; exit 1; }
ok "PUT /api/alert-receivers with CSRF → ok=true"

list=$(aegis_get /api/alert-receivers)
echo "$list" | jq -e ".receivers[] | select(.name == \"$TEST_NAME\")" >/dev/null \
  || { echo "FAIL: receiver not visible after PUT" >&2; exit 1; }
ok "GET reflects PUT immediately"

# ---------------------------------------------------------------
# 4. PUT with a duplicate name → 400 validation
# ---------------------------------------------------------------
dup_body=$(jq -nc --argjson new "$new_receiver" '{
  receivers: [$new, $new]
}')
status=$(aegis_put_status "/api/alert-receivers" "$dup_body")
assert_eq "$status" "400" "duplicate name must be rejected"
ok "PUT duplicate names → 400 validation"

# ---------------------------------------------------------------
# 5. DELETE on the test receiver → 200; GET no longer lists it
# ---------------------------------------------------------------
del_status=$(curl "${AEGIS_CURL_OPTS[@]}" -X DELETE \
  -H "x-csrf-token: $AEGIS_CSRF" \
  -o /tmp/aegis-cct2-del.json -w "%{http_code}" \
  "$AEGIS_ADMIN/api/alert-receivers/$TEST_NAME")
assert_eq "$del_status" "200" "DELETE existing receiver"
jq -e '.ok == true' /tmp/aegis-cct2-del.json >/dev/null \
  || { echo "FAIL: DELETE response missing ok=true" >&2; cat /tmp/aegis-cct2-del.json; exit 1; }
ok "DELETE /api/alert-receivers/$TEST_NAME → 200 ok=true"

list=$(aegis_get /api/alert-receivers)
if echo "$list" | jq -e ".receivers[] | select(.name == \"$TEST_NAME\")" >/dev/null 2>&1; then
  echo "FAIL: receiver still visible after DELETE" >&2
  exit 1
fi
ok "GET after DELETE no longer lists $TEST_NAME"

# ---------------------------------------------------------------
# 6. DELETE on an unknown name → 400 validation
# ---------------------------------------------------------------
del_status=$(curl "${AEGIS_CURL_OPTS[@]}" -X DELETE \
  -H "x-csrf-token: $AEGIS_CSRF" \
  -o /tmp/aegis-cct2-del-missing.json -w "%{http_code}" \
  "$AEGIS_ADMIN/api/alert-receivers/cc_t2_audit_does_not_exist")
assert_eq "$del_status" "400" "DELETE unknown receiver → 400"
ok "DELETE unknown name → 400 validation"

# ---------------------------------------------------------------
# 7. Audit chain advanced by at least 2 (the successful PUT and
#    the successful DELETE). Failed mutations don't advance the
#    chain — that's the audit-chain invariant.
# ---------------------------------------------------------------
version_after=$(aegis_get /api/config/version | jq -r '.version')
delta=$((version_after - version_before))
if (( delta < 2 )); then
  echo "FAIL: expected audit chain to advance by ≥ 2; got delta=$delta" >&2
  echo "      before=$version_before after=$version_after"
  exit 1
fi
ok "audit chain advanced by $delta entries (≥ 2 expected)"

echo "PASS: tests/api/alert-receivers-crud.sh"
