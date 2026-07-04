#!/usr/bin/env bash
# CI-T9 — OpenAPI shape test.
#
# Validates that the live admin API matches the contract in
# `docs/control-plane/api.openapi.yaml`. Pure curl + jq — boots
# nothing, expects a `make run` instance already up.
#
# This is intentionally a contract *shape* test, not full schema
# validation. We assert on:
#   - HTTP status codes match what the spec promises
#   - Required top-level fields exist on each successful response
#   - The error envelope `{ok:false, reason}` shape on rejections
# A future iteration could pipe responses through a JSON-Schema
# validator (e.g. `ajv`) for full coverage.
#
# Usage:
#   AEGIS_ADMIN=http://localhost:9443 \
#       bash tests/api/openapi-shape.sh
#
# Exits 0 only when every check passes.

set -euo pipefail

AEGIS_ADMIN="${AEGIS_ADMIN:-http://127.0.0.1:9443}"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

PASS=0
FAIL=0
ok()   { echo "PASS: $*"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $*" >&2; FAIL=$((FAIL + 1)); }

require() {
  command -v "$1" >/dev/null \
    || { echo "FAIL: missing tool: $1" >&2; exit 1; }
}
require curl
require jq

# --------------------------------------------------------------- #
# Pre-flight                                                      #
# --------------------------------------------------------------- #
if ! curl --silent --max-time 2 -o /dev/null \
        -w "%{http_code}" "$AEGIS_ADMIN/healthz/ready" \
        | grep -q '^2'; then
  echo "FAIL: $AEGIS_ADMIN/healthz/ready not 2xx — start aegis-bin first" >&2
  exit 1
fi

# Helper: GET and assert (a) HTTP code, (b) every required field
# is present in the response body. Stores body in a tempfile so
# we can show context on failure.
assert_get() {
  local label="$1" path="$2" expected_code="$3"
  shift 3
  local fields=("$@")
  local out="$TMPDIR/$(echo "$label" | tr -c '[:alnum:]' _)"
  local code
  code=$(curl --silent --max-time 5 -o "$out" \
              -w "%{http_code}" "$AEGIS_ADMIN$path")
  if [[ "$code" != "$expected_code" ]]; then
    fail "$label: expected $expected_code, got $code (body: $(head -c 100 "$out"))"
    return
  fi
  for f in "${fields[@]}"; do
    if ! jq -e "$f" "$out" >/dev/null 2>&1; then
      fail "$label: missing field $f (body: $(head -c 200 "$out"))"
      return
    fi
  done
  ok "$label ($code, ${#fields[@]} fields)"
}

# Helper: assert a 4xx/5xx body matches the Error envelope.
assert_error_envelope() {
  local label="$1" code="$2" body_file="$3"
  if [[ "$code" -ge 400 ]] \
     && jq -e '.ok == false and (.reason | type) == "string"' "$body_file" >/dev/null 2>&1; then
    ok "$label error envelope ({ok:false, reason})"
  else
    fail "$label not error-enveloped (code=$code, body: $(head -c 200 "$body_file"))"
  fi
}

# --------------------------------------------------------------- #
# System group                                                    #
# --------------------------------------------------------------- #
assert_get "GET /api/about" /api/about 200 \
  '.name | type == "string"' \
  '.version | type == "string"'

assert_get "GET /api/runtime" /api/runtime 200 \
  '.workers | type == "number"' \
  '.blocking_threads | type == "number"' \
  '.host_logical_cpus | type == "number"'

assert_get "GET /api/config/version" /api/config/version 200 \
  '.version | type == "number"' \
  '.applied_at_ms | type == "number"' \
  '.applied_on_node | type == "string"'

# --------------------------------------------------------------- #
# Stats group                                                     #
# --------------------------------------------------------------- #
assert_get "GET /api/stats" /api/stats 200 \
  '.request_rate | type == "number"' \
  '.blocks_total | type == "number"' \
  '.upstream.state | type == "string"' \
  '.ts | type == "string"'

assert_get "GET /api/stats/timeseries" "/api/stats/timeseries?window=60&step=1" 200 \
  '.window_seconds == 60' \
  '.step_seconds == 1' \
  '.points | type == "array"'

assert_get "GET /api/attacks/distribution" "/api/attacks/distribution?window=900" 200 \
  '.window_seconds == 900' \
  '.categories | type == "array"'

assert_get "GET /api/attacks/top" "/api/attacks/top?window=900&limit=5" 200 \
  '.window_seconds == 900' \
  '.limit == 5' \
  '.attackers | type == "array"'

# --------------------------------------------------------------- #
# Audit + Rules + Lists                                           #
# --------------------------------------------------------------- #
assert_get "GET /api/audit/since" "/api/audit/since?limit=10" 200 \
  '.cursor | type == "number"' \
  '.next_cursor | type == "number"' \
  '.events | type == "array"' \
  '.gap | type == "boolean"'

assert_get "GET /api/rules" /api/rules 200 \
  '.rules | type == "array"'

assert_get "GET /api/blacklist" /api/blacklist 200 \
  '.entries | type == "array"'

assert_get "GET /api/whitelist" /api/whitelist 200 \
  '.entries | type == "array"'

assert_get "GET /api/tiers" /api/tiers 200 \
  '.tiers | type == "array"'

assert_get "GET /api/routes" /api/routes 200 \
  '.routes | type == "array"'

# --------------------------------------------------------------- #
# Tracking                                                        #
# --------------------------------------------------------------- #
assert_get "GET /api/upstreams" /api/upstreams 200 \
  '.pools | type == "array"'

# CC-T1.1 — full upstream config view (members + lb + connection
# pool + referenced_by_routes per pool, BTreeMap-sorted).
assert_get "GET /api/upstreams/config" /api/upstreams/config 200 \
  '.pools | type == "object"'

# CC-T2.1 — alert-channel inventory with secrets redacted.
assert_get "GET /api/alert-receivers" /api/alert-receivers 200 \
  '.receivers | type == "array"'

assert_get "GET /api/cluster" /api/cluster 200 \
  '.peers | type == "array"' \
  '.is_leader | type == "boolean"' \
  '.our_node | type == "string"'

assert_get "GET /api/slo" /api/slo 200 \
  '.slis | type == "array"' \
  '(.slis[0] | (.burn_1h | type == "number"))'

assert_get "GET /api/certs" /api/certs 200 \
  '.certs | type == "array"'

assert_get "GET /api/alerts" /api/alerts 200 \
  '.firing  | type == "array"' \
  '.pending | type == "array"' \
  '.resolved| type == "array"'

# PE-1 (2026-07-04): /api/gitops/status removed — assert it stays gone.
assert_get "GET /api/gitops/status (removed)" /api/gitops/status 404 \
  '.error == "not found"'

# --------------------------------------------------------------- #
# Settings (read-only checks; mutations need CSRF)                #
# --------------------------------------------------------------- #
assert_get "GET /api/mode" /api/mode 200 \
  '.mode | type == "string"' \
  '.mode | IN("enforce", "log_only")'

assert_get "GET /api/loadmode" /api/loadmode 200 \
  '.mode | type == "string"' \
  '.elevated_rps | type == "number"' \
  '.critical_rps | type == "number"'

assert_get "GET /api/detectors" /api/detectors 200 \
  '.mask | type == "object"' \
  '.overrides | type == "object"' \
  '.locked_classes | type == "array"'

# --------------------------------------------------------------- #
# Mutation gates — CSRF must reject without cookie                #
# --------------------------------------------------------------- #
csrf_body="$TMPDIR/csrf_body"
csrf_code=$(curl --silent --max-time 3 -o "$csrf_body" \
                 -w "%{http_code}" \
                 -X POST \
                 -H "content-type: application/json" \
                 -d '{"id":"x","body":"","enabled":true}' \
                 "$AEGIS_ADMIN/api/rules")
assert_error_envelope "POST /api/rules (no CSRF)" "$csrf_code" "$csrf_body"

mode_body="$TMPDIR/mode_body"
mode_code=$(curl --silent --max-time 3 -o "$mode_body" \
                 -w "%{http_code}" \
                 -X PUT \
                 -H "content-type: application/json" \
                 -d '{"mode":"log_only"}' \
                 "$AEGIS_ADMIN/api/mode")
assert_error_envelope "PUT /api/mode (no CSRF)" "$mode_code" "$mode_body"

ack_body="$TMPDIR/ack_body"
ack_code=$(curl --silent --max-time 3 -o "$ack_body" \
                -w "%{http_code}" \
                -X POST \
                "$AEGIS_ADMIN/api/alerts/test-alert/ack")
assert_error_envelope "POST /api/alerts/{id}/ack (no CSRF)" "$ack_code" "$ack_body"

# CC-T1.1.b — upstream-config writes must reject unauthenticated
# mutations with the same {ok:false, reason} envelope.
upstreams_put_body="$TMPDIR/upstreams_put_body"
upstreams_put_code=$(curl --silent --max-time 3 -o "$upstreams_put_body" \
                        -w "%{http_code}" \
                        -X PUT \
                        -H "content-type: application/json" \
                        -d '{"pools":{}}' \
                        "$AEGIS_ADMIN/api/upstreams/config")
assert_error_envelope "PUT /api/upstreams/config (no CSRF)" "$upstreams_put_code" "$upstreams_put_body"

pool_put_body="$TMPDIR/pool_put_body"
pool_put_code=$(curl --silent --max-time 3 -o "$pool_put_body" \
                    -w "%{http_code}" \
                    -X PUT \
                    -H "content-type: application/json" \
                    -d '{"members":[{"addr":"127.0.0.1:1"}],"lb":"round_robin"}' \
                    "$AEGIS_ADMIN/api/upstreams/pool/cc_t3_smoke")
assert_error_envelope "PUT /api/upstreams/pool/{id} (no CSRF)" "$pool_put_code" "$pool_put_body"

pool_del_body="$TMPDIR/pool_del_body"
pool_del_code=$(curl --silent --max-time 3 -o "$pool_del_body" \
                    -w "%{http_code}" \
                    -X DELETE \
                    "$AEGIS_ADMIN/api/upstreams/pool/cc_t3_smoke")
assert_error_envelope "DELETE /api/upstreams/pool/{id} (no CSRF)" "$pool_del_code" "$pool_del_body"

# CC-T2.1.b — alert-receiver writes follow the same rejection contract.
ar_put_body="$TMPDIR/ar_put_body"
ar_put_code=$(curl --silent --max-time 3 -o "$ar_put_body" \
                  -w "%{http_code}" \
                  -X PUT \
                  -H "content-type: application/json" \
                  -d '{"receivers":[]}' \
                  "$AEGIS_ADMIN/api/alert-receivers")
assert_error_envelope "PUT /api/alert-receivers (no CSRF)" "$ar_put_code" "$ar_put_body"

ar_test_body="$TMPDIR/ar_test_body"
ar_test_code=$(curl --silent --max-time 3 -o "$ar_test_body" \
                   -w "%{http_code}" \
                   -X POST \
                   "$AEGIS_ADMIN/api/alert-receivers/cc_t3_smoke/test")
assert_error_envelope "POST /api/alert-receivers/{name}/test (no CSRF)" "$ar_test_code" "$ar_test_body"

# --------------------------------------------------------------- #
# Summary                                                         #
# --------------------------------------------------------------- #
echo
echo "----------------------------------------"
echo "OpenAPI shape test: $PASS passed, $FAIL failed"
echo "----------------------------------------"
[[ "$FAIL" -eq 0 ]] || exit 1
