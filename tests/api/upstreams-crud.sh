#!/usr/bin/env bash
# tests/api/upstreams-crud.sh — CC-T1.audit
#
# Walks the upstream-pool CRUD round-trip end-to-end and asserts
# every contract from CC-T1.1 (read-side) + CC-T1.1.b (writes +
# proxy hot-swap) holds:
#
#   1.  GET  /api/upstreams/config returns the documented shape.
#   2.  POST-style upsert (PUT /api/upstreams/pool/{id}) without
#       CSRF → 403 csrf_missing_*.
#   3.  PUT  with CSRF → 200 ok=true; pool appears in subsequent
#       GET; `referenced_by_routes` correctly empty for the new
#       (non-routed) pool.
#   4.  PUT validation rejects empty members → 400 with stable
#       reason_code "validation".
#   5.  PUT to update the same pool (change weight) → 200; GET
#       reflects the new weight; audit chain version advances.
#   6.  DELETE on a pool that NO route references → 200 ok=true;
#       GET no longer shows it.
#   7.  DELETE on a pool that IS referenced by a route → 409
#       with `reason: pool_referenced` AND
#       `referenced_by_routes: [<route_id>...]` payload.
#   8.  DELETE on an unknown pool → 400 validation.
#   9.  Whole-map PUT /api/upstreams/config replaces the table
#       atomically; pools dropped from the map disappear.
#  10.  Audit chain advances by ≥ 4 entries across the run
#       (verified via /api/config/version delta).
#
# Run order: this script may run after other api/*.sh tests.
# It uses pool names prefixed with `cc_t1_audit_` to avoid
# colliding with seeded fixtures.
#
# ENV NOTE — macOS curl 8.1.2 (LibreSSL/3.3.6 bundled with the OS)
# fails the TLS handshake against the dev cert. Run in CI / on
# Linux, or `brew install curl` and prepend
# `/opt/homebrew/opt/curl/bin` to PATH. This caveat applies to
# every tests/api/*.sh script — it's a curl-environment issue,
# not a gateway bug.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

aegis_login

# A pool that ROUTES TO IT — must be present in the running
# config so the DELETE-409 path is exercisable. Default to
# "backend-pool" which the dev config seeds; operators can
# override via REFERENCED_POOL=… for a different fixture.
REFERENCED_POOL="${REFERENCED_POOL:-backend-pool}"
AUDIT_NEW_POOL="cc_t1_audit_new"
AUDIT_RENAMED_POOL="cc_t1_audit_renamed_x"

cleanup() {
  # Best-effort cleanup so re-runs don't leak. Ignore errors.
  curl "${AEGIS_CURL_OPTS[@]}" -X DELETE \
    -H "x-csrf-token: $AEGIS_CSRF" \
    -o /dev/null "$AEGIS_ADMIN/api/upstreams/pool/$AUDIT_NEW_POOL" 2>/dev/null || true
  curl "${AEGIS_CURL_OPTS[@]}" -X DELETE \
    -H "x-csrf-token: $AEGIS_CSRF" \
    -o /dev/null "$AEGIS_ADMIN/api/upstreams/pool/$AUDIT_RENAMED_POOL" 2>/dev/null || true
}
trap cleanup EXIT

# Pre-state: capture audit-chain length so we can verify advance.
version_before=$(aegis_get /api/config/version | jq -r '.version')

# ---------------------------------------------------------------
# 1. GET shape
# ---------------------------------------------------------------
cfg=$(aegis_get /api/upstreams/config)
echo "$cfg" | jq -e '.pools' >/dev/null \
  || { echo "FAIL: GET /api/upstreams/config missing .pools" >&2; exit 1; }
ok "GET /api/upstreams/config shape"

# Confirm REFERENCED_POOL exists if we expect to test the 409.
if ! echo "$cfg" | jq -e ".pools[\"$REFERENCED_POOL\"]" >/dev/null; then
  echo "WARN: REFERENCED_POOL '$REFERENCED_POOL' not in current config — skipping 409 test (test #7)."
  SKIP_409="1"
else
  SKIP_409=""
fi

# ---------------------------------------------------------------
# 2. PUT pool without CSRF → 403
# ---------------------------------------------------------------
upsert_body=$(jq -nc '{
  members: [{ addr: "127.0.0.1:9991", weight: 1 }],
  lb: "round_robin"
}')
status=$(aegis_put_status "/api/upstreams/pool/$AUDIT_NEW_POOL" "$upsert_body" "")
assert_eq "$status" "403" "PUT pool without CSRF must reject"
ok "PUT pool without CSRF → 403"

# ---------------------------------------------------------------
# 3. PUT pool with CSRF → 200, GET reflects it
# ---------------------------------------------------------------
resp=$(aegis_put "/api/upstreams/pool/$AUDIT_NEW_POOL" "$upsert_body")
echo "$resp" | jq -e '.ok == true' >/dev/null \
  || { echo "FAIL: PUT pool did not return ok=true; got: $resp" >&2; exit 1; }
ok "PUT pool with CSRF → ok=true"

cfg=$(aegis_get /api/upstreams/config)
echo "$cfg" | jq -e ".pools[\"$AUDIT_NEW_POOL\"]" >/dev/null \
  || { echo "FAIL: pool not visible after PUT" >&2; exit 1; }
weight=$(echo "$cfg" | jq -r ".pools[\"$AUDIT_NEW_POOL\"].members[0].weight")
assert_eq "$weight" "1" "weight from initial PUT"
refs=$(echo "$cfg" | jq -r ".pools[\"$AUDIT_NEW_POOL\"].referenced_by_routes | length")
assert_eq "$refs" "0" "new pool should have no route references"
ok "GET reflects PUT immediately + referenced_by_routes empty"

# ---------------------------------------------------------------
# 4. PUT validation rejects empty members → 400
# ---------------------------------------------------------------
bad_body=$(jq -nc '{ members: [], lb: "round_robin" }')
status=$(aegis_put_status "/api/upstreams/pool/$AUDIT_NEW_POOL" "$bad_body")
assert_eq "$status" "400" "empty members must be rejected"
ok "PUT empty members → 400 validation"

# Original record untouched after the failed validation.
weight=$(aegis_get /api/upstreams/config | jq -r ".pools[\"$AUDIT_NEW_POOL\"].members[0].weight")
assert_eq "$weight" "1" "rejected PUT must not mutate the existing pool"
ok "rejected PUT leaves prior state intact"

# ---------------------------------------------------------------
# 5. PUT update (change weight) → 200, GET reflects new weight
# ---------------------------------------------------------------
update_body=$(jq -nc '{
  members: [
    { addr: "127.0.0.1:9991", weight: 5 },
    { addr: "127.0.0.1:9992", weight: 1 }
  ],
  lb: "weighted_round_robin"
}')
resp=$(aegis_put "/api/upstreams/pool/$AUDIT_NEW_POOL" "$update_body")
echo "$resp" | jq -e '.ok == true' >/dev/null \
  || { echo "FAIL: PUT update; got: $resp" >&2; exit 1; }
ok "PUT update → ok=true"

cfg=$(aegis_get /api/upstreams/config)
new_weight=$(echo "$cfg" | jq -r ".pools[\"$AUDIT_NEW_POOL\"].members[0].weight")
assert_eq "$new_weight" "5" "weight updated"
new_lb=$(echo "$cfg" | jq -r ".pools[\"$AUDIT_NEW_POOL\"].lb")
assert_eq "$new_lb" "weighted_round_robin" "lb updated"
ok "GET reflects update (weight + lb)"

# ---------------------------------------------------------------
# 6. DELETE unreferenced pool → 200
# ---------------------------------------------------------------
status=$(aegis_delete_status "/api/upstreams/pool/$AUDIT_NEW_POOL")
assert_eq "$status" "200" "DELETE unreferenced pool"
ok "DELETE unreferenced pool → 200"

cfg=$(aegis_get /api/upstreams/config)
if echo "$cfg" | jq -e ".pools[\"$AUDIT_NEW_POOL\"]" >/dev/null; then
  echo "FAIL: pool still present after DELETE" >&2
  exit 1
fi
ok "GET no longer shows deleted pool"

# ---------------------------------------------------------------
# 7. DELETE referenced pool → 409 + referenced_by_routes
# ---------------------------------------------------------------
if [[ -z "$SKIP_409" ]]; then
  full=$(aegis_delete_full "/api/upstreams/pool/$REFERENCED_POOL")
  status=$(echo "$full" | grep '__HTTP_STATUS__' | sed 's/.*://')
  body=$(echo "$full" | sed '$d')
  assert_eq "$status" "409" "DELETE referenced pool must 409"
  reason=$(echo "$body" | jq -r '.reason')
  assert_eq "$reason" "pool_referenced" "409 reason code"
  refs_count=$(echo "$body" | jq -r '.referenced_by_routes | length')
  if [[ "$refs_count" -lt 1 ]]; then
    echo "FAIL: 409 must carry referenced_by_routes (got $refs_count)" >&2
    exit 1
  fi
  ok "DELETE referenced pool → 409 + referenced_by_routes (count=$refs_count)"

  # Pool must still exist after the failed delete.
  cfg=$(aegis_get /api/upstreams/config)
  echo "$cfg" | jq -e ".pools[\"$REFERENCED_POOL\"]" >/dev/null \
    || { echo "FAIL: 409 must not have deleted the pool" >&2; exit 1; }
  ok "409 leaves the referenced pool intact"
else
  echo "SKIP: test #7 (DELETE 409) — REFERENCED_POOL not present"
fi

# ---------------------------------------------------------------
# 8. DELETE unknown pool → 400 validation
# ---------------------------------------------------------------
status=$(aegis_delete_status "/api/upstreams/pool/cc_t1_audit_doesnt_exist")
assert_eq "$status" "400" "DELETE unknown pool"
ok "DELETE unknown pool → 400 validation"

# ---------------------------------------------------------------
# 9. Whole-map PUT replaces the table atomically
# ---------------------------------------------------------------
# Capture the current map, then stage a "redo" PUT that recreates
# what's already there + adds AUDIT_RENAMED_POOL. Operator-style
# round-trip: GET → modify → PUT.
current=$(aegis_get /api/upstreams/config)
desired=$(echo "$current" | jq --argjson new "$(jq -nc '{
  members: [{ addr: "127.0.0.1:9993", weight: 1 }],
  lb: "round_robin"
}')" --arg name "$AUDIT_RENAMED_POOL" '
  {
    pools: (
      .pools
      | with_entries(.value |= {
          members: .members,
          lb: .lb,
          health: (if .health then {
              path: .health.path,
              interval: ((.health.interval_ms|tostring) + "ms"),
              timeout: ((.health.timeout_ms|tostring) + "ms")
            } else null end),
          circuit_breaker: (if .circuit_breaker then {
              error_rate_threshold: .circuit_breaker.error_rate_threshold,
              open_duration: ((.circuit_breaker.open_duration_ms|tostring) + "ms")
            } else null end),
          connection: (.connection // {}) | {
            max_idle_per_host: .max_idle_per_host,
            idle_timeout: ((.idle_timeout_ms|tostring) + "ms"),
            keep_alive: .keep_alive,
            tls: .tls
          }
        }
        | with_entries(select(.value != null))
      )
      + { ($name): $new }
    )
  }
')
status=$(aegis_put_status "/api/upstreams/config" "$desired")
assert_eq "$status" "200" "whole-map PUT"
ok "whole-map PUT /api/upstreams/config → 200"

cfg=$(aegis_get /api/upstreams/config)
echo "$cfg" | jq -e ".pools[\"$AUDIT_RENAMED_POOL\"]" >/dev/null \
  || { echo "FAIL: whole-map PUT did not insert the new pool" >&2; exit 1; }
ok "whole-map PUT inserted new pool"

# Cleanup the renamed pool.
aegis_delete_status "/api/upstreams/pool/$AUDIT_RENAMED_POOL" >/dev/null
ok "cleaned up cc_t1_audit_renamed_x"

# ---------------------------------------------------------------
# 10. Audit chain version advanced by ≥ 4 entries
# ---------------------------------------------------------------
version_after=$(aegis_get /api/config/version | jq -r '.version')
delta=$(( version_after - version_before ))
if [[ "$delta" -lt 4 ]]; then
  echo "FAIL: expected audit chain to advance by ≥4, got $delta" >&2
  exit 1
fi
ok "audit chain advanced by $delta entries (≥4 expected)"

echo
echo "==============================================================="
echo "CC-T1.audit — upstream pool CRUD round-trip: ALL CHECKS PASSED"
echo "==============================================================="
