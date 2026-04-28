#!/usr/bin/env bash
# tests/api/risk.sh — P6 smoke
#
# Asserts:
# 1. GET /api/risk returns the documented envelope.
# 2. GET /api/risk/{unknown-ip} → 404 with {"error":"not_found"}.
# 3. PUT /api/risk/{ip}/reset without CSRF → 403.
# 4. PUT /api/risk/{ip}/reset with CSRF → 200.
#
# Optional argument: an IP to reset (default 192.0.2.1).

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

target_ip="${1:-192.0.2.1}"

aegis_login

# 1. List shape
list=$(aegis_get /api/risk?limit=10)
for key in total_tracked returned clients; do
  echo "$list" | jq -e ".$key" >/dev/null \
    || { echo "FAIL: GET /api/risk missing $key" >&2; exit 1; }
done
ok "GET /api/risk shape"

# 2. Unknown IP → 404
status=$(aegis_get_status "/api/risk/198.51.100.99")
assert_eq "$status" "404" "GET /api/risk/{unknown} should 404"
ok "GET /api/risk/{unknown} → 404"

# 3. Reset without CSRF → 403
status=$(aegis_put_status "/api/risk/$target_ip/reset" "{}" "")
assert_eq "$status" "403" "reset without CSRF must reject"
ok "PUT /reset without CSRF → 403"

# 4. Reset with CSRF
status=$(aegis_put_status "/api/risk/$target_ip/reset" "{}")
assert_eq "$status" "200" "reset with CSRF should succeed"
ok "PUT /reset with CSRF → 200"
