#!/usr/bin/env bash
# tests/manual/csrf-cookie-flow.sh
#
# Walks through the login → CSRF cookie → mutation pipeline so you
# can confirm:
#   1) `aegis_csrf` cookie is set after login
#   2) authenticated mutations succeed when the X-CSRF-Token header
#      matches the cookie
#   3) missing or stale CSRF returns 403 with the expected reason
#
# Set ADMIN_USER + ADMIN_PASS before running.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
source "$HERE/../api/_common.sh"

show_cookies() {
  echo "  cookie jar:"
  awk '/aegis_(session|csrf)/{printf "    %s = %s\n", $6, $7}' "$AEGIS_COOKIES"
}

echo "==> 1) login"
aegis_login
show_cookies

echo
echo "==> 2) authenticated PUT with valid CSRF (should succeed)"
status=$(curl "${AEGIS_CURL_OPTS[@]}" -o /dev/null -w "%{http_code}" \
  -X PUT \
  -H "content-type: application/json" \
  -H "x-csrf-token: $AEGIS_CSRF" \
  -d '{
    "id": "csrf-roundtrip",
    "kind": "ip",
    "value": "203.0.113.99",
    "reason": "csrf-flow validation"
  }' \
  "$AEGIS_ADMIN/api/blacklist") || true
echo "    PUT status = $status (expect 200/204)"

echo
echo "==> 3) PUT with NO CSRF header (should 403)"
status=$(curl "${AEGIS_CURL_OPTS[@]}" -o /tmp/aegis-csrf-resp -w "%{http_code}" \
  -X PUT \
  -H "content-type: application/json" \
  -d '{
    "id": "csrf-roundtrip-2",
    "kind": "ip",
    "value": "203.0.113.100",
    "reason": "csrf-flow validation (missing token)"
  }' \
  "$AEGIS_ADMIN/api/blacklist") || true
echo "    PUT status = $status (expect 403)"
echo "    response body:"
sed 's/^/      /' /tmp/aegis-csrf-resp
echo

echo "==> 4) PUT with WRONG CSRF header (should 403)"
status=$(curl "${AEGIS_CURL_OPTS[@]}" -o /tmp/aegis-csrf-resp -w "%{http_code}" \
  -X PUT \
  -H "content-type: application/json" \
  -H "x-csrf-token: wrong-value-deadbeef" \
  -d '{
    "id": "csrf-roundtrip-3",
    "kind": "ip",
    "value": "203.0.113.101",
    "reason": "csrf-flow validation (wrong token)"
  }' \
  "$AEGIS_ADMIN/api/blacklist") || true
echo "    PUT status = $status (expect 403)"
echo "    response body:"
sed 's/^/      /' /tmp/aegis-csrf-resp
echo

echo "==> 5) cleanup"
curl "${AEGIS_CURL_OPTS[@]}" -X DELETE \
  -H "x-csrf-token: $AEGIS_CSRF" \
  "$AEGIS_ADMIN/api/blacklist/csrf-roundtrip" >/dev/null
echo "    removed csrf-roundtrip entry"

echo
echo "Expected reasons in the 403 bodies:"
echo "  - missing token → reason: csrf_missing"
echo "  - wrong token   → reason: csrf_mismatch"
echo "Both reason codes are what the dashboard's global fetch"
echo "interceptor watches for to auto-redirect to /admin/login."
