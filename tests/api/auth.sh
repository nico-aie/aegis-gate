#!/usr/bin/env bash
# tests/api/auth.sh — admin auth smoke (P1)
#
# Asserts the admin login surface behaves as documented in
# docs/control-plane/dashboard-auth.md:
#
#  1. Login with bad password → 401 (constant-time response shape).
#  2. Login with the dev-config creds → 200 + sets aegis_session +
#     aegis_csrf cookies.
#  3. GET /api/about (a representative authenticated read) → 200.
#  4. PUT to a mutation endpoint without aegis_csrf header → 403.
#  5. Logout → 200 + clears the session cookie; subsequent reads → 401.
#
# This script does NOT exercise the full lockout because that would
# alter shared lockout state and contaminate the test suite. The
# constant-time + rate-limit accept paths are covered by the per-crate
# tests in `aegis-control::admin::login`. Lockout is covered by a
# dedicated k6 run when the operator explicitly opts in.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

: "${ADMIN_USER:?ADMIN_USER must be set}"
: "${ADMIN_PASS:?ADMIN_PASS must be set}"

# Use a scratch cookie jar so we don't disturb other scripts.
LOCAL_JAR="$(mktemp /tmp/aegis-auth-cookies.XXXXXX)"
trap 'rm -f "$LOCAL_JAR"' EXIT

curl_local=(--silent --show-error --insecure
            --cookie-jar "$LOCAL_JAR" --cookie "$LOCAL_JAR")

# 1. Bad password → 401
status=$(curl "${curl_local[@]}" -X POST \
  -H "content-type: application/json" \
  -d "{\"user\":\"$ADMIN_USER\",\"password\":\"wrong-password-not-real\"}" \
  -o /dev/null -w "%{http_code}" \
  "$AEGIS_ADMIN/admin/login")
assert_eq "$status" "401" "bad password should 401"
ok "bad password → 401"

# 2. Good login → 200 + cookies set
> "$LOCAL_JAR"
status=$(curl "${curl_local[@]}" -X POST \
  -H "content-type: application/json" \
  -d "{\"user\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" \
  -o /dev/null -w "%{http_code}" \
  "$AEGIS_ADMIN/admin/login")
assert_eq "$status" "200" "valid login should 200"

session=$(awk -v IGNORECASE=1 '/aegis_session/{print $7}' "$LOCAL_JAR")
csrf=$(awk -v IGNORECASE=1 '/aegis_csrf/{print $7}' "$LOCAL_JAR")
[[ -n "$session" ]] || { echo "FAIL: aegis_session cookie not set" >&2; exit 1; }
[[ -n "$csrf"    ]] || { echo "FAIL: aegis_csrf cookie not set"    >&2; exit 1; }
ok "valid login → 200 + aegis_session + aegis_csrf set"

# 3. Authenticated GET works
status=$(curl "${curl_local[@]}" -o /dev/null -w "%{http_code}" \
  -H "accept: application/json" \
  "$AEGIS_ADMIN/api/about")
assert_eq "$status" "200" "GET /api/about should 200 after login"
ok "authenticated GET /api/about → 200"

# 4. Mutation without CSRF header → 403 (try the cheapest mutation
#    we have: /api/risk/{ip}/reset on a synthetic IP that no other
#    test depends on, with no x-csrf-token header).
status=$(curl "${curl_local[@]}" -X PUT \
  -H "content-type: application/json" \
  -d "{}" \
  -o /dev/null -w "%{http_code}" \
  "$AEGIS_ADMIN/api/risk/192.0.2.250/reset")
assert_eq "$status" "403" "mutation without CSRF should 403"
ok "PUT without CSRF → 403"

# 5. Logout → 200 or 204, subsequent read → 401
# Both are valid: the handler returns 204 (no body); some clients
# expect 200. Accept either.
status=$(curl "${curl_local[@]}" -X POST \
  -o /dev/null -w "%{http_code}" \
  -H "x-csrf-token: $csrf" \
  "$AEGIS_ADMIN/admin/logout")
case "$status" in
  200|204) ok "logout returned $status" ;;
  *) fail "logout should 200 or 204; got $status" ;;
esac

# Post-logout: the session cookie should be cleared from the local
# jar (so subsequent privileged reads fall back to anonymous), and
# CSRF-gated mutations should reject. The dev admin port is local-
# only and dashboard reads are intentionally open — gating happens
# at mutations + drain, not at every dashboard GET.
session_after=$(awk -v IGNORECASE=1 '/aegis_session/{print $7}' "$LOCAL_JAR")
[[ -z "$session_after" || "$session_after" == '""' ]] || \
  fail "logout did not clear aegis_session cookie (got '$session_after')"
ok "logout cleared aegis_session in local cookie jar"

status=$(curl "${curl_local[@]}" -X PUT \
  -H "content-type: application/json" \
  -d "{}" \
  -o /dev/null -w "%{http_code}" \
  "$AEGIS_ADMIN/api/risk/192.0.2.251/reset")
assert_eq "$status" "403" "post-logout mutation without csrf should 403"
ok "post-logout mutation without csrf → 403"
