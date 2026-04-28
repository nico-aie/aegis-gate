#!/usr/bin/env bash
# Common helper sourced by every tests/api/*.sh script.
#
# Sets up:
#   AEGIS_ADMIN     — control-plane base URL (default https://127.0.0.1:9443)
#   AEGIS_COOKIES   — cookie jar path (default /tmp/aegis-cookies.jar)
#   AEGIS_CSRF      — CSRF token, available after `aegis_login`
#
# Defines:
#   aegis_login            — logs in as ${ADMIN_USER} / ${ADMIN_PASS}
#   aegis_get  <path>      — authenticated GET
#   aegis_put  <path> <body> — authenticated PUT with CSRF header
#   require    <name>      — abort if a tool is missing

set -euo pipefail

AEGIS_ADMIN="${AEGIS_ADMIN:-https://127.0.0.1:9443}"
AEGIS_COOKIES="${AEGIS_COOKIES:-/tmp/aegis-cookies.jar}"
AEGIS_CURL_OPTS=(--silent --show-error --insecure --cookie-jar "$AEGIS_COOKIES" --cookie "$AEGIS_COOKIES")

require() {
  command -v "$1" >/dev/null || { echo "FAIL: missing tool: $1" >&2; exit 1; }
}
require curl
require jq

aegis_login() {
  : "${ADMIN_USER:?ADMIN_USER must be set}"
  : "${ADMIN_PASS:?ADMIN_PASS must be set}"
  curl "${AEGIS_CURL_OPTS[@]}" -X POST \
    -H "content-type: application/json" \
    -d "{\"user\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" \
    "$AEGIS_ADMIN/admin/login" >/dev/null
  AEGIS_CSRF=$(awk -v IGNORECASE=1 '/aegis_csrf/{print $7}' "$AEGIS_COOKIES")
  if [[ -z "${AEGIS_CSRF:-}" ]]; then
    echo "FAIL: aegis_csrf cookie not set after login" >&2
    exit 1
  fi
  export AEGIS_CSRF
}

aegis_get() {
  curl "${AEGIS_CURL_OPTS[@]}" -H "accept: application/json" "$AEGIS_ADMIN$1"
}

aegis_get_status() {
  curl "${AEGIS_CURL_OPTS[@]}" -o /dev/null -w "%{http_code}" "$AEGIS_ADMIN$1"
}

aegis_put() {
  local path="$1" body="$2"
  curl "${AEGIS_CURL_OPTS[@]}" -X PUT \
    -H "content-type: application/json" \
    -H "x-csrf-token: $AEGIS_CSRF" \
    -d "$body" "$AEGIS_ADMIN$path"
}

aegis_put_status() {
  local path="$1" body="$2" csrf="${3:-$AEGIS_CSRF}"
  local hdr=()
  [[ -n "$csrf" ]] && hdr=(-H "x-csrf-token: $csrf")
  curl "${AEGIS_CURL_OPTS[@]}" -X PUT \
    -H "content-type: application/json" \
    "${hdr[@]}" \
    -d "$body" -o /dev/null -w "%{http_code}" "$AEGIS_ADMIN$path"
}

assert_eq() {
  if [[ "$1" != "$2" ]]; then
    echo "FAIL: expected '$2' got '$1' (${3:-})" >&2
    exit 1
  fi
}

ok() { printf "PASS: %s\n" "$1"; }
