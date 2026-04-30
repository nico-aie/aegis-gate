#!/usr/bin/env bash
# Shared helpers for the multi-protocol smoke tests.
#
# Endpoints (all configurable via env):
#   AEGIS_DATA_HTTP   plaintext data plane (HTTP/1.1)
#   AEGIS_DATA_HTTPS  TLS data plane (HTTP/1.1 + h2 + h3 if enabled)
#   AEGIS_DATA_H3     HTTP/3 listener (UDP/QUIC) — usually same host:port as HTTPS
#   AEGIS_ADMIN       admin plane (used for /healthz)

set -euo pipefail

AEGIS_DATA_HTTP="${AEGIS_DATA_HTTP:-http://127.0.0.1:8080}"
AEGIS_DATA_HTTPS="${AEGIS_DATA_HTTPS:-https://127.0.0.1:8443}"
AEGIS_DATA_H3="${AEGIS_DATA_H3:-https://127.0.0.1:8443}"
AEGIS_ADMIN="${AEGIS_ADMIN:-http://127.0.0.1:9443}"

# Strip ANSI for cleaner CI output.
NO_COLOR="${NO_COLOR:-}"

ok()    { echo "PASS: $*"; }
fail()  { echo "FAIL: $*" >&2; exit 1; }
skip()  { echo "SKIP: $*"; exit 0; }
info()  { echo "INFO: $*"; }

require() {
  command -v "$1" >/dev/null \
    || { echo "FAIL: missing tool: $1" >&2; exit 1; }
}

# Verify the WAF is up before running anything else.
ensure_admin_ready() {
  if ! curl --silent --max-time 2 -o /dev/null \
          -w "%{http_code}" "$AEGIS_ADMIN/healthz/ready" \
          | grep -q '^2'; then
    skip "WAF admin plane $AEGIS_ADMIN/healthz/ready is not 200; start with \`make run\` first"
  fi
}

# `curl_alpn target` returns the ALPN protocol negotiated. Useful
# for asserting that h2 / h3 / http/1.1 actually showed up.
curl_alpn() {
  curl --silent --insecure --max-time 5 \
       --connect-timeout 2 \
       -o /dev/null -w "%{http_version}\n" "$@"
}
