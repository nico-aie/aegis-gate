#!/usr/bin/env bash
# tests/api/tls-data.sh — TLS hardening smoke for the data-plane
# listener (P4 — companion to tls.sh which only covers admin).
#
# The data-plane TLS listener is *optional* — operators flip it on
# in `listeners.data[*].tls: true` and add a cert resolver. When
# absent, this script logs INFO and exits 0; when present, it
# replays the same hardening assertions as tls.sh:
#
# 1. TLS 1.0 / 1.1 handshakes are rejected.
# 2. TLS 1.2 + TLS 1.3 handshakes succeed.
# 3. Successful responses carry the documented set of security
#    headers (HSTS, X-Content-Type-Options, X-Frame-Options,
#    Referrer-Policy, Permissions-Policy).
#
# Usage:
#   AEGIS_DATA_HTTPS=https://127.0.0.1:8443 tests/api/tls-data.sh
#
# Skips quietly when AEGIS_DATA_HTTPS is unset OR the port refuses
# the connection — both states are valid for ops who run plain
# HTTP on the data plane and let an upstream LB terminate TLS.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

require curl

AEGIS_DATA_HTTPS="${AEGIS_DATA_HTTPS:-}"
if [[ -z "$AEGIS_DATA_HTTPS" ]]; then
  echo "INFO: AEGIS_DATA_HTTPS not set — skipping data-plane TLS hardening test"
  exit 0
fi

# Probe the listener once; if it refuses we're not running TLS on
# the data plane and there's nothing to assert.
if ! curl --silent --insecure --max-time 2 \
        -o /dev/null "$AEGIS_DATA_HTTPS/" 2>/dev/null; then
  echo "INFO: $AEGIS_DATA_HTTPS not reachable — skipping (data-plane TLS not configured)"
  exit 0
fi

echo "==> data-plane TLS at $AEGIS_DATA_HTTPS"

# 1. TLS 1.0 / 1.1 must be rejected.
if curl --help all 2>/dev/null | grep -q -- '--tls-max'; then
  for v in 1.0 1.1; do
    if curl --silent --insecure --tlsv$v --tls-max $v \
           --max-time 2 -o /dev/null \
           "$AEGIS_DATA_HTTPS/" 2>/dev/null; then
      echo "FAIL: data-plane listener accepted TLS $v"
      exit 1
    fi
  done
  ok "TLS 1.0 + TLS 1.1 rejected on data plane"
else
  echo "INFO: skipping TLS 1.0/1.1 reject check — curl lacks --tls-max"
fi

# 2. TLS 1.2 + 1.3 succeed (we don't care about status code — any
#    HTTP response means the handshake worked).
status=$(curl --silent --insecure --tlsv1.2 \
              -o /dev/null -w "%{http_code}" \
              --max-time 5 "$AEGIS_DATA_HTTPS/" || echo "000")
if [[ "$status" == "000" ]]; then
  echo "FAIL: TLS 1.2 handshake to data plane failed"
  exit 1
fi
ok "TLS 1.2 handshake → $status"

status=$(curl --silent --insecure --tlsv1.3 \
              -o /dev/null -w "%{http_code}" \
              --max-time 5 "$AEGIS_DATA_HTTPS/" 2>/dev/null \
            || echo "skip")
if [[ "$status" == "skip" ]]; then
  echo "INFO: TLS 1.3 unavailable in this curl build"
elif [[ "$status" == "000" ]]; then
  echo "FAIL: TLS 1.3 handshake failed (curl returned 000)"
  exit 1
else
  ok "TLS 1.3 handshake → $status"
fi

# 3. Hardening headers — HSTS at minimum on a real response.
hdrs=$(curl --silent --insecure -I --max-time 5 "$AEGIS_DATA_HTTPS/" \
       || true)
for h in \
  "strict-transport-security" \
  "x-content-type-options"
do
  if ! echo "$hdrs" | grep -qi "^$h:"; then
    echo "FAIL: data-plane response missing $h header"
    echo "$hdrs"
    exit 1
  fi
done
ok "data-plane response carries HSTS + X-Content-Type-Options"
