#!/usr/bin/env bash
# tests/api/tls.sh — TLS hardening smoke (P4)
#
# Asserts the admin listener (always TLS — :9443) enforces the
# hardening contract documented in docs/data-plane/tls-termination.md
# and docs/control-plane/dashboard-auth.md §"Transport":
#
# 1. TLS 1.0 / 1.1 handshakes are rejected.
# 2. TLS 1.2 + TLS 1.3 handshakes succeed.
# 3. Successful responses carry the documented set of security
#    headers (HSTS, X-Content-Type-Options, X-Frame-Options,
#    Referrer-Policy, Permissions-Policy).
#
# Notes:
# - Some old curl builds drop --tls-max support; we skip the
#   "TLS 1.1 rejected" assertion in that case rather than fail the
#   whole run.
# - This script does NOT cover the data-plane :8443 listener
#   because it's optional; tests/load/baseline.js exercises it
#   under live traffic.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

require curl

# 1. TLS 1.0 / 1.1 must be rejected.
if curl --help all 2>/dev/null | grep -q -- '--tls-max'; then
  for v in 1.0 1.1; do
    if curl --silent --insecure --tlsv$v --tls-max $v \
         -o /dev/null -w "%{http_code}" \
         "$AEGIS_ADMIN/healthz/ready" 2>/dev/null; then
      echo "FAIL: admin listener accepted TLS $v"
      exit 1
    fi
  done
  ok "TLS 1.0 + TLS 1.1 rejected"
else
  echo "INFO: skipping TLS 1.0/1.1 reject check — curl lacks --tls-max"
fi

# 2. TLS 1.2 + 1.3 succeed.
status=$(curl --silent --insecure --tlsv1.2 -o /dev/null -w "%{http_code}" \
  "$AEGIS_ADMIN/healthz/ready")
assert_eq "$status" "200" "TLS 1.2 should succeed"
ok "TLS 1.2 handshake → 200"

status=$(curl --silent --insecure --tlsv1.3 -o /dev/null -w "%{http_code}" \
  "$AEGIS_ADMIN/healthz/ready" 2>/dev/null || echo "skip")
if [[ "$status" == "200" ]]; then
  ok "TLS 1.3 handshake → 200"
elif [[ "$status" == "skip" ]]; then
  echo "INFO: TLS 1.3 unavailable in this curl build"
else
  echo "FAIL: TLS 1.3 expected 200, got $status"
  exit 1
fi

# 3. Security headers on a representative response.
hdrs=$(curl --silent --insecure -I "$AEGIS_ADMIN/healthz/ready")
for h in \
  "strict-transport-security" \
  "x-content-type-options" \
  "x-frame-options" \
  "referrer-policy" \
  "permissions-policy"
do
  if ! echo "$hdrs" | grep -qi "^$h:"; then
    echo "FAIL: response missing $h header"
    echo "$hdrs"
    exit 1
  fi
done
ok "response carries HSTS + 4 hardening headers"
