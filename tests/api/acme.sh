#!/usr/bin/env bash
# tests/api/acme.sh — Pebble round-trip smoke (F-T7).
#
# Asserts that:
# 1. Pebble's directory URL is reachable from the host.
# 2. The InstantAcmeProvider builds a CSR via `rcgen`
#    (covered by aegis-proxy's unit tests; here we just verify
#    the helper is callable from the gateway command line).
# 3. (Future) Once F-T8 wires AcmeManager into run(), this
#    script will trigger a real ACME issue against Pebble and
#    assert the cert lands under cert_dir.
#
# Today this is a thin reachability + config-shape check —
# the full issue flow lands once cert-store hot-swap is wired.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=tests/api/_common.sh
source "$HERE/_common.sh"

PEBBLE_DIR_URL="${PEBBLE_DIR_URL:-https://127.0.0.1:14000/dir}"

# 1. Pebble directory reachable
status=$(curl -sk -o /dev/null -w "%{http_code}" "$PEBBLE_DIR_URL" || echo "000")
if [[ "$status" != "200" ]]; then
  echo "FAIL: Pebble directory unreachable at $PEBBLE_DIR_URL (got $status)"
  echo "      Bring it up with:"
  echo "        docker compose -f deploy/docker-compose.dev.yml \\"
  echo "                       -f deploy/docker-compose.test.yml \\"
  echo "                       up -d pebble"
  exit 1
fi
ok "Pebble directory reachable ($PEBBLE_DIR_URL → 200)"

# 2. Directory document parses + advertises the expected endpoints
body=$(curl -sk "$PEBBLE_DIR_URL")
for key in newAccount newOrder newNonce; do
  echo "$body" | jq -e "has(\"$key\")" >/dev/null \
    || { echo "FAIL: directory missing $key field"; exit 1; }
done
ok "directory document advertises newAccount + newOrder + newNonce"

# 3. (Placeholder) Once F-T8 lands, this section triggers a
#    real ACME issue and asserts the cert appears under cert_dir.
echo "INFO: end-to-end ACME issue check is pending F-T8 (wire AcmeManager into run())"
