#!/usr/bin/env bash
# tests/manual/access-list-roundtrip.sh
#
# Adds and removes blacklist + whitelist entries via the Console API
# and asserts each one takes effect against the data plane within a
# single request — i.e. the runtime matcher reads the same Arc the
# CRUD endpoints write to.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
source "$HERE/../api/_common.sh"

AEGIS_DATA="${AEGIS_DATA:-http://127.0.0.1:8080}"

probe() {
  # $1 = X-Forwarded-For value
  # echoes "<status> <rule_id|->"
  local resp status rule_id
  resp=$(mktemp)
  status=$(curl -s -o "$resp" -D "$resp.h" \
                -w "%{http_code}" \
                -H "X-Forwarded-For: $1" \
                "$AEGIS_DATA/" || echo "000")
  rule_id=$(grep -i '^x-waf-rule-id:' "$resp.h" | awk '{print $2}' | tr -d '\r')
  rm -f "$resp" "$resp.h"
  printf "%s %s\n" "$status" "${rule_id:--}"
}

aegis_login

echo "==> Baseline: probe with 203.0.113.7 (TEST-NET-3)"
probe "203.0.113.7"

echo
echo "==> Adding IP blacklist for 203.0.113.7"
aegis_put /api/blacklist '{
  "id": "manual-ip-block",
  "kind": "ip",
  "value": "203.0.113.7",
  "reason": "access-list roundtrip"
}' >/dev/null
sleep 0.1   # ArcSwap reload is sync; small grace just in case
echo "==> Probe again — should now block"
probe "203.0.113.7"

echo
echo "==> Cleanup IP blacklist"
curl "${AEGIS_CURL_OPTS[@]}" -X DELETE \
  -H "x-csrf-token: $AEGIS_CSRF" \
  "$AEGIS_ADMIN/api/blacklist/manual-ip-block" >/dev/null

echo
echo "==> Adding CIDR blacklist 198.51.100.0/24 (TEST-NET-2)"
aegis_put /api/blacklist '{
  "id": "manual-cidr-block",
  "kind": "cidr",
  "value": "198.51.100.0/24",
  "reason": "access-list roundtrip"
}' >/dev/null
sleep 0.1
echo "  198.51.100.42 — should block"
probe "198.51.100.42"
echo "  198.51.100.7  — should also block"
probe "198.51.100.7"
echo "  192.0.2.7     — outside CIDR, should pass"
probe "192.0.2.7"

aegis_login
curl "${AEGIS_CURL_OPTS[@]}" -X DELETE \
  -H "x-csrf-token: $AEGIS_CSRF" \
  "$AEGIS_ADMIN/api/blacklist/manual-cidr-block" >/dev/null

echo
echo "==> Whitelist precedence — adding whitelist for 192.0.2.99"
aegis_put /api/whitelist '{
  "id": "manual-whitelist",
  "kind": "ip",
  "value": "192.0.2.99",
  "reason": "access-list roundtrip"
}' >/dev/null
sleep 0.1
echo "  Whitelisted IPs skip the detector chain. A SQLi-shaped"
echo "  payload from a non-whitelisted IP should normally trip a"
echo "  detector; from the whitelisted IP it should pass through."
echo "  192.0.2.99 (whitelisted) + sqli-ish path:"
probe "192.0.2.99"
curl "${AEGIS_CURL_OPTS[@]}" -o /dev/null -w "  %{http_code}\n" \
  -H "X-Forwarded-For: 192.0.2.99" \
  "$AEGIS_DATA/?q=UNION+SELECT+null,version()" || true

echo
aegis_login
curl "${AEGIS_CURL_OPTS[@]}" -X DELETE \
  -H "x-csrf-token: $AEGIS_CSRF" \
  "$AEGIS_ADMIN/api/whitelist/manual-whitelist" >/dev/null
echo "  removed manual-whitelist"

echo
echo "Expected:"
echo "  - baseline probe with 203.0.113.7 → 200 / -"
echo "  - after IP blacklist add → 403 / blacklist:manual-ip-block"
echo "  - after CIDR add → both .42 and .7 block, .192.0.2.7 passes"
echo "  - whitelisted IP with SQLi-shaped path → 200 (detector chain skipped)"
