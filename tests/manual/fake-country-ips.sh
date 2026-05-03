#!/usr/bin/env bash
# tests/manual/fake-country-ips.sh
#
# Drive the runtime blacklist `kind: country` matcher with spoofed
# X-Forwarded-For headers from known-country IPs. The data plane
# treats loopback as a trusted proxy, so `curl -H "X-Forwarded-For: ..."`
# from localhost lets you simulate "request from country X" without
# needing a real source from that country.
#
# Use: make run-dev in one shell, then this script in another.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
source "$HERE/../api/_common.sh"

AEGIS_DATA="${AEGIS_DATA:-http://127.0.0.1:8080}"

# Known-country IPs that resolve cleanly against MaxMind's GeoLite2.
declare -A SAMPLE_IPS=(
  [US]=8.8.8.8
  [CN]=223.5.5.5
  [RU]=77.88.8.8
  [DE]=195.30.6.6
  [JP]=210.130.0.1
  [BR]=200.221.11.100
  [GB]=80.0.0.1
)

aegis_login

echo "==> 1) Adding 'CN' country blacklist entry"
aegis_put /api/blacklist '{
  "id": "manual-cn-block",
  "kind": "country",
  "value": "CN",
  "reason": "manual validation: country-code blacklist test"
}' >/dev/null
echo "    blacklist now has the CN entry; verifying via GET"
aegis_get /api/blacklist | jq '.entries[] | select(.id == "manual-cn-block")'

echo
echo "==> 2) Driving the data plane with one IP per known country"
for country in "${!SAMPLE_IPS[@]}"; do
  ip="${SAMPLE_IPS[$country]}"
  status=$(curl -s -o /tmp/aegis-fake-country.body \
                -w "%{http_code}" \
                -H "X-Forwarded-For: $ip" \
                "$AEGIS_DATA/" || true)
  rule_id=$(curl -s -D - -o /dev/null \
                 -H "X-Forwarded-For: $ip" \
                 "$AEGIS_DATA/" | grep -i '^x-waf-rule-id:' | tr -d '\r' || true)
  printf "  %-3s %-16s status=%-3s rule_id=%s\n" \
    "$country" "$ip" "$status" "${rule_id:-(none)}"
done

echo
echo "==> 3) Cleanup"
aegis_login   # refresh CSRF in case it expired during the loop
curl "${AEGIS_CURL_OPTS[@]}" -X DELETE \
  -H "x-csrf-token: $AEGIS_CSRF" \
  "$AEGIS_ADMIN/api/blacklist/manual-cn-block" >/dev/null
echo "    removed manual-cn-block"

echo
echo "Expected outcome:"
echo "  - CN should land status=403 with rule_id=blacklist:manual-cn-block"
echo "  - all other countries land status=200 (or whatever the catch-all returns)"
echo "  - if every country shows 'unknown country', cfg.geoip.country_db isn't"
echo "    wired or the .mmdb file is missing — run 'make geoip-link' first."
