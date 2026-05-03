#!/usr/bin/env bash
# skills/aegis-waf-tester/scripts/reset-state.sh
#
# Cleans dashboard-side state between test runs so a fresh
# functional pass starts from a known-clean blacklist /
# whitelist / risk strikes / detector-mask shape.  Idempotent.
#
# Does NOT touch:
#   - Redis itself (state survives — restart the WAF if you want
#     a true cold boot)
#   - cfg.* files
#   - the audit chain on disk

set -uo pipefail

ADMIN="${AEGIS_ADMIN:-http://127.0.0.1:9443}"
USER="${ADMIN_USER:-admin}"
PASS="${ADMIN_PASS:-aegis-test-1234}"
JAR="$(mktemp -t aegis-cookies.XXXXXX)"

echo "==> Logging in"
curl -fsS -c "$JAR" -X POST \
  -H "content-type: application/json" \
  -d "{\"user\":\"$USER\",\"password\":\"$PASS\"}" \
  "$ADMIN/admin/login" >/dev/null
CSRF=$(awk -v IGNORECASE=1 '/aegis_csrf/{print $7}' "$JAR")
[[ -n "$CSRF" ]] || { echo "FAIL: no CSRF after login" >&2; exit 1; }

echo "==> Clearing access lists"
for kind in blacklist whitelist; do
  ids=$(curl -fsS -b "$JAR" "$ADMIN/api/$kind" | jq -r '.entries[].id // empty')
  for id in $ids; do
    curl -fsS -b "$JAR" -H "x-csrf-token: $CSRF" \
      -X DELETE "$ADMIN/api/$kind/$id" >/dev/null
    echo "  removed $kind/$id"
  done
done

echo "==> Resetting risk strikes (best effort)"
curl -fsS -b "$JAR" -H "x-csrf-token: $CSRF" \
  -X POST "$ADMIN/api/risk/reset" >/dev/null 2>&1 \
  && echo "  risk reset ok" \
  || echo "  risk reset endpoint unavailable (skipping)"

rm -f "$JAR"
echo "==> Done"
