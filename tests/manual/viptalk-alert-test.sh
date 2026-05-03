#!/usr/bin/env bash
# tests/manual/viptalk-alert-test.sh
#
# Posts a synthetic alert at /api/alert-receivers/<id>/test and
# inspects the dispatch summary so you can verify VipTalk delivery
# (or the `skipped_feature_off` bucket when the binary was built
# without `--features alerts`).

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
source "$HERE/../api/_common.sh"

aegis_login

echo "==> 1) Listing receivers"
aegis_get /api/alert-receivers | jq '.receivers[] | {id, kind, address}'
echo

echo "==> 2) Adding a stub VipTalk receiver"
aegis_put /api/alert-receivers '{
  "id": "manual-stub",
  "kind": "viptalk",
  "address": "viptalk:dev-token@dev-room",
  "enabled": true
}' >/dev/null

echo "==> 3) Firing the test endpoint"
TEST_RESP=$(curl "${AEGIS_CURL_OPTS[@]}" -X POST \
  -H "content-type: application/json" \
  -H "x-csrf-token: $AEGIS_CSRF" \
  "$AEGIS_ADMIN/api/alert-receivers/manual-stub/test")

echo "Dispatch summary:"
echo "$TEST_RESP" | jq '.'

echo
echo "==> 4) Cleanup"
curl "${AEGIS_CURL_OPTS[@]}" -X DELETE \
  -H "x-csrf-token: $AEGIS_CSRF" \
  "$AEGIS_ADMIN/api/alert-receivers/manual-stub" >/dev/null

echo
echo "Expected:"
echo "  - if the binary is built WITHOUT --features alerts:"
echo "      summary.skipped_feature_off includes 'manual-stub'"
echo "      summary.delivered does NOT include it"
echo "    (this is the post-fix behaviour — pre-fix the dashboard"
echo "     mistakenly showed 'delivered' for a no-op send)"
echo "  - if the binary HAS --features alerts and the address is reachable:"
echo "      summary.delivered includes 'manual-stub'"
echo "  - on credential or address failure: summary.failed includes"
echo "      'manual-stub' with a reason string"
