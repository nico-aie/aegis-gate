#!/usr/bin/env bash
# tests/api/logging.sh — P8 smoke
#
# Asserts:
# 1. GET /api/logging returns the level + ladder.
# 2. The ladder is exactly [silent, error, warn, info, debug, trace].
# 3. PUT each level round-trips.
# 4. PUT unknown level → 400 with validation reason.
# 5. Restores level=info before exit.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

aegis_login

# 1. GET shape
body=$(aegis_get /api/logging)
echo "$body" | jq -e '.level, .levels' >/dev/null \
  || { echo "FAIL: GET missing level/levels" >&2; exit 1; }
ok "GET /api/logging shape"

# 2. Ladder order
expected='["silent","error","warn","info","debug","trace"]'
got=$(echo "$body" | jq -c '.levels')
assert_eq "$got" "$expected" "ladder order"
ok "ladder = $expected"

# 3. Round-trip every level
for lv in silent error warn info debug trace; do
  aegis_put /api/logging "{\"level\":\"$lv\"}" >/dev/null
  cur=$(aegis_get /api/logging | jq -r '.level')
  assert_eq "$cur" "$lv" "round-trip $lv"
done
ok "all 6 levels round-trip"

# 4. Unknown level
status=$(aegis_put_status /api/logging '{"level":"loud"}')
assert_eq "$status" "400" "unknown level must reject"
ok "unknown level → 400"

# 5. Restore default
aegis_put /api/logging '{"level":"info"}' >/dev/null
ok "restored level=info"
