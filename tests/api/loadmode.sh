#!/usr/bin/env bash
# tests/api/loadmode.sh — P7 smoke
#
# Asserts:
# 1. GET /api/loadmode returns documented shape.
# 2. PUT pin → response shows override_active=true.
# 3. PUT "unset" → override_active=false.
# 4. PUT unknown mode → 400 validation error.
# 5. Script clears any override it set before exit.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

aegis_login

# 1. GET shape — use `has` so false-valued fields aren't
#    treated as missing by `jq -e` (which returns 1 on null OR false).
body=$(aegis_get /api/loadmode)
for key in mode effective_mode rps_last_sample override_active elevated_rps critical_rps; do
  echo "$body" | jq -e "has(\"$key\")" >/dev/null \
    || { echo "FAIL: GET missing $key" >&2; exit 1; }
done
ok "GET /api/loadmode shape"

# 2. Pin to elevated
aegis_put /api/loadmode '{"override":"elevated"}' >/dev/null
ov=$(aegis_get /api/loadmode | jq -r '.override_active')
assert_eq "$ov" "true" "override_active after pin"
eff=$(aegis_get /api/loadmode | jq -r '.effective_mode')
assert_eq "$eff" "elevated" "effective_mode reflects pin"
ok "PUT pin elevated → override_active true"

# 3. Unset
aegis_put /api/loadmode '{"override":"unset"}' >/dev/null
ov=$(aegis_get /api/loadmode | jq -r '.override_active')
assert_eq "$ov" "false" "override_active after unset"
ok "PUT unset → override_active false"

# 4. Unknown mode
status=$(aegis_put_status /api/loadmode '{"override":"hyperdrive"}')
assert_eq "$status" "400" "unknown mode must reject"
ok "PUT unknown mode → 400"
