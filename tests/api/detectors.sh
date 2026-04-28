#!/usr/bin/env bash
# tests/api/detectors.sh — P2 + P3 smoke
#
# Exercises GET + PUT /api/detectors:
# 1. GET returns documented shape with mask, overrides,
#    locked_classes, compliance_modes.
# 2. PUT without a CSRF header → 403 csrf_missing_header.
# 3. PUT with CSRF + a valid body round-trips.
# 4. The flipped class (recon=false) shows up on the next GET.
# 5. The script restores recon=true before exit.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=tests/api/_common.sh
source "$HERE/_common.sh"

aegis_login

# 1. GET shape
body=$(aegis_get /api/detectors)
for key in mask overrides locked_classes compliance_modes; do
  echo "$body" | jq -e ".$key" >/dev/null \
    || { echo "FAIL: GET missing $key" >&2; exit 1; }
done
ok "GET /api/detectors shape"

# 2. PUT without CSRF → 403
status=$(aegis_put_status /api/detectors '{"mask":{}}' "")
assert_eq "$status" "403" "PUT without CSRF should be 403"
ok "PUT without CSRF → 403"

# 3. PUT with CSRF, flip recon off
flip='{"mask":{"sqli":true,"xss":true,"path_traversal":true,"ssrf":true,
              "header_injection":true,"body_abuse":true,
              "recon":false,"brute_force":true}}'
status=$(aegis_put_status /api/detectors "$flip")
assert_eq "$status" "200" "PUT flip should succeed"
ok "PUT flip → 200"

# 4. Verify the new state
recon=$(aegis_get /api/detectors | jq -r '.mask.recon')
assert_eq "$recon" "false" "recon should be off after flip"
ok "recon off after flip"

# 5. Restore default
restore='{"mask":{"sqli":true,"xss":true,"path_traversal":true,"ssrf":true,
                  "header_injection":true,"body_abuse":true,
                  "recon":true,"brute_force":true}}'
aegis_put /api/detectors "$restore" >/dev/null
ok "restored recon=true"
