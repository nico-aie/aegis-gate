#!/usr/bin/env bash
# DR-T2 — `/__waf_control/*` endpoints reply with the contract
# JSON shape and reject missing/wrong secrets.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"
require curl
require jq

trap trap_cleanup EXIT
start_waf

# 1. Auth: missing secret → 403.
status=$(curl -s -o /dev/null --max-time 3 \
              -w "%{http_code}" "$ADMIN/__waf_control/capabilities")
[[ "$status" == "403" ]] || fail "no-auth → $status (expected 403)"
ok "no auth → 403"

# 2. Auth: wrong secret → 403.
status=$(curl -s -o /dev/null --max-time 3 \
              -H "X-Benchmark-Secret: nope" \
              -w "%{http_code}" "$ADMIN/__waf_control/capabilities")
[[ "$status" == "403" ]] || fail "bad-secret → $status (expected 403)"
ok "wrong secret → 403"

# 3. capabilities — required keys.
body=$(curl -s --max-time 3 -H "X-Benchmark-Secret: $SECRET" \
            "$ADMIN/__waf_control/capabilities")
echo "$body" | jq -e '.ok == true' >/dev/null \
  || fail "capabilities .ok != true ($body)"
echo "$body" | jq -e '.features | type == "object"' >/dev/null \
  || fail "capabilities .features must be object"
echo "$body" | jq -e '.active.default_mode | type == "string"' >/dev/null \
  || fail "capabilities .active.default_mode must be string"
echo "$body" | jq -e '.active.overrides | type == "object"' >/dev/null \
  || fail "capabilities .active.overrides must be object"
echo "$body" | jq -e '.features | length > 0' >/dev/null \
  || fail "capabilities must list at least one feature"
ok "capabilities shape valid (features=$(echo "$body" | jq -r '.features | keys | length'))"

# 4. set_profile — scope=all.
body=$(curl -s --max-time 3 -X POST \
            -H "X-Benchmark-Secret: $SECRET" \
            -H "content-type: application/json" \
            -d '{"scope":"all","mode":"log_only"}' \
            "$ADMIN/__waf_control/set_profile")
echo "$body" | jq -e '.ok == true' >/dev/null \
  || fail "set_profile .ok != true ($body)"
echo "$body" | jq -e '.action == "set_profile"' >/dev/null \
  || fail "set_profile .action != \"set_profile\""
echo "$body" | jq -e '.applied.scope == "all"' >/dev/null \
  || fail "set_profile .applied.scope != all"
echo "$body" | jq -e '.applied.mode == "log_only"' >/dev/null \
  || fail "set_profile .applied.mode != log_only"
echo "$body" | jq -e '.active.default_mode == "log_only"' >/dev/null \
  || fail "set_profile .active.default_mode != log_only"
echo "$body" | jq -e '.unsupported | type == "array"' >/dev/null \
  || fail "set_profile .unsupported must be array"
echo "$body" | jq -e '.ts_ms | type == "number"' >/dev/null \
  || fail "set_profile .ts_ms must be number"
ok "set_profile scope=all shape valid"

# 5. set_profile — scope=features.
body=$(curl -s --max-time 3 -X POST \
            -H "X-Benchmark-Secret: $SECRET" \
            -H "content-type: application/json" \
            -d '{"scope":"features","mode":"enforce","features":["access_control"]}' \
            "$ADMIN/__waf_control/set_profile")
echo "$body" | jq -e '.applied.features == ["access_control"]' >/dev/null \
  || fail "set_profile features didn't echo back ($body)"
ok "set_profile scope=features shape valid"

# 6. set_profile — scope=policies.
body=$(curl -s --max-time 3 -X POST \
            -H "X-Benchmark-Secret: $SECRET" \
            -H "content-type: application/json" \
            -d '{"scope":"policies","mode":"log_only","feature":"access_control","policies":["blacklist"]}' \
            "$ADMIN/__waf_control/set_profile")
echo "$body" | jq -e '.applied.feature == "access_control"' >/dev/null \
  || fail "set_profile feature field missing ($body)"
echo "$body" | jq -e '.applied.policies == ["blacklist"]' >/dev/null \
  || fail "set_profile policies field missing"
echo "$body" | jq -e '.active.overrides["access_control.blacklist"] == "log_only"' >/dev/null \
  || fail "set_profile didn't record policy override"
ok "set_profile scope=policies shape valid"

# 7. set_profile — invalid body returns 400.
status=$(curl -s -o /dev/null --max-time 3 \
              -X POST -H "X-Benchmark-Secret: $SECRET" \
              -H "content-type: application/json" \
              -d '{"bogus":"shape"}' \
              -w "%{http_code}" "$ADMIN/__waf_control/set_profile")
[[ "$status" == "400" ]] || fail "invalid body → $status (expected 400)"
ok "set_profile invalid body → 400"

# 8. set_profile — unknown feature in features list shows up unsupported.
body=$(curl -s --max-time 3 -X POST \
            -H "X-Benchmark-Secret: $SECRET" \
            -H "content-type: application/json" \
            -d '{"scope":"features","mode":"log_only","features":["does-not-exist"]}' \
            "$ADMIN/__waf_control/set_profile")
echo "$body" | jq -e '.unsupported | length == 1' >/dev/null \
  || fail "unknown feature must populate .unsupported (got $body)"
ok "set_profile unknown feature → .unsupported populated"

# 9. reset_state — required keys.
body=$(curl -s --max-time 3 -X POST \
            -H "X-Benchmark-Secret: $SECRET" \
            "$ADMIN/__waf_control/reset_state")
echo "$body" | jq -e '.ok == true' >/dev/null \
  || fail "reset_state .ok != true"
echo "$body" | jq -e '.action == "reset_state"' >/dev/null \
  || fail "reset_state .action wrong"
echo "$body" | jq -e '.audit_log_preserved == true' >/dev/null \
  || fail "reset_state must report audit_log_preserved=true"
echo "$body" | jq -e '.ts_ms | type == "number"' >/dev/null \
  || fail "reset_state ts_ms missing"
ok "reset_state shape valid"

# 10. flush_cache — supported field present.
body=$(curl -s --max-time 3 -X POST \
            -H "X-Benchmark-Secret: $SECRET" \
            "$ADMIN/__waf_control/flush_cache")
echo "$body" | jq -e '.ok == true' >/dev/null \
  || fail "flush_cache .ok != true"
echo "$body" | jq -e '.supported | type == "boolean"' >/dev/null \
  || fail "flush_cache .supported must be boolean"
ok "flush_cache shape valid (supported=$(echo "$body" | jq -r '.supported'))"

ok "DR-T2 control-plane shape: 10/10 checks green"
