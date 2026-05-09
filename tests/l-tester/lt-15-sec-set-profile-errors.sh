#!/usr/bin/env bash
# LT-15 — set_profile: error semantics  (400 vs 422 vs 200-with-unsupported)
#
# Bug-hunter test: verifies the precise HTTP status codes returned for
# various invalid set_profile payloads.  Many WAF implementations return
# a generic 400 for all errors, but the v2.3 contract distinguishes:
#
#   400 Bad Request  — malformed body, missing required fields,
#                      scope=all with extra fields, empty lists
#   422 Unprocessable— scope=policies with unknown feature
#   200 OK + unsupported[] — scope=features or scope=policies with
#                             unknown feature/policy under a KNOWN parent
#
# Bugs targeted:
#   - scope=all ignoring extra "features"/"feature"/"policies" fields
#   - scope=policies unknown feature returning 200 instead of 422
#   - Unknown JSON field silently ignored instead of returning 400
#   - scope=features with no "features" key not rejected
#   - scope=features with empty features list not rejected

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"
require curl
require jq

trap trap_cleanup EXIT
start_waf
reset_to_enforce

# Helper: POST set_profile, return HTTP status code only
set_profile_status() {
  curl -s --max-time 5 -X POST \
       -H "X-Benchmark-Secret: $SECRET" \
       -H "content-type: application/json" \
       -d "$1" \
       -o /dev/null -w '%{http_code}' \
       "$ADMIN/__waf_control/set_profile" || echo 000
}

# Helper: POST set_profile, return full body
set_profile_body() {
  curl -s --max-time 5 -X POST \
       -H "X-Benchmark-Secret: $SECRET" \
       -H "content-type: application/json" \
       -d "$1" \
       "$ADMIN/__waf_control/set_profile" || echo '{}'
}

# ------------------------------------------------------------------
# 1. scope=all + extra "features" field → 400
# ------------------------------------------------------------------
s=$(set_profile_status '{"scope":"all","mode":"enforce","features":["rules_engine"]}')
[[ "$s" == "400" ]] \
  || fail "scope=all + 'features' field → $s (expected 400); scope=all must reject extra fields"
ok "scope=all + extra 'features' field → 400"

# ------------------------------------------------------------------
# 2. scope=all + extra "feature" field → 400
# ------------------------------------------------------------------
s=$(set_profile_status '{"scope":"all","mode":"enforce","feature":"rules_engine"}')
[[ "$s" == "400" ]] \
  || fail "scope=all + 'feature' field → $s (expected 400)"
ok "scope=all + extra 'feature' field → 400"

# ------------------------------------------------------------------
# 3. scope=all + extra "policies" field → 400
# ------------------------------------------------------------------
s=$(set_profile_status '{"scope":"all","mode":"enforce","policies":["sqli"]}')
[[ "$s" == "400" ]] \
  || fail "scope=all + 'policies' field → $s (expected 400)"
ok "scope=all + extra 'policies' field → 400"

# ------------------------------------------------------------------
# 4. scope=features + missing "features" key → 400
# ------------------------------------------------------------------
s=$(set_profile_status '{"scope":"features","mode":"log_only"}')
[[ "$s" == "400" ]] \
  || fail "scope=features without 'features' key → $s (expected 400)"
ok "scope=features + missing 'features' key → 400"

# ------------------------------------------------------------------
# 5. scope=features + empty features list → 400
# ------------------------------------------------------------------
s=$(set_profile_status '{"scope":"features","mode":"log_only","features":[]}')
[[ "$s" == "400" ]] \
  || fail "scope=features + empty list → $s (expected 400)"
ok "scope=features + empty features list → 400"

# ------------------------------------------------------------------
# 6. scope=policies + unknown FEATURE → 422 (not 200!)
# ------------------------------------------------------------------
s=$(set_profile_status '{"scope":"policies","mode":"log_only","feature":"nonexistent_feature_xyz","policies":["sqli"]}')
[[ "$s" == "422" ]] \
  || fail "scope=policies + unknown feature → $s (expected 422 Unprocessable, not 200)"
ok "scope=policies + unknown feature → 422"

# ------------------------------------------------------------------
# 7. scope=policies + known feature + unknown policy → 200 with unsupported
# ------------------------------------------------------------------
body=$(set_profile_body '{"scope":"policies","mode":"log_only","feature":"rules_engine","policies":["__nonexistent_policy_xyz__"]}')
s=$(curl -s --max-time 5 -X POST \
     -H "X-Benchmark-Secret: $SECRET" \
     -H "content-type: application/json" \
     -d '{"scope":"policies","mode":"log_only","feature":"rules_engine","policies":["__nonexistent_policy_xyz__"]}' \
     -o /dev/null -w '%{http_code}' \
     "$ADMIN/__waf_control/set_profile" || echo 000)
[[ "$s" == "200" ]] \
  || fail "scope=policies + unknown policy under known feature → $s (expected 200 with unsupported)"
unsupported_len=$(printf '%s' "$body" | jq '.unsupported | length' 2>/dev/null || echo 0)
[[ "$unsupported_len" -ge 1 ]] \
  || fail "unknown policy should appear in .unsupported (body: $body)"
ok "scope=policies + unknown policy → 200 with unsupported entry"

# ------------------------------------------------------------------
# 8. Unknown JSON field in body → 400 (deny_unknown_fields)
# ------------------------------------------------------------------
s=$(set_profile_status '{"scope":"all","mode":"enforce","UNKNOWN_FIELD_XYZ":"value"}')
[[ "$s" == "400" ]] \
  || fail "unknown JSON field → $s (expected 400; deny_unknown_fields must be enforced)"
ok "unknown JSON field in set_profile body → 400"

# ------------------------------------------------------------------
# 9. scope=features + unknown feature → 200 with unsupported (not 422)
# ------------------------------------------------------------------
body=$(set_profile_body '{"scope":"features","mode":"log_only","features":["__nonexistent_feat_xyz__"]}')
s=$(curl -s --max-time 5 -X POST \
     -H "X-Benchmark-Secret: $SECRET" \
     -H "content-type: application/json" \
     -d '{"scope":"features","mode":"log_only","features":["__nonexistent_feat_xyz__"]}' \
     -o /dev/null -w '%{http_code}' \
     "$ADMIN/__waf_control/set_profile" || echo 000)
[[ "$s" == "200" ]] \
  || fail "scope=features + unknown feature → $s (expected 200 with .unsupported, not 422)"
unsupported_len=$(printf '%s' "$body" | jq '.unsupported | length' 2>/dev/null || echo 0)
[[ "$unsupported_len" -ge 1 ]] \
  || fail "unknown feature in scope=features should appear in .unsupported"
ok "scope=features + unknown feature → 200 with unsupported (not 422)"

ctrl_post "/__waf_control/set_profile" '{"scope":"all","mode":"enforce"}' >/dev/null

ok "LT-15 set-profile-errors: all checks green"
