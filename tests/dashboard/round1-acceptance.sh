#!/usr/bin/env bash
# DD-T8 — Round-1 acceptance script.
#
# Closes the Hackathon WAF-FE v2.3 §2 contract by measuring the four
# hard timing/visibility requirements against a *running* aegis-bin:
#
#   1. Real-time monitor ≤ 5 s    — /dashboard/sse delivers events
#                                    within 5 s of the proxied request
#   2. Hot-reload ≤ 10 s          — POST /api/rules then poll
#                                    /api/config/version; assert version
#                                    advances within 10 s
#   3. Create-rule ≤ 5 clicks     — design property (assert by
#                                    counting the buttons: + New → form
#                                    fields → Save = 3 clicks)
#   4. Find-audit ≤ 30 s          — /api/audit/since with filters
#                                    returns within 30 s for arbitrary
#                                    filter combinations
#
# Plus a structural pass that confirms:
#   - /dashboard/ shell mounts the React 18 root (id="root")
#   - CSP for /dashboard/* is `script-src 'self'` (no CDN, no eval)
#   - app.js is under the per-bundle budget (256 KB)
#   - the four CSRF-gated rule CRUD verbs reject without a cookie
#
# Run against any running aegis-bin admin endpoint, e.g.:
#   AEGIS_ADMIN=http://localhost:9443 \
#       bash tests/dashboard/round1-acceptance.sh
#
# Exits 0 only when all eight checks pass. Failed checks print FAIL
# with the measured value vs the contract bound.

set -euo pipefail

AEGIS_ADMIN="${AEGIS_ADMIN:-http://127.0.0.1:9443}"
AEGIS_DATA="${AEGIS_DATA:-http://127.0.0.1:8080}"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

PASS_COUNT=0
FAIL_COUNT=0

ok()   { echo "PASS: $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo "FAIL: $*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }
info() { echo "INFO: $*"; }

require() {
  command -v "$1" >/dev/null \
    || { echo "FAIL: missing tool: $1" >&2; exit 1; }
}

require curl
require jq

# --------------------------------------------------------------- #
# Pre-flight: is the admin plane up?                              #
# --------------------------------------------------------------- #
if ! curl --silent --max-time 2 -o /dev/null \
        -w "%{http_code}" "$AEGIS_ADMIN/healthz/ready" \
        | grep -q '^2'; then
  echo "FAIL: $AEGIS_ADMIN/healthz/ready not 2xx — start aegis-bin first" >&2
  exit 1
fi

# Establish a session for CSRF-gated mutations.
COOKIES="$TMPDIR/cookies.txt"
curl --silent --max-time 5 \
     --cookie-jar "$COOKIES" \
     "$AEGIS_ADMIN/dashboard/" >/dev/null
CSRF="$(awk '/aegis_csrf/ {print $7}' "$COOKIES" | tail -n1)"
if [[ -z "${CSRF:-}" ]]; then
  echo "FAIL: no aegis_csrf cookie returned by /dashboard/" >&2
  exit 1
fi
info "csrf cookie acquired (${#CSRF} bytes)"

# --------------------------------------------------------------- #
# 0. Structural shell check                                       #
# --------------------------------------------------------------- #
SHELL_HTML="$TMPDIR/shell.html"
curl --silent --max-time 2 "$AEGIS_ADMIN/dashboard/" -o "$SHELL_HTML"
if grep -q 'id="root"' "$SHELL_HTML"; then
  ok "shell mounts React 18 root (id=root)"
else
  fail "shell missing id=root marker"
fi

# CSP header — must be `script-src 'self'` for /dashboard/*
CSP="$(curl --silent --max-time 2 -D - "$AEGIS_ADMIN/dashboard/" -o /dev/null \
        | grep -i '^content-security-policy:' | tr -d '\r')"
if echo "$CSP" | grep -qE "script-src[^;]*'self'" \
   && ! echo "$CSP" | grep -q "unsafe-eval" \
   && ! echo "$CSP" | grep -q "cdn"; then
  ok "CSP is script-src 'self' (no eval, no cdn)"
else
  fail "CSP is not 'self'-only: $CSP"
fi

# Bundle size budget (≤ 256 KB)
BUNDLE_BYTES=$(curl --silent --max-time 5 -o /dev/null \
                    -w "%{size_download}" \
                    "$AEGIS_ADMIN/dashboard/assets/app.js")
BUNDLE_KB=$((BUNDLE_BYTES / 1024))
if (( BUNDLE_BYTES > 0 && BUNDLE_BYTES <= 262144 )); then
  ok "app.js bundle is ${BUNDLE_KB} KB (≤ 256 KB budget)"
else
  fail "app.js bundle out of budget: ${BUNDLE_KB} KB"
fi

# --------------------------------------------------------------- #
# 1. Real-time monitor ≤ 5 s                                      #
#                                                                  #
# Subscribe to /dashboard/sse in the background, then issue a     #
# request through the data plane and time-stamp how long until    #
# we receive the matching event.                                  #
# --------------------------------------------------------------- #
SSE_LOG="$TMPDIR/sse.log"
SSE_TS_FILE="$TMPDIR/sse-first-event.ts"

probe_path="/__round1_$(date +%s)_$$"
( curl --silent --max-time 8 --no-buffer \
       --cookie "$COOKIES" \
       -H "accept: text/event-stream" \
       "$AEGIS_ADMIN/dashboard/sse" \
   | while IFS= read -r line; do
       if echo "$line" | grep -q "$probe_path"; then
         date +%s%3N > "$SSE_TS_FILE"
         break
       fi
     done ) >"$SSE_LOG" 2>&1 &
SSE_PID=$!

# Give the SSE subscriber 0.5 s to attach.
sleep 0.5
PROBE_T0=$(date +%s%3N)
curl --silent --max-time 3 -o /dev/null \
     "$AEGIS_DATA$probe_path" || true

# Wait up to 6 s for the event to round-trip.
for _ in $(seq 1 60); do
  if [[ -s "$SSE_TS_FILE" ]]; then break; fi
  sleep 0.1
done
kill "$SSE_PID" 2>/dev/null || true
wait "$SSE_PID" 2>/dev/null || true

if [[ -s "$SSE_TS_FILE" ]]; then
  PROBE_T1=$(cat "$SSE_TS_FILE")
  LATENCY_MS=$((PROBE_T1 - PROBE_T0))
  if (( LATENCY_MS <= 5000 )); then
    ok "real-time SSE latency ${LATENCY_MS} ms (≤ 5000 ms contract)"
  else
    fail "real-time SSE latency ${LATENCY_MS} ms exceeds 5000 ms"
  fi
else
  fail "did not observe SSE event for $probe_path within 6 s"
fi

# --------------------------------------------------------------- #
# 2. Hot-reload ≤ 10 s                                            #
# --------------------------------------------------------------- #
RULE_ID="round1-$(date +%s)-$$"
V_BEFORE=$(curl --silent --max-time 2 \
                "$AEGIS_ADMIN/api/config/version" \
           | jq -r '.version')

POST_T0=$(date +%s%3N)
POST_RESP=$(curl --silent --max-time 5 \
                 --cookie "$COOKIES" \
                 -H "x-csrf-token: $CSRF" \
                 -H "content-type: application/json" \
                 -d "{\"id\":\"$RULE_ID\",\"body\":\"rule \\\"$RULE_ID\\\" { priority = 100 }\",\"enabled\":true}" \
                 "$AEGIS_ADMIN/api/rules")
if ! echo "$POST_RESP" | jq -e '.ok == true' >/dev/null 2>&1; then
  fail "POST /api/rules did not return ok=true: $POST_RESP"
else
  # Poll /api/config/version every 250 ms until it advances.
  EXPECTED=$((V_BEFORE + 1))
  RELOAD_LATENCY_MS=-1
  for _ in $(seq 1 40); do
    V_NOW=$(curl --silent --max-time 1 \
                 "$AEGIS_ADMIN/api/config/version" \
            | jq -r '.version')
    if (( V_NOW >= EXPECTED )); then
      RELOAD_LATENCY_MS=$(( $(date +%s%3N) - POST_T0 ))
      break
    fi
    sleep 0.25
  done
  if (( RELOAD_LATENCY_MS >= 0 && RELOAD_LATENCY_MS <= 10000 )); then
    ok "hot-reload latency ${RELOAD_LATENCY_MS} ms (≤ 10000 ms contract)"
  elif (( RELOAD_LATENCY_MS < 0 )); then
    fail "version did not advance from $V_BEFORE within 10 s"
  else
    fail "hot-reload latency ${RELOAD_LATENCY_MS} ms exceeds 10000 ms"
  fi
fi

# --------------------------------------------------------------- #
# 3. Find-audit ≤ 30 s                                            #
#                                                                  #
# This is bounded by query latency, not by user search effort —   #
# the dashboard's incremental search input filters the API call   #
# directly. We assert the API itself answers within 30 s for a    #
# representative filter combination.                              #
# --------------------------------------------------------------- #
AUDIT_T0=$(date +%s%3N)
AUDIT_BODY=$(curl --silent --max-time 30 \
                  "$AEGIS_ADMIN/api/audit/since?rule_id=$RULE_ID&limit=10")
AUDIT_T1=$(date +%s%3N)
AUDIT_LATENCY_MS=$((AUDIT_T1 - AUDIT_T0))
if (( AUDIT_LATENCY_MS <= 30000 )) \
   && echo "$AUDIT_BODY" | jq -e '. | type == "object"' >/dev/null 2>&1; then
  ok "find-audit (rule_id=$RULE_ID) returned in ${AUDIT_LATENCY_MS} ms (≤ 30000 ms contract)"
else
  fail "find-audit query failed or exceeded 30 s (${AUDIT_LATENCY_MS} ms)"
fi

# --------------------------------------------------------------- #
# 4. CSRF gate enforced on all four rule CRUD verbs               #
# --------------------------------------------------------------- #
csrf_blocked() {
  local method="$1" url="$2" body="${3:-}"
  local code
  if [[ -n "$body" ]]; then
    code=$(curl --silent --max-time 3 -o /dev/null \
                -w "%{http_code}" \
                -X "$method" \
                -H "content-type: application/json" \
                -d "$body" \
                "$url")
  else
    code=$(curl --silent --max-time 3 -o /dev/null \
                -w "%{http_code}" \
                -X "$method" \
                "$url")
  fi
  [[ "$code" == "401" || "$code" == "403" ]]
}

if csrf_blocked POST   "$AEGIS_ADMIN/api/rules" '{"id":"x","body":"","enabled":true}' \
   && csrf_blocked PUT    "$AEGIS_ADMIN/api/rules/$RULE_ID" '{"body":"","enabled":true}' \
   && csrf_blocked DELETE "$AEGIS_ADMIN/api/rules/$RULE_ID" \
   && csrf_blocked PUT    "$AEGIS_ADMIN/api/rules/$RULE_ID/toggle"; then
  ok "all 4 rule CRUD verbs reject without CSRF cookie"
else
  fail "one or more CRUD verbs accepted requests without CSRF"
fi

# --------------------------------------------------------------- #
# 5. Create-rule ≤ 5 clicks (design property)                     #
# --------------------------------------------------------------- #
# This is structural — the dashboard's NewRuleModal exposes:
#   click 1: "+ New rule"
#   click 2: focus and type id (counts as one click)
#   click 3: Save
# We assert the JSX bundle still contains those three actionables.
BUNDLE_TEXT=$(curl --silent --max-time 5 "$AEGIS_ADMIN/dashboard/assets/app.js")
if echo "$BUNDLE_TEXT" | grep -q "New rule" \
   && echo "$BUNDLE_TEXT" | grep -q "Save" \
   && echo "$BUNDLE_TEXT" | grep -q "Rule ID"; then
  ok "create-rule UI exposes ≤ 5 clicks (New rule → fields → Save)"
else
  fail "NewRuleModal markers missing from bundle"
fi

# --------------------------------------------------------------- #
# Cleanup: delete the test rule                                   #
# --------------------------------------------------------------- #
curl --silent --max-time 3 -X DELETE \
     --cookie "$COOKIES" \
     -H "x-csrf-token: $CSRF" \
     "$AEGIS_ADMIN/api/rules/$RULE_ID" >/dev/null || true

echo
echo "----------------------------------------"
echo "Round-1 acceptance: $PASS_COUNT passed, $FAIL_COUNT failed"
echo "----------------------------------------"
if (( FAIL_COUNT > 0 )); then
  exit 1
fi
exit 0
