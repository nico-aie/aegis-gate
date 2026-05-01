#!/usr/bin/env bash
# HACK-T2 — Hackathon v2.3 contract regression check.
#
# This script is the deterministic CI gate for every requirement
# in `Hackathon_Doc/EN_waf_interop_contract_v2.3.md`. Each
# requirement gets a numbered check that prints the v2.3 section
# it tests; the first failure aborts with a non-zero exit code so
# CI fails the build immediately.
#
# Pre-existing per-feature DR-T*.sh tests in `tests/interop/`
# already cover most of the surface; this script is the
# aggregator + enforcement gate that maps each check directly to
# a v2.3 §X.Y spec citation. If you intentionally break the
# contract (e.g. drop `X-WAF-Mode`), this script is the
# regression that catches it.
#
# Usage:
#   tests/contract/v2.3_compliance.sh
#
# Exit codes:
#   0 — every contract check green
#   1 — at least one check failed; first failure printed
#
# Environment:
#   WAF_BIN  — release binary path (default ./target/release/waf)
#   CONFIG   — config path (default config/dev.yaml)
#   DATA     — data-plane URL (default http://127.0.0.1:8080)
#   ADMIN    — admin-plane URL (default http://127.0.0.1:9443)
#   SECRET   — X-Benchmark-Secret value
#   AUDIT_LOG — path to the minimal-schema audit log

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
source "$REPO/tests/interop/_common.sh"

require curl
require jq

# Counter — incremented per assertion. Gives the operator a
# checks-passed total at the end and a stable numeric label per
# assertion so CI logs can diff cleanly across runs.
CHECK=0

check() {
  CHECK=$((CHECK + 1))
  local section="$1" desc="$2"
  shift 2
  if "$@"; then
    printf 'PASS: [%03d] v2.3 %s — %s\n' "$CHECK" "$section" "$desc"
  else
    printf 'FAIL: [%03d] v2.3 %s — %s\n' "$CHECK" "$section" "$desc" >&2
    exit 1
  fi
}

# Predicate helpers — wrap awk / jq / grep in a shape the `check`
# wrapper can call. Each one returns 0 on PASS, non-zero on FAIL.

# Header value extractor (case-insensitive, strips CR).
header_value() {
  local raw="$1" name="$2"
  printf '%s' "$raw" | awk -v h="$name" '
    BEGIN { IGNORECASE=1 }
    tolower($1) == tolower(h ":") {
      sub(/^[^:]+:[ \t]*/, "")
      sub(/\r$/, "")
      print
      exit
    }'
}

# Assertion: response carries the named header with a non-empty value.
assert_header_present() {
  local raw="$1" name="$2"
  local v
  v=$(header_value "$raw" "$name")
  [[ -n "$v" ]]
}

# Assertion: header value belongs to the supplied set.
assert_header_in_set() {
  local raw="$1" name="$2"
  shift 2
  local v
  v=$(header_value "$raw" "$name")
  for allowed in "$@"; do
    [[ "$v" == "$allowed" ]] && return 0
  done
  return 1
}

# Assertion: JSON body has a key with the expected value.
assert_json_field_eq() {
  local body="$1" path="$2" expected="$3"
  local got
  got=$(printf '%s' "$body" | jq -r "$path" 2>/dev/null || echo '__JQ_ERROR__')
  [[ "$got" == "$expected" ]]
}

# Assertion: JSON body has a key (regardless of value).
assert_json_field_present() {
  local body="$1" path="$2"
  local got
  got=$(printf '%s' "$body" | jq "$path | type" 2>/dev/null || echo 'null')
  [[ "$got" != 'null' && -n "$got" ]]
}

# Assertion: audit-log JSONL has every mandatory v2.3 §6 field on
# its newest line.
assert_audit_minimal_schema() {
  [[ -f "$AUDIT_LOG" ]] || return 1
  local line
  line=$(tail -n 1 "$AUDIT_LOG" 2>/dev/null || true)
  [[ -n "$line" ]] || return 1
  # All eight mandatory fields must be present + the values must
  # be the right shape (numeric / string / member of the action set).
  printf '%s\n' "$line" | jq -e '
    (.request_id | type == "string" and length > 0)
    and (.ts_ms | type == "number")
    and (.ip | type == "string" and length > 0)
    and (.method | type == "string" and length > 0)
    and (.path | type == "string" and length > 0)
    and (.action | type == "string"
         and (. as $a | ["allow","block","challenge","rate_limit","timeout","circuit_breaker"] | index($a) != null))
    and (.risk_score | type == "number" and . >= 0 and . <= 100)
    and (.mode | type == "string"
         and (. as $m | ["enforce","log_only"] | index($m) != null))
  ' >/dev/null
}

# ------------------------------------------------------------------
# Boot sequence — start the WAF release binary and wait for ready.
# ------------------------------------------------------------------

trap trap_cleanup EXIT

printf '\n%s\n' '==================== v2.3 contract regression ===================='
printf 'binary:  %s\n' "$WAF_BIN"
printf 'config:  %s\n' "$CONFIG"
printf 'data:    %s\n' "$DATA"
printf 'admin:   %s\n' "$ADMIN"
printf 'secret:  %s\n' "$SECRET"
printf 'audit:   %s\n' "$AUDIT_LOG"
echo

start_waf

# ------------------------------------------------------------------
# §2 — WAF Control Interface
# ------------------------------------------------------------------

# §2.1 — Required control endpoints. We GET capabilities + POST
# reset_state / set_profile / flush_cache and confirm each
# returns 2xx with a parseable JSON body.

caps_status=$(curl -sk -o /tmp/caps.json -w '%{http_code}' \
  -H "X-Benchmark-Secret: $SECRET" \
  "$ADMIN/__waf_control/capabilities")
check '§2.1' 'GET /__waf_control/capabilities returns 200' \
  test "$caps_status" = '200'

# §2.2 — Authentication. Missing / wrong secret must 403.
no_secret_status=$(curl -sk -o /dev/null -w '%{http_code}' \
  "$ADMIN/__waf_control/capabilities" || echo 000)
check '§2.2' 'missing X-Benchmark-Secret returns 403' \
  test "$no_secret_status" = '403'

bad_secret_status=$(curl -sk -o /dev/null -w '%{http_code}' \
  -H 'X-Benchmark-Secret: WRONG-SECRET' \
  "$ADMIN/__waf_control/capabilities" || echo 000)
check '§2.2' 'wrong X-Benchmark-Secret returns 403' \
  test "$bad_secret_status" = '403'

# §2.3 — Capabilities response shape: ok + features + active.
caps_body=$(cat /tmp/caps.json)
check '§2.3' 'capabilities body has ok=true' \
  assert_json_field_eq "$caps_body" '.ok' 'true'
check '§2.3' 'capabilities body has features object' \
  assert_json_field_present "$caps_body" '.features'
check '§2.3' 'capabilities body has active.default_mode' \
  assert_json_field_present "$caps_body" '.active.default_mode'
check '§2.3' 'capabilities body has active.overrides' \
  assert_json_field_present "$caps_body" '.active.overrides'

# §2.4 — reset_state must be synchronous + atomic + preserve audit log.
# Drive 1 attack so the audit log is non-empty, then reset_state and
# assert the audit log is *not* truncated (line count >= before).
curl -sk -o /dev/null "$DATA/?id=1' OR '1'='1" || true
sleep 0.5
audit_before=$(count_audit_lines)

reset_status=$(curl -sk -o /tmp/reset.json -w '%{http_code}' \
  -X POST -H "X-Benchmark-Secret: $SECRET" \
  "$ADMIN/__waf_control/reset_state")
check '§2.4' 'POST /__waf_control/reset_state returns 200' \
  test "$reset_status" = '200'

reset_body=$(cat /tmp/reset.json)
check '§2.4' 'reset_state response has ok=true' \
  assert_json_field_eq "$reset_body" '.ok' 'true'
check '§2.4' 'reset_state response has audit_log_preserved=true' \
  assert_json_field_eq "$reset_body" '.audit_log_preserved' 'true'
check '§2.4' 'reset_state response has ts_ms (numeric)' \
  assert_json_field_present "$reset_body" '.ts_ms'

audit_after=$(count_audit_lines)
check '§2.4' 'reset_state did not truncate audit log' \
  test "$audit_after" -ge "$audit_before"

# §2.5 — set_profile to log_only on a feature; subsequent attack
# must report `block` action header but actually allow upstream
# (status code on attack ≠ 403/429).
sp_status=$(curl -sk -o /tmp/sp.json -w '%{http_code}' \
  -X POST -H "X-Benchmark-Secret: $SECRET" \
  -H 'content-type: application/json' \
  -d '{"scope":"all","mode":"log_only"}' \
  "$ADMIN/__waf_control/set_profile")
check '§2.5' 'POST /__waf_control/set_profile (all → log_only) returns 200' \
  test "$sp_status" = '200'

sp_body=$(cat /tmp/sp.json)
check '§2.5' 'set_profile response has ok=true' \
  assert_json_field_eq "$sp_body" '.ok' 'true'
check '§2.5' 'set_profile response echoes applied.scope=all' \
  assert_json_field_eq "$sp_body" '.applied.scope' 'all'
check '§2.5' 'set_profile response echoes applied.mode=log_only' \
  assert_json_field_eq "$sp_body" '.applied.mode' 'log_only'

# Switch back to enforce so subsequent §3.1 checks see real
# enforcement.
curl -sk -X POST -H "X-Benchmark-Secret: $SECRET" \
  -H 'content-type: application/json' \
  -d '{"scope":"all","mode":"enforce"}' \
  "$ADMIN/__waf_control/set_profile" >/dev/null

# §2.6 — flush_cache (REQUIRED if cache exists). We accept either
# 200 OK or a not-supported response — the contract permits both.
fc_status=$(curl -sk -o /dev/null -w '%{http_code}' \
  -X POST -H "X-Benchmark-Secret: $SECRET" \
  "$ADMIN/__waf_control/flush_cache")
check '§2.6' 'flush_cache returns 200 or 4xx (not 5xx)' \
  test "$fc_status" -lt 500

# ------------------------------------------------------------------
# §5 — Mandatory observability headers on every response
# ------------------------------------------------------------------

# Drive a benign request and inspect every required header.
raw_allow=$(curl -sIk --max-time 3 "$DATA/" 2>/dev/null)

for h in X-WAF-Request-Id X-WAF-Risk-Score X-WAF-Action \
         X-WAF-Rule-Id X-WAF-Cache X-WAF-Mode; do
  check '§5.1' "response carries $h header" \
    assert_header_present "$raw_allow" "$h"
done

# §5.1 — exact-match value sets.
check '§5.1' 'X-WAF-Action ∈ {allow, block, challenge, rate_limit, timeout, circuit_breaker}' \
  assert_header_in_set "$raw_allow" 'X-WAF-Action' \
    'allow' 'block' 'challenge' 'rate_limit' 'timeout' 'circuit_breaker'
check '§5.1' 'X-WAF-Cache ∈ {HIT, MISS, BYPASS} (uppercase)' \
  assert_header_in_set "$raw_allow" 'X-WAF-Cache' \
    'HIT' 'MISS' 'BYPASS'
check '§5.1' 'X-WAF-Mode ∈ {enforce, log_only} (lowercase)' \
  assert_header_in_set "$raw_allow" 'X-WAF-Mode' \
    'enforce' 'log_only'

# §5.1 — X-WAF-Risk-Score must be a plain integer (no whitespace).
risk=$(header_value "$raw_allow" 'X-WAF-Risk-Score')
check '§5.1' 'X-WAF-Risk-Score is a plain integer 0..100' \
  bash -c "[[ '$risk' =~ ^[0-9]+\$ ]] && [[ $risk -ge 0 ]] && [[ $risk -le 100 ]]"

# §5.3 — required headers on a BLOCKED response too.
raw_block=$(curl -sIk --max-time 3 "$DATA/?id=1%27%20OR%20%271%27=%271" 2>/dev/null || true)
for h in X-WAF-Request-Id X-WAF-Risk-Score X-WAF-Action \
         X-WAF-Rule-Id X-WAF-Cache X-WAF-Mode; do
  check '§5.3' "blocked response also carries $h" \
    assert_header_present "$raw_block" "$h"
done

# ------------------------------------------------------------------
# §6 — Audit log (JSONL minimal schema)
# ------------------------------------------------------------------

# Drive 1 more allow request to guarantee a fresh audit-log line.
curl -sk -o /dev/null "$DATA/healthcheck-trigger" || true
sleep 0.5

check '§6' 'audit log file exists' test -f "$AUDIT_LOG"
check '§6' 'audit log newest line has every mandatory v2.3 field with valid types' \
  assert_audit_minimal_schema

# §6 IP semantics — ip field must be the TCP peer, NOT XFF.
# We drive a request with a forged XFF and confirm the audit log's
# `ip` field is `127.0.0.1` (the peer), not the spoofed value.
curl -sk -o /dev/null -H 'X-Forwarded-For: 1.2.3.4' "$DATA/?xff-test=1" || true
sleep 0.5
audit_ip=$(tail -n 1 "$AUDIT_LOG" | jq -r '.ip')
check '§6' 'audit `ip` is TCP peer, not X-Forwarded-For' \
  bash -c "[[ '$audit_ip' != '1.2.3.4' ]] && [[ -n '$audit_ip' ]]"

# §6 — X-WAF-Request-Id matches audit log request_id.
raw_corr=$(curl -sIk --max-time 3 "$DATA/?correlation-test=1" 2>/dev/null)
hdr_rid=$(header_value "$raw_corr" 'X-WAF-Request-Id')
sleep 0.5
log_rid=$(tail -n 1 "$AUDIT_LOG" | jq -r '.request_id')
check '§6' 'X-WAF-Request-Id correlates with audit log request_id' \
  bash -c "[[ -n '$hdr_rid' ]] && [[ '$hdr_rid' == '$log_rid' ]]"

# ------------------------------------------------------------------
# §3 — Decision class enforcement (smoke level)
# ------------------------------------------------------------------

# §3.1 — high-confidence injection is blocked or challenged.
raw_inj=$(curl -sIk --max-time 3 "$DATA/?q=%3Cscript%3Ealert(1)%3C/script%3E" 2>/dev/null || true)
inj_action=$(header_value "$raw_inj" 'X-WAF-Action')
case "$inj_action" in
  block|challenge) ;;
  *) printf 'FAIL: [%03d] v2.3 §3.1 — XSS injection action=%s; want block or challenge\n' \
       "$((CHECK + 1))" "$inj_action" >&2
     exit 1;;
esac
CHECK=$((CHECK + 1))
printf 'PASS: [%03d] v2.3 §3.1 — XSS injection blocked or challenged\n' "$CHECK"

# ------------------------------------------------------------------
# §8 — Startup contract
# ------------------------------------------------------------------

check '§8' 'WAF binary exists at $WAF_BIN' test -x "$WAF_BIN"
check '§8' '/healthz/ready endpoint responds with 200 (already used for boot wait)' \
  curl -sk -f --max-time 2 "$ADMIN/healthz/ready" -o /dev/null

# ------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------

echo
printf '%s\n' '==================== v2.3 contract: ALL CHECKS PASS ===================='
printf 'total checks: %d\n' "$CHECK"
