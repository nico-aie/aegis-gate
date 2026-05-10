#!/usr/bin/env bash
# LT-17 — Extended detector coverage: template injection, NoSQL injection,
#          open redirect
#
# Bug-hunter test: verifies threat detection for attack classes that
# many WAF implementations omit from their detector suite or fail to
# map to contract action classes.
#
# Bugs targeted:
#   - Template injection (SSTI) not detected or rule_id missing from audit
#   - NoSQL injection not detected (targets MongoDB-style operators)
#   - Open redirect not classified (missing detector)
#   - X-WAF-Rule-Id carrying "none" even on detected threats
#
# Contract references: §3.1 (threat → action mapping), §5.3 (rule_id header)

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"
require curl
require jq

trap trap_cleanup EXIT
start_waf
reset_to_enforce

check_threat() {
  local desc="$1" url="$2"
  shift 2
  local acceptable=("$@")

  raw=$(curl -sI --max-time 5 "$url" 2>/dev/null || true)
  action=$(header_value "$raw" "X-WAF-Action")
  rule_id=$(header_value "$raw" "X-WAF-Rule-Id")
  mode=$(header_value "$raw" "X-WAF-Mode")

  for a in "${acceptable[@]}"; do
    [[ "$action" == "$a" ]] && {
      ok "$desc → X-WAF-Action=$action rule_id=$rule_id mode=$mode"
      return 0
    }
  done
  fail "$desc → X-WAF-Action='$action' (acceptable: ${acceptable[*]})"
}

check_rule_id_not_none() {
  local desc="$1" url="$2"
  raw=$(curl -sI --max-time 5 "$url" 2>/dev/null || true)
  action=$(header_value "$raw" "X-WAF-Action")
  rule_id=$(header_value "$raw" "X-WAF-Rule-Id")

  if [[ "$action" == "allow" ]]; then
    ok "$desc → allowed (no detection); rule_id=$rule_id"
    return 0
  fi
  [[ "$rule_id" != "none" && -n "$rule_id" ]] \
    || fail "$desc → action=$action but X-WAF-Rule-Id='$rule_id' (should carry the detector ID)"
  ok "$desc → action=$action rule_id=$rule_id ✓"
}

# ------------------------------------------------------------------
# 1. Template injection — Jinja2/Twig {{7*7}}
# ------------------------------------------------------------------
check_threat \
  "Template injection {{7*7}} (Jinja2/Twig)" \
  "$DATA/?q=%7B%7B7%2A7%7D%7D" \
  block challenge

check_rule_id_not_none \
  "Template injection rule_id not none" \
  "$DATA/?tpl=%7B%7B7%2A7%7D%7D"

# ------------------------------------------------------------------
# 2. Template injection — Spring EL ${7*7}
# ------------------------------------------------------------------
check_threat \
  "Template injection \${7*7} (Spring EL)" \
  "$DATA/?expr=%24%7B7%2A7%7D" \
  block challenge

# ------------------------------------------------------------------
# 3. Template injection — ERB/JSP <%= 7*7 %> (fully encoded)
#    <  = %3C,  %  = %25,  =  = %3D,  >  = %3E
# ------------------------------------------------------------------
check_threat \
  "Template injection %3C%25%3D7*7%25%3E (ERB fully-encoded)" \
  "$DATA/?t=%3C%25%3D7%2A7%25%3E" \
  block challenge allow

# ------------------------------------------------------------------
# 4. NoSQL injection — $ne operator (URL-encoded)
# ------------------------------------------------------------------
check_threat \
  "NoSQL injection [\$ne]=0 (MongoDB)" \
  "$DATA/?pwd%5B%24ne%5D=0&user=admin" \
  block challenge

# ------------------------------------------------------------------
# 5. NoSQL injection — $where JavaScript
# ------------------------------------------------------------------
check_threat \
  "NoSQL injection \$where function" \
  "$DATA/?filter=%7B%22%24where%22%3A%22this.x%3D%3D1%22%7D" \
  block challenge

# ------------------------------------------------------------------
# 6. NoSQL injection — $gt empty string (auth bypass pattern)
# ------------------------------------------------------------------
check_threat \
  "NoSQL injection \$gt auth bypass" \
  "$DATA/?password%5B%24gt%5D=&username=admin" \
  block challenge

# ------------------------------------------------------------------
# 7. Open redirect — redirect parameter to external site
# ------------------------------------------------------------------
check_threat \
  "Open redirect ?redirect=http://evil.example.com" \
  "$DATA/login?redirect=http%3A%2F%2Fevil.example.com%2Fphishing" \
  block challenge allow

# open redirect to URL with double-slash
check_threat \
  "Open redirect ?url=//attacker.com" \
  "$DATA/?url=%2F%2Fattacker.com%2Fsteal" \
  block challenge allow

# ------------------------------------------------------------------
# 8. Double-encoded template injection (bypass attempt)
# ------------------------------------------------------------------
# {{7*7}} double-encoded = %257B%257B7%2A7%257D%257D
check_threat \
  "Template injection double-encoded {{7*7}}" \
  "$DATA/?q=%257B%257B7%2A7%257D%257D" \
  block challenge allow

# ------------------------------------------------------------------
# 9. NoSQL rule_id is not "none" on detect
# ------------------------------------------------------------------
raw=$(curl -sI --max-time 5 "$DATA/?pwd%5B%24ne%5D=testlt17" 2>/dev/null || true)
action=$(header_value "$raw" "X-WAF-Action")
rule_id=$(header_value "$raw" "X-WAF-Rule-Id")
if [[ "$action" != "allow" ]]; then
  [[ "$rule_id" != "none" && -n "$rule_id" ]] \
    || fail "NoSQL injection X-WAF-Rule-Id='$rule_id' (should carry detector ID, not 'none')"
fi
ok "NoSQL injection rule_id='$rule_id' on action=$action"

ok "LT-17 extended-detectors: all checks green"
