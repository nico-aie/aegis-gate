#!/usr/bin/env bash
# LT-22 — Hacker: POST body injection bypass
#
# Attacker perspective: many WAF implementations only inspect the URL
# (path + query string) and ignore the request body.  By moving attack
# payloads from the query string into the POST body, an attacker can
# bypass URL-based detectors entirely.
#
# Bugs targeted:
#   - SQLi in POST body (URL-encoded form field) not detected
#   - XSS in POST body not detected
#   - Command injection in POST body not detected
#   - JSON body with SQLi value not detected
#   - Multipart form data with SQLi not detected (if Content-Type varies)
#
# Contract reference: §3.1 — all data from the request (including body)
# must be inspected for threats.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"
require curl
require jq

trap trap_cleanup EXIT
start_waf
reset_to_enforce

# Helper: send a POST and assert the WAF blocked it.
# Uses -si (lowercase i = include response headers in output) NOT -sI (HEAD mode)
# because -sI (HEAD) suppresses the request body even with --data.
check_post_blocked() {
  local desc="$1" url="$2"
  shift 2
  # remaining args forwarded to curl as-is
  raw=$(curl -si --max-time 5 -X POST "$@" "$url" 2>/dev/null || true)
  action=$(header_value "$raw" "X-WAF-Action")
  if [[ "$action" == "allow" || -z "$action" ]]; then
    fail "$desc → BYPASS: WAF allowed attack in request body (action='$action')"
  fi
  ok "$desc → action=$action (detected)"
}

# ------------------------------------------------------------------
# 1. Baseline: SQLi in query string (must block — sanity check)
# ------------------------------------------------------------------
raw=$(curl -sI --max-time 5 "$DATA/?id=1%27%20OR%20%271%27%3D%271-lt22" 2>/dev/null || true)
action=$(header_value "$raw" "X-WAF-Action")
[[ "$action" != "allow" && -n "$action" ]] \
  || fail "Baseline SQLi in URL (query) was NOT detected — prerequisite failed"
ok "Baseline: SQLi in URL detected (action=$action)"

# ------------------------------------------------------------------
# 2. SQLi in URL-encoded POST body field
#    Clean path; all malicious content lives in the body.
# ------------------------------------------------------------------
check_post_blocked \
  "SQLi in POST body (form field: id)" \
  "$DATA/search" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "id=1%27%20OR%20%271%27%3D%271-lt22"

# ------------------------------------------------------------------
# 3. XSS in POST body
# ------------------------------------------------------------------
check_post_blocked \
  "XSS in POST body (form field: comment)" \
  "$DATA/comment" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "comment=%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E-lt22"

# ------------------------------------------------------------------
# 4. Command injection in POST body
# ------------------------------------------------------------------
check_post_blocked \
  "CMDi in POST body (form field: cmd)" \
  "$DATA/execute" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "cmd=%3Bcat%20%2Fetc%2Fpasswd"

# ------------------------------------------------------------------
# 5. SQLi in JSON POST body (Content-Type: application/json)
# ------------------------------------------------------------------
check_post_blocked \
  "SQLi in JSON POST body" \
  "$DATA/api/query" \
  -H "Content-Type: application/json" \
  -d '{"id":"1'\'' OR '\''1'\''='\''1","action":"search"}'

# ------------------------------------------------------------------
# 6. XSS in JSON POST body
# ------------------------------------------------------------------
check_post_blocked \
  "XSS in JSON POST body" \
  "$DATA/api/post" \
  -H "Content-Type: application/json" \
  -d '{"title":"Hello","body":"<script>alert(1)</script>"}'

# ------------------------------------------------------------------
# 7. Path traversal in POST body
# ------------------------------------------------------------------
check_post_blocked \
  "Path traversal in POST body (file field)" \
  "$DATA/upload" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "file=..%2F..%2F..%2Fetc%2Fpasswd"

# ------------------------------------------------------------------
# 8. Template injection in POST body
# ------------------------------------------------------------------
check_post_blocked \
  "Template injection in POST body (tpl field)" \
  "$DATA/render" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "tpl=%7B%7B7%2A7%7D%7D"

# ------------------------------------------------------------------
# 9. NoSQL injection in POST JSON body
# ------------------------------------------------------------------
check_post_blocked \
  "NoSQL injection in POST JSON body" \
  "$DATA/api/auth" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$ne":"wrong"}}'

# ------------------------------------------------------------------
# 10. SSRF URL in POST body
# ------------------------------------------------------------------
check_post_blocked \
  "SSRF URL in POST body (url field)" \
  "$DATA/fetch" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "url=http%3A%2F%2F127.0.0.1%2Finternal-lt22"

ok "LT-22 hack-body-injection: all checks complete"
