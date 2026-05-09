#!/usr/bin/env bash
# LT-24 — Hacker: regex pattern evasion techniques
#
# Attacker perspective: WAF regex detectors are often anchored on exact
# token structure.  Inserting whitespace, using alternative delimiters,
# switching case, or using encoding variants can cause the pattern to
# miss a dangerous payload.
#
# Bugs targeted:
#   - Template injection with spaces: "{ { 7*7 } }" vs "{{7*7}}"
#   - Spring EL with spaces: "${ 7*7 }" vs "${7*7}"
#   - NoSQL operator in mixed/upper case: $NE $GT $WHERE
#   - XSS via SVG event handler without <script> tag
#   - XSS data: URI scheme (client-side MIME confusion)
#   - XSS via HTML comment injection: <!--<script>-->
#   - Path traversal via URL-encoded dot variations
#   - CMDi via $() subshell
#
# Contract reference: §3.1 — detector must catch semantic equivalents,
# not just the canonical representation.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"
require curl

trap trap_cleanup EXIT
start_waf
reset_to_enforce

check_blocked() {
  local desc="$1" url="$2"
  raw=$(curl -sI --max-time 5 "$url" 2>/dev/null || true)
  action=$(header_value "$raw" "X-WAF-Action")
  if [[ "$action" == "allow" || -z "$action" ]]; then
    fail "$desc → BYPASS: pattern not matched (action='$action')"
  fi
  ok "$desc → action=$action (detected)"
}

# ------------------------------------------------------------------
# 1. Baseline: Jinja2 {{7*7}} without spaces (sanity check)
# ------------------------------------------------------------------
check_blocked \
  "Baseline template injection: {{7*7}}" \
  "$DATA/?q=%7B%7B7%2A7%7D%7D"

# ------------------------------------------------------------------
# 2. Template injection WITH spaces inside braces: { { 7*7 } }
#    Pattern \{\{.+?\}\} requires literal "{{" — space breaks it.
# ------------------------------------------------------------------
# { { 7*7 } } URL-encoded: %7B%20%7B%207%2A7%20%7D%20%7D
check_blocked \
  "Template injection with spaces: { { 7*7 } } (evasion)" \
  "$DATA/?q=%7B%20%7B%207%2A7%20%7D%20%7D"

# ------------------------------------------------------------------
# 3. Spring EL with spaces: ${ 7*7 }
#    Pattern \$\{.+?\} requires "${" — space between $ and { breaks it.
# ------------------------------------------------------------------
# ${ 7*7 } encoded: %24%7B%207%2A7%20%7D
check_blocked \
  "Spring EL with space: \${ 7*7 } (evasion)" \
  "$DATA/?expr=%24%7B%207%2A7%20%7D"

# ------------------------------------------------------------------
# 4. NoSQL operator in uppercase: $NE (pattern uses \$ne case-insensitive
#    but only if re.IGNORECASE is applied)
# ------------------------------------------------------------------
check_blocked \
  "NoSQL \$NE uppercase operator" \
  "$DATA/?pwd%5B%24NE%5D=0&user=admin-lt24"

# ------------------------------------------------------------------
# 5. NoSQL $WHERE in mixed case
# ------------------------------------------------------------------
check_blocked \
  "NoSQL \$Where mixed-case operator" \
  "$DATA/?filter=%7B%22%24Where%22%3A%22this.x%3D%3D1%22%7D-lt24"

# ------------------------------------------------------------------
# 6. XSS via SVG onload (no <script> tag): <svg/onload=alert(1)>
#    Does not match <script[^>]*> but does match on\w+\s*=
# ------------------------------------------------------------------
check_blocked \
  "XSS SVG onload: <svg/onload=alert(1)>" \
  "$DATA/?q=%3Csvg%2Fonload%3Dalert%281%29%3E-lt24"

# ------------------------------------------------------------------
# 7. XSS via <img> onerror with unusual spacing
# ------------------------------------------------------------------
check_blocked \
  "XSS img onerror with space: <img src=x onerror =alert(1)>" \
  "$DATA/?q=%3Cimg%20src%3Dx%20onerror%20%3Dalert%281%29%3E-lt24"

# ------------------------------------------------------------------
# 8. XSS via data: URI embedded in href attribute
#    "javascript:" in data:text/html is same as direct JS
# ------------------------------------------------------------------
check_blocked \
  "XSS javascript: URI scheme" \
  "$DATA/?href=javascript%3Aalert%281%29-lt24"

# ------------------------------------------------------------------
# 9. Path traversal: %2e%2e%2f (URL-encoded ../): already caught by
#    pattern — but ....// (quadruple-dot slash) might bypass
# ------------------------------------------------------------------
check_blocked \
  "Path traversal double-dot encoded: %2e%2e%2f" \
  "$DATA/?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd"

# ------------------------------------------------------------------
# 10. Path traversal Windows-style: ..\\ URL-encoded
# ------------------------------------------------------------------
check_blocked \
  "Path traversal Windows backslash: ..%5C..%5C" \
  "$DATA/?path=..%5C..%5Cwindows%5Csystem32%5Cconfig"

# ------------------------------------------------------------------
# 11. CMDi via subshell: $(cat /etc/passwd)
# ------------------------------------------------------------------
check_blocked \
  "CMDi via subshell \$(cat /etc/passwd)" \
  "$DATA/?cmd=%24%28cat%20%2Fetc%2Fpasswd%29-lt24"

# ------------------------------------------------------------------
# 12. CMDi via backtick: \`id\`
# ------------------------------------------------------------------
# `id` URL-encoded: %60id%60
check_blocked \
  "CMDi via backtick: \`id\`" \
  "$DATA/?cmd=%60id%60-lt24"

ok "LT-24 hack-pattern-evasion: all checks complete"
