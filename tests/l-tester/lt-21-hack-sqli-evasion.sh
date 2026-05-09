#!/usr/bin/env bash
# LT-21 — Hacker: SQL injection evasion techniques
#
# Attacker perspective: tries to craft SQLi payloads that slip past the
# WAF's regex-based SQL injection detector.
#
# Bugs targeted:
#   - Newline (\\n / %0A) inside SELECT..FROM breaks "." matching  →  bypass
#   - Parenthesis-adjacent OR/AND without whitespace: OR(1=1)       →  bypass
#   - Tab as keyword separator (%09) instead of space               →  should catch
#   - MySQL version comment bypass: /*!50000UNION*/ SELECT          →  catch via "/*"
#   - Comment-split UNION: UNI/**/ON SELECT 1 FROM users           →  catch via "/*"
#   - Double-URL-encoded keywords                                   →  should catch
#   - HEX literal strings in injection payload                      →  should catch
#   - stacked query via semicolon                                   →  should catch
#
# Contract reference: §3.1 — detected threat → action must be block or challenge

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"
require curl
require jq

trap trap_cleanup EXIT
start_waf
reset_to_enforce

# Helper: assert the WAF DID detect the attack (action != allow/empty)
check_blocked() {
  local desc="$1" url="$2"
  raw=$(curl -sI --max-time 5 "$url" 2>/dev/null || true)
  action=$(header_value "$raw" "X-WAF-Action")
  if [[ "$action" == "allow" || -z "$action" ]]; then
    fail "$desc → BYPASS: WAF allowed attack (action='$action')"
  fi
  ok "$desc → action=$action (detected)"
}

# Helper: also accepts a POST variant
check_blocked_post() {
  local desc="$1" url="$2" body="$3"
  raw=$(curl -sI --max-time 5 -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "q=$body" \
    "$url" 2>/dev/null || true)
  action=$(header_value "$raw" "X-WAF-Action")
  if [[ "$action" == "allow" || -z "$action" ]]; then
    fail "$desc → BYPASS: WAF allowed attack in POST (action='$action')"
  fi
  ok "$desc → action=$action (detected)"
}

# ------------------------------------------------------------------
# 1. Baseline: standard SQLi (must block — sanity check)
# ------------------------------------------------------------------
check_blocked \
  "Baseline SQLi: 1' OR '1'='1" \
  "$DATA/?id=1%27%20OR%20%271%27%3D%271"

# ------------------------------------------------------------------
# 2. Comment-split UNION: UNI/**/ON SELECT 1 FROM users
#    The "/*" itself triggers the comment-detection pattern.
# ------------------------------------------------------------------
check_blocked \
  "Comment-split UNION: UNI/**/ON SELECT" \
  "$DATA/?id=UNI%2F**%2FON%20SELECT%201%20FROM%20users"

# ------------------------------------------------------------------
# 3. Tab as keyword separator: UNION%09SELECT%091%09FROM%09users
#    Tabs are matched by "." so the select..from pattern still fires.
# ------------------------------------------------------------------
check_blocked \
  "Tab-separated keywords: UNION\\tSELECT\\tFROM" \
  "$DATA/?id=UNION%09SELECT%091%09FROM%09users-lt21"

# ------------------------------------------------------------------
# 4. Newline inside SELECT..FROM: SELECT%0AFROM users
#    Python re "." does NOT match \n by default → pattern misses it!
#    This is a BYPASS BUG: the detector must use re.DOTALL or [\s\S].
# ------------------------------------------------------------------
check_blocked \
  "Newline-split SELECT\\nFROM (bypass attempt)" \
  "$DATA/?id=SELECT%0A1%0AFROM%0Ausers-lt21"

# ------------------------------------------------------------------
# 5. MySQL version comment: /*!50000UNION*/ SELECT 1 FROM users
#    The "/*" is caught by the comment-detection sub-pattern.
# ------------------------------------------------------------------
check_blocked \
  "MySQL version comment: /*!50000UNION*/ SELECT" \
  "$DATA/?id=%2F%2A%2150000UNION%2A%2F%20SELECT%201%20FROM%20users"

# ------------------------------------------------------------------
# 6. UNION with newline between keywords: UNION%0ASELECT%0A1%0AFROM
#    Same newline-bypass vector as #4, UNION variant.
# ------------------------------------------------------------------
check_blocked \
  "Newline UNION\\nSELECT\\nFROM (bypass attempt)" \
  "$DATA/?q=UNION%0ASELECT%0A1%0AFROM%0Ausers-lt21b"

# ------------------------------------------------------------------
# 7. OR without whitespace before parenthesis: 1 OR(1=1)
#    Pattern 2 requires \s+ after OR; OR( has no space → bypass risk.
# ------------------------------------------------------------------
check_blocked \
  "OR without space before paren: 1 OR(1=1)--" \
  "$DATA/?id=1%20OR%281%3D1%29--lt21"

# ------------------------------------------------------------------
# 8. Stacked query (semicolon): SELECT 1; DROP TABLE users--
#    The ";" is a meta-char but "DROP TABLE" → DROP + TABLE pattern.
# ------------------------------------------------------------------
check_blocked \
  "Stacked query: SELECT 1; DROP TABLE users" \
  "$DATA/?id=SELECT%201%3BDROP%20TABLE%20users--lt21"

# ------------------------------------------------------------------
# 9. SLEEP-based blind SQLi (time-based)
# ------------------------------------------------------------------
check_blocked \
  "Time-based blind: sleep(5) injection" \
  "$DATA/?id=1%27%20AND%20SLEEP%285%29--lt21"

# ------------------------------------------------------------------
# 10. Double URL-encoded SQLi: %2527 = encoded %27 = '
#     The WAF double-decodes so %2527 → %27 → '
# ------------------------------------------------------------------
check_blocked \
  "Double-URL-encoded quote: %2527 OR %25271%2527%253D%25271" \
  "$DATA/?id=%25271%2527%2520OR%2520%25271%2527%253D%25271-lt21"

ok "LT-21 hack-sqli-evasion: all checks complete"
