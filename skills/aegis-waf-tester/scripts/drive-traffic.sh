#!/usr/bin/env bash
# skills/aegis-waf-tester/scripts/drive-traffic.sh
#
# 30 seconds of mixed traffic so the dashboard has real signal
# during the QA pass:
#
#   - legit GETs (different paths, different XFF IPs)
#   - SQLi-shaped requests (sqli detector should fire)
#   - XSS-shaped requests (xss detector should fire)
#   - path-traversal attempts
#   - one bad-creds login attempt against the admin
#
# Honest about what each curl is doing so the operator can read
# the audit chain and match it back to a row.

set -u

DATA="${AEGIS_DATA:-http://127.0.0.1:8080}"
DURATION="${DURATION:-30}"

echo "==> Driving $DURATION s of mixed traffic at $DATA"
end=$(( $(date +%s) + DURATION ))

# Spread requests across three plausible attacker IPs so the
# Top-Attackers page has variety.
ATTACKER_IPS=( 8.8.8.8 1.1.1.1 9.9.9.9 )
LEGIT_IPS=( 192.0.2.10 192.0.2.11 192.0.2.12 )

i=0
while [[ $(date +%s) -lt $end ]]; do
  i=$((i + 1))
  case $((i % 6)) in
    0)
      # Legit GET
      ip="${LEGIT_IPS[$((RANDOM % 3))]}"
      curl -s -o /dev/null -H "X-Forwarded-For: $ip" \
        "$DATA/api/users/$((RANDOM % 1000))"
      ;;
    1)
      # SQLi attempt — should trip sqli detector.
      ip="${ATTACKER_IPS[$((RANDOM % 3))]}"
      curl -s -o /dev/null -H "X-Forwarded-For: $ip" \
        "$DATA/login?user=admin'+OR+1=1--"
      ;;
    2)
      # XSS attempt — should trip xss detector.
      ip="${ATTACKER_IPS[$((RANDOM % 3))]}"
      curl -s -o /dev/null -H "X-Forwarded-For: $ip" \
        "$DATA/comment?text=<script>alert(1)</script>"
      ;;
    3)
      # Path-traversal — should trip path_traversal.
      ip="${ATTACKER_IPS[$((RANDOM % 3))]}"
      curl -s -o /dev/null -H "X-Forwarded-For: $ip" \
        "$DATA/files?p=../../../../etc/passwd"
      ;;
    4)
      # Recon-shaped — admin / phpMyAdmin / .env probes.
      ip="${ATTACKER_IPS[$((RANDOM % 3))]}"
      paths=("/.env" "/wp-admin" "/phpmyadmin" "/.git/config" "/admin.php")
      p="${paths[$((RANDOM % 5))]}"
      curl -s -o /dev/null -H "X-Forwarded-For: $ip" "$DATA$p"
      ;;
    5)
      # Plain legit POST
      ip="${LEGIT_IPS[$((RANDOM % 3))]}"
      curl -s -o /dev/null -X POST \
        -H "content-type: application/json" \
        -H "X-Forwarded-For: $ip" \
        -d '{"q":"hello"}' \
        "$DATA/api/search"
      ;;
  esac
  sleep 0.1
done

echo "==> Sent ~$i requests across $DURATION s"
echo "    Inspect dashboard at http://127.0.0.1:9443/ — Live Feed"
echo "    + Top Attackers + Investigation should now have signal."
