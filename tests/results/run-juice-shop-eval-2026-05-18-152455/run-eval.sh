#!/usr/bin/env bash
# Juice Shop × Aegis-Gate WAF exploit corpus eval.
# Reads cases from a data table; never lets exploit strings touch bash parsing.

set -u
WAF="${WAF:-https://localhost:8443}"
OUT="${1:?usage: $0 OUT_PSV}"
HDR=/tmp/aegis-eval-hdrs
BODY=/tmp/aegis-eval-body
> "$OUT"

probe() {
  # $1=category $2=label $3=expected $4=method $5=path $6=extra-arg-1 ($7=arg-2 ...)
  local cat="$1" label="$2" expected="$3" method="$4" path="$5"
  shift 5
  local code
  code=$(curl -sk -o "$BODY" -w "%{http_code}" -D "$HDR" -X "$method" "$@" "$WAF$path" 2>/dev/null || echo 000)
  local action rid rule
  action=$(awk 'BEGIN{IGNORECASE=1} /^x-waf-action:/ {gsub(/[\r\n]/,""); print substr($0,index($0,":")+2)}' "$HDR" | tail -1 | tr -d ' ')
  rid=$(   awk 'BEGIN{IGNORECASE=1} /^x-waf-request-id:/ {gsub(/[\r\n]/,""); print substr($0,index($0,":")+2)}' "$HDR" | tail -1 | tr -d ' ')
  rule=$(  awk 'BEGIN{IGNORECASE=1} /^x-waf-rule-id:/ {gsub(/[\r\n]/,""); print substr($0,index($0,":")+2)}' "$HDR" | tail -1 | tr -d ' ')
  printf '%s|%s|%s|%s|%s|%s|%s\n' "$cat" "$label" "$expected" "$code" "${action:-none}" "${rule:-none}" "${rid:-none}" >> "$OUT"
}

# ---------- Legitimate baseline (FP check) ----------
probe legit home_page         allowed GET  "/"
probe legit product_search    allowed GET  "/rest/products/search?q=apple"
probe legit version           allowed GET  "/rest/admin/application-version"
probe legit api_quantitys     allowed GET  "/api/Quantitys/"
probe legit static_js         allowed GET  "/main.js"

# ---------- SQL Injection ----------
probe sqli login_or_1eq1      block   POST "/rest/user/login" -H "Content-Type: application/json" --data-raw "{\"email\":\"' OR 1=1--\",\"password\":\"x\"}"
probe sqli search_union       block   GET  "/rest/products/search?q=apple%27))%20UNION%20SELECT%20*%20FROM%20users--"
probe sqli search_drop        block   GET  "/rest/products/search?q=%27;drop+table+users--"
probe sqli classic_or_1eq1    block   GET  "/rest/products/search?q=1+OR+1=1"
probe sqli sleep_payload      block   GET  "/rest/products/search?q=1%27%20AND%20SLEEP(5)--"

# ---------- XSS ----------
probe xss script_tag          block   GET  "/rest/products/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
probe xss img_onerror         block   GET  "/rest/products/search?q=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E"
probe xss svg_onload          block   GET  "/rest/products/search?q=%3Csvg%2Fonload%3Dalert(1)%3E"
probe xss js_uri              block   GET  "/rest/products/search?q=javascript%3Aalert(document.cookie)"

# ---------- Path Traversal ----------
probe path_traversal deep_dots       block GET "/ftp/../../../../../../etc/passwd"
probe path_traversal url_encoded     block GET "/ftp/..%2f..%2f..%2fetc/passwd"
probe path_traversal juice_specific  block GET "/ftp/legal.md....//....//etc/passwd"

# ---------- Command Injection ----------
probe cmd_injection semicolon_cat block GET "/rest/products/search?q=apple%3Bcat+%2Fetc%2Fpasswd"
probe cmd_injection backticks     block GET "/rest/products/search?q=apple%60id%60"
probe cmd_injection pipe_whoami   block GET "/rest/products/search?q=apple%7Cwhoami"

# ---------- SSRF ----------
probe ssrf loopback_admin     block GET "/redirect?to=http%3A%2F%2Flocalhost%3A9443%2Fadmin"
probe ssrf imds_metadata      block GET "/redirect?to=http%3A%2F%2F169.254.169.254%2F"
probe ssrf file_scheme        block GET "/redirect?to=file%3A%2F%2F%2Fetc%2Fpasswd"

# ---------- Auth / IDOR ----------
probe auth admin_config_unauth allowed GET "/rest/admin/application-configuration"
probe auth list_all_users      allowed GET "/api/Users/"

# ---------- Header injection ----------
probe header long_ua            allowed GET "/" -A "$(printf 'A%.0s' {1..2000})"

# ---------- Bot / scanner UA ----------
probe bot sqlmap_ua             challenge GET "/" -A "sqlmap/1.7.2"
probe bot nikto_ua              challenge GET "/" -A "Mozilla/5.00 (Nikto/2.5.0)"
probe bot zap_ua                challenge GET "/" -A "OWASP ZAP/2.14.0"
probe bot generic_curl          allowed   GET "/" -A "curl/8.0.0"

# ---------- Rate limit burst (15 quick same-source hits) ----------
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  probe rate_limit "burst_${i}" rate_limit GET "/rest/products/reviews/1"
done

echo "rows: $(wc -l < "$OUT")"
