#!/usr/bin/env bash
# E2E + smoke probes against the live WAF (AI detector ON).
export PATH=/usr/bin:/bin:/usr/sbin:/sbin:$PATH
set -u

WAF="${WAF:-http://127.0.0.1:8080}"
OUT="${1:?usage: $0 OUT_PSV}"
HDR=/tmp/aegis-eval-hdrs
BODY=/tmp/aegis-eval-body
: > "$OUT"

probe() {
  local cat="$1" label="$2" expected="$3" method="$4" path="$5"
  shift 5
  local code action rid rule ai_class ai_conf
  code=$(curl -s -o "$BODY" -w "%{http_code}" -D "$HDR" -X "$method" \
    -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)' \
    "$@" "$WAF$path" 2>/dev/null || echo 000)
  action=$(awk 'BEGIN{IGNORECASE=1} /^x-waf-action:/ {gsub(/[\r\n]/,""); print substr($0,index($0,":")+2)}' "$HDR" | tail -1 | tr -d ' ')
  rid=$(awk 'BEGIN{IGNORECASE=1} /^x-waf-request-id:/ {gsub(/[\r\n]/,""); print substr($0,index($0,":")+2)}' "$HDR" | tail -1 | tr -d ' ')
  rule=$(awk 'BEGIN{IGNORECASE=1} /^x-waf-rule-id:/ {gsub(/[\r\n]/,""); print substr($0,index($0,":")+2)}' "$HDR" | tail -1 | tr -d ' ')
  ai_class=$(awk 'BEGIN{IGNORECASE=1} /^x-waf-ai-class:/ {gsub(/[\r\n]/,""); print substr($0,index($0,":")+2)}' "$HDR" | tail -1 | tr -d ' ')
  ai_conf=$(awk 'BEGIN{IGNORECASE=1} /^x-waf-ai-confidence:/ {gsub(/[\r\n]/,""); print substr($0,index($0,":")+2)}' "$HDR" | tail -1 | tr -d ' ')
  printf '%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
    "$cat" "$label" "$expected" "$code" \
    "${action:-none}" "${rule:-none}" "${rid:-none}" \
    "${ai_class:-na}" "${ai_conf:-na}" >> "$OUT"
}

# header
printf 'category|label|expected|http|action|rule|request_id|ai_class|ai_conf\n' >> "$OUT"

# Legit baseline (FP check)
probe legit home              allowed  GET  "/"
probe legit api_list          allowed  GET  "/api/list"
probe legit static_js         allowed  GET  "/static/app.js"
probe legit favicon           allowed  GET  "/favicon.ico"
probe legit product_search    allowed  GET  "/rest/products/search?q=apple"
probe legit health_app        allowed  GET  "/api/health"
probe legit login_clean       allowed  POST "/api/login" -H "Content-Type: application/json" --data '{"email":"u@example.com","password":"pw1234"}'
probe legit unicode_query     allowed  GET  "/search?q=cafe%CC%81"
probe legit utf8_emoji        allowed  GET  "/search?q=%F0%9F%98%80"
probe legit long_url_safe     allowed  GET  "/api/list?page=2&limit=20&sort=created_desc"

# SQLi
probe sqli login_or1eq1       block    POST "/rest/user/login" -H "Content-Type: application/json" --data-raw "{\"email\":\"' OR 1=1--\",\"password\":\"x\"}"
probe sqli search_union       block    GET  "/rest/products/search?q=apple%27))%20UNION%20SELECT%20*%20FROM%20users--"
probe sqli search_drop        block    GET  "/rest/products/search?q=%27;drop+table+users--"
probe sqli sleep              block    GET  "/rest/products/search?q=1%27%20AND%20SLEEP(5)--"
probe sqli extract_value      block    GET  "/api/q?u=1%27%20AND%20extractvalue(1,concat(0x7e,(SELECT%20version())))--"

# XSS
probe xss script_tag          block    GET  "/q?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
probe xss img_onerror         block    GET  "/q?q=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E"
probe xss svg_onload          block    GET  "/q?q=%3Csvg%2Fonload%3Dalert(1)%3E"
probe xss js_uri              block    GET  "/q?q=javascript%3Aalert(document.cookie)"

# Path traversal
probe path deep_dots          block    GET  "/static/../../../../../../etc/passwd"
probe path url_encoded        block    GET  "/static/..%2f..%2f..%2fetc%2fpasswd"
probe path nested             block    GET  "/files/legal.md....//....//etc/passwd"

# SSRF
probe ssrf imds               block    GET  "/redirect?to=http%3A%2F%2F169.254.169.254%2F"
probe ssrf file_scheme        block    GET  "/redirect?to=file%3A%2F%2F%2Fetc%2Fpasswd"
probe ssrf loopback           block    GET  "/redirect?to=http%3A%2F%2Flocalhost%3A9443%2Fadmin"

# Command injection
probe cmd semicolon_cat       block    GET  "/q?q=apple%3Bcat+%2Fetc%2Fpasswd"
probe cmd backticks           block    GET  "/q?q=apple%60id%60"
probe cmd pipe_whoami         block    GET  "/q?q=apple%7Cwhoami"

# Header injection
probe hdr crlf_inject         block    GET  "/" -H $'X-Foo: bar\r\nX-Injected: yes'

# Recon — scanner UAs
probe recon sqlmap            block    GET  "/" -A "sqlmap/1.7.2"
probe recon nikto             block    GET  "/" -A "Mozilla/5.00 (Nikto/2.5.0)"
probe recon zap               block    GET  "/" -A "OWASP ZAP/2.14.0"

echo "rows: $(wc -l < "$OUT")"
