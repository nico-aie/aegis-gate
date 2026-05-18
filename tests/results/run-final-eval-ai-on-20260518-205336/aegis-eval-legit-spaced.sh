#!/usr/bin/env bash
export PATH=/usr/bin:/bin:/usr/sbin:/sbin:$PATH
set -u

WAF="${WAF:-http://127.0.0.1:8080}"
OUT="${1:?usage: $0 OUT_PSV}"
HDR=/tmp/aegis-eval-hdrs-legit
BODY=/tmp/aegis-eval-body-legit
: > "$OUT"

probe() {
  local label="$1" method="$2" path="$3"; shift 3
  local code action rule
  code=$(curl -s -o "$BODY" -w "%{http_code}" -D "$HDR" -X "$method" \
    -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605 Safari/605' \
    -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9' \
    -H 'Accept-Language: en-US,en;q=0.9' \
    -H 'Referer: https://example.com/' \
    "$@" "$WAF$path" 2>/dev/null || echo 000)
  action=$(awk 'BEGIN{IGNORECASE=1} /^x-waf-action:/ {gsub(/[\r\n]/,""); print substr($0,index($0,":")+2)}' "$HDR" | tail -1 | tr -d ' ')
  rule=$(awk 'BEGIN{IGNORECASE=1} /^x-waf-rule-id:/ {gsub(/[\r\n]/,""); print substr($0,index($0,":")+2)}' "$HDR" | tail -1 | tr -d ' ')
  printf '%s|%s|%s|%s\n' "$label" "$code" "${action:-allow}" "${rule:-none}" >> "$OUT"
  sleep 2
}

printf 'label|http|action|rule\n' >> "$OUT"
probe home               GET  "/"
probe api_list           GET  "/api/list?page=1&limit=10"
probe static_js          GET  "/static/app.js"
probe favicon            GET  "/favicon.ico"
probe product_search     GET  "/rest/products/search?q=apple"
probe health_app         GET  "/api/health"
probe unicode_query      GET  "/search?q=cafe%CC%81"
probe utf8_emoji         GET  "/search?q=%F0%9F%98%80"
probe long_url_safe      GET  "/api/list?page=2&limit=20&sort=created_desc"
probe login_clean        POST "/api/login" -H "Content-Type: application/json" --data '{"email":"u@example.com","password":"pw1234"}'
probe product_detail     GET  "/rest/products/1"
probe contact_form       POST "/contact" -H "Content-Type: application/json" --data '{"name":"Alice","message":"Hello team, when is the next release scheduled?"}'
probe oauth_callback     GET  "/oauth/callback?code=abc123&state=xyz"
probe paginated_orders   GET  "/api/orders?from=2026-01-01&to=2026-02-01"
probe search_typed       GET  "/search?q=running+shoes+size+10"
probe upload_meta        POST "/api/upload/init" -H "Content-Type: application/json" --data '{"filename":"report.pdf","size":1048576}'
probe metrics_proxy      GET  "/api/metrics?metric=cpu&range=1h"
probe news_article       GET  "/news/2026/02/release-notes"
probe localised_view     GET  "/?lang=zh-TW"
probe webhook_ping       POST "/webhooks/stripe" -H "Content-Type: application/json" --data '{"id":"evt_123","type":"ping"}'

echo "rows: $(wc -l < "$OUT")"
