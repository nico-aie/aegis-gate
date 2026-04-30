#!/usr/bin/env bash
# 02-http2.sh — HTTP/2 over TLS smoke.
#
# Asserts the TLS listener advertises `h2` in ALPN and that curl
# negotiates HTTP/2 against it. Skips cleanly when:
#   - The TLS listener isn't bound (operators run plain HTTP)
#   - curl was built without nghttp2 (rare; macOS ships it)

HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

require curl
ensure_admin_ready

# Curl HTTP/2 build check.
if ! curl --version | grep -qE "Features:.*HTTP2"; then
  skip "curl built without HTTP/2 support"
fi

echo "==> HTTP/2 (h2 ALPN) on $AEGIS_DATA_HTTPS"

# `--http2` requests h2; with `-k` we accept the self-signed
# dev cert. `%{http_version}` returns "2" when h2 negotiated.
out=$(curl --silent --insecure --max-time 5 \
           --http2 \
           -o /dev/null \
           -w "version=%{http_version} code=%{http_code} alpn=%{ssl_verify_result}\n" \
           "$AEGIS_DATA_HTTPS/" 2>&1)

if echo "$out" | grep -q "version=000\|Could not connect"; then
  skip "TLS data-plane listener not reachable on $AEGIS_DATA_HTTPS"
fi

ver=$(echo "$out" | sed -n 's/.*version=\([^ ]*\).*/\1/p')
code=$(echo "$out" | sed -n 's/.*code=\([0-9]*\).*/\1/p')

if [[ "$ver" != "2" ]]; then
  fail "expected HTTP/2, got $ver (curl negotiated h1 — check ALPN)"
fi

ok "HTTP/2 negotiated (response code $code)"

# Bonus check: explicit ALPN inspection via openssl.
if command -v openssl >/dev/null; then
  host_port=${AEGIS_DATA_HTTPS#https://}
  alpn=$(echo | openssl s_client -connect "$host_port" -alpn h2,http/1.1 \
           -servername "${host_port%:*}" 2>/dev/null \
           | grep -E "^ALPN protocol:" | head -1)
  if echo "$alpn" | grep -q "h2"; then
    ok "ALPN advertised: $(echo "$alpn" | sed 's/.*: //')"
  else
    info "openssl ALPN probe: $alpn (curl already confirmed h2 above)"
  fi
fi
