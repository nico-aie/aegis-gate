#!/usr/bin/env bash
# 01-http1.sh — HTTP/1.1 plaintext smoke.
#
# Asserts the data plane accepts an HTTP/1.1 request on the
# plaintext listener and proxies it through to upstreams (or
# returns a deterministic gateway error when no upstream is up).

HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

require curl
ensure_admin_ready

echo "==> HTTP/1.1 plaintext on $AEGIS_DATA_HTTP"

# Force HTTP/1.1, capture both http_version and code.
out=$(curl --silent --max-time 5 \
           --http1.1 \
           -o /dev/null \
           -w "version=%{http_version} code=%{http_code}\n" \
           "$AEGIS_DATA_HTTP/")

ver=$(echo "$out" | sed -n 's/.*version=\([^ ]*\).*/\1/p')
code=$(echo "$out" | sed -n 's/.*code=\([0-9]*\).*/\1/p')

if [[ "$ver" != "1.1" ]]; then
  fail "expected HTTP/1.1, got $ver"
fi

# 502 is acceptable — the placeholder upstream is down in
# default dev. We just need to prove the proxy handled the
# request (status 502 means it tried to forward, not 000
# connect-refused).
if [[ "$code" == "000" ]]; then
  fail "connection refused / no listener on $AEGIS_DATA_HTTP"
fi

ok "HTTP/1.1 negotiated (response code $code)"
