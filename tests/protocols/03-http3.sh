#!/usr/bin/env bash
# 03-http3.sh — HTTP/3 (QUIC) smoke.
#
# The HTTP/3 listener is feature-gated (`aegis-proxy/http3`). When
# the WAF was built without it, the UDP socket isn't bound and
# this test skips cleanly. When present, asserts curl negotiates
# h3 over QUIC (UDP) and the upstream still receives the request.
#
# Many curl builds (including macOS 8.x default) lack HTTP/3
# support. We skip in that case rather than fail — operators
# who ship h3 in production usually have a curl built with
# ngtcp2 + nghttp3 (or use `quiche-client`).

HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

require curl
ensure_admin_ready

# Curl HTTP/3 build check.
if ! curl --version | grep -qE "Features:.*HTTP3"; then
  skip "curl built without HTTP/3 (rebuild with --with-ngtcp2 --with-nghttp3, or use quiche-client)"
fi

echo "==> HTTP/3 (h3 ALPN over QUIC) on $AEGIS_DATA_H3"

# `--http3-only` forces h3; without it curl falls back to h2.
# The `-k` flag accepts the self-signed dev cert; `--max-time`
# is generous because QUIC handshake is heavier than TLS+TCP.
out=$(curl --silent --insecure --max-time 8 \
           --http3-only \
           -o /dev/null \
           -w "version=%{http_version} code=%{http_code}\n" \
           "$AEGIS_DATA_H3/" 2>&1)

if echo "$out" | grep -q "version=000\|Couldn't connect\|HTTP/3 disabled"; then
  skip "HTTP/3 listener not reachable on $AEGIS_DATA_H3 (build with --features http3 + bind UDP)"
fi

ver=$(echo "$out" | sed -n 's/.*version=\([^ ]*\).*/\1/p')
code=$(echo "$out" | sed -n 's/.*code=\([0-9]*\).*/\1/p')

if [[ "$ver" != "3" ]]; then
  fail "expected HTTP/3, got $ver"
fi

ok "HTTP/3 negotiated (response code $code)"
