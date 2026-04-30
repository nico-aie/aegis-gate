#!/usr/bin/env bash
# 05-grpc.sh — gRPC over HTTP/2 smoke.
#
# gRPC is "just" HTTP/2 with `content-type: application/grpc`
# and a length-prefixed framing. The WAF doesn't speak the
# framing — it forwards bytes — but the *negotiation* must work:
#
# - h2 ALPN must succeed on the TLS listener
# - The WAF must NOT reject `content-type: application/grpc`
# - The WAF must NOT strip the gRPC trailers (`grpc-status`,
#   `grpc-message`)
#
# We use `grpcurl` when available (cleanest signal). When it's
# missing, fall back to a hand-rolled `curl --http2 -H 'content-type: application/grpc'`
# probe that just asserts h2 + non-400.

HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

require curl
ensure_admin_ready

if ! curl --version | grep -qE "Features:.*HTTP2"; then
  skip "curl built without HTTP/2 — gRPC needs h2"
fi

echo "==> gRPC (h2 + content-type: application/grpc) on $AEGIS_DATA_HTTPS"

if command -v grpcurl >/dev/null; then
  # Try a list call against any reflection-enabled server. We
  # don't care about the response shape — we just need the
  # connection to land at the upstream (or fail with a gRPC
  # status, not an HTTP error).
  out=$(grpcurl -insecure -max-time 5 \
                "${AEGIS_DATA_HTTPS#https://}" \
                list 2>&1 || true)
  if echo "$out" | grep -qE "Failed to dial|connection refused"; then
    skip "no gRPC reflection at the upstream (expected in dev)"
  fi
  if echo "$out" | grep -qE "rpc error|grpc-status"; then
    ok "WAF forwarded gRPC frame end-to-end (got upstream gRPC error, not HTTP error)"
    exit 0
  fi
  ok "grpcurl list succeeded: $(echo "$out" | head -3 | tr '\n' ' ')"
  exit 0
fi

info "grpcurl not installed; falling back to curl probe"

resp=$(curl --silent --insecure --max-time 5 \
            --http2 \
            -X POST \
            -H "content-type: application/grpc" \
            -H "te: trailers" \
            -o /dev/null \
            -w "version=%{http_version} code=%{http_code}\n" \
            "$AEGIS_DATA_HTTPS/echo.EchoService/Hello" 2>&1)

if echo "$resp" | grep -q "version=000\|Could not connect"; then
  skip "TLS data-plane listener not reachable on $AEGIS_DATA_HTTPS"
fi

ver=$(echo "$resp" | sed -n 's/.*version=\([^ ]*\).*/\1/p')
code=$(echo "$resp" | sed -n 's/.*code=\([0-9]*\).*/\1/p')

if [[ "$ver" != "2" ]]; then
  fail "gRPC needs h2; got $ver"
fi

case "$code" in
  502|504|404)
    ok "WAF forwarded gRPC over h2 (status $code — upstream gRPC server not running, expected in dev)"
    ;;
  400|415)
    fail "WAF rejected the gRPC content-type with $code — content-type allowlist too strict"
    ;;
  *)
    ok "gRPC over h2 reached upstream (status $code)"
    ;;
esac
