#!/usr/bin/env bash
# 04-websocket.sh — WebSocket upgrade smoke.
#
# Asserts the WAF passes through the `Upgrade: websocket`
# handshake. We don't need a real WS upstream — we just need
# the WAF to recognise the upgrade and either:
#   (a) forward to upstream (101 Switching Protocols if WS upstream is up)
#   (b) cleanly fail with a non-400 (e.g. 502 from a dead upstream)
#       — the WAF must NOT have rejected the handshake on its own.
#
# A 400 on the WAF's side would mean it stripped the upgrade
# headers, which would break legitimate WS clients.

HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

require curl
ensure_admin_ready

echo "==> WebSocket upgrade smoke on $AEGIS_DATA_HTTP"

# 16 random bytes, base64 — what real browsers send.
KEY=$(head -c 16 /dev/urandom | base64)

resp=$(curl --silent --max-time 5 -i \
            -H "Connection: Upgrade" \
            -H "Upgrade: websocket" \
            -H "Sec-WebSocket-Version: 13" \
            -H "Sec-WebSocket-Key: $KEY" \
            "$AEGIS_DATA_HTTP/ws" 2>&1)

if echo "$resp" | grep -q "Could not connect\|Connection refused"; then
  fail "data plane refused connection on $AEGIS_DATA_HTTP"
fi

# Pull the status code from the first line.
status=$(echo "$resp" | head -1 | grep -oE '[0-9]{3}' | head -1)

case "$status" in
  101)
    ok "WebSocket upgrade accepted (101 Switching Protocols)"
    ;;
  502|504)
    ok "WAF forwarded the upgrade (status $status — upstream WS server not running, expected in dev)"
    ;;
  400|426)
    fail "WAF rejected the upgrade with $status — Upgrade headers were stripped or WS support is off"
    ;;
  *)
    info "got status $status — not a clear pass/fail; check the WAF logs"
    ;;
esac
