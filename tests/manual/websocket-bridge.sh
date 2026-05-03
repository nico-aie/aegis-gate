#!/usr/bin/env bash
# tests/manual/websocket-bridge.sh
#
# Drives a real WebSocket session through the WAF's data plane to a
# local echo backend.  Prereqs:
#   - `make run-dev` is up
#   - `websocat` (or `wscat`) is installed
#   - one route in your dev YAML resolves the host you'll use
#     ("ws.local" by default) to a pool whose member is a local WS
#     echo backend.
#
# The WS echo backend can be any tiny tool — example with a stock
# `python -m websockets`:
#     python3 -m pip install websockets
#     python3 -c "
# import asyncio, websockets
# async def echo(ws): \
#   async for m in ws: await ws.send(m)
# asyncio.run(websockets.serve(echo, 'localhost', 9091).__await__().send(None))
#     "
# (or run any tiny echo server on port 9091)

set -euo pipefail

AEGIS_DATA="${AEGIS_DATA:-127.0.0.1:8080}"
WS_HOST="${WS_HOST:-ws.local}"
WS_PATH="${WS_PATH:-/ws}"

if ! command -v websocat >/dev/null && ! command -v wscat >/dev/null; then
  echo "FAIL: install websocat (cargo install websocat) or wscat (npm i -g wscat)"
  exit 1
fi
TOOL=$(command -v websocat || command -v wscat)

URL="ws://${AEGIS_DATA}${WS_PATH}"
echo "==> connecting via $TOOL → $URL with Host: $WS_HOST"
echo "    (the WAF will route this to the upstream pool that"
echo "     matches the configured host)"

case "$TOOL" in
  *websocat*)
    echo "hello-from-bridge-validation" | \
      "$TOOL" -t -H "Host: $WS_HOST" "$URL" || true
    ;;
  *wscat*)
    # wscat doesn't take stdin → message in non-interactive mode the
    # same way; the operator is expected to type into the prompt.
    "$TOOL" -c "$URL" -H "Host: $WS_HOST" \
      -x "hello-from-bridge-validation" || true
    ;;
esac

echo
echo "Expected:"
echo "  - websocat / wscat exits cleanly with the echoed message"
echo "  - 'docker logs' / journal of the WAF shows:"
echo "      websocket_open ... ws_bridge_started"
echo "      websocket_close ... ws_bridge_closed (with byte counters)"
echo "  - if you see 'BAD_GATEWAY: websocket_no_healthy_member',"
echo "    your upstream echo backend isn't running on the configured"
echo "    pool member."
