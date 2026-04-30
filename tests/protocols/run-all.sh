#!/usr/bin/env bash
# Drive every multi-protocol test in sequence.
#
# Each script skips cleanly when its dependency isn't met
# (curl without h2/h3, no TLS listener, etc.) so this can run
# against any deployment shape — dev, staging, production.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "==> 01 HTTP/1.1"
"$HERE/01-http1.sh"
echo
echo "==> 02 HTTP/2"
"$HERE/02-http2.sh"
echo
echo "==> 03 HTTP/3"
"$HERE/03-http3.sh"
echo
echo "==> 04 WebSocket"
"$HERE/04-websocket.sh"
echo
echo "==> 05 gRPC"
"$HERE/05-grpc.sh"
echo
echo "all multi-protocol tests passed (or skipped cleanly)"
