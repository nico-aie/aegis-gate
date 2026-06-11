#!/usr/bin/env bash
# Native (host) nginx LB control — no root, no Docker. See nginx-stream-native.conf
# for WHY (rootless Docker SNATs the client IP; native nginx sees the real source).
#
#   ./native-lb.sh start|stop|reload|test|status
set -euo pipefail
PFX="$(cd "$(dirname "${BASH_SOURCE[0]}")/native" && pwd)"
CONF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/nginx-stream-native.conf"
NGINX=(conda run -n nginx-lb nginx -p "$PFX" -c "$CONF")

case "${1:-status}" in
  test)   "${NGINX[@]}" -t ;;
  start)  "${NGINX[@]}" -t && "${NGINX[@]}" && echo "native nginx LB started (pid $(cat "$PFX/run/nginx.pid" 2>/dev/null||echo ?))" ;;
  reload) "${NGINX[@]}" -t && "${NGINX[@]}" -s reload && echo "reloaded" ;;
  stop)   "${NGINX[@]}" -s quit && echo "stopped" ;;
  status) ss -ltn 2>/dev/null | grep -E ':(56208|56243|56244|56245)\b' || echo "(no LB ports listening)" ;;
  *) echo "usage: $0 start|stop|reload|test|status"; exit 1 ;;
esac
