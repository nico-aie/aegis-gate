#!/usr/bin/env bash
# collect-audit.sh — gather + merge every node's local audit log into one
# fleet-wide, time-ordered stream (cluster plan Phase 4 / C-4).
#
# WHY: the cross-node live event feed (cluster Phase 2, `cluster.fleet_events`)
# is a LOSSY monitor — great for "what's happening now" on any node's
# dashboard, but it drops under load and during Redis outages. For the
# COMPLETE forensic record, each node's local `waf_audit.log` (+ SigNoz)
# remain the source of truth. In a leaderless fleet a round-robined request
# is decided on whichever node the LB picked, so its audit row lives only in
# THAT node's file. This script pulls every node's file and merges them,
# ordered by `ts_ms` and correlatable by `request_id` (every response also
# carries `X-WAF-Request-Id`).
#
# USAGE:
#   ./collect-audit.sh [-o OUT] [-p REMOTE_PATH] NODE [NODE ...]
#
#   NODE          ssh target for each fleet node (e.g. user@10.0.0.1)
#   -o OUT        merged output file            (default: ./fleet-audit.jsonl)
#   -p REMOTE_PATH path to waf_audit.log on each node
#                                               (default: /opt/aegis/waf_audit.log)
#
# EXAMPLE:
#   ./collect-audit.sh -o run42.jsonl waf@10.0.0.11 waf@10.0.0.12 waf@10.0.0.13
#   jq 'select(.request_id=="abc123")' run42.jsonl   # trace one request fleet-wide
#
# Requires: ssh/scp. `jq` is used for a robust numeric `ts_ms` sort when
# present; falls back to a key-prefixed `sort -n` otherwise.
set -euo pipefail

OUT="./fleet-audit.jsonl"
REMOTE_PATH="/opt/aegis/waf_audit.log"

while getopts "o:p:h" opt; do
  case "$opt" in
    o) OUT="$OPTARG" ;;
    p) REMOTE_PATH="$OPTARG" ;;
    h) sed -n '2,28p' "$0"; exit 0 ;;
    *) echo "see -h for usage" >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))

if [ "$#" -lt 1 ]; then
  echo "error: at least one NODE ssh target required (see -h)" >&2
  exit 2
fi

TMP="$(mktemp -d -t aegis-audit.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

echo "collecting ${REMOTE_PATH} from $# node(s) ..." >&2
for node in "$@"; do
  dest="$TMP/${node//[^A-Za-z0-9._-]/_}.jsonl"
  if scp -q "${node}:${REMOTE_PATH}" "$dest" 2>/dev/null; then
    echo "  ok   $node ($(wc -l < "$dest" | tr -d ' ') lines)" >&2
  else
    echo "  WARN $node — could not fetch ${REMOTE_PATH} (skipped)" >&2
  fi
done

shopt -s nullglob
files=("$TMP"/*.jsonl)
if [ "${#files[@]}" -eq 0 ]; then
  echo "error: no audit files fetched — nothing to merge" >&2
  exit 1
fi

echo "merging → ${OUT} (ordered by ts_ms) ..." >&2
if command -v jq >/dev/null 2>&1; then
  # Slurp every line, sort numerically by ts_ms, re-emit as JSONL.
  cat "${files[@]}" | jq -c -s 'sort_by(.ts_ms) | .[]' > "$OUT"
else
  # No jq: prefix each line with its ts_ms, numeric-sort, strip the key.
  # `ts_ms` is the contract's epoch-ms integer field (aegis-core audit §6).
  cat "${files[@]}" \
    | sed -E 's/^.*"ts_ms":([0-9]+).*$/\1\t&/' \
    | sort -n -k1,1 \
    | cut -f2- > "$OUT"
fi

echo "done: $(wc -l < "$OUT" | tr -d ' ') merged events in ${OUT}" >&2
