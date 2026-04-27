#!/usr/bin/env bash
# Aegis-Gate — etcd bootstrap
#
# Seeds the dev etcd with a minimal valid WafConfig so that
# `cargo run -p aegis-bin -- run` can boot without a chicken-and-egg.
# Idempotent: only writes if the key is absent, unless --force is given.
#
# Usage:
#   ./deploy/etcd/bootstrap.sh             # seed if absent
#   ./deploy/etcd/bootstrap.sh --force     # overwrite
#   ./deploy/etcd/bootstrap.sh --show      # print current value and exit
#
# Requires `etcdctl` on PATH (or run inside the aegis-etcd container).

set -euo pipefail

ETCD_ENDPOINTS="${ETCD_ENDPOINTS:-http://localhost:2379}"
KEY="${AEGIS_CONFIG_KEY:-/aegis/config/waf}"
SEED_FILE="${SEED_FILE:-$(dirname "$0")/seed.yaml}"

_etcdctl() {
  if command -v etcdctl >/dev/null 2>&1; then
    etcdctl --endpoints="$ETCD_ENDPOINTS" "$@"
  else
    docker exec aegis-etcd etcdctl --endpoints="$ETCD_ENDPOINTS" "$@"
  fi
}

case "${1:-}" in
  --show)
    _etcdctl get "$KEY" --print-value-only
    exit 0
    ;;
  --force)
    FORCE=1
    ;;
  "")
    FORCE=0
    ;;
  *)
    echo "usage: $0 [--show|--force]" >&2
    exit 64
    ;;
esac

if [[ ! -f "$SEED_FILE" ]]; then
  echo "seed file not found: $SEED_FILE" >&2
  exit 1
fi

EXISTING=$(_etcdctl get "$KEY" --print-value-only || true)
if [[ -n "$EXISTING" && "$FORCE" != "1" ]]; then
  echo "key $KEY already set (use --force to overwrite)"
  exit 0
fi

_etcdctl put "$KEY" -- "$(cat "$SEED_FILE")"
echo "seeded $KEY from $SEED_FILE"
