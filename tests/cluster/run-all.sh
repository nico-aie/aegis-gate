#!/usr/bin/env bash
# tests/cluster/run-all.sh — drive every cluster smoke test in
# sequence. Each script cleans up its own nodes/Redis on exit.
#
# Skips the whole track when:
#   - docker is not on $PATH
#   - the release binary at target/release/waf is missing
#
# Otherwise runs in dependency order:
#   1. 01-shared-counter      — proves Redis-backed state sharing
#   2. 02-leaderless-roster   — proves the flat leaderless roster (P1)
#   3. 03-rehydrate-readiness — proves the readiness gate
#   4. 04-partition-fallback  — proves partition + heal
#   5. 07-control-plane-sync  — proves cluster-native set_profile (C-1)
#   6. 08-fleet-events        — proves cross-node event fanout (P2)
#   7. 09-fleet-view          — proves merged fleet metrics view (P3)

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

if ! command -v docker >/dev/null 2>&1; then
  echo "SKIP: docker not on PATH — cluster tests need a redis container"
  exit 0
fi

if [[ ! -x "$HERE/../../target/release/waf" ]]; then
  echo "SKIP: target/release/waf not built — \`cargo build -p aegis-bin --release\` first"
  exit 0
fi

trap 'echo "tests/cluster/run-all.sh aborted"; exit 1' ERR

for script in 01-shared-counter.sh 02-leaderless-roster.sh \
              03-rehydrate-readiness.sh 04-partition-fallback.sh \
              07-control-plane-sync.sh 08-fleet-events.sh 09-fleet-view.sh; do
  echo "==================== $script ===================="
  "$HERE/$script"
  echo
done

# Opt-in LB tests (HA-T2). Off by default because they pull
# the haproxy:2.9-alpine image and bring up an extra
# container; not every dev iteration needs them. Set
# `AEGIS_LB_TESTS=1` (or pass --lb) to run.
if [[ "${AEGIS_LB_TESTS:-0}" == "1" || "${1:-}" == "--lb" ]]; then
  for script in 05-single-vip-baseline.sh 06-mid-burst-failover.sh; do
    echo "==================== $script ===================="
    "$HERE/$script"
    echo
  done
  echo "all cluster smoke tests + LB tests passed"
else
  echo "(LB tests skipped — set AEGIS_LB_TESTS=1 or pass --lb to run 05/06)"
  echo "all cluster smoke tests passed"
fi
