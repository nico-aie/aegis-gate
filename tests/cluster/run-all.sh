#!/usr/bin/env bash
# tests/cluster/run-all.sh — drive every cluster smoke test in
# sequence. Each script cleans up its own nodes/Redis on exit.
#
# Skips the whole track when:
#   - docker is not on $PATH
#   - the release binary at target/release/waf is missing
#
# Otherwise runs in dependency order:
#   1. 01-shared-counter   — proves Redis-backed sharing
#   2. 02-leader-failover  — proves cross-node lease
#   3. 03-rehydrate-readiness — proves the readiness gate
#   4. 04-partition-fallback  — proves partition + heal

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

for script in 01-shared-counter.sh 02-leader-failover.sh \
              03-rehydrate-readiness.sh 04-partition-fallback.sh; do
  echo "==================== $script ===================="
  "$HERE/$script"
  echo
done

echo "all cluster smoke tests passed"
