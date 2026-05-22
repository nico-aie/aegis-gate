#!/usr/bin/env bash
# Run every DR-T*.sh sequentially. First failure aborts.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
for s in dr-t1-headers.sh dr-t2-control.sh dr-t3-mode-cycle.sh \
         dr-t4-audit-preservation.sh dr-t5-correlation.sh \
         dr-t6-mode-enforcement.sh; do
  printf '\n==================== %s ====================\n' "$s"
  bash "$HERE/$s"
done
echo
echo "all interop dry-run scripts passed"
