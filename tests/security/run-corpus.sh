#!/usr/bin/env bash
# Aegis-Gate — corpus replay runner
#
# Usage:
#   ./tests/security/run-corpus.sh benign
#   ./tests/security/run-corpus.sh malicious [--class sqli]
#
# For the benign corpus: fails if ANY request is blocked.
# For the malicious corpus: fails if true-positive rate is below
# the per-class thresholds in corpus/malicious/INDEX.md.
#
# This is a thin skeleton — the full replay runner is implemented
# in M2 T2.4 once the rule engine can accept raw HTTP input.

set -euo pipefail

KIND="${1:-}"
CLASS=""
if [[ "${2:-}" == "--class" ]]; then
  CLASS="${3:-}"
fi

TARGET="${WAF_TARGET:-http://localhost:8080}"
CORPUS_DIR="$(dirname "$0")/corpus"

case "$KIND" in
  benign)
    DIR="$CORPUS_DIR/benign"
    EXPECT_BLOCK=0
    ;;
  malicious)
    DIR="$CORPUS_DIR/malicious${CLASS:+/$CLASS}"
    EXPECT_BLOCK=1
    ;;
  *)
    echo "usage: $0 <benign|malicious> [--class <name>]" >&2
    exit 64
    ;;
esac

if [[ ! -d "$DIR" ]]; then
  echo "corpus directory not found: $DIR" >&2
  exit 1
fi

TOTAL=0
BLOCKED=0
ALLOWED=0

while IFS= read -r -d '' file; do
  TOTAL=$((TOTAL + 1))
  # TODO(M2 T2.4): replay raw HTTP file via a small Rust helper;
  # for now we shell out to curl with a best-effort translation.
  url=$(awk 'NR==1 {print $2}' "$file")
  status=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}${url}" || echo 000)
  if [[ "$status" == "403" ]]; then
    BLOCKED=$((BLOCKED + 1))
  else
    ALLOWED=$((ALLOWED + 1))
  fi
done < <(find "$DIR" -name "*.http" -print0)

printf "total=%d blocked=%d allowed=%d\n" "$TOTAL" "$BLOCKED" "$ALLOWED"

if [[ "$EXPECT_BLOCK" == "0" && "$BLOCKED" -gt 0 ]]; then
  echo "FAIL: benign corpus saw $BLOCKED false positives" >&2
  exit 1
fi

if [[ "$EXPECT_BLOCK" == "1" && "$TOTAL" -gt 0 ]]; then
  RATE=$(( BLOCKED * 100 / TOTAL ))
  echo "true-positive rate: ${RATE}%"
  # Per-class thresholds enforced in the full runner (M2 T2.4).
fi
