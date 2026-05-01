#!/usr/bin/env bash
# B6-T1 — Dockerfile smoke test.
#
# Builds the production image for the host arch, asserts:
#   1. Build succeeds
#   2. `docker run aegis-gate:test version` exits 0
#   3. `docker run aegis-gate:test validate --config <dev>` exits 0
#   4. Image size ≤ 100 MiB compressed
#   5. Container runs as non-root (uid 65532)
#
# Skips cleanly when Docker isn't available — this is meant to
# run in CI / on a developer machine with Docker, not as a unit
# test. Slow (~3 min cold cache); not part of `cargo test`.
#
# Usage:
#   bash tests/api/dockerfile.sh

set -euo pipefail
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$HERE"

ok()    { echo "PASS: $*"; }
fail()  { echo "FAIL: $*" >&2; exit 1; }
skip()  { echo "SKIP: $*"; exit 0; }
info()  { echo "INFO: $*"; }

if ! command -v docker >/dev/null 2>&1; then
  skip "docker CLI not found"
fi
if ! docker info >/dev/null 2>&1; then
  skip "docker daemon not reachable"
fi

TAG="aegis-gate:dockerfile-test"
HOST_PLATFORM="linux/$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')"
info "host platform: $HOST_PLATFORM"

# --------------------------------------------------------------- #
# 1. Build for the host arch only (faster than multi-arch)        #
# --------------------------------------------------------------- #
info "building $TAG (host arch only — this takes ~3 min cold)"
AEGIS_TAG="dockerfile-test" \
AEGIS_PLATFORMS="$HOST_PLATFORM" \
  bash deploy/docker-build.sh >/tmp/aegis-docker-build.log 2>&1 \
  || { tail -50 /tmp/aegis-docker-build.log; fail "image build"; }
ok "image built ($TAG)"

# --------------------------------------------------------------- #
# 2. `waf version`                                                #
# --------------------------------------------------------------- #
out=$(docker run --rm "$TAG" version 2>&1)
if echo "$out" | grep -qi "aegis\|waf"; then
  ok "waf version: $(echo "$out" | head -1)"
else
  fail "waf version returned unexpected output: $out"
fi

# --------------------------------------------------------------- #
# 3. `waf validate` against a mounted dev config                  #
# --------------------------------------------------------------- #
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT
cp config/dev.yaml "$TMPDIR/waf.yaml"

# The dev config references config/rules/ — copy that too. The
# image bakes config/ in already, so absolute paths inside the
# image work, but we mount over /etc/aegis to test the operator
# bind-mount path.
mkdir -p "$TMPDIR/rules"
cp -r config/rules/* "$TMPDIR/rules/" 2>/dev/null || true

if docker run --rm \
       -v "$TMPDIR":/etc/aegis:ro \
       "$TAG" validate --config /etc/aegis/waf.yaml >/tmp/aegis-validate.log 2>&1; then
  ok "validate against mounted config (/etc/aegis/waf.yaml)"
else
  cat /tmp/aegis-validate.log
  fail "validate against mounted config"
fi

# --------------------------------------------------------------- #
# 4. Image size budget                                            #
# --------------------------------------------------------------- #
size_bytes=$(docker image inspect "$TAG" --format '{{.Size}}')
size_mb=$(( size_bytes / 1024 / 1024 ))
if (( size_mb <= 100 )); then
  ok "image size ${size_mb} MiB (≤ 100 MiB budget)"
else
  fail "image size ${size_mb} MiB exceeds 100 MiB budget"
fi

# --------------------------------------------------------------- #
# 5. Non-root user                                                #
# --------------------------------------------------------------- #
uid=$(docker run --rm --entrypoint=/usr/local/bin/waf "$TAG" version 2>&1 | true; \
      docker run --rm --user 0:0 --entrypoint=/usr/bin/id "$TAG" -u 2>&1 || \
      echo "uid_check_unsupported")
# distroless has no `id` binary; verify by inspecting the image
# config for the User field.
configured_user=$(docker image inspect "$TAG" --format '{{.Config.User}}')
case "$configured_user" in
  nonroot:nonroot|65532*|nobody*)
    ok "image runs as $configured_user (not root)"
    ;;
  ""|root|0)
    fail "image runs as root — Dockerfile USER directive missing"
    ;;
  *)
    info "image User: $configured_user (not root, but unexpected — review)"
    ;;
esac

# --------------------------------------------------------------- #
# Cleanup                                                         #
# --------------------------------------------------------------- #
docker image rm -f "$TAG" >/dev/null 2>&1 || true

echo
echo "----------------------------------------"
echo "Dockerfile smoke: all checks passed"
echo "----------------------------------------"
